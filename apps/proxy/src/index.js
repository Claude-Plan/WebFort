// apps/proxy/src/index.js
import http from 'node:http';
import httpProxy from 'http-proxy';
import crypto from 'node:crypto';
import dotenv from 'dotenv';
import { WafEngine, evaluateRule } from '@patchproof/waf-engine';

dotenv.config();

const PROXY_PORT = parseInt(process.env.PROXY_PORT || '8080', 10);
const TARGET_URL = process.env.TARGET_URL || 'http://localhost:3001';
const API_URL = `http://localhost:${process.env.API_PORT || '4000'}`;
const INTERNAL_TOKEN = process.env.INTERNAL_TOKEN || 'sec_tok_patchproof_2026_demo_internal_token_xyz';
const FAIL_MODE = process.env.FAIL_MODE || 'open';

const wafEngine = new WafEngine([]);
let currentEtag = '';
let targetId = null;

// Proxy instance
const proxy = httpProxy.createProxyServer({
  target: TARGET_URL,
  changeOrigin: true,
  autoRewrite: true
});

proxy.on('error', (err, req, res) => {
  console.error('[Proxy Error]', err.message);
  if (!res.headersSent) {
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: { code: 'BAD_GATEWAY', message: err.message } }));
  }
});

// Cache for candidate rules during verification
const candidateRuleCache = new Map();

async function fetchCandidateRule(patchId) {
  if (candidateRuleCache.has(patchId)) {
    const cached = candidateRuleCache.get(patchId);
    if (Date.now() - cached.ts < 5000) return cached.rule;
  }
  try {
    const resp = await fetch(`${API_URL}/internal/v1/rules/candidate/${patchId}`, {
      headers: { 'X-Internal-Token': INTERNAL_TOKEN }
    });
    if (resp.ok) {
      const data = await resp.json();
      candidateRuleCache.set(patchId, { rule: data.rule, ts: Date.now() });
      return data.rule;
    }
  } catch (err) {
    console.error(`[Proxy] Failed to fetch candidate rule ${patchId}:`, err.message);
  }
  return null;
}

// Background polling for deployed rules
async function pollActiveRules() {
  try {
    const url = targetId
      ? `${API_URL}/internal/v1/rules/active?target_id=${targetId}`
      : `${API_URL}/internal/v1/rules/active`;
    const headers = { 'X-Internal-Token': INTERNAL_TOKEN };
    if (currentEtag) headers['If-None-Match'] = currentEtag;

    const resp = await fetch(url, { headers });
    if (resp.status === 200) {
      currentEtag = resp.headers.get('etag') || '';
      const body = await resp.json();
      if (Array.isArray(body.rules)) {
        wafEngine.setRules(body.rules);
      }
    }
  } catch (err) {
    // Non-fatal, poll again
  }
}

setInterval(pollActiveRules, 2000);
pollActiveRules();

// Fire-and-forget event reporter
const eventQueue = [];
let flushTimeout = null;

function recordEvent(event) {
  eventQueue.push(event);
  if (eventQueue.length >= 10) {
    flushEvents();
  } else if (!flushTimeout) {
    flushTimeout = setTimeout(flushEvents, 500);
  }
}

async function flushEvents() {
  if (flushTimeout) {
    clearTimeout(flushTimeout);
    flushTimeout = null;
  }
  if (eventQueue.length === 0) return;

  const batch = eventQueue.splice(0, eventQueue.length);
  try {
    await fetch(`${API_URL}/internal/v1/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Token': INTERNAL_TOKEN
      },
      body: JSON.stringify({ events: batch })
    });
  } catch {
    // Swallow network errors on fire-and-forget
  }
}

// HTTP Server
const server = http.createServer(async (req, res) => {
  const requestId = crypto.randomUUID();
  const startTime = performance.now();

  // Read entire body for inspection if content length or chunked
  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', async () => {
    const rawBodyBuffer = Buffer.concat(chunks);
    const bodyStr = rawBodyBuffer.toString('utf-8');

    // Parse URL & Query
    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const query = {};
    for (const [k, v] of parsedUrl.searchParams.entries()) {
      if (query[k]) {
        if (Array.isArray(query[k])) query[k].push(v);
        else query[k] = [query[k], v];
      } else {
        query[k] = v;
      }
    }

    const inspectableReq = {
      method: req.method,
      url: req.url,
      path: parsedUrl.pathname,
      rawQuery: parsedUrl.search.replace(/^\?/, ''),
      query,
      headers: req.headers,
      body: bodyStr
    };

    try {
      let evaluation = null;
      let evaluatedRuleId = null;
      let evaluatedPatchId = null;

      // Check if this request is a verification candidate evaluation
      const verifyPatchId = req.headers['x-shield-verify-patch'];
      const verifyToken = req.headers['x-shield-verify-token'];

      if (verifyPatchId && verifyToken === INTERNAL_TOKEN) {
        const candidateRule = await fetchCandidateRule(verifyPatchId);
        if (candidateRule) {
          // In verification, candidate rule evaluates with enforce mode
          const testRule = { ...candidateRule, mode: 'enforce' };
          evaluation = evaluateRule(testRule, inspectableReq);
          evaluatedRuleId = testRule.id || testRule.name;
          evaluatedPatchId = verifyPatchId;
        }
      }

      // If no verification rule was evaluated, evaluate deployed active rules
      if (!evaluation) {
        evaluation = wafEngine.inspectRequest(inspectableReq);
        evaluatedRuleId = evaluation.rule_id;
      }

      const latencyMs = Math.round((performance.now() - startTime) * 100) / 100;

      // Set diagnostic response headers
      res.setHeader('X-Request-Id', requestId);
      res.setHeader('X-Shield-Decision', evaluation.decision);
      res.setHeader('X-Shield-Would-Block', evaluation.would_block ? '1' : '0');
      if (evaluatedRuleId) {
        res.setHeader('X-Shield-Rule', evaluatedRuleId);
      }

      // Record Proxy Event
      recordEvent({
        ts: new Date().toISOString(),
        method: req.method,
        path: parsedUrl.pathname,
        decision: evaluation.decision,
        rule_id: evaluatedRuleId,
        patch_id: evaluatedPatchId,
        latency_ms: latencyMs,
        status_code: evaluation.decision === 'block' ? 403 : 200,
        meta: {
          would_block: evaluation.would_block,
          matched_target: evaluation.matched_target,
          matched_value: evaluation.matched_value
        }
      });

      // Handle Blocking Decision
      if (evaluation.decision === 'block') {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          blocked: true,
          rule_id: evaluatedRuleId || 'shield_rule',
          request_id: requestId,
          message: 'Request blocked by PatchProof WAF virtual patch'
        }));
        return;
      }

      // Forward request to victim lab target
      // Re-stream buffered body
      proxy.web(req, res, {
        target: TARGET_URL,
        buffer: {
          pipe: (dest) => {
            if (rawBodyBuffer.length > 0) {
              dest.write(rawBodyBuffer);
            }
            dest.end();
          }
        }
      });

    } catch (err) {
      console.error('[Engine Exception]', err);
      const latencyMs = Math.round((performance.now() - startTime) * 100) / 100;

      recordEvent({
        ts: new Date().toISOString(),
        method: req.method,
        path: parsedUrl.pathname,
        decision: 'error',
        latency_ms: latencyMs,
        status_code: 500,
        meta: { error: err.message }
      });

      if (FAIL_MODE === 'open') {
        // Forward despite engine error
        proxy.web(req, res, {
          target: TARGET_URL,
          buffer: {
            pipe: (dest) => {
              if (rawBodyBuffer.length > 0) dest.write(rawBodyBuffer);
              dest.end();
            }
          }
        });
      } else {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { code: 'ENGINE_ERROR', message: err.message } }));
      }
    }
  });
});

server.listen(PROXY_PORT, () => {
  console.log(`[PatchProof Proxy] Data-plane listening on port ${PROXY_PORT} -> ${TARGET_URL}`);
});
