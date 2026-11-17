// apps/api/src/routes/attack-lab.js
import express from 'express';
import crypto from 'node:crypto';
import dotenv from 'dotenv';
import { RECIPES } from '../recipes/index.js';
import { query } from '../db/index.js';
import { computePriorityScore } from '@patchproof/contracts';

dotenv.config();

const router = express.Router();
const TARGET_URL = process.env.TARGET_URL || 'http://localhost:3001';
const PROXY_URL = process.env.PROXY_URL || 'http://localhost:8080';

// Redact sensitive secrets, hashes, and tokens per Section 4 requirements
export function redactSensitiveData(input) {
  if (typeof input !== 'string') {
    if (input && typeof input === 'object') {
      return JSON.parse(JSON.stringify(input, (key, value) => {
        if (typeof value === 'string') return redactSensitiveData(value);
        return value;
      }));
    }
    return input;
  }
  return input
    // Redact bcrypt hashes: $2a$10$...
    .replace(/\$2[aby]\$\d+\$[A-Za-z0-9./]{20,}/g, '[REDACTED_PASSWORD_HASH]')
    // Redact JWT tokens: eyJ...
    .replace(/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, '[REDACTED_JWT_TOKEN]')
    // Redact raw password fields
    .replace(/("password"\s*:\s*)"[^"]+"/gi, '$1"[REDACTED_PASSWORD]"');
}

// 1. Direct Target Attack (PATH A - Unprotected)
router.post('/attack-lab/direct', async (req, res) => {
  const recipeId = req.body?.recipe_id || 'R1';
  const recipe = RECIPES[recipeId];
  if (!recipe) {
    return res.status(400).json({ error: { message: `Unknown recipe: ${recipeId}` } });
  }

  const requestId = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const reqUrl = `${TARGET_URL}${recipe.exploit_request.url}`;
  const reqHeaders = {
    ...recipe.exploit_request.headers,
    'X-Request-Id': requestId,
    'User-Agent': 'PatchProof-AttackLab/1.0 (Direct-Probe)'
  };

  const t0 = performance.now();
  let statusCode = 0;
  let statusText = '';
  let respHeaders = {};
  let bodyText = '';
  let reachedTarget = false;

  try {
    const fetchOptions = {
      method: recipe.exploit_request.method,
      headers: reqHeaders
    };
    if (recipe.exploit_request.body) {
      fetchOptions.body = recipe.exploit_request.body;
    }

    const resp = await fetch(reqUrl, fetchOptions);
    statusCode = resp.status;
    statusText = resp.statusText;
    reachedTarget = true;
    bodyText = await resp.text();

    resp.headers.forEach((val, key) => {
      if (['content-type', 'access-control-allow-origin', 'date', 'server', 'connection'].includes(key.toLowerCase())) {
        respHeaders[key] = val;
      }
    });
  } catch (err) {
    statusCode = 502;
    statusText = 'Bad Gateway';
    bodyText = JSON.stringify({ error: `Connection to bare target failed: ${err.message}` });
  }

  const latencyMs = Math.round((performance.now() - t0) * 100) / 100;

  // Evaluate Exploit Oracle: must match actual vulnerable behavior (not HTTP 200 alone)
  let oracleMatched = false;
  if (recipe.exploit_oracle?.success_body_regex) {
    const re = new RegExp(recipe.exploit_oracle.success_body_regex, 'i');
    oracleMatched = re.test(bodyText);
  }
  const exploitConfirmed = oracleMatched && (recipe.exploit_oracle.success_status || [200]).includes(statusCode);

  // Redact evidence for display
  const sanitizedBody = redactSensitiveData(bodyText);

  // Persist finding & triage result if confirmed
  let findingId = null;
  if (exploitConfirmed) {
    const targetQ = await query('select id from targets limit 1');
    const targetId = targetQ.rows[0]?.id || crypto.randomUUID();

    const findingRes = await query(
      `insert into findings (
        target_id, title, category, scanner_risk, method, url, route_template,
        param, param_location, evidence, exploit_request, exploit_oracle,
        exploit_confirmed, status, dedupe_key, provenance
      ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
      returning *`,
      [
        targetId, recipe.title, recipe.category, recipe.scanner_risk,
        recipe.method, recipe.url, recipe.route_template, recipe.param,
        recipe.param_location, recipe.evidence, JSON.stringify(recipe.exploit_request),
        JSON.stringify(recipe.exploit_oracle), true, 'open',
        recipe.dedupe_key, recipe.provenance
      ]
    );
    const finding = findingRes.rows[0];
    findingId = finding?.id;

    if (finding) {
      const triage = computePriorityScore(finding);
      await query(
        `insert into triage_results (finding_id, priority_score, priority_band, signals)
         values ($1, $2, $3, $4)
         on conflict (finding_id) do update set
           priority_score = excluded.priority_score,
           priority_band = excluded.priority_band,
           signals = excluded.signals`,
        [finding.id, triage.priority_score, triage.priority_band, JSON.stringify(triage.signals)]
      );
    }
  }

  const inspectorPayload = {
    run_id: requestId,
    timestamp,
    recipe_id: recipeId,
    path_type: 'direct_target',
    target_info: {
      name: 'OWASP Juice Shop Replica',
      url: TARGET_URL,
      mode: 'DIRECT_UNPROTECTED (Bypasses WAF)'
    },
    request: {
      method: recipe.exploit_request.method,
      url: reqUrl,
      endpoint: recipe.route_template || recipe.url.split('?')[0],
      headers: reqHeaders,
      param: recipe.param,
      param_location: recipe.param_location,
      sanitized_payload: redactSensitiveData(recipe.exploit_request.body || recipe.url)
    },
    response: {
      status: statusCode,
      status_text: statusText,
      headers: respHeaders,
      body_excerpt: sanitizedBody.slice(0, 800),
      reached_target: reachedTarget,
      exploit_oracle: {
        pattern: recipe.exploit_oracle?.success_body_regex,
        matched: oracleMatched,
        description: oracleMatched
          ? 'Exploit Oracle confirmed: Leaked unauthorized database records or credentials.'
          : 'Exploit Oracle failed: No vulnerable data pattern detected.'
      },
      verdict: exploitConfirmed ? 'EXPLOIT CONFIRMED' : 'EXPLOIT FAILED'
    },
    latency_ms: latencyMs,
    finding_id: findingId
  };

  // Persist run
  await query(
    `insert into attack_lab_runs (recipe_id, run_type, request_data, response_data, verdict, latency_ms)
     values ($1, $2, $3, $4, $5, $6)`,
    [
      recipeId,
      'direct',
      JSON.stringify(inspectorPayload.request),
      JSON.stringify(inspectorPayload.response),
      inspectorPayload.response.verdict,
      latencyMs
    ]
  );

  res.json({ data: inspectorPayload });
});

// 2. Protected Proxy Attack (PATH B - Through PatchProof WAF)
router.post('/attack-lab/proxy', async (req, res) => {
  const recipeId = req.body?.recipe_id || 'R1';
  const recipe = RECIPES[recipeId];
  if (!recipe) {
    return res.status(400).json({ error: { message: `Unknown recipe: ${recipeId}` } });
  }

  const requestId = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const reqUrl = `${PROXY_URL}${recipe.exploit_request.url}`;
  const reqHeaders = {
    ...recipe.exploit_request.headers,
    'X-Request-Id': requestId,
    'User-Agent': 'PatchProof-AttackLab/1.0 (Proxy-Protected)'
  };

  const t0 = performance.now();
  let statusCode = 0;
  let statusText = '';
  let respHeaders = {};
  let bodyText = '';

  try {
    const fetchOptions = {
      method: recipe.exploit_request.method,
      headers: reqHeaders
    };
    if (recipe.exploit_request.body) {
      fetchOptions.body = recipe.exploit_request.body;
    }

    const resp = await fetch(reqUrl, fetchOptions);
    statusCode = resp.status;
    statusText = resp.statusText;
    bodyText = await resp.text();

    resp.headers.forEach((val, key) => {
      respHeaders[key] = val;
    });
  } catch (err) {
    statusCode = 502;
    statusText = 'Bad Gateway';
    bodyText = JSON.stringify({ error: `Connection to proxy :8080 failed: ${err.message}` });
  }

  const latencyMs = Math.round((performance.now() - t0) * 100) / 100;

  // Extract WAF headers from Proxy
  const wafDecision = respHeaders['x-shield-decision'] || (statusCode === 403 ? 'block' : 'allow');
  const matchingRule = respHeaders['x-shield-rule'] || null;
  const reachedTarget = wafDecision !== 'block' && statusCode !== 403;

  // Check deployed active rules for context
  const deployedPatches = await query("select * from patches where status = 'deployed' order by version desc limit 1");
  const activePatch = deployedPatches.rows[0];

  const sanitizedBody = redactSensitiveData(bodyText);

  const isBlocked = statusCode === 403 || wafDecision === 'block';
  const verdict = isBlocked ? 'ATTACK BLOCKED' : 'ATTACK FORWARDED';

  const inspectorPayload = {
    run_id: requestId,
    timestamp,
    recipe_id: recipeId,
    path_type: 'proxy_request',
    target_info: {
      name: 'PatchProof WAF Reverse Proxy',
      url: PROXY_URL,
      mode: isBlocked ? 'ACTIVE ENFORCEMENT (403 Blocked)' : 'FORWARDING (Unprotected / Permitted)'
    },
    request: {
      method: recipe.exploit_request.method,
      url: reqUrl,
      endpoint: recipe.route_template || recipe.url.split('?')[0],
      headers: reqHeaders,
      param: recipe.param,
      param_location: recipe.param_location,
      sanitized_payload: redactSensitiveData(recipe.exploit_request.body || recipe.url)
    },
    response: {
      status: statusCode,
      status_text: statusText,
      headers: {
        'x-shield-decision': wafDecision,
        'x-shield-rule': matchingRule || activePatch?.rule?.name || 'none',
        'x-request-id': respHeaders['x-request-id'] || requestId,
        'content-type': respHeaders['content-type'] || 'application/json'
      },
      body_excerpt: sanitizedBody.slice(0, 800),
      reached_target: reachedTarget,
      waf_decision: wafDecision,
      matching_rule_id: matchingRule || activePatch?.id || null,
      patch_version: activePatch?.version || null,
      verdict
    },
    latency_ms: latencyMs
  };

  // Persist run
  await query(
    `insert into attack_lab_runs (recipe_id, run_type, request_data, response_data, verdict, latency_ms)
     values ($1, $2, $3, $4, $5, $6)`,
    [
      recipeId,
      'proxy',
      JSON.stringify(inspectorPayload.request),
      JSON.stringify(inspectorPayload.response),
      verdict,
      latencyMs
    ]
  );

  res.json({ data: inspectorPayload });
});

// 3. Benign Traffic Request (Verify Legitimate Traffic Allowed)
router.post('/attack-lab/benign', async (req, res) => {
  const queryParam = req.body?.query || 'apple';
  const requestId = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const reqUrl = `${PROXY_URL}/rest/products/search?q=${encodeURIComponent(queryParam)}`;
  const reqHeaders = {
    'Accept': 'application/json',
    'X-Request-Id': requestId,
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) User-Browser'
  };

  const t0 = performance.now();
  let statusCode = 0;
  let statusText = '';
  let respHeaders = {};
  let bodyText = '';

  try {
    const resp = await fetch(reqUrl, { headers: reqHeaders });
    statusCode = resp.status;
    statusText = resp.statusText;
    bodyText = await resp.text();

    resp.headers.forEach((val, key) => {
      respHeaders[key] = val;
    });
  } catch (err) {
    statusCode = 502;
    statusText = 'Bad Gateway';
    bodyText = JSON.stringify({ error: err.message });
  }

  const latencyMs = Math.round((performance.now() - t0) * 100) / 100;
  const wafDecision = respHeaders['x-shield-decision'] || 'allow';
  const verdict = statusCode === 200 ? 'BENIGN TRAFFIC ALLOWED' : 'FALSE POSITIVE BLOCKED';

  const inspectorPayload = {
    run_id: requestId,
    timestamp,
    recipe_id: 'BENIGN_SEARCH',
    path_type: 'benign_request',
    target_info: {
      name: 'PatchProof WAF Reverse Proxy',
      url: PROXY_URL,
      mode: 'FORWARDING (Legitimate User Traffic)'
    },
    request: {
      method: 'GET',
      url: reqUrl,
      endpoint: '/rest/products/search',
      headers: reqHeaders,
      param: 'q',
      param_location: 'query',
      sanitized_payload: `q=${queryParam}`
    },
    response: {
      status: statusCode,
      status_text: statusText,
      headers: {
        'x-shield-decision': wafDecision,
        'x-request-id': respHeaders['x-request-id'] || requestId,
        'content-type': respHeaders['content-type'] || 'application/json'
      },
      body_excerpt: bodyText.slice(0, 500),
      reached_target: statusCode === 200,
      waf_decision: wafDecision,
      verdict
    },
    latency_ms: latencyMs
  };

  // Persist run
  await query(
    `insert into attack_lab_runs (recipe_id, run_type, request_data, response_data, verdict, latency_ms)
     values ($1, $2, $3, $4, $5, $6)`,
    [
      'BENIGN_SEARCH',
      'benign',
      JSON.stringify(inspectorPayload.request),
      JSON.stringify(inspectorPayload.response),
      verdict,
      latencyMs
    ]
  );

  res.json({ data: inspectorPayload });
});

// 4. Attack Lab History & State
router.get('/attack-lab/history', async (req, res) => {
  try {
    const runsQ = await query('select * from attack_lab_runs order by created_at desc limit 20');
    const runs = runsQ.rows || [];

    const latestDirect = runs.find(r => r.run_type === 'direct');
    const latestProxy = runs.find(r => r.run_type === 'proxy');
    const latestBenign = runs.find(r => r.run_type === 'benign');

    res.json({
      data: {
        latest_direct: latestDirect || null,
        latest_proxy: latestProxy || null,
        latest_benign: latestBenign || null,
        recent_runs: runs
      }
    });
  } catch (err) {
    res.status(500).json({ error: { message: err.message } });
  }
});

// 5. Reset Lab State
router.post('/attack-lab/reset', async (req, res) => {
  try {
    // Rollback any deployed patches
    await query("update patches set status = 'rolled_back' where status = 'deployed'");
    res.json({ data: { message: 'Attack Lab state reset to baseline (all rules rolled back).' } });
  } catch (err) {
    res.status(500).json({ error: { message: err.message } });
  }
});

export default router;
