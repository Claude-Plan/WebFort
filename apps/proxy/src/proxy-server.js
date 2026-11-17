import http from 'node:http';
import https from 'node:https';
import { randomUUID } from 'node:crypto';
import { URL } from 'node:url';
import { WafEngine } from '../../../packages/waf-engine/src/index.js';
import { RuleSynchronizer } from './rule-sync.js';
import { ProxyEventLogger } from './event-logger.js';

export function createProxyServer(config = {}) {
  const targetUrlStr = config.targetUrl || process.env.TARGET_URL || 'http://localhost:3001';
  const targetUrl = new URL(targetUrlStr);
  const failMode = config.failMode || process.env.FAIL_MODE || 'open';
  const internalToken = config.internalToken || process.env.INTERNAL_TOKEN || 'patchproof_secret_internal_token_2026';
  const apiUrl = config.apiUrl || process.env.API_URL || 'http://localhost:4000';

  const engine = new WafEngine({ failMode });

  const ruleSync = new RuleSynchronizer({
    apiUrl,
    internalToken,
    targetId: config.targetId,
    pollIntervalMs: config.pollIntervalMs || 2000,
    onRulesUpdated: (rules) => {
      engine.setRules(rules);
    }
  });

  const eventLogger = new ProxyEventLogger({
    apiUrl,
    internalToken
  });

  // Start polling and logging if not in test mock mode
  if (!config.disableAutoStart) {
    ruleSync.start();
    eventLogger.start();
  }

  const server = http.createServer(async (req, res) => {
    const requestId = randomUUID();
    const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = reqUrl.pathname;
    const queryString = reqUrl.search;

    // Buffer inbound request body for inspection & forwarding
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));

    req.on('end', async () => {
      const rawBody = Buffer.concat(chunks);
      let bodyString = rawBody.toString('utf-8');

      const reqData = {
        method: req.method,
        path: pathname,
        queryString: queryString,
        headers: req.headers,
        body: bodyString
      };

      // Check if this request is a verification candidate evaluation
      const candidatePatchId = req.headers['x-shield-verify-patch'];
      const verifyToken = req.headers['x-shield-verify-token'];
      let candidateRule = null;

      if (candidatePatchId && verifyToken === internalToken) {
        candidateRule = await ruleSync.fetchCandidateRule(candidatePatchId);
      }

      // Evaluate WAF Engine
      const evalResult = engine.evaluate(reqData, candidateRule);

      // Set Common Shield Headers
      res.setHeader('X-Request-Id', requestId);
      res.setHeader('X-Shield-Decision', evalResult.decision);
      res.setHeader('X-Shield-Would-Block', evalResult.would_block ? '1' : '0');
      if (evalResult.rule_id) {
        res.setHeader('X-Shield-Rule', evalResult.rule_id);
      }

      // Enforce Block: return 403 Forbidden immediately
      if (evalResult.decision === 'block') {
        const errorBody = JSON.stringify({
          blocked: true,
          rule_id: evalResult.rule_id || 'unspecified',
          request_id: requestId
        });

        res.writeHead(403, {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(errorBody)
        });
        res.end(errorBody);

        eventLogger.log({
          method: req.method,
          path: pathname,
          decision: 'block',
          rule_id: evalResult.rule_id,
          patch_id: candidatePatchId || null,
          latency_ms: evalResult.latency_ms,
          status_code: 403,
          meta: { requestId }
        });
        return;
      }

      // Forward request to TARGET_URL
      const isHttps = targetUrl.protocol === 'https:';
      const forwardLib = isHttps ? https : http;

      // Prepare forwarded headers
      const forwardedHeaders = { ...req.headers };
      forwardedHeaders.host = targetUrl.host;
      forwardedHeaders['x-forwarded-for'] = req.socket.remoteAddress;
      forwardedHeaders['x-forwarded-proto'] = 'http';
      forwardedHeaders['x-request-id'] = requestId;

      const proxyReqOptions = {
        protocol: targetUrl.protocol,
        hostname: targetUrl.hostname,
        port: targetUrl.port || (isHttps ? 443 : 80),
        method: req.method,
        path: req.url,
        headers: forwardedHeaders,
        timeout: 10000
      };

      const proxyReq = forwardLib.request(proxyReqOptions, (proxyRes) => {
        // Forward status code and upstream headers to client
        const responseHeaders = { ...proxyRes.headers };
        responseHeaders['x-request-id'] = requestId;
        responseHeaders['x-shield-decision'] = evalResult.decision;
        responseHeaders['x-shield-would-block'] = evalResult.would_block ? '1' : '0';
        if (evalResult.rule_id) {
          responseHeaders['x-shield-rule'] = evalResult.rule_id;
        }

        res.writeHead(proxyRes.statusCode, responseHeaders);
        proxyRes.pipe(res);

        eventLogger.log({
          method: req.method,
          path: pathname,
          decision: evalResult.decision,
          rule_id: evalResult.rule_id,
          patch_id: candidatePatchId || null,
          latency_ms: evalResult.latency_ms,
          status_code: proxyRes.statusCode,
          meta: { requestId }
        });
      });

      proxyReq.on('error', (err) => {
        if (!res.headersSent) {
          const errMsg = JSON.stringify({
            error: 'BAD_GATEWAY',
            message: `Target ${targetUrlStr} unreachable: ${err.message}`,
            request_id: requestId
          });
          res.writeHead(502, {
            'Content-Type': 'application/json',
            'X-Request-Id': requestId,
            'X-Shield-Decision': 'error'
          });
          res.end(errMsg);
        }

        eventLogger.log({
          method: req.method,
          path: pathname,
          decision: 'error',
          rule_id: evalResult.rule_id,
          latency_ms: evalResult.latency_ms,
          status_code: 502,
          meta: { error: err.message, requestId }
        });
      });

      if (rawBody.length > 0) {
        proxyReq.write(rawBody);
      }
      proxyReq.end();
    });

    req.on('error', (err) => {
      if (!res.headersSent) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'BAD_REQUEST', message: err.message }));
      }
    });
  });

  return {
    server,
    engine,
    ruleSync,
    eventLogger,
    syncRules: () => ruleSync.fetchActiveRules(),
    listen: (port, callback) => server.listen(port, callback),
    close: (callback) => {
      ruleSync.stop();
      eventLogger.stop();
      server.close(callback);
    }
  };
}
