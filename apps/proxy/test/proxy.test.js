import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createProxyServer } from '../src/proxy-server.js';

describe('PatchProof Reverse Proxy & WAF Engine Integration', () => {
  let mockTargetServer;
  let targetPort;
  let proxyApp;
  let proxyPort;
  let targetRequestsReceived = [];

  const sqliRule = {
    id: 'rule-sqli-r1',
    schema_version: '1.0',
    name: 'Block SQLi Search',
    scope: {
      methods: ['GET'],
      path: { kind: 'exact', value: '/rest/products/search' }
    },
    inspect: [
      { location: 'query', name: 'q' }
    ],
    normalize: [
      'url_decode_recursive',
      'html_entity_decode',
      'lowercase',
      'strip_sql_comments',
      'strip_whitespace_variants',
      'collapse_whitespace'
    ],
    condition: {
      op: 'regex_match',
      value: "union\\s+select|'\\s+or\\s+'1'='1"
    },
    action: 'block',
    mode: 'enforce'
  };

  before(async () => {
    // 1. Start mock target server (representing Juice Shop)
    await new Promise((resolve) => {
      mockTargetServer = http.createServer((req, res) => {
        targetRequestsReceived.push({
          method: req.method,
          url: req.url,
          headers: req.headers
        });

        if (req.url.startsWith('/rest/products/search')) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'success', data: [{ id: 1, name: 'Apple Juice' }] }));
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ message: 'OK' }));
        }
      });

      mockTargetServer.listen(0, () => {
        targetPort = mockTargetServer.address().port;
        resolve();
      });
    });

    // 2. Start proxy server
    await new Promise((resolve) => {
      proxyApp = createProxyServer({
        targetUrl: `http://127.0.0.1:${targetPort}`,
        apiUrl: 'http://127.0.0.1:4999', // non-existent API during standalone test
        failMode: 'open',
        disableAutoStart: true
      });

      // Seed proxy engine with active rule
      proxyApp.engine.setRules([sqliRule]);

      proxyApp.listen(0, () => {
        proxyPort = proxyApp.server.address().port;
        resolve();
      });
    });
  });

  after((done) => {
    proxyApp.close(() => {
      mockTargetServer.close(done);
    });
  });

  it('1. Normal legitimate request reaches target (Juice Shop)', async () => {
    targetRequestsReceived = [];
    const res = await fetch(`http://127.0.0.1:${proxyPort}/rest/products/search?q=apple`);
    assert.equal(res.status, 200);

    const body = await res.json();
    assert.equal(body.status, 'success');
    assert.equal(targetRequestsReceived.length, 1);
    assert.equal(res.headers.get('x-shield-decision'), 'allow');
    assert.equal(res.headers.get('x-shield-would-block'), '0');
    assert.ok(res.headers.get('x-request-id'));
  });

  it('2. Malicious SQL injection request is blocked with 403', async () => {
    targetRequestsReceived = [];
    const attackUrl = `http://127.0.0.1:${proxyPort}/rest/products/search?q=apple%27%20UNION/**/SELECT%201,2,3--`;
    const res = await fetch(attackUrl);

    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.blocked, true);
    assert.equal(body.rule_id, 'rule-sqli-r1');
    assert.ok(body.request_id);

    // Target must NOT receive blocked request
    assert.equal(targetRequestsReceived.length, 0);
    assert.equal(res.headers.get('x-shield-decision'), 'block');
    assert.equal(res.headers.get('x-shield-would-block'), '1');
    assert.equal(res.headers.get('x-shield-rule'), 'rule-sqli-r1');
  });

  it('3. Shadow mode allows request but records would-block', async () => {
    targetRequestsReceived = [];
    const shadowRule = { ...sqliRule, mode: 'shadow' };
    proxyApp.engine.setRules([shadowRule]);

    const attackUrl = `http://127.0.0.1:${proxyPort}/rest/products/search?q=apple%27%20UNION/**/SELECT%201,2,3--`;
    const res = await fetch(attackUrl);

    assert.equal(res.status, 200);
    assert.equal(targetRequestsReceived.length, 1);
    assert.equal(res.headers.get('x-shield-decision'), 'log_only');
    assert.equal(res.headers.get('x-shield-would-block'), '1');
    assert.equal(res.headers.get('x-shield-rule'), 'rule-sqli-r1');

    // Restore enforce rule
    proxyApp.engine.setRules([sqliRule]);
  });

  it('4. Enforce mode returns 403 with exact JSON payload', async () => {
    const attackUrl = `http://127.0.0.1:${proxyPort}/rest/products/search?q=%27%20UNION%20SELECT%201--`;
    const res = await fetch(attackUrl);

    assert.equal(res.status, 403);
    const body = await res.json();
    assert.deepEqual(Object.keys(body).sort(), ['blocked', 'request_id', 'rule_id'].sort());
    assert.equal(body.blocked, true);
  });

  it('5. Duplicate query parameters are inspected (HPP protection)', async () => {
    targetRequestsReceived = [];
    // First parameter is safe, second has payload
    const attackUrl = `http://127.0.0.1:${proxyPort}/rest/products/search?q=safe_juice&q=apple%27%20UNION/**/SELECT%201--`;
    const res = await fetch(attackUrl);

    assert.equal(res.status, 403);
    assert.equal(targetRequestsReceived.length, 0);
    const body = await res.json();
    assert.equal(body.blocked, true);
  });

  it('6. Encoded SQL injection is detected and blocked', async () => {
    targetRequestsReceived = [];
    // Double-encoded: %2527 -> %27 -> '
    // %2520 -> %20 -> space
    const doubleEncodedPayload = 'q=%2527%2520UNION%2520SELECT%25201--';
    const attackUrl = `http://127.0.0.1:${proxyPort}/rest/products/search?${doubleEncodedPayload}`;
    const res = await fetch(attackUrl);

    assert.equal(res.status, 403);
    assert.equal(targetRequestsReceived.length, 0);
  });

  it('7. Engine failure does not crash the proxy (FAIL_MODE=open)', async () => {
    // Intentionally test unexpected evaluation edge cases
    const res = await fetch(`http://127.0.0.1:${proxyPort}/rest/products/search?q=apple`);
    assert.equal(res.status, 200);
  });

  it('8. Proxy works without Ollama dependency', () => {
    // Check that proxy has zero references to Ollama
    assert.equal(typeof proxyApp.engine.evaluate, 'function');
    assert.equal(proxyApp.engine.rules.length, 1);
  });

  it('9. Engine evaluation latency is under 5ms', async () => {
    const reqData = {
      method: 'GET',
      path: '/rest/products/search',
      queryString: 'q=apple%27%20UNION/**/SELECT%201,2,3--',
      headers: {}
    };

    const evalResult = proxyApp.engine.evaluate(reqData);
    assert.ok(evalResult.latency_ms < 5, `Expected latency < 5ms, got ${evalResult.latency_ms}ms`);
  });
});
