import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createApiServer } from '../src/server.js';
import { createProxyServer } from '../../proxy/src/proxy-server.js';

describe('PatchProof End-to-End Vertical Slice (§10)', () => {
  let mockTargetServer;
  let targetPort;
  let apiApp;
  let apiPort;
  let proxyApp;
  let proxyPort;

  let createdTargetId;
  let createdFindingId;
  let createdPatchId;

  before(async () => {
    // 1. Start Mock Juice Shop Target
    await new Promise((resolve) => {
      mockTargetServer = http.createServer((req, res) => {
        if (req.url.startsWith('/rest/products/search')) {
          if (req.url.includes('UNION') || req.url.includes('union')) {
            // Vulnerable response: leaking admin user record
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              status: 'success',
              data: [{ id: 1, email: 'admin@juice-sh.op', role: 'admin' }]
            }));
            return;
          }
          // Benign query response
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'success', data: [{ id: 1, name: 'Apple Juice' }] }));
          return;
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok' }));
      });

      mockTargetServer.listen(0, () => {
        targetPort = mockTargetServer.address().port;
        resolve();
      });
    });

    // 2. Start API Control Plane Server
    await new Promise((resolve) => {
      process.env.TARGET_URL = `http://127.0.0.1:${targetPort}`;
      apiApp = createApiServer();
      apiApp.listen(0, () => {
        apiPort = apiApp.server.address().port;
        resolve();
      });
    });

    // 3. Start WAF Reverse Proxy
    await new Promise((resolve) => {
      proxyApp = createProxyServer({
        targetUrl: `http://127.0.0.1:${targetPort}`,
        apiUrl: `http://127.0.0.1:${apiPort}`,
        failMode: 'open',
        internalToken: 'patchproof_secret_internal_token_2026',
        pollIntervalMs: 500, // fast sync for tests
        disableAutoStart: false
      });

      proxyApp.listen(0, () => {
        proxyPort = proxyApp.server.address().port;
        process.env.PROXY_URL = `http://127.0.0.1:${proxyPort}`;
        resolve();
      });
    });
  });

  after((done) => {
    proxyApp.close(() => {
      apiApp.close(() => {
        mockTargetServer.close(done);
      });
    });
  });

  it('Step 1-6: Health check and Lab Target Creation', async () => {
    const healthRes = await fetch(`http://127.0.0.1:${apiPort}/health`);
    assert.equal(healthRes.status, 200);

    const targetRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Juice Shop Slice Target',
        base_url: `http://127.0.0.1:${targetPort}`,
        proxy_url: `http://127.0.0.1:${proxyPort}`
      })
    });

    assert.equal(targetRes.status, 201);
    const target = (await targetRes.json()).data;
    createdTargetId = target.id;
    assert.ok(createdTargetId);
  });

  it('Step 7-9: Fire Recipe R1 against bare target and confirm exploit', async () => {
    const recipeRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/recipes/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipe_id: 'R1', target_id: createdTargetId })
    });

    assert.equal(recipeRes.status, 201);
    const body = await recipeRes.json();
    assert.equal(body.data.finding.exploit_confirmed, true);
    assert.equal(body.data.finding.category, 'sqli');
    createdFindingId = body.data.finding.id;
  });

  it('Step 10: Run deterministic triage and verify P0 prioritization', async () => {
    const triageRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/triage/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding_ids: [createdFindingId] })
    });

    assert.equal(triageRes.status, 200);
    const triageList = (await triageRes.json()).data;
    assert.equal(triageList[0].priority_band, 'P0');
    assert.ok(triageList[0].priority_score >= 75);
  });

  it('Step 11: Generate virtual patch from deterministic template', async () => {
    const patchRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/findings/${createdFindingId}/patches`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ strategy: 'auto' })
    });

    assert.equal(patchRes.status, 201);
    const patch = (await patchRes.json()).data;
    assert.equal(patch.rule.schema_version, '1.0');
    assert.equal(patch.status, 'draft');
    createdPatchId = patch.id;
  });

  it('Step 12-13: Verify patch with exploit replay and 200 benign requests', async () => {
    const verifyRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/patches/${createdPatchId}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ benignCount: 200 })
    });

    assert.equal(verifyRes.status, 200);
    const resData = (await verifyRes.json()).data;
    assert.equal(resData.verification.status, 'passed');
    assert.equal(resData.verification.summary.gate.passed, true);
    assert.equal(resData.patch.status, 'verified');
  });

  it('Step 14: Deploy patch in shadow mode and verify audit logging', async () => {
    const deployRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/patches/${createdPatchId}/deploy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'shadow' })
    });

    assert.equal(deployRes.status, 200);
    const deployed = (await deployRes.json()).data;
    assert.equal(deployed.status, 'deployed');
    assert.equal(deployed.mode, 'shadow');

    // Trigger rule sync on proxy
    await proxyApp.syncRules();

    // Send exploit through proxy in shadow mode
    const attackUrl = `http://127.0.0.1:${proxyPort}/rest/products/search?q=apple%27%20UNION%20SELECT%201,2,3--`;
    const proxyRes = await fetch(attackUrl);

    // Shadow mode must ALLOW request through to target
    assert.equal(proxyRes.status, 200);
    assert.equal(proxyRes.headers.get('x-shield-decision'), 'log_only');
    assert.equal(proxyRes.headers.get('x-shield-would-block'), '1');
  });

  it('Step 15-17: Switch to enforce mode and confirm HTTP 403 Forbidden', async () => {
    const enforceRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/patches/${createdPatchId}/deploy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'enforce' })
    });

    assert.equal(enforceRes.status, 200);
    const deployed = (await enforceRes.json()).data;
    assert.equal(deployed.mode, 'enforce');

    // Trigger rule sync on proxy
    await proxyApp.syncRules();

    // Send exploit through proxy in enforce mode
    const attackUrl = `http://127.0.0.1:${proxyPort}/rest/products/search?q=apple%27%20UNION%20SELECT%201,2,3--`;
    const proxyRes = await fetch(attackUrl);

    // Enforce mode must BLOCK with HTTP 403
    assert.equal(proxyRes.status, 403);
    assert.equal(proxyRes.headers.get('x-shield-decision'), 'block');
    assert.equal(proxyRes.headers.get('x-shield-would-block'), '1');

    const body = await proxyRes.json();
    assert.equal(body.blocked, true);
    assert.ok(body.request_id);
    assert.ok(body.rule_id);
  });

  it('Step 18: Roll back patch and confirm exploit is no longer blocked', async () => {
    const rollbackRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/patches/${createdPatchId}/rollback`, {
      method: 'POST'
    });

    assert.equal(rollbackRes.status, 200);
    const rolledBack = (await rollbackRes.json()).data;
    assert.equal(rolledBack.status, 'rolled_back');

    // Trigger rule sync on proxy
    await proxyApp.syncRules();

    // Send exploit through proxy after rollback
    const attackUrl = `http://127.0.0.1:${proxyPort}/rest/products/search?q=apple%27%20UNION%20SELECT%201,2,3--`;
    const proxyRes = await fetch(attackUrl);

    // Post-rollback: rule is no longer active, request passes through
    assert.equal(proxyRes.status, 200);
    assert.equal(proxyRes.headers.get('x-shield-decision'), 'allow');
  });
});
