import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createApiApp } from '../src/index.js';
import { Repository } from '../src/db/repository.js';
import { calculateTriageScore } from '../src/triage/index.js';

describe('PatchProof Backend Control Plane API', () => {
  let server;
  let apiPort;
  let baseUrl;

  before(async () => {
    process.env.NODE_ENV = 'test';
    const app = createApiApp();
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        apiPort = server.address().port;
        baseUrl = `http://127.0.0.1:${apiPort}`;
        resolve();
      });
    });
  });

  after((done) => {
    server.close(done);
  });

  it('1. GET /health returns service statuses', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.status);
    assert.ok(data.services.db);
    assert.ok(data.services.ollama);
  });

  it('2. POST /targets and GET /targets', async () => {
    const createRes = await fetch(`${baseUrl}/api/v1/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Test Target Lab',
        base_url: 'http://localhost:3001',
        proxy_url: 'http://localhost:8080'
      })
    });
    assert.equal(createRes.status, 201);
    const created = (await createRes.json()).data;
    assert.equal(created.name, 'Test Target Lab');

    const listRes = await fetch(`${baseUrl}/api/v1/targets`);
    assert.equal(listRes.status, 200);
    const list = (await listRes.json()).data;
    assert.ok(list.length > 0);
  });

  it('3. POST /scans/import ingests ZAP baseline alerts as unconfirmed findings', async () => {
    const sampleZap = {
      site: [{
        alerts: [
          {
            pluginId: '40018',
            alert: 'SQL Injection in Search',
            riskcode: '3',
            riskdesc: 'High',
            url: 'http://localhost:3001/rest/products/search?q=test',
            param: 'q',
            evidence: 'SQL syntax error'
          },
          {
            pluginId: '40012',
            alert: 'Cross Site Scripting (DOM Based)',
            riskcode: '2',
            riskdesc: 'Medium',
            url: 'http://localhost:3001/#/search',
            param: 'q',
            evidence: '<script>alert(1)</script>'
          }
        ]
      }]
    };

    const res = await fetch(`${baseUrl}/api/v1/scans/import`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(sampleZap)
    });

    assert.equal(res.status, 201);
    const data = (await res.json()).data;
    assert.equal(data.length, 2);
    // Non-negotiable: scanner alone is NEVER exploit_confirmed
    assert.equal(data[0].exploit_confirmed, false);
    assert.equal(data[0].scanner_risk, 'high');
  });

  it('4. Deterministic Triage Engine calculates exact frozen formula', () => {
    // Case 1: Critical SQLi with exploit confirmed
    // score = 100 * (0.40 * 1.0 + 0.40 * 1.0 + 0.20 * 0.90) = 40 + 40 + 18 = 98 -> P0
    const findingP0 = {
      scanner_risk: 'critical',
      exploit_confirmed: true,
      category: 'sqli'
    };
    const triageP0 = calculateTriageScore(findingP0);
    assert.equal(triageP0.score, 98);
    assert.equal(triageP0.band, 'P0');

    // Case 2: High SQLi without exploit confirmed (scanner noise)
    // score = 100 * (0.40 * 0.75 + 0.40 * 0 + 0.20 * 0.90) = 30 + 0 + 18 = 48 -> P2
    const findingP2 = {
      scanner_risk: 'high',
      exploit_confirmed: false,
      category: 'sqli'
    };
    const triageP2 = calculateTriageScore(findingP2);
    assert.equal(triageP2.score, 48);
    assert.equal(triageP2.band, 'P2');
  });

  it('5. POST /recipes/run fires recipe and registers finding', async () => {
    const res = await fetch(`${baseUrl}/api/v1/recipes/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipe_id: 'R1' })
    });

    assert.equal(res.status, 201);
    const body = await res.json();
    assert.ok(body.data.finding);
    assert.equal(body.data.finding.category, 'sqli');
  });

  it('6. POST /triage/run executes scoring with Ollama fallback', async () => {
    const findingsRes = await fetch(`${baseUrl}/api/v1/findings`);
    const findings = (await findingsRes.json()).data;
    assert.ok(findings.length > 0);

    const res = await fetch(`${baseUrl}/api/v1/triage/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding_ids: [findings[0].id] })
    });

    assert.equal(res.status, 200);
    const triageList = (await res.json()).data;
    assert.equal(triageList.length, 1);
    assert.ok(triageList[0].priority_score >= 0);
    assert.ok(['P0', 'P1', 'P2', 'P3'].includes(triageList[0].priority_band));
    assert.ok(triageList[0].llm_explanation);
  });

  it('7. POST /findings/:id/patches generates patch with rule DSL', async () => {
    const findingsRes = await fetch(`${baseUrl}/api/v1/findings`);
    const findings = (await findingsRes.json()).data;
    const finding = findings[0];

    const res = await fetch(`${baseUrl}/api/v1/findings/${finding.id}/patches`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ strategy: 'auto' })
    });

    assert.equal(res.status, 201);
    const patch = (await res.json()).data;
    assert.ok(patch.rule);
    assert.equal(patch.rule.schema_version, '1.0');
    assert.equal(patch.status, 'draft');
  });

  it('8. POST /patches/:id/verify runs verification', async () => {
    const patchesRes = await fetch(`${baseUrl}/api/v1/patches`);
    const patches = (await patchesRes.json()).data;
    assert.ok(patches.length > 0);
    const patch = patches[0];

    const res = await fetch(`${baseUrl}/api/v1/patches/${patch.id}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ benignCount: 200 })
    });

    assert.equal(res.status, 200);
    const result = (await res.json()).data;
    assert.ok(result.verification);
    assert.ok(result.verification.summary.suites);
    assert.equal(result.verification.summary.suites.benign_replay.total, 200);
  });

  it('9. POST /patches/:id/deploy and /rollback', async () => {
    const patchesRes = await fetch(`${baseUrl}/api/v1/patches`);
    const patches = (await patchesRes.json()).data;
    const patch = patches[0];

    // Deploy
    const deployRes = await fetch(`${baseUrl}/api/v1/patches/${patch.id}/deploy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'enforce' })
    });
    assert.equal(deployRes.status, 200);
    const deployed = (await deployRes.json()).data;
    assert.equal(deployed.status, 'deployed');
    assert.equal(deployed.mode, 'enforce');

    // Check active rules internal route for proxy sync
    const activeRes = await fetch(`${baseUrl}/internal/v1/rules/active`, {
      headers: { 'X-Internal-Token': 'patchproof_secret_internal_token_2026' }
    });
    assert.equal(activeRes.status, 200);
    const activeData = await activeRes.json();
    assert.ok(activeData.rules.length > 0);
    assert.ok(activeData.etag);

    // Rollback
    const rollbackRes = await fetch(`${baseUrl}/api/v1/patches/${patch.id}/rollback`, {
      method: 'POST'
    });
    assert.equal(rollbackRes.status, 200);
    const rolledBack = (await rollbackRes.json()).data;
    assert.equal(rolledBack.status, 'rolled_back');
  });
});
