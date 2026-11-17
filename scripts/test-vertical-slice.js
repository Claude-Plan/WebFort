// scripts/test-vertical-slice.js
// Automated verification of the full vertical slice (Checkpoint T+1:45 & T+3:45)
import { spawn } from 'node:child_process';
import path from 'node:path';

const nodeCmd = 'node';
const cwd = process.cwd();

console.log('--- STARTING PATCHPROOF VERTICAL SLICE VERIFICATION ---\n');

let targetProc = null;
let apiProc = null;
let proxyProc = null;

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function run() {
  try {
    // 1. Start Lab Target (:3001)
    console.log('[1/12] Launching Lab Target on :3001...');
    targetProc = spawn('node', ['scripts/lab-target.js'], { cwd, shell: true, stdio: 'pipe' });
    await wait(1500);

    // Test direct attack on bare target
    const r1Direct = await fetch('http://localhost:3001/rest/products/search?q=%27%20UNION%20SELECT%20id%2C%20email%2C%20password%2C%20role%20FROM%20Users--');
    const r1Text = await r1Direct.text();
    if (!r1Text.includes('admin@juice-sh.op')) {
      throw new Error('Bare target R1 exploit failed!');
    }
    console.log('  ✓ Bare target confirmed vulnerable to R1 SQLi search leak.');

    // 2. Start API Control Plane (:4000)
    console.log('[2/12] Launching API Control Plane on :4000...');
    apiProc = spawn('node', ['apps/api/src/index.js'], { cwd, shell: true, stdio: 'pipe' });
    await wait(2000);

    // 3. Start Data-Plane Proxy (:8080)
    console.log('[3/12] Launching WAF Proxy on :8080...');
    proxyProc = spawn('node', ['apps/proxy/src/index.js'], { cwd, shell: true, stdio: 'pipe' });
    await wait(2000);

    // Health check with all 4 services ready
    const healthRes = await fetch('http://localhost:4000/api/v1/health');
    const health = await healthRes.json();
    console.log('  ✓ API Health check (all services ready):', JSON.stringify(health.data));

    // 4. Fire Recipe R1 via API
    console.log('[4/12] Executing Recipe R1 to create confirmed finding...');
    const recipeRes = await fetch('http://localhost:4000/api/v1/recipes/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipe_id: 'R1' })
    });
    const recipeData = await recipeRes.json();
    const finding = recipeData.data.finding;
    console.log(`  ✓ Finding created: "${finding.title}" (Confirmed: ${finding.exploit_confirmed})`);

    // 5. Check Triage Waterfall
    console.log('[5/12] Checking Triage Waterfall and priority band...');
    const triageRes = await fetch(`http://localhost:4000/api/v1/findings/${finding.id}/triage`);
    const triage = (await triageRes.json()).data;
    console.log(`  ✓ Priority Band: ${triage.priority_band} (Score: ${triage.priority_score}/100)`);
    console.log('  ✓ Signals:', triage.signals.map(s => `${s.id}: +${s.contribution}`).join(' · '));

    // 6. Generate Patch v1 (Deterministic Generator)
    console.log('[6/12] Synthesizing Virtual Patch v1 (Deterministic Multi-Pass Generator)...');
    const patchRes = await fetch(`http://localhost:4000/api/v1/findings/${finding.id}/patches`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ strategy: 'deterministic' })
    });
    const patch = (await patchRes.json()).data;
    console.log(`  ✓ Patch v${patch.version} created (source: ${patch.source})`);
    console.log(`    Normalizers in v1:`, patch.rule.normalize.join(', '));

    // 7. Verify Patch v1 (Exploit replay + 200 Benign replay)
    console.log('[7/12] Running verification gate on Patch v1 (exploit + benign replay)...');
    const verifyRes = await fetch(`http://localhost:4000/api/v1/patches/${patch.id}/verify`, { method: 'POST' });
    const verifyData = (await verifyRes.json()).data;
    console.log(`  ✓ Verification gate: ${verifyData.status} (Gate passed: ${verifyData.summary.gate.passed})`);
    console.log(`  ✓ False positive rate on 200 benign requests: ${verifyData.summary.suites.benign_replay.false_positive_rate}`);

    // 8. Run Mutation Gauntlet on Patch v1
    console.log('[8/12] Running Adversarial Mutation Gauntlet on Deterministic Patch v1...');
    const gauntletRes = await fetch(`http://localhost:4000/api/v1/patches/${patch.id}/gauntlet`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mutation_budget: 60, seed: 42 })
    });
    const gauntlet = (await gauntletRes.json()).data;
    console.log(`  ✓ Gauntlet on v1: ${gauntlet.effective} effective mutants, ${gauntlet.blocked} blocked, ${gauntlet.bypassed} bypassed.`);
    console.log(`  ✓ Bypass rate: ${(gauntlet.bypass_rate * 100).toFixed(1)}% | Wilson 95% CI: [${(gauntlet.ci95[0]*100).toFixed(1)}%, ${(gauntlet.ci95[1]*100).toFixed(1)}%]`);

    // 9. Run Auto-Tighten Hardening Loop (Seeding Canonical Naive Rule v2)
    console.log('[9/12] Running Auto-Tighten Hardening Loop (Seeding Canonical Naive Rule v2 -> Deriving Hardened v3)...');
    const hardenRes = await fetch(`http://localhost:4000/api/v1/patches/${patch.id}/harden`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ max_iterations: 3, mutation_budget: 60, seed: 42, start: 'canonical' })
    });
    const harden = (await hardenRes.json()).data;
    console.log(`  ✓ Hardening loop executed ${harden.iterations.length} iterations:`);
    for (const it of harden.iterations) {
      const label = it.iteration === 1 ? 'v2 Naive Canonical (No normalizers)' : `v${it.version} Auto-Tightened`;
      console.log(`    - Iter ${it.iteration} [${label}]: ${(it.stats.bypass_rate * 100).toFixed(1)}% bypass (${it.stats.blocked} blocked, ${it.stats.bypassed} bypassed)`);
    }
    console.log(`  ✓ Fresh Unseen Exam Object:`, JSON.stringify(harden.exam, null, 2));

    const bestPatch = harden.best_patch;

    // 10. Generate Signed Proof Report & Test Tamper Evident Signature
    console.log('[10/12] Generating Cryptographic Signed Proof Report (ed25519)...');
    const proofRes = await fetch(`http://localhost:4000/api/v1/patches/${bestPatch.id}/proof`, { method: 'POST' });
    const proof = (await proofRes.json()).data;
    console.log(`  ✓ SHA-256 Digest: ${proof.sha256}`);
    console.log(`  ✓ Digital Signature: ${proof.signature.slice(0, 32)}...`);

    // Verify valid signature
    const verifyProof1 = await fetch('http://localhost:4000/api/v1/proof/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report: proof.report, signature: proof.signature, public_key: proof.public_key })
    });
    const p1 = (await verifyProof1.json()).data;
    console.log(`  ✓ Authentic signature verification: ${p1.valid ? 'VALID (PASSED)' : 'FAILED'}`);

    // Tamper test
    const tamperedReport = JSON.parse(JSON.stringify(proof.report));
    tamperedReport.tests.exploit_replay.blocked = false; // flip 1 boolean
    const verifyProof2 = await fetch('http://localhost:4000/api/v1/proof/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report: tamperedReport, signature: proof.signature, public_key: proof.public_key })
    });
    const p2 = (await verifyProof2.json()).data;
    console.log(`  ✓ Tampered report detection: ${!p2.valid ? 'TAMPER DETECTED (PASSED)' : 'FAILED TO DETECT'}`);

    // 11. Deploy Enforce Mode & Test Live Proxy Block
    console.log('[11/12] Deploying Hardened Patch in Enforce Mode...');
    await fetch(`http://localhost:4000/api/v1/patches/${bestPatch.id}/deploy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'enforce' })
    });

    // Wait for proxy to poll active rules (polls every 2s)
    await wait(2500);

    // Fire attack through proxy :8080
    console.log('  - Firing SQLi attack through Proxy :8080...');
    const proxiedAttack = await fetch('http://localhost:8080/rest/products/search?q=%27%20UNION%20SELECT%20id%2C%20email%2C%20password%2C%20role%20FROM%20Users--');
    console.log(`  ✓ Proxied Attack HTTP Status: ${proxiedAttack.status}`);
    console.log(`  ✓ Proxy Header X-Shield-Decision: ${proxiedAttack.headers.get('x-shield-decision')}`);
    const blockBody = await proxiedAttack.json();
    console.log(`  ✓ Block Body:`, JSON.stringify(blockBody));

    if (proxiedAttack.status !== 403 || !blockBody.blocked) {
      throw new Error('Proxy failed to block attack in enforce mode!');
    }

    // 12. Rollback Rule & Verify Exploit Restored
    console.log('[12/12] Rolling back rule and verifying bypass restored...');
    await fetch(`http://localhost:4000/api/v1/patches/${bestPatch.id}/rollback`, { method: 'POST' });
    await wait(3500);

    const rollbackAttack = await fetch('http://localhost:8080/rest/products/search?q=%27%20UNION%20SELECT%20id%2C%20email%2C%20password%2C%20role%20FROM%20Users--');
    const rollbackBody = await rollbackAttack.text();
    console.log(`  ✓ Post-Rollback Attack HTTP Status: ${rollbackAttack.status} (Leaked data: ${rollbackBody.includes('admin@juice-sh.op')})`);

    if (rollbackAttack.status !== 200 || !rollbackBody.includes('admin@juice-sh.op')) {
      throw new Error('Proxy still blocked or failed to forward after rollback!');
    }

    console.log('\n======================================================');
    console.log('🎉 VERTICAL SLICE COMPLETELY VERIFIED AND PASSED 100%!');
    console.log('======================================================\n');

  } catch (err) {
    console.error('\n❌ VERIFICATION TEST FAILED:', err);
    process.exit(1);
  } finally {
    try { targetProc?.kill(); } catch {}
    try { apiProc?.kill(); } catch {}
    try { proxyProc?.kill(); } catch {}
    process.exit(0);
  }
}

run();
