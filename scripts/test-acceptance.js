// scripts/test-acceptance.js
// Master Acceptance Test Suite (TEST 1 to TEST 10 from Section 9)
import { spawn } from 'node:child_process';

const cwd = process.cwd();
function wait(ms) { return new Promise(r => setTimeout(r, ms)); }

console.log('================================================================');
console.log('🛡️  PATCHPROOF MASTER ACCEPTANCE TEST SUITE (TEST 1 - TEST 10)');
console.log('================================================================\n');

let targetProc = null;
let apiProc = null;
let proxyProc = null;

async function runAcceptanceTests() {
  try {
    // Spin up the 3 backend services
    console.log('[Setup] Launching Target (:3001), API (:4000), and Proxy (:8080)...');
    targetProc = spawn('node', ['scripts/lab-target.js'], { cwd, shell: true, stdio: 'pipe' });
    apiProc = spawn('node', ['apps/api/src/index.js'], { cwd, shell: true, stdio: 'pipe' });
    proxyProc = spawn('node', ['apps/proxy/src/index.js'], { cwd, shell: true, stdio: 'pipe' });
    await wait(2500);

    // TEST 1: Direct R1 exploit succeeds against Juice Shop
    console.log('[TEST 1/10] Direct R1 exploit succeeds against Juice Shop (:3001)...');
    const r1Direct = await fetch('http://localhost:3001/rest/products/search?q=%27%20UNION%20SELECT%20id%2C%20email%2C%20password%2C%20role%20FROM%20Users--');
    const r1DirectText = await r1Direct.text();
    if (r1Direct.status !== 200 || !r1DirectText.includes('admin@juice-sh.op')) {
      throw new Error(`TEST 1 FAILED: Direct exploit did not leak data (Status: ${r1Direct.status})`);
    }
    console.log('  ✓ TEST 1 PASSED: Direct R1 exploit leaked Users table on bare target.\n');

    // TEST 2: Same R1 request through the unprotected proxy also succeeds
    console.log('[TEST 2/10] Same R1 request through unprotected proxy (:8080) succeeds...');
    // Ensure clean state: no rules deployed
    await fetch('http://localhost:4000/api/v1/attack-lab/reset', { method: 'POST' });
    await wait(2200); // Allow proxy 2s poll

    const r1ProxyBaseline = await fetch('http://localhost:8080/rest/products/search?q=%27%20UNION%20SELECT%20id%2C%20email%2C%20password%2C%20role%20FROM%20Users--');
    const r1ProxyText = await r1ProxyBaseline.text();
    if (r1ProxyBaseline.status !== 200 || !r1ProxyText.includes('admin@juice-sh.op')) {
      throw new Error(`TEST 2 FAILED: Unprotected proxy did not forward exploit (Status: ${r1ProxyBaseline.status})`);
    }
    console.log('  ✓ TEST 2 PASSED: Exploit forwarded through proxy and leaked data as expected.\n');

    // Create confirmed finding
    const recipeRes = await fetch('http://localhost:4000/api/v1/recipes/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipe_id: 'R1' })
    });
    const finding = (await recipeRes.json()).data.finding;

    // Synthesize candidate patch
    const patchRes = await fetch(`http://localhost:4000/api/v1/findings/${finding.id}/patches`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ strategy: 'deterministic' })
    });
    const patch = (await patchRes.json()).data;

    // TEST 3: Generated candidate rule blocks the exploit during verification
    console.log('[TEST 3/10] Candidate rule blocks exploit during verification gate...');
    const verifyRes = await fetch(`http://localhost:4000/api/v1/patches/${patch.id}/verify`, { method: 'POST' });
    const verifyData = (await verifyRes.json()).data;
    if (!verifyData.summary.gate.passed || !verifyData.summary.suites.exploit_replay.passed) {
      throw new Error('TEST 3 FAILED: Verification gate failed or exploit was not blocked!');
    }
    console.log(`  ✓ TEST 3 PASSED: Exploit blocked in candidate verification. FPR: ${verifyData.summary.suites.benign_replay.false_positive_rate}\n`);

    // TEST 4: Deployed enforce-mode rule blocks the same request through the proxy with 403
    console.log('[TEST 4/10] Deployed enforce-mode rule blocks request through proxy with 403...');
    await fetch(`http://localhost:4000/api/v1/patches/${patch.id}/deploy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'enforce' })
    });
    await wait(2500); // Allow proxy to poll active rules

    const proxiedAttack = await fetch('http://localhost:8080/rest/products/search?q=%27%20UNION%20SELECT%20id%2C%20email%2C%20password%2C%20role%20FROM%20Users--');
    const proxiedAttackBody = await proxiedAttack.json();
    if (proxiedAttack.status !== 403 || !proxiedAttackBody.blocked) {
      throw new Error(`TEST 4 FAILED: Proxy did not enforce HTTP 403 (Status: ${proxiedAttack.status})`);
    }
    console.log(`  ✓ TEST 4 PASSED: Proxied attack blocked with HTTP 403 (Decision: ${proxiedAttack.headers.get('x-shield-decision')})\n`);

    // TEST 5: Normal product search still succeeds through the proxy
    console.log('[TEST 5/10] Normal product search still succeeds through the proxy (200 OK)...');
    const benignReq = await fetch('http://localhost:8080/rest/products/search?q=apple');
    const benignData = await benignReq.json();
    if (benignReq.status !== 200 || !Array.isArray(benignData.data)) {
      throw new Error(`TEST 5 FAILED: Legitimate traffic was blocked or failed (Status: ${benignReq.status})`);
    }
    console.log(`  ✓ TEST 5 PASSED: Normal product search succeeded with HTTP 200 (${benignData.data.length} products returned).\n`);

    // TEST 6: The Gauntlet finds at least one genuine effective bypass against intentionally weak canonical rule
    console.log('[TEST 6/10] Gauntlet evaluates weak canonical rule and discovers effective bypasses...');
    const hardenRes = await fetch(`http://localhost:4000/api/v1/patches/${patch.id}/harden`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ max_iterations: 3, mutation_budget: 60, seed: 42, start: 'canonical' })
    });
    const harden = (await hardenRes.json()).data;
    const naiveIteration = harden.iterations[0];
    if (naiveIteration.stats.bypassed <= 0) {
      throw new Error('TEST 6 FAILED: Naive canonical rule had 0 bypasses in the Gauntlet!');
    }
    console.log(`  ✓ TEST 6 PASSED: Gauntlet found ${naiveIteration.stats.bypassed} effective bypasses on naive canonical rule (${(naiveIteration.stats.bypass_rate * 100).toFixed(1)}% bypass rate).\n`);

    // TEST 7: Auto-Tighten creates a new persisted version and retests the bypass
    console.log('[TEST 7/10] Auto-Tighten creates a new version and retests bypass...');
    const hardenedIteration = harden.iterations[harden.iterations.length - 1];
    if (hardenedIteration.stats.bypassed !== 0) {
      throw new Error(`TEST 7 FAILED: Hardened patch did not eliminate bypasses (Bypassed: ${hardenedIteration.stats.bypassed})`);
    }
    console.log(`  ✓ TEST 7 PASSED: Hardened Patch v${hardenedIteration.version} achieved 0.0% bypass rate across all regression cases.\n`);

    // TEST 8: Fresh exam results are recorded independently
    console.log('[TEST 8/10] Fresh exam results recorded independently on unseen seed...');
    if (!harden.exam || harden.exam.effective < 30 || harden.exam.claim !== 'VALID') {
      throw new Error(`TEST 8 FAILED: Exam threshold E >= 30 not satisfied (E=${harden.exam?.effective})`);
    }
    console.log(`  ✓ TEST 8 PASSED: Exam recorded E=${harden.exam.effective} effective mutants (Seed: ${harden.exam.seed}), Claim: ${harden.exam.claim}.\n`);

    // TEST 9: Signed report verifies and fails after tampering
    console.log('[TEST 9/10] Signed report verifies and fails after client-side tampering...');
    const bestPatch = harden.best_patch;
    const proofRes = await fetch(`http://localhost:4000/api/v1/patches/${bestPatch.id}/proof`, { method: 'POST' });
    const proof = (await proofRes.json()).data;

    const verifyAuthentic = await fetch('http://localhost:4000/api/v1/proof/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report: proof.report, signature: proof.signature, public_key: proof.public_key })
    });
    const p1 = (await verifyAuthentic.json()).data;
    if (!p1.valid) throw new Error('TEST 9 FAILED: Authentic signature did not verify!');

    const tampered = JSON.parse(JSON.stringify(proof.report));
    tampered.tests.exploit_replay.blocked = false; // flip 1 bit
    const verifyTampered = await fetch('http://localhost:4000/api/v1/proof/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report: tampered, signature: proof.signature, public_key: proof.public_key })
    });
    const p2 = (await verifyTampered.json()).data;
    if (p2.valid) throw new Error('TEST 9 FAILED: Tampered report was falsely verified as valid!');
    console.log('  ✓ TEST 9 PASSED: Authentic report verified (valid: true); Tampered report rejected (valid: false).\n');

    // TEST 10: Rollback actually changes proxy enforcement
    console.log('[TEST 10/10] Rollback changes proxy enforcement and restores attack pass-through...');
    // Rollback active patch
    await fetch(`http://localhost:4000/api/v1/patches/${bestPatch.id}/rollback`, { method: 'POST' });
    await wait(3500); // Allow proxy to poll and flush rule

    const postRollbackAttack = await fetch('http://localhost:8080/rest/products/search?q=%27%20UNION%20SELECT%20id%2C%20email%2C%20password%2C%20role%20FROM%20Users--');
    const rollbackText = await postRollbackAttack.text();
    if (postRollbackAttack.status !== 200 || !rollbackText.includes('admin@juice-sh.op')) {
      throw new Error(`TEST 10 FAILED: Post-rollback attack did not succeed (Status: ${postRollbackAttack.status})`);
    }
    console.log('  ✓ TEST 10 PASSED: Proxy evicted rule upon rollback; HTTP 200 pass-through verified.\n');

    console.log('================================================================');
    console.log('🎉 ALL 10 ACCEPTANCE TESTS COMPLETED AND VERIFIED 100% GREEN!');
    console.log('================================================================\n');

  } catch (err) {
    console.error('\n❌ ACCEPTANCE TEST FAILED:', err);
    process.exit(1);
  } finally {
    try { targetProc?.kill(); } catch {}
    try { apiProc?.kill(); } catch {}
    try { proxyProc?.kill(); } catch {}
    process.exit(0);
  }
}

runAcceptanceTests();
