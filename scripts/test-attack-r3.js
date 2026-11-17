// scripts/test-attack-r3.js
// Live Simulation of Attack R3: Path Traversal / Arbitrary File Read (LFI)
import { spawn } from 'node:child_process';

const cwd = process.cwd();
function wait(ms) { return new Promise(r => setTimeout(r, ms)); }

console.log('===============================================================');
console.log('🎯 SIMULATING ATTACK R3: PATH TRAVERSAL / ARBITRARY FILE READ');
console.log('===============================================================\n');

let targetProc = null;
let apiProc = null;
let proxyProc = null;

async function run() {
  try {
    // 1. Start Services
    console.log('[1/7] Initializing target (:3001), API (:4000), and proxy (:8080)...');
    targetProc = spawn('node', ['scripts/lab-target.js'], { cwd, shell: true, stdio: 'pipe' });
    apiProc = spawn('node', ['apps/api/src/index.js'], { cwd, shell: true, stdio: 'pipe' });
    proxyProc = spawn('node', ['apps/proxy/src/index.js'], { cwd, shell: true, stdio: 'pipe' });
    await wait(2500);

    // 2. Bare Target Exploit (Unprotected)
    console.log('[2/7] Firing raw Path Traversal exploit at bare target (:3001)...');
    const bareRes = await fetch('http://localhost:3001/rest/file/download?file=../../../../etc/passwd');
    const bareText = await bareRes.text();
    console.log(`  ✓ HTTP Status: ${bareRes.status}`);
    console.log(`  ✓ Sensitive leak detected: ${bareText.includes('root:x:0:0:') && bareText.includes('JUICE_SECRET_FLAG')}`);
    console.log(`  ✓ Evidence snippet:\n    ${bareText.trim().split('\n').slice(0, 2).join('\n    ')}`);

    if (bareRes.status !== 200 || !bareText.includes('root:x:0:0:')) {
      throw new Error('Bare target failed to reproduce Path Traversal vulnerability!');
    }

    // 3. Fire Recipe R3 via Control Plane API
    console.log('\n[3/7] Ingesting & confirming exploit via Recipe Runner (R3)...');
    const recipeRes = await fetch('http://localhost:4000/api/v1/recipes/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipe_id: 'R3' })
    });
    const recipeData = (await recipeRes.json()).data;
    const finding = recipeData.finding;
    console.log(`  ✓ Finding Created: "${finding.title}"`);
    console.log(`  ✓ Category: ${finding.category} | Confirmed: ${finding.exploit_confirmed}`);

    // 4. Compute Triage Score
    console.log('\n[4/7] Checking Triage Waterfall & Risk Prior...');
    const triageRes = await fetch(`http://localhost:4000/api/v1/findings/${finding.id}/triage`);
    const triage = (await triageRes.json()).data;
    console.log(`  ✓ Priority Score: ${triage.priority_score}/100 (Band: ${triage.priority_band})`);
    console.log(`  ✓ Signals: ${triage.signals.map(s => `${s.id}: +${s.contribution}`).join(' · ')}`);
    console.log(`  ✓ AI / Deterministic Explanation: "${triage.llm_explanation.explanation}"`);

    // 5. Synthesize Virtual Patch
    console.log('\n[5/7] Synthesizing Virtual Patch (shield_path_traversal_patch_file)...');
    const patchRes = await fetch(`http://localhost:4000/api/v1/findings/${finding.id}/patches`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ strategy: 'deterministic' })
    });
    const patch = (await patchRes.json()).data;
    console.log(`  ✓ Patch v${patch.version} created (source: ${patch.source})`);
    console.log(`  ✓ Inspection: ${JSON.stringify(patch.rule.inspect)}`);
    console.log(`  ✓ Normalizers: ${patch.rule.normalize.join(', ')}`);
    console.log(`  ✓ Condition: ${patch.rule.condition.op} => ${patch.rule.condition.value}`);

    // 6. Deploy in Enforce Mode & Test Live Proxy Block
    console.log('\n[6/7] Deploying patch to Proxy (:8080) in Enforce mode...');
    await fetch(`http://localhost:4000/api/v1/patches/${patch.id}/deploy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'enforce' })
    });
    await wait(2500); // Allow proxy 2s ETag polling

    // Test 6a: Traversal attack through proxy
    console.log('  - Testing raw traversal attack via Proxy :8080...');
    const proxiedAttack = await fetch('http://localhost:8080/rest/file/download?file=../../../../etc/passwd');
    console.log(`    ✓ HTTP Status: ${proxiedAttack.status} (Expected: 403 Forbidden)`);
    console.log(`    ✓ X-Shield-Decision: ${proxiedAttack.headers.get('x-shield-decision')}`);
    const blockBody = await proxiedAttack.json();
    console.log(`    ✓ Diagnostic Body:`, JSON.stringify(blockBody));

    if (proxiedAttack.status !== 403 || !blockBody.blocked) {
      throw new Error('Proxy failed to block raw traversal attack in enforce mode!');
    }

    // Test 6b: Evasion attempt with double encoding
    console.log('  - Testing evasive double-encoded traversal via Proxy (:8080)...');
    const evasiveAttack = await fetch('http://localhost:8080/rest/file/download?file=..%252f..%252fetc%252fpasswd');
    console.log(`    ✓ HTTP Status: ${evasiveAttack.status} (Expected: 403 Forbidden)`);
    if (evasiveAttack.status !== 403) {
      throw new Error('Proxy failed to block double-encoded traversal evasion!');
    }

    // Test 6c: Benign request through proxy
    console.log('  - Testing legitimate file download through Proxy (:8080)...');
    const benignReq = await fetch('http://localhost:8080/rest/file/download?file=legal.md');
    const benignBody = await benignReq.text();
    console.log(`    ✓ HTTP Status: ${benignReq.status} (Expected: 200 OK)`);
    console.log(`    ✓ Response snippet: "${benignBody.trim()}"`);
    if (benignReq.status !== 200) {
      throw new Error('Proxy blocked legitimate benign file download!');
    }

    // 7. Generate Signed Proof Report
    console.log('\n[7/7] Generating and verifying ed25519 Cryptographic Proof Report...');
    const proofRes = await fetch(`http://localhost:4000/api/v1/patches/${patch.id}/proof`, { method: 'POST' });
    const proof = (await proofRes.json()).data;
    console.log(`  ✓ SHA-256 Digest: ${proof.sha256}`);
    console.log(`  ✓ Signature: ${proof.signature.slice(0, 32)}...`);

    const verifyRes = await fetch('http://localhost:4000/api/v1/proof/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report: proof.report, signature: proof.signature, public_key: proof.public_key })
    });
    const verifyData = (await verifyRes.json()).data;
    console.log(`  ✓ Cryptographic Signature: ${verifyData.valid ? 'VALID (PASSED)' : 'INVALID'}`);

    console.log('\n===============================================================');
    console.log('🎉 ATTACK R3 (PATH TRAVERSAL) SIMULATION & DEFENSE SUCCESSFUL!');
    console.log('===============================================================\n');

  } catch (err) {
    console.error('\n❌ ATTACK SIMULATION FAILED:', err);
    process.exit(1);
  } finally {
    try { targetProc?.kill(); } catch {}
    try { apiProc?.kill(); } catch {}
    try { proxyProc?.kill(); } catch {}
    process.exit(0);
  }
}

run();
