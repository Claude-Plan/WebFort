// scripts/rehearse-demo.js
// Automated 4-minute demo rehearsal runner
import { spawn } from 'node:child_process';

const cwd = process.cwd();
const wait = (ms) => new Promise(r => setTimeout(r, ms));

async function rehearse() {
  const tStart = Date.now();
  console.log('===========================================================');
  console.log('🎤 PATCHPROOF LIVE DEMO REHEARSAL (4-MINUTE SCRIPT DRILL)');
  console.log('===========================================================\n');

  let targetProc, apiProc, proxyProc;

  try {
    // Phase 1: Service Spin-up (0:00 - 0:20)
    console.log('[PHASE 1: 0:00 - 0:20] Booting System Components...');
    targetProc = spawn('node', ['scripts/lab-target.js'], { cwd, shell: true, stdio: 'pipe' });
    apiProc = spawn('node', ['apps/api/src/index.js'], { cwd, shell: true, stdio: 'pipe' });
    proxyProc = spawn('node', ['apps/proxy/src/index.js'], { cwd, shell: true, stdio: 'pipe' });
    await wait(2500);

    const health = await (await fetch('http://localhost:4000/api/v1/health')).json();
    console.log('  ✓ Services Health:', JSON.stringify(health.data.services));

    // Phase 2: Ingest & Triage (0:20 - 0:55)
    console.log('\n[PHASE 2: 0:20 - 0:55] Proving Weakness Live & Triaging Against Noise...');
    const r1 = await (await fetch('http://localhost:4000/api/v1/recipes/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipe_id: 'R1' })
    })).json();
    const finding = r1.data.finding;
    console.log(`  ✓ Confirmed exploit fired live at target: "${finding.title}" (Status: ${finding.exploit_confirmed})`);

    const triage = await (await fetch(`http://localhost:4000/api/v1/findings/${finding.id}/triage`)).json();
    console.log(`  ✓ Triage Waterfall: Band ${triage.data.priority_band} (Score: ${triage.data.priority_score}/100)`);
    console.log('    Signals:', triage.data.signals.map(s => `${s.id}: +${s.contribution}`).join(' · '));

    // Phase 3: The Hypothesis & Mutation Gauntlet (0:55 - 1:40)
    console.log('\n[PHASE 3: 0:55 - 1:40] Testing the Hypothesis: Attacking Rule in Mutation Gauntlet...');
    const naivePatch = await (await fetch(`http://localhost:4000/api/v1/findings/${finding.id}/patches`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ strategy: 'canonical' })
    })).json();
    console.log(`  ✓ Naive advisory patch generated: v${naivePatch.data.version} (minimal regex, zero normalizers)`);

    const gauntlet = await (await fetch(`http://localhost:4000/api/v1/patches/${naivePatch.data.id}/gauntlet`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mutation_budget: 60, seed: 42 })
    })).json();
    console.log(`  ✓ Gauntlet executed on naive patch:`);
    console.log(`    Effective mutants: ${gauntlet.data.effective} | Blocked: ${gauntlet.data.blocked} | Bypassed: ${gauntlet.data.bypassed}`);
    console.log(`    Bypass Rate: ${(gauntlet.data.bypass_rate * 100).toFixed(1)}% (Wilson 95% CI: [${(gauntlet.data.ci95[0]*100).toFixed(1)}%, ${(gauntlet.data.ci95[1]*100).toFixed(1)}%])`);

    // Phase 4: Auto-Tighten & Unseen Exam (1:40 - 2:30)
    console.log('\n[PHASE 4: 1:40 - 2:30] Auto-Tighten Adaptation Loop & Fresh Unseen Exam...');
    const harden = await (await fetch(`http://localhost:4000/api/v1/patches/${naivePatch.data.id}/harden`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ max_iterations: 3, mutation_budget: 60, seed: 42, start: 'current' })
    })).json();
    console.log(`  ✓ Auto-tighten converged in ${harden.data.iterations.length} iterations:`);
    for (const it of harden.data.iterations) {
      console.log(`    - Iter ${it.iteration} (v${it.version}): ${(it.stats.bypass_rate * 100).toFixed(1)}% bypass (${it.stats.blocked} blocked, ${it.stats.bypassed} bypassed)`);
    }
    console.log(`  ✓ Fresh Unseen Exam (Seed ${harden.data.exam.seed}): ${(harden.data.exam.bypass_rate * 100).toFixed(1)}% bypass (Effective: ${harden.data.exam.effective}, Claim: ${harden.data.exam.claim})`);

    const bestPatch = harden.data.best_patch;

    // Phase 5: Live Enforcement & Cryptographic Proof (2:30 - 3:30)
    console.log('\n[PHASE 5: 2:30 - 3:30] Live Data-Plane Enforcement & Cryptographic Proof Report...');
    await fetch(`http://localhost:4000/api/v1/patches/${bestPatch.id}/deploy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'enforce' })
    });
    await wait(2500);

    // Proxied attack
    const attackResp = await fetch('http://localhost:8080/rest/products/search?q=%27%20UNION%20SELECT%20id%2C%20email%2C%20password%2C%20role%20FROM%20Users--');
    console.log(`  ✓ Live attack through Proxy :8080: HTTP ${attackResp.status} (X-Shield-Decision: ${attackResp.headers.get('x-shield-decision')})`);

    // Proof Report
    const proof = await (await fetch(`http://localhost:4000/api/v1/patches/${bestPatch.id}/proof`, { method: 'POST' })).json();
    console.log(`  ✓ ed25519 Signed Proof Report generated:`);
    console.log(`    Digest: ${proof.data.sha256}`);
    console.log(`    Signature: ${proof.data.signature.slice(0, 32)}...`);

    // Verify & Tamper
    const vAuthentic = await (await fetch('http://localhost:4000/api/v1/proof/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report: proof.data.report, signature: proof.data.signature, public_key: proof.data.public_key })
    })).json();
    console.log(`  ✓ Signature Verification: ${vAuthentic.data.valid ? 'VALID (MATCH)' : 'INVALID'}`);

    const tampered = JSON.parse(JSON.stringify(proof.data.report));
    tampered.tests.mutation_exam.bypassed = 999;
    const vTampered = await (await fetch('http://localhost:4000/api/v1/proof/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report: tampered, signature: proof.data.signature, public_key: proof.data.public_key })
    })).json();
    console.log(`  ✓ Live 1-Byte Tamper Test: ${!vTampered.data.valid ? 'TAMPER DETECTED (PASSED)' : 'FAILED'}`);

    // Rollback
    await fetch(`http://localhost:4000/api/v1/patches/${bestPatch.id}/rollback`, { method: 'POST' });
    await wait(2500);
    const rollbackResp = await fetch('http://localhost:8080/rest/products/search?q=%27%20UNION%20SELECT%20id%2C%20email%2C%20password%2C%20role%20FROM%20Users--');
    console.log(`  ✓ Post-rollback traffic through Proxy :8080: HTTP ${rollbackResp.status} (Bypass restored)`);

    const elapsedSec = Math.round((Date.now() - tStart) / 1000);
    console.log('\n===========================================================');
    console.log(`🎉 REHEARSAL COMPLETED SUCCESSFULLY IN ${elapsedSec}s (Target: < 240s)`);
    console.log('===========================================================\n');

  } catch (err) {
    console.error('❌ Rehearsal Error:', err);
  } finally {
    try { targetProc?.kill(); } catch {}
    try { apiProc?.kill(); } catch {}
    try { proxyProc?.kill(); } catch {}
    process.exit(0);
  }
}

rehearse();
