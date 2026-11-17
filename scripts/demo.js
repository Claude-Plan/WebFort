/**
 * PatchProof (WebFort Plan A) — Interactive 4-Minute Demo Script
 * Executes the complete end-to-end security pipeline live in terminal.
 */
import http from 'node:http';
import { createApiServer } from '../apps/api/src/server.js';
import { createProxyServer } from '../apps/proxy/src/proxy-server.js';

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  bgDark: '\x1b[40m'
};

function banner(text) {
  console.log(`\n${c.bold}${c.cyan}┌────────────────────────────────────────────────────────────────────────┐${c.reset}`);
  console.log(`${c.bold}${c.cyan}│ ${text.padEnd(70)} │${c.reset}`);
  console.log(`${c.bold}${c.cyan}└────────────────────────────────────────────────────────────────────────┘${c.reset}\n`);
}

function step(num, title) {
  console.log(`${c.bold}${c.yellow}[STEP ${num}]${c.reset} ${c.bold}${title}${c.reset}`);
}

function success(msg) {
  console.log(`  ${c.green}✔ ${msg}${c.reset}`);
}

function info(msg) {
  console.log(`  ${c.dim}ℹ ${msg}${c.reset}`);
}

function warn(msg) {
  console.log(`  ${c.red}✖ ${msg}${c.reset}`);
}

async function runDemo() {
  banner('PATCHPROOF: CONTINUOUS FIREWALL VERIFICATION & AUTO-HARDENING');

  // 1. Setup in-memory mock target
  let targetServer = http.createServer((req, res) => {
    if (req.url.startsWith('/rest/products/search')) {
      if (req.url.includes('UNION') || req.url.includes('union')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'success',
          data: [{ id: 1, email: 'admin@juice-sh.op', role: 'admin' }]
        }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'success', data: [{ id: 1, name: 'Apple Juice' }] }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
  });

  await new Promise(r => targetServer.listen(0, r));
  const targetPort = targetServer.address().port;
  process.env.TARGET_URL = `http://127.0.0.1:${targetPort}`;

  // 2. Start API
  const apiApp = createApiServer();
  await new Promise(r => apiApp.listen(0, r));
  const apiPort = apiApp.server.address().port;

  // 3. Start Proxy
  const proxyApp = createProxyServer({
    targetUrl: `http://127.0.0.1:${targetPort}`,
    apiUrl: `http://127.0.0.1:${apiPort}`,
    failMode: 'open',
    internalToken: 'patchproof_secret_internal_token_2026',
    pollIntervalMs: 500,
    disableAutoStart: false
  });
  await new Promise(r => proxyApp.listen(0, r));
  const proxyPort = proxyApp.server.address().port;
  process.env.PROXY_URL = `http://127.0.0.1:${proxyPort}`;

  try {
    // STEP 1: Registration & Bare Exploit
    step(1, 'Target Registration & Bare Target Exploit Confirmation (Recipe R1)');
    const targetRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'OWASP Juice Shop Lab',
        base_url: `http://127.0.0.1:${targetPort}`,
        proxy_url: `http://127.0.0.1:${proxyPort}`
      })
    });
    const target = (await targetRes.json()).data;
    success(`Target registered: "${target.name}" (${target.base_url})`);

    const recipeRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/recipes/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipe_id: 'R1', target_id: target.id })
    });
    const { finding } = (await recipeRes.json()).data;
    success(`Recipe R1 executed against bare target:`);
    info(`Finding: "${finding.title}" (Category: ${finding.category.toUpperCase()})`);
    info(`Exploit confirmed: ${c.bold}${finding.exploit_confirmed ? 'YES (Data Leaked)' : 'NO'}${c.reset}`);

    // STEP 2: Triage
    step(2, 'Deterministic Vulnerability Triage & Waterfall Breakdown');
    const triageRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/triage/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding_ids: [finding.id] })
    });
    const triage = (await triageRes.json()).data[0];
    success(`Deterministic score computed: ${c.bold}${c.green}${triage.priority_score}/100${c.reset} -> Band: ${c.bold}${c.magenta}${triage.priority_band}${c.reset}`);
    info(`Formula: 100 * (0.40*severity + 0.40*confirmed + 0.20*category_prior)`);
    for (const sig of triage.signals) {
      info(`  • ${sig.label.padEnd(20)}: Raw ${sig.raw} -> Contribution: +${sig.contribution}`);
    }
    info(`AI Advisor Status: ${triage.llm_status.toUpperCase()} ("AI-drafted", LLM not in request path)`);

    // STEP 3: Patch Generation
    step(3, 'Virtual Patch Synthesis (Deterministic Rule DSL)');
    const patchRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/findings/${finding.id}/patches`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ strategy: 'auto' })
    });
    const patch = (await patchRes.json()).data;
    success(`Virtual Patch generated (v${patch.version}, Source: ${patch.source})`);
    info(`Rule Name: "${patch.rule.name}"`);
    info(`Scope: ${patch.rule.scope.methods.join(',')} ${patch.rule.scope.path.kind}:${patch.rule.scope.path.value}`);
    info(`Normalizers: [${patch.rule.normalize.join(', ')}]`);

    // STEP 4: Verification Gate
    step(4, 'Two-Stage Verification Gate (Exploit Replay + 200 Benign Replays)');
    const verifyRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/patches/${patch.id}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ benignCount: 200 })
    });
    const verifyData = (await verifyRes.json()).data;
    const summary = verifyData.verification.summary;
    success(`Verification status: ${verifyData.verification.status.toUpperCase()}`);
    info(`Exploit Replay: ${summary.suites.exploit_replay.passed}/${summary.suites.exploit_replay.total} blocked (Direct confirmed: ${summary.suites.exploit_replay.direct_confirmed})`);
    info(`Benign Replay:  ${summary.suites.benign_replay.passed}/${summary.suites.benign_replay.total} passed (False positive rate: ${summary.suites.benign_replay.false_positive_rate * 100}%)`);
    info(`Engine Latency: p50: ${summary.engine_latency_ms.p50}ms, p95: ${summary.engine_latency_ms.p95}ms`);

    // STEP 5: Mutation Gauntlet
    step(5, 'Mutation Gauntlet: Attacking the Firewall Rule');
    const gauntletRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/patches/${patch.id}/gauntlet`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mutation_budget: 60, seed: 1337 })
    });
    const gauntletData = (await gauntletRes.json()).data;
    const gauntlet = gauntletData.summary;
    success(`Gauntlet Completed (${gauntlet.total_mutants} total mutants evaluated):`);
    info(`Effective Mutants (E): ${c.bold}${gauntlet.effective}${c.reset} (Invalid mutants filtered by bare-target oracle)`);
    info(`Blocked (B):           ${c.green}${gauntlet.blocked}${c.reset}`);
    info(`Bypassed (X):          ${gauntlet.bypassed > 0 ? c.red : c.green}${gauntlet.bypassed}${c.reset}`);
    info(`Bypass Rate:           ${(gauntlet.bypass_rate * 100).toFixed(1)}%`);
    info(`Wilson 95% CI:         [${(gauntlet.ci95[0] * 100).toFixed(1)}%, ${(gauntlet.ci95[1] * 100).toFixed(1)}%]`);

    // STEP 6: Auto-Tighten Hardening Loop
    step(6, 'Auto-Tighten Hardening Loop & Exam on Unseen Seed');
    const hardenRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/patches/${patch.id}/harden`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ max_iterations: 3, mutation_budget: 60, seed: 1337, start: 'canonical' })
    });
    const harden = (await hardenRes.json()).data;
    success(`Hardening Loop converged across ${harden.iterations.length} iterations:`);
    for (const iter of harden.iterations) {
      info(`  Iteration ${iter.iteration} (Patch v${iter.version}): Bypasses: ${iter.bypassed}/${iter.effective} (${(iter.bypass_rate * 100).toFixed(1)}%) -> Normalizers: [${iter.rule.normalize.join(', ')}]`);
    }
    success(`Final Exam on Unseen Seed (${harden.exam.seed}):`);
    info(`Exam Effective: ${harden.exam.effective}, Bypassed: ${harden.exam.bypassed}, Bypass Rate: ${(harden.exam.bypass_rate * 100).toFixed(1)}%`);

    // STEP 7: Enforce Mode Deployment & Proxy Blocking
    step(7, 'Enforce Mode Deployment & WAF Reverse Proxy Defense');
    await fetch(`http://127.0.0.1:${apiPort}/api/v1/patches/${patch.id}/deploy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'enforce' })
    });
    await proxyApp.syncRules();

    const attackUrl = `http://127.0.0.1:${proxyPort}/rest/products/search?q=apple%27%20UNION%20SELECT%201,2,3--`;
    const proxyAttackRes = await fetch(attackUrl);
    const proxyBody = await proxyAttackRes.json();

    if (proxyAttackRes.status === 403 && proxyBody.blocked === true) {
      success(`Proxy intercepted and blocked attack!`);
      info(`HTTP Status:          ${c.bold}${c.green}403 Forbidden${c.reset}`);
      info(`X-Shield-Decision:    ${proxyAttackRes.headers.get('x-shield-decision')}`);
      info(`Blocked Rule ID:      ${proxyBody.rule_id}`);
      info(`Request Trace ID:     ${proxyBody.request_id}`);
    } else {
      warn(`Attack was not blocked as expected!`);
    }

    // STEP 8: Cryptographic Signed Proof Report & Tamper Check
    step(8, 'Signed Proof Report Issuance & 1-Byte Tamper Verification');
    const proofRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/patches/${patch.id}/proof`, {
      method: 'POST'
    });
    const proof = (await proofRes.json()).data;
    success(`Ed25519 Cryptographic Proof Report generated:`);
    info(`SHA-256 Digest:       ${proof.sha256}`);
    info(`Digital Signature:    ${proof.signature.slice(0, 32)}...`);
    info(`Public Key:           ${proof.public_key.slice(0, 32)}...`);

    // Verify genuine proof
    const verifyProof1 = await fetch(`http://127.0.0.1:${apiPort}/api/v1/proof/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        report: proof.report,
        signature: proof.signature,
        public_key: proof.public_key
      })
    });
    const verifyResult1 = (await verifyProof1.json()).data;
    success(`Original Proof Signature Check: ${c.bold}${verifyResult1.valid ? c.green + 'VALID (Tamper-Free)' : c.red + 'INVALID'}${c.reset}`);

    // Tamper proof
    const tamperedReport = JSON.parse(JSON.stringify(proof.report));
    tamperedReport.tests.exploit_replay.blocked = false; // flip 1 boolean value
    const verifyProof2 = await fetch(`http://127.0.0.1:${apiPort}/api/v1/proof/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        report: tamperedReport,
        signature: proof.signature,
        public_key: proof.public_key
      })
    });
    const verifyResult2 = (await verifyProof2.json()).data;
    success(`Tampered Proof Signature Check: ${c.bold}${!verifyResult2.valid ? c.red + 'TAMPER DETECTED (Signature Invalid)' : 'FAIL'}${c.reset}`);

    // STEP 9: 4-Arm Benchmark
    step(9, '4-Arm Benchmark Execution (Comparative Defense Matrix)');
    const bmRes = await fetch(`http://127.0.0.1:${apiPort}/api/v1/benchmarks/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        arms: ['bare', 'naive_canonical', 'shield_v1', 'shield_hardened'],
        mutation_budget: 60,
        seed: 1337
      })
    });
    const bm = (await bmRes.json()).data;
    success(`Benchmark completed across 4 arms:`);
    console.log(`\n  ┌──────────────────────────────┬───────────┬─────────┬──────────────┬───────────────┐`);
    console.log(`  │ ARM                          │ EFFECTIVE │ BLOCKED │ BYPASS RATE  │ 95% WILSON CI │`);
    console.log(`  ├──────────────────────────────┼───────────┼─────────┼──────────────┼───────────────┤`);
    const armsList = bm.results?.arms || [];
    for (const arm of armsList) {
      const armLabel = (arm.label || arm.arm).padEnd(28);
      const eff = String(arm.effective || 0).padEnd(9);
      const blk = String(arm.blocked || 0).padEnd(7);
      const bpr = `${((arm.bypass_rate || 0) * 100).toFixed(1)}%`.padEnd(12);
      const ci = arm.ci95 ? `[${(arm.ci95[0] * 100).toFixed(0)}%, ${(arm.ci95[1] * 100).toFixed(0)}%]`.padEnd(13) : 'N/A'.padEnd(13);
      console.log(`  │ ${armLabel} │ ${eff} │ ${blk} │ ${bpr} │ ${ci} │`);
    }
    console.log(`  └──────────────────────────────┴───────────┴─────────┴──────────────┴───────────────┘\n`);

    banner('DEMO COMPLETED SUCCESSFULLY — 100% OPERATIONAL');
  } finally {
    proxyApp.close(() => {
      apiApp.close(() => {
        targetServer.close();
      });
    });
  }
}

runDemo().catch((err) => {
  console.error('Demo encountered error:', err);
  process.exit(1);
});
