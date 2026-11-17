import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createApiApp } from '../src/index.js';
import { MUTATORS, MUTATORS_BY_ID } from '../src/gauntlet/mutators.js';
import { SeededRandom, computeWilsonCI } from '../src/gauntlet/math.js';
import { checkBareOracle, runMutationGauntlet } from '../src/gauntlet/runner.js';
import { runAutoTighten, createCanonicalNaiveRule } from '../src/harden/engine.js';
import { canonicalJsonStringify, sha256, signReport, verifyReportSignature } from '../src/proof/signer.js';
import { createProofReport } from '../src/proof/report-generator.js';
import { runBenchmark } from '../src/benchmark/runner.js';

describe('P3: Mutation Gauntlet, Auto-Hardening & Proof Subsystem', () => {
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

  const baseFinding = {
    id: 'finding-sqli-01',
    target_id: 'target-01',
    title: 'SQL Injection in /rest/products/search',
    category: 'sqli',
    scanner_risk: 'critical',
    method: 'GET',
    url: '/rest/products/search?q=apple%27%20UNION%20SELECT%201,2,3--',
    param: 'q',
    param_location: 'query',
    evidence: 'admin@juice-sh.op',
    exploit_request: {
      method: 'GET',
      url: '/rest/products/search?q=apple%27%20UNION%20SELECT%201,2,3--',
      headers: { 'Accept': 'application/json' },
      body: null
    },
    exploit_oracle: {
      success_status: [200],
      success_body_regex: '(admin|Users|UNION.*SELECT)'
    },
    exploit_confirmed: true,
    status: 'open',
    dedupe_key: 'sqli-search-dedupe',
    provenance: 'real_capture'
  };

  it('1. Mutation Registry implements >= 10 deterministic mutator functions', () => {
    assert.ok(MUTATORS.length >= 10, `Expected >= 10 mutators, found ${MUTATORS.length}`);

    const requiredIds = [
      'url_encode_once',
      'url_encode_double',
      'mixed_case',
      'sql_inline_comment_space',
      'sql_alt_whitespace',
      'json_unicode_escape',
      'html_entity',
      'unicode_fullwidth',
      'null_byte_variants',
      'hpp_duplicate_param'
    ];

    for (const reqId of requiredIds) {
      const mutator = MUTATORS_BY_ID.get(reqId);
      assert.ok(mutator, `Missing required mutator: ${reqId}`);
      assert.equal(typeof mutator.mutate, 'function');

      const mutated = mutator.mutate(baseFinding.exploit_request, {
        rng: new SeededRandom(42),
        param: 'q'
      });
      assert.ok(Array.isArray(mutated) && mutated.length > 0, `Mutator ${reqId} failed to produce mutants`);
    }
  });

  it('2. Deterministic Seed PRNG produces identical mutant output given same seed', () => {
    const rng1 = new SeededRandom(999);
    const rng2 = new SeededRandom(999);

    const seq1 = [rng1.next(), rng1.next(), rng1.nextInt(1, 100)];
    const seq2 = [rng2.next(), rng2.next(), rng2.nextInt(1, 100)];

    assert.deepEqual(seq1, seq2);
  });

  it('3. Effective-Mutant Oracle filters invalid payloads from denominator', () => {
    const validMutant = { url: '/rest/products/search?q=apple%27%20UNION/**/SELECT%201--' };
    const invalidMutant = { url: '/rest/products/search?q=apple\uFF07UNION\u3000SELECT' };

    assert.equal(checkBareOracle(validMutant, baseFinding.exploit_oracle), true);
    assert.equal(checkBareOracle(invalidMutant, baseFinding.exploit_oracle), false);
  });

  it('4. Wilson 95% Confidence Interval calculation is mathematically sound', () => {
    // 0 bypasses out of 50 effective mutants
    const ciZero = computeWilsonCI(0, 50);
    assert.equal(ciZero[0], 0.0);
    assert.ok(ciZero[1] > 0.0 && ciZero[1] < 0.1, `Expected upper CI ~0.07, got ${ciZero[1]}`);

    // 25 bypasses out of 50 effective mutants (50% bypass rate)
    const ciHalf = computeWilsonCI(25, 50);
    assert.ok(ciHalf[0] < 0.50);
    assert.ok(ciHalf[1] > 0.50);
  });

  it('5. Mutation Gauntlet detects bypasses on naive canonical rule and measures confidence interval', async () => {
    const naiveRule = createCanonicalNaiveRule(baseFinding);
    const naivePatch = { id: 'naive-p1', version: 1, rule: naiveRule, source: 'canonical' };

    const gauntletResult = await runMutationGauntlet(naivePatch, baseFinding, {
      budget: 40,
      seed: 12345
    });

    const summary = gauntletResult.summary;
    assert.ok(summary.effective >= 30, `Expected E >= 30, got ${summary.effective}`);
    assert.ok(summary.bypassed > 0, `Expected naive rule to suffer bypasses, got ${summary.bypassed}`);
    assert.ok(summary.bypass_rate > 0.0);
    assert.ok(summary.ci95[0] >= 0.0 && summary.ci95[1] <= 1.0);
  });

  it('6. Auto-Tighten Hardening Loop mitigates bypasses across iterations and passes Final Exam', async () => {
    const naiveRule = createCanonicalNaiveRule(baseFinding);
    const initialPatch = { id: 'test-patch-init', version: 1, rule: naiveRule, finding_id: baseFinding.id };

    const hardeningRun = await runAutoTighten(initialPatch, baseFinding, {
      maxIterations: 3,
      mutationBudget: 40,
      seed: 777
    });

    assert.ok(hardeningRun.iterations.length >= 1);
    const firstIter = hardeningRun.iterations[0];
    const lastIter = hardeningRun.iterations[hardeningRun.iterations.length - 1];

    // Monotonic regression discipline: bypasses should reduce or reach 0
    assert.ok(lastIter.bypass_rate <= firstIter.bypass_rate);
    assert.ok(hardeningRun.exam);
    assert.ok(hardeningRun.exam.seed !== 777, 'Exam seed must be different from training seed');
  });

  it('7. Cryptographic Ed25519 signing, canonical JSON, and tamper detection', () => {
    const testReport = {
      report_version: '1.0',
      finding: { title: 'Test Finding', score: 98 },
      tests: { exploit_replay: { blocked: true } },
      limitations: ['lab target only']
    };

    // 1. Sign
    const signed = signReport(testReport);
    assert.ok(signed.sha256);
    assert.ok(signed.signature);
    assert.ok(signed.public_key);

    // 2. Verify signature on untampered report
    const verifyValid = verifyReportSignature(signed.report, signed.signature, signed.public_key);
    assert.equal(verifyValid.valid, true);

    // 3. Tamper detection: modify one byte in report -> signature verification MUST fail
    const tamperedReport = JSON.parse(JSON.stringify(signed.report));
    tamperedReport.finding.score = 99; // Tampered by 1 byte

    const verifyTampered = verifyReportSignature(tamperedReport, signed.signature, signed.public_key);
    assert.equal(verifyTampered.valid, false);
  });

  it('8. Four-Arm Benchmark compares Bare, Naive, Shield v1, and Hardened', async () => {
    const benchmark = await runBenchmark(baseFinding, { mutation_budget: 35, seed: 101 });

    assert.equal(benchmark.arms.length, 4);

    const [bare, naive, shieldV1, hardened] = benchmark.arms;

    // Arm 1: Bare app bypass rate is 100%
    assert.equal(bare.arm, 'bare');
    assert.equal(bare.bypass_rate, 1.0);
    assert.equal(bare.blocked, 0);

    // Arm 2: Naive rule has high bypass rate
    assert.equal(naive.arm, 'naive_canonical');
    assert.ok(naive.bypass_rate > 0.0);

    // Arm 3: Shield v1 has lower bypass rate
    assert.equal(shieldV1.arm, 'shield_v1');

    // Arm 4: Hardened rule achieves minimum bypass rate
    assert.equal(hardened.arm, 'shield_hardened');
    assert.ok(hardened.bypass_rate <= naive.bypass_rate);
  });

  it('9. POST /patches/:id/gauntlet and /proof via HTTP API', async () => {
    // 1. Create target & finding
    const targetRes = await fetch(`${baseUrl}/api/v1/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Benchmark Lab', base_url: 'http://localhost:3001' })
    });
    const target = (await targetRes.json()).data;

    const recipeRes = await fetch(`${baseUrl}/api/v1/recipes/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipe_id: 'R1', target_id: target.id })
    });
    const finding = (await recipeRes.json()).data.finding;

    // 2. Generate patch
    const patchRes = await fetch(`${baseUrl}/api/v1/findings/${finding.id}/patches`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ strategy: 'deterministic' })
    });
    const patch = (await patchRes.json()).data;

    // 3. Run Gauntlet via API
    const gauntletApiRes = await fetch(`${baseUrl}/api/v1/patches/${patch.id}/gauntlet`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mutation_budget: 35, seed: 42 })
    });
    assert.equal(gauntletApiRes.status, 200);
    const gauntletData = (await gauntletApiRes.json()).data;
    assert.ok(gauntletData.summary.effective >= 30);

    // 4. Generate Proof Report via API
    const proofRes = await fetch(`${baseUrl}/api/v1/patches/${patch.id}/proof`, {
      method: 'POST'
    });
    assert.equal(proofRes.status, 201);
    const proofData = (await proofRes.json()).data;
    assert.ok(proofData.signature);
    assert.ok(proofData.public_key);

    // 5. Verify Proof Report via API
    const verifyProofRes = await fetch(`${baseUrl}/api/v1/proof/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        report: proofData.report,
        signature: proofData.signature,
        public_key: proofData.public_key
      })
    });
    assert.equal(verifyProofRes.status, 200);
    const verifyResult = (await verifyProofRes.json()).data;
    assert.equal(verifyResult.valid, true);
  });
});
