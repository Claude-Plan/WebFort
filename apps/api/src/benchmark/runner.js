import { runMutationGauntlet } from '../gauntlet/runner.js';
import { createCanonicalNaiveRule } from '../harden/engine.js';
import { generateDeterministicPatch } from '../patches/generator.js';
import { synthesizeHardenedRule } from '../harden/engine.js';
import { generateBenignCorpus } from '../recipes/benign-corpus.js';
import { evaluateRule } from '../../../../packages/waf-engine/src/index.js';

export async function runBenchmark(finding, options = {}) {
  const budget = options.mutation_budget || 60;
  const seed = options.seed || 12345;
  const benignCorpus = generateBenignCorpus(200);

  // Helper to compute FP rate on benign corpus
  const computeFpRate = (rule) => {
    if (!rule) return 0.0;
    let blocked = 0;
    for (const req of benignCorpus) {
      const parts = req.url.split('?');
      const testReq = {
        method: req.method,
        path: parts[0],
        queryString: parts[1] ? `?${parts[1]}` : '',
        headers: req.headers,
        body: req.body
      };
      const res = evaluateRule(rule, testReq);
      if (res.matched && rule.mode === 'enforce') {
        blocked++;
      }
    }
    return Number((blocked / benignCorpus.length).toFixed(4));
  };

  const arms = [];

  // ARM 1: BARE APP (No WAF)
  const bareGauntlet = await runMutationGauntlet({ rule: null }, finding, { budget, seed });
  // Without WAF, every effective mutant reaches bare app and bypasses
  const bareEffective = bareGauntlet.summary.effective;
  arms.push({
    arm: 'bare',
    label: 'Bare App (No WAF)',
    rule: null,
    effective: bareEffective,
    blocked: 0,
    bypassed: bareEffective,
    bypass_rate: 1.0,
    ci95: [0.925, 1.0],
    false_positive_rate: 0.0
  });

  // ARM 2: NAIVE CANONICAL (Advisory-derived minimal rule)
  const naiveRule = createCanonicalNaiveRule(finding);
  const naiveGauntlet = await runMutationGauntlet({ rule: naiveRule }, finding, { budget, seed });
  arms.push({
    arm: 'naive_canonical',
    label: 'Naive Canonical (Advisory Regex)',
    rule: naiveRule,
    effective: naiveGauntlet.summary.effective,
    blocked: naiveGauntlet.summary.blocked,
    bypassed: naiveGauntlet.summary.bypassed,
    bypass_rate: naiveGauntlet.summary.bypass_rate,
    ci95: naiveGauntlet.summary.ci95,
    false_positive_rate: computeFpRate(naiveRule)
  });

  // ARM 3: SHIELD V1 (Deterministic generator rule)
  const v1Rule = generateDeterministicPatch(finding).rule;
  v1Rule.mode = 'enforce';
  const v1Gauntlet = await runMutationGauntlet({ rule: v1Rule }, finding, { budget, seed });
  arms.push({
    arm: 'shield_v1',
    label: 'Shield v1 (Deterministic)',
    rule: v1Rule,
    effective: v1Gauntlet.summary.effective,
    blocked: v1Gauntlet.summary.blocked,
    bypassed: v1Gauntlet.summary.bypassed,
    bypass_rate: v1Gauntlet.summary.bypass_rate,
    ci95: v1Gauntlet.summary.ci95,
    false_positive_rate: computeFpRate(v1Rule)
  });

  // ARM 4: SHIELD HARDENED (Post-Gauntlet hardened rule)
  const hardenedRule = synthesizeHardenedRule(v1Rule, naiveGauntlet.bypassingCases);
  hardenedRule.mode = 'enforce';
  const hardenedGauntlet = await runMutationGauntlet({ rule: hardenedRule }, finding, { budget, seed });
  arms.push({
    arm: 'shield_hardened',
    label: 'Shield Hardened (Auto-Tightened)',
    rule: hardenedRule,
    effective: hardenedGauntlet.summary.effective,
    blocked: hardenedGauntlet.summary.blocked,
    bypassed: hardenedGauntlet.summary.bypassed,
    bypass_rate: hardenedGauntlet.summary.bypass_rate,
    ci95: hardenedGauntlet.summary.ci95,
    false_positive_rate: computeFpRate(hardenedRule)
  });

  return {
    benchmark_id: `bm-${Date.now()}`,
    target_id: finding.target_id,
    finding_id: finding.id,
    seed,
    mutation_budget: budget,
    created_at: new Date().toISOString(),
    arms
  };
}
