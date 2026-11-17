import { runMutationGauntlet } from '../gauntlet/runner.js';
import { runVerification } from '../patches/verifier.js';
import { Repository } from '../db/repository.js';
import { evaluateRule } from '../../../../packages/waf-engine/src/index.js';

export function createCanonicalNaiveRule(finding) {
  const method = finding.method || 'GET';
  const cleanPath = (finding.url || '/').split('?')[0];
  const param = finding.param || 'q';
  const paramLocation = finding.param_location || (method === 'POST' ? 'body_json' : 'query');

  return {
    schema_version: '1.0',
    name: `Naive Canonical Advisory Rule for ${cleanPath}`,
    scope: {
      methods: [method],
      path: { kind: 'exact', value: cleanPath }
    },
    inspect: [
      { location: paramLocation, name: param }
    ],
    normalize: [], // Deliberately empty: naive rule lacks normalizers
    condition: {
      op: 'regex_match',
      value: "union\\s+select" // Minimal pattern without encoding/casing protection
    },
    action: 'block',
    mode: 'enforce'
  };
}

export function synthesizeHardenedRule(currentRule, bypassingCases) {
  const nextRule = JSON.parse(JSON.stringify(currentRule));
  const normalizers = new Set(nextRule.normalize || []);
  const inspectTargets = nextRule.inspect || [];

  for (const item of bypassingCases) {
    const mutatorId = item.primary_mutator || item.mutator_id;

    // S1: Normalizer corrections
    if (mutatorId.includes('url_encode_double') || mutatorId.includes('url_encode_once')) {
      normalizers.add('url_decode_recursive');
    }
    if (mutatorId.includes('mixed_case')) {
      normalizers.add('lowercase');
    }
    if (mutatorId.includes('sql_inline_comment_space')) {
      normalizers.add('strip_sql_comments');
    }
    if (mutatorId.includes('sql_alt_whitespace')) {
      normalizers.add('strip_whitespace_variants');
      normalizers.add('collapse_whitespace');
    }
    if (mutatorId.includes('html_entity')) {
      normalizers.add('html_entity_decode');
    }
    if (mutatorId.includes('null_byte_variants')) {
      normalizers.add('remove_null_bytes');
    }
    if (mutatorId.includes('unicode_fullwidth')) {
      normalizers.add('unicode_nfkc');
    }

    // S2: Scope and Inspection corrections
    if (mutatorId.includes('param_location_shift')) {
      // Widen inspect locations to include query, body_form, and body_json
      const paramName = inspectTargets[0]?.name || 'q';
      const existingLocs = new Set(inspectTargets.map(t => t.location));
      if (!existingLocs.has('body_form')) {
        inspectTargets.push({ location: 'body_form', name: paramName });
      }
      if (!existingLocs.has('body_json')) {
        inspectTargets.push({ location: 'body_json', name: paramName });
      }
    }

    if (mutatorId.includes('path_variants')) {
      // Widen scope from exact to prefix
      if (nextRule.scope?.path) {
        nextRule.scope.path.kind = 'prefix';
      }
    }
  }

  // Preserve canonical normalizer ordering as per §7
  const canonicalOrder = [
    'url_decode_recursive',
    'html_entity_decode',
    'lowercase',
    'strip_sql_comments',
    'strip_whitespace_variants',
    'collapse_whitespace',
    'remove_null_bytes',
    'unicode_nfkc'
  ];

  nextRule.normalize = canonicalOrder.filter(n => normalizers.has(n));
  nextRule.inspect = inspectTargets;

  // Enhance regex condition to match SQLi variants
  if (!nextRule.condition.value.includes("'\\s+or\\s+1=1")) {
    nextRule.condition.value = "union\\s+select|'\\s*or\\s*'?1'?='?1|'\\s+or\\s+1=1|--|#|/\\*.*\\*/";
  }

  return nextRule;
}

/**
 * Auto-Tighten Hardening Loop (§9.2)
 */
export async function runAutoTighten(initialPatch, finding, options = {}) {
  const maxIterations = options.maxIterations || 5;
  const budget = options.mutationBudget || 60;
  const trainingSeed = options.seed !== undefined ? options.seed : 42;
  const startMode = options.start || 'current';
  const sseEmitter = options.sseEmitter || null;

  let currentPatch = initialPatch;

  // If startMode is canonical, initialize v1 as naive rule
  if (startMode === 'canonical') {
    const naiveRule = createCanonicalNaiveRule(finding);
    currentPatch = await Repository.createPatch({
      finding_id: finding.id,
      version: 1,
      source: 'canonical',
      rule: naiveRule,
      mode: 'shadow',
      status: 'draft',
      rationale: 'Naive canonical patch derived from minimal advisory specification for baseline comparison.'
    });
  }

  const iterations = [];
  const regressionSet = []; // Persistent regression discipline
  let bestPatch = currentPatch;

  for (let iter = 1; iter <= maxIterations; iter++) {
    // 1. Run Gauntlet with training seed
    const gauntletResult = await runMutationGauntlet(currentPatch, finding, {
      budget,
      seed: trainingSeed + iter * 17
    });

    // 2. Test regression set
    let regressionBypasses = 0;
    for (const regMutant of regressionSet) {
      const evalRes = evaluateRule(currentPatch.rule, regMutant.testReq);
      if (!evalRes.matched) {
        regressionBypasses++;
      }
    }

    const iterSummary = {
      iteration: iter,
      version: currentPatch.version,
      patch_id: currentPatch.id,
      rule: currentPatch.rule,
      effective: gauntletResult.summary.effective,
      blocked: gauntletResult.summary.blocked,
      bypassed: gauntletResult.summary.bypassed,
      bypass_rate: gauntletResult.summary.bypass_rate,
      ci95: gauntletResult.summary.ci95,
      regression_count: regressionSet.length,
      regression_bypasses: regressionBypasses
    };

    iterations.push(iterSummary);

    if (sseEmitter) {
      sseEmitter('hardening.progress', iterSummary);
    }

    // Check termination: 0 bypasses on gauntlet + regression set
    if (gauntletResult.summary.bypassed === 0 && regressionBypasses === 0) {
      bestPatch = currentPatch;
      break;
    }

    // Accumulate newly identified bypasses into regression set
    for (const bCase of gauntletResult.bypassingCases) {
      regressionSet.push(bCase);
    }

    // 3. Synthesize next tightened rule version
    const tightenedRule = synthesizeHardenedRule(currentPatch.rule, gauntletResult.bypassingCases);

    const nextVersion = currentPatch.version + 1;
    const newPatch = await Repository.createPatch({
      finding_id: finding.id,
      version: nextVersion,
      parent_patch_id: currentPatch.id,
      source: 'hardened',
      rule: tightenedRule,
      mode: 'enforce',
      status: 'draft',
      rationale: `Auto-tightened rule version ${nextVersion} mitigating ${gauntletResult.bypassingCases.length} detected mutation bypasses.`
    });

    currentPatch = newPatch;
    bestPatch = newPatch;
  }

  // 4. Final Exam on Unseen Seed (§9.2 #5)
  const examSeed = (trainingSeed + 99991) >>> 0;
  const examResult = await runMutationGauntlet(bestPatch, finding, {
    budget,
    seed: examSeed
  });

  const examSummary = {
    seed: examSeed,
    budget,
    effective: examResult.summary.effective,
    blocked: examResult.summary.blocked,
    bypassed: examResult.summary.bypassed,
    bypass_rate: examResult.summary.bypass_rate,
    ci95: examResult.summary.ci95,
    status: examResult.summary.status
  };

  const hardeningRun = {
    patch_id: initialPatch.id,
    best_patch_id: bestPatch.id,
    start_mode: startMode,
    max_iterations: maxIterations,
    mutation_budget: budget,
    seed: trainingSeed,
    iterations,
    exam: examSummary,
    status: 'completed',
    created_at: new Date().toISOString()
  };

  return hardeningRun;
}
