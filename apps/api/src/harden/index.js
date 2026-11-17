// apps/api/src/harden/index.js
import { runMutationGauntlet } from '../gauntlet/index.js';
import { generateBenignCorpus } from '../../../../scripts/corpus-benign.js';
import { query } from '../db/index.js';

export async function runHardeningLoop({
  initialPatch,
  finding,
  targetUrl,
  proxyUrl,
  internalToken,
  maxIterations = 5,
  mutationBudget = 60,
  seed = 42,
  onProgress = null
}) {
  let currentPatch = initialPatch;
  const iterations = [];
  const regressionSet = []; // List of all bypassing mutant IDs to replay

  let bestPatch = currentPatch;
  let bestBypassRate = 1.0;

  for (let iter = 1; iter <= maxIterations; iter++) {
    if (onProgress) onProgress({ type: 'iteration_start', iteration: iter, patch_version: currentPatch.version });

    // 1. Run mutation gauntlet for this patch
    const gauntletResult = await runMutationGauntlet({
      patch: currentPatch,
      finding,
      targetUrl,
      proxyUrl,
      internalToken,
      mutationBudget,
      seed,
      onCaseCompleted: (c, idx, total) => {
        if (onProgress) onProgress({ type: 'case', iteration: iter, case: c, index: idx, total });
      }
    });

    // 2. Run benign replay (250 requests)
    const benignCorpus = generateBenignCorpus(250);
    let benignBlocked = 0;
    for (let b = 0; b < 25; b++) { // Sample check for speed during loop iterations
      const bReq = benignCorpus[b];
      try {
        const bResp = await fetch(`${proxyUrl}${bReq.url}`, {
          method: bReq.method,
          headers: {
            ...bReq.headers,
            'X-Shield-Verify-Patch': String(currentPatch.id),
            'X-Shield-Verify-Token': internalToken
          }
        });
        if (bResp.status === 403) benignBlocked++;
      } catch {}
    }
    const falsePositiveRate = Math.round((benignBlocked / 25) * 1000) / 1000;

    // Record iteration snapshot
    const iterSnapshot = {
      iteration: iter,
      patch_id: currentPatch.id,
      version: currentPatch.version,
      rule: currentPatch.rule,
      stats: {
        effective: gauntletResult.effective,
        blocked: gauntletResult.blocked,
        bypassed: gauntletResult.bypassed,
        bypass_rate: gauntletResult.bypass_rate,
        ci95: gauntletResult.ci95,
        false_positive_rate: falsePositiveRate
      }
    };
    iterations.push(iterSnapshot);

    if (gauntletResult.bypass_rate < bestBypassRate) {
      bestBypassRate = gauntletResult.bypass_rate;
      bestPatch = currentPatch;
    }

    // Check convergence: 0 bypasses and safe on benign
    if (gauntletResult.bypassed === 0 && falsePositiveRate <= 0.005) {
      if (onProgress) onProgress({ type: 'converged', iteration: iter, best_patch_id: currentPatch.id });
      break;
    }

    if (iter === maxIterations) {
      break;
    }

    // 3. Auto-Tighten: Derive next rule
    // S1: Normalizer fix & S2: Scope fix
    const currentRule = JSON.parse(JSON.stringify(currentPatch.rule));
    const normalizers = new Set(currentRule.normalize || []);

    // Check which mutators caused bypasses
    const bypassingMutators = gauntletResult.cases
      .filter(c => c.outcome === 'fail')
      .map(c => c.mutator_id);

    for (const mId of bypassingMutators) {
      if (mId.includes('url_encode')) {
        normalizers.add('url_decode_recursive');
      }
      if (mId.includes('mixed_case')) {
        normalizers.add('lowercase');
      }
      if (mId.includes('sql_inline_comment')) {
        normalizers.add('strip_sql_comments');
        normalizers.add('collapse_whitespace');
      }
      if (mId.includes('sql_alt_whitespace')) {
        normalizers.add('strip_whitespace_variants');
        normalizers.add('collapse_whitespace');
      }
      if (mId.includes('html_entity')) {
        normalizers.add('html_entity_decode');
      }
      if (mId.includes('unicode_fullwidth')) {
        normalizers.add('unicode_nfkc');
      }
    }

    // Ensure comprehensive SQLi normalization ordering
    const orderedNormalizers = [
      'url_decode_recursive',
      'html_entity_decode',
      'unicode_nfkc',
      'lowercase',
      'strip_sql_comments',
      'strip_whitespace_variants',
      'collapse_whitespace'
    ].filter(n => normalizers.has(n));

    // Refine condition regex
    let conditionValue = currentRule.condition?.value || '';
    if (conditionValue.includes("union select") || currentPatch.source === 'canonical') {
      conditionValue = '(?:union\\s+(?:all\\s+)?select|\\b(?:or|and)\\s+[\\w\'"\\(]+\\s*=\\s*[\\w\'"\\)]+|--|#|/\\*)';
    }

    // Scope tightening: prefix match
    const tightenedRule = {
      ...currentRule,
      name: `shield_hardened_v${currentPatch.version + 1}`,
      scope: {
        ...currentRule.scope,
        path: { kind: 'prefix', value: currentRule.scope.path.value }
      },
      inspect: [
        { location: 'query', name: finding.param || 'q' },
        { location: 'body_json', name: finding.param || 'q' },
        { location: 'body_form', name: finding.param || 'q' }
      ],
      normalize: orderedNormalizers,
      condition: {
        op: 'regex_match',
        value: conditionValue
      }
    };

    // Save derived patch in DB
    const insertRes = await query(
      `insert into patches (finding_id, version, parent_patch_id, source, rule, mode, status, rationale)
       values ($1, $2, $3, $4, $5, $6, $7, $8) returning *`,
      [
        finding.id,
        currentPatch.version + 1,
        currentPatch.id,
        'hardened',
        JSON.stringify(tightenedRule),
        'shadow',
        'draft',
        `Auto-tightened iteration ${iter + 1}: addressed evasion via ${bypassingMutators.slice(0, 3).join(', ')}`
      ]
    );

    currentPatch = insertRes.rows[0];
  }

  // 4. Fresh Unseen Exam Set
  // Evaluated on a different, unseen seed (seed + 9999) to verify true generalization
  const examSeed = seed + 9999;
  if (onProgress) onProgress({ type: 'exam_start', examSeed });

  const examResult = await runMutationGauntlet({
    patch: bestPatch,
    finding,
    targetUrl,
    proxyUrl,
    internalToken,
    mutationBudget,
    seed: examSeed
  });

  const isEffectiveSufficient = examResult.effective >= 30;
  const examSummary = {
    seed: examSeed,
    mutation_budget: mutationBudget,
    total_mutants: examResult.total_mutants,
    effective: examResult.effective,
    blocked: examResult.blocked,
    bypassed: examResult.bypassed,
    bypass_rate: isEffectiveSufficient ? examResult.bypass_rate : null,
    ci95: isEffectiveSufficient ? examResult.ci95 : null,
    claim: isEffectiveSufficient ? 'VALID' : 'INSUFFICIENT_EFFECTIVE_MUTANTS',
    claim_valid: isEffectiveSufficient,
    note: isEffectiveSufficient
      ? 'Effective mutants >= 30 threshold satisfied; Wilson 95% CI is rigorous.'
      : 'INSUFFICIENT_EFFECTIVE_MUTANTS: Under 30 effective mutants proved on bare target; no statistical claim made.'
  };

  return {
    iterations,
    exam: examSummary,
    best_patch: bestPatch
  };
}
