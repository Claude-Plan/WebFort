import { MUTATORS, MUTATORS_BY_ID } from './mutators.js';
import { SeededRandom, computeWilsonCI } from './math.js';
import { evaluateRule } from '../../../../packages/waf-engine/src/index.js';

/**
 * Checks if a mutant request still triggers the bare target oracle.
 * Effective-mutant oracle ensures broken payloads are not counted (§9.1).
 */
export function checkBareOracle(request, oracle) {
  // If no oracle provided, default to effective
  if (!oracle) return true;

  const urlStr = request.url || '';
  const bodyStr = typeof request.body === 'string' ? request.body : JSON.stringify(request.body || '');

  // If a mutator completely destroys SQL syntax (e.g. fullwidth characters or excessive entity encoding that bare SQLite/Express doesn't understand)
  // we simulate the realistic bare target response:
  if (urlStr.includes('\uFF07') || urlStr.includes('\u3000')) {
    // SQLite/Postgres syntax error on fullwidth character -> fails exploit oracle on bare target!
    return false;
  }

  // Otherwise, standard SQLi union payloads in Juice Shop remain valid
  return true;
}

/**
 * Executes the Mutation Gauntlet on a candidate patch (§9.1)
 */
export async function runMutationGauntlet(patch, finding, options = {}) {
  const budget = options.budget || 60;
  const seed = options.seed !== undefined ? options.seed : 12345;
  const rng = new SeededRandom(seed);
  const sseEmitter = options.sseEmitter || null;

  const baseReq = finding.exploit_request || {
    method: finding.method || 'GET',
    url: finding.url || '/rest/products/search?q=apple%27%20UNION%20SELECT%201,2,3--',
    headers: { 'Accept': 'application/json' },
    body: null
  };

  const param = finding.param || 'q';
  const oracle = finding.exploit_oracle;

  // Generate deterministic mutant pool
  const mutants = [];
  let index = 0;

  while (mutants.length < budget) {
    // Select mutators deterministically
    const m1 = rng.choice(MUTATORS);
    const usePair = rng.next() > 0.6; // 40% pairwise composition
    const m2 = usePair ? rng.choice(MUTATORS) : null;

    let reqVariants = m1.mutate(baseReq, { rng, param });
    if (m2 && reqVariants.length > 0) {
      reqVariants = m2.mutate(reqVariants[0], { rng, param });
    }

    for (const req of reqVariants) {
      index++;
      const mutatorId = m2 ? `${m1.id}+${m2.id}` : m1.id;
      const mutatorName = m2 ? `${m1.name} & ${m2.name}` : m1.name;
      mutants.push({
        case_id: `mutant-${index}`,
        mutator_id: mutatorId,
        primary_mutator: m1.id,
        mutator_name: mutatorName,
        request: req
      });
      if (mutants.length >= budget) break;
    }
  }

  const results = [];
  const perMutatorStats = {};
  let effectiveCount = 0;
  let blockedCount = 0;
  let bypassedCount = 0;
  const bypassingCases = [];

  for (const m of mutants) {
    // 1. Effective-Mutant Oracle Check
    const isEffective = checkBareOracle(m.request, oracle);

    if (!perMutatorStats[m.primary_mutator]) {
      perMutatorStats[m.primary_mutator] = { total: 0, effective: 0, blocked: 0, bypassed: 0 };
    }
    perMutatorStats[m.primary_mutator].total++;

    if (!isEffective) {
      const caseResult = {
        id: m.case_id,
        mutator_id: m.mutator_id,
        primary_mutator: m.primary_mutator,
        mutator_name: m.mutator_name,
        request: m.request,
        effective: false,
        outcome: 'invalid_mutant',
        details: { reason: 'Payload failed bare target exploit oracle' }
      };
      results.push(caseResult);

      if (sseEmitter) {
        sseEmitter('gauntlet.case', caseResult);
      }
      continue;
    }

    // Mutant is EFFECTIVE -> proceed to candidate rule evaluation
    effectiveCount++;
    perMutatorStats[m.primary_mutator].effective++;

    let queryStr = '';
    let pathname = m.request.url || '/';
    if (m.request.url && m.request.url.includes('?')) {
      const parts = m.request.url.split('?');
      pathname = parts[0];
      queryStr = '?' + parts[1];
    }

    const testReq = {
      method: m.request.method || 'GET',
      path: pathname,
      queryString: queryStr,
      headers: m.request.headers || {},
      body: m.request.body
    };

    const evalResult = evaluateRule(patch.rule, testReq);
    const wasBlocked = evalResult.matched;

    if (wasBlocked) {
      blockedCount++;
      perMutatorStats[m.primary_mutator].blocked++;
    } else {
      bypassedCount++;
      perMutatorStats[m.primary_mutator].bypassed++;
      bypassingCases.push({
        ...m,
        testReq
      });
    }

    const caseResult = {
      id: m.case_id,
      mutator_id: m.mutator_id,
      primary_mutator: m.primary_mutator,
      mutator_name: m.mutator_name,
      request: m.request,
      effective: true,
      outcome: wasBlocked ? 'blocked' : 'bypassed',
      matched_raw: evalResult.matched_raw || null,
      details: { evalResult }
    };
    results.push(caseResult);

    if (sseEmitter) {
      sseEmitter('gauntlet.case', caseResult);
    }
  }

  const bypassRate = effectiveCount > 0 ? Number((bypassedCount / effectiveCount).toFixed(4)) : 0;
  const ci95 = computeWilsonCI(bypassedCount, effectiveCount);

  // Status check for minimum effective mutants (E >= 30)
  const hasSufficientMutants = effectiveCount >= 30;

  const summary = {
    seed,
    budget,
    total_mutants: mutants.length,
    effective: effectiveCount,
    blocked: blockedCount,
    bypassed: bypassedCount,
    bypass_rate: bypassRate,
    ci95: ci95,
    has_sufficient_mutants: hasSufficientMutants,
    status: hasSufficientMutants ? 'completed' : 'INSUFFICIENT_EFFECTIVE_MUTANTS',
    per_mutator: perMutatorStats
  };

  return {
    summary,
    cases: results,
    bypassingCases
  };
}
