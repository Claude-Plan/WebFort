// apps/api/src/gauntlet/index.js
import { calculateWilsonCI } from '@patchproof/contracts';

// PRNG (Mulberry32) for deterministic seeding
function mulberry32(a) {
  return function() {
    let t = a += 0x6D2B79F5;
    t = Math.imul(t ^ t >>> 15, t | 1);
    t ^= t + Math.imul(t ^ t >>> 7, t | 61);
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
}

export const MUTATORS = [
  {
    id: 'url_encode_once',
    name: 'URL Encode (Single)',
    description: 'Encodes characters to standard percent encoding (%27, %20)',
    mutate: (req) => {
      const copy = JSON.parse(JSON.stringify(req));
      if (copy.url.includes('=')) {
        const [path, qs] = copy.url.split('?');
        const sp = new URLSearchParams(qs);
        for (const [k, v] of Array.from(sp.entries())) {
          sp.set(k, encodeURIComponent(v));
        }
        copy.url = `${path}?${sp.toString()}`;
      }
      return [copy];
    }
  },
  {
    id: 'url_encode_double',
    name: 'URL Encode (Double)',
    description: 'Double percent encoding (%2527, %2520)',
    mutate: (req) => {
      const copy = JSON.parse(JSON.stringify(req));
      if (copy.url.includes('?')) {
        const [path, qs] = copy.url.split('?');
        const parts = qs.split('&').map(pair => {
          const [k, v] = pair.split('=');
          const dbl = encodeURIComponent(encodeURIComponent(decodeURIComponent(v || '')));
          return `${k}=${dbl}`;
        });
        copy.url = `${path}?${parts.join('&')}`;
      }
      return [copy];
    }
  },
  {
    id: 'mixed_case',
    name: 'Mixed / Alternate Case',
    description: 'Randomizes case of SQL and payload keywords (uNiOn, SeLeCt)',
    mutate: (req, prng) => {
      const copy = JSON.parse(JSON.stringify(req));
      const randomize = (str) => str.split('').map(c => (prng() > 0.5 ? c.toUpperCase() : c.toLowerCase())).join('');
      if (copy.url.includes('?')) {
        const [path, qs] = copy.url.split('?');
        copy.url = `${path}?${randomize(qs)}`;
      }
      if (copy.body && typeof copy.body === 'string') {
        copy.body = randomize(copy.body);
      }
      return [copy];
    }
  },
  {
    id: 'sql_inline_comment_space',
    name: 'SQL Inline Comment Space',
    description: 'Replaces spaces with SQL inline comment blocks (/**/)',
    mutate: (req) => {
      const copy = JSON.parse(JSON.stringify(req));
      if (copy.url.includes('?')) {
        copy.url = copy.url.replace(/(%20|\+|\s)/g, '/**/');
      }
      if (copy.body && typeof copy.body === 'string') {
        copy.body = copy.body.replace(/\s+/g, '/**/');
      }
      return [copy];
    }
  },
  {
    id: 'sql_alt_whitespace',
    name: 'Alternate Whitespace Variants',
    description: 'Substitutes space with tabs (%09), newlines (%0A), formfeeds (%0C)',
    mutate: (req, prng) => {
      const copy = JSON.parse(JSON.stringify(req));
      const whitespaces = ['%09', '%0A', '%0B', '%0C', '%A0'];
      const pick = () => whitespaces[Math.floor(prng() * whitespaces.length)];
      if (copy.url.includes('?')) {
        copy.url = copy.url.replace(/(%20|\+|\s)/g, () => pick());
      }
      return [copy];
    }
  },
  {
    id: 'json_unicode_escape',
    name: 'JSON Unicode Escaping',
    description: 'Encodes payload characters into \\u00xx Unicode JSON escapes',
    mutate: (req) => {
      const copy = JSON.parse(JSON.stringify(req));
      if (copy.body && typeof copy.body === 'string') {
        try {
          const parsed = JSON.parse(copy.body);
          for (const key of Object.keys(parsed)) {
            if (typeof parsed[key] === 'string') {
              parsed[key] = parsed[key].replace(/['= -]/g, c => `\\u00${c.charCodeAt(0).toString(16)}`);
            }
          }
          copy.body = JSON.stringify(parsed);
        } catch {}
      }
      return [copy];
    }
  },
  {
    id: 'html_entity',
    name: 'HTML Entity Encoding',
    description: 'Replaces quotes and operators with HTML entities (&#39;, &apos;)',
    mutate: (req) => {
      const copy = JSON.parse(JSON.stringify(req));
      const entityMap = { "'": '&#39;', '"': '&quot;', '<': '&lt;', '>': '&gt;' };
      const repl = (s) => s.replace(/['"<>]/g, m => entityMap[m] || m);
      if (copy.url.includes('?')) copy.url = repl(copy.url);
      if (copy.body && typeof copy.body === 'string') copy.body = repl(copy.body);
      return [copy];
    }
  },
  {
    id: 'unicode_fullwidth',
    name: 'Unicode Fullwidth Characters',
    description: 'Substitutes ASCII quotes with full-width Unicode characters',
    mutate: (req) => {
      const copy = JSON.parse(JSON.stringify(req));
      // Full-width single quote \uFF07 (＇)
      const repl = (s) => s.replace(/'/g, '\uFF07');
      if (copy.url.includes('?')) copy.url = repl(copy.url);
      return [copy];
    }
  },
  {
    id: 'null_byte_variants',
    name: 'Null Byte Injection Variants',
    description: 'Prepends or appends null byte tokens (%00, %2500)',
    mutate: (req, prng) => {
      const copy = JSON.parse(JSON.stringify(req));
      const nulls = ['%00', '%2500'];
      const chosen = nulls[Math.floor(prng() * nulls.length)];
      if (copy.url.includes('=')) {
        copy.url = copy.url + chosen;
      }
      return [copy];
    }
  },
  {
    id: 'hpp_duplicate_param',
    name: 'HTTP Parameter Pollution (HPP)',
    description: 'Injects prefixed benign parameter before the malicious payload parameter',
    mutate: (req) => {
      const copy = JSON.parse(JSON.stringify(req));
      if (copy.url.includes('q=')) {
        // Prepend innocent q parameter
        copy.url = copy.url.replace('q=', 'q=apple&q=');
      }
      return [copy];
    }
  },
  {
    id: 'param_location_shift',
    name: 'Parameter Location Shift',
    description: 'Copies query parameter value into a duplicate header',
    mutate: (req) => {
      const copy = JSON.parse(JSON.stringify(req));
      copy.headers = copy.headers || {};
      copy.headers['X-Query-Override'] = "') UNION SELECT id, email FROM Users--";
      return [copy];
    }
  },
  {
    id: 'path_variants',
    name: 'Path Normalization Evasion',
    description: 'Uses redundant slashes or path segments (//, /./)',
    mutate: (req) => {
      const copy = JSON.parse(JSON.stringify(req));
      copy.url = copy.url.replace('/rest/products/search', '/rest//products/./search');
      return [copy];
    }
  }
];

// Generate an exact suite of deterministic mutants
export function generateMutants(baseRequest, budget = 60, seed = 42) {
  const prng = mulberry32(seed);
  const mutants = [];

  // Pass 1: Individual mutators
  for (const m of MUTATORS) {
    try {
      const res = m.mutate(baseRequest, prng);
      for (const item of res) {
        mutants.push({
          id: `${m.id}_single_${mutants.length + 1}`,
          mutator_id: m.id,
          mutator_name: m.name,
          request: item
        });
      }
    } catch {}
  }

  // Pass 2: Pairwise combinations to reach requested budget >= 30
  let pIdx = 0;
  while (mutants.length < budget && pIdx < 200) {
    pIdx++;
    const m1 = MUTATORS[Math.floor(prng() * MUTATORS.length)];
    const m2 = MUTATORS[Math.floor(prng() * MUTATORS.length)];
    if (m1.id === m2.id) continue;

    try {
      const intermediate = m1.mutate(baseRequest, prng);
      for (const inter of intermediate) {
        const paired = m2.mutate(inter, prng);
        for (const p of paired) {
          mutants.push({
            id: `combo_${m1.id}_${m2.id}_${mutants.length + 1}`,
            mutator_id: `${m1.id}+${m2.id}`,
            mutator_name: `${m1.name} + ${m2.name}`,
            request: p
          });
          if (mutants.length >= budget) break;
        }
        if (mutants.length >= budget) break;
      }
    } catch {}
  }

  return mutants.slice(0, budget);
}

// Executes the full Mutation Gauntlet with the Effective-Mutant Oracle
export async function runMutationGauntlet({
  patch,
  finding,
  targetUrl,
  proxyUrl,
  internalToken,
  mutationBudget = 60,
  seed = 42,
  onCaseCompleted = null
}) {
  const mutants = generateMutants(finding.exploit_request, mutationBudget, seed);

  let effectiveCount = 0;
  let blockedCount = 0;
  let bypassedCount = 0;
  let invalidCount = 0;

  const cases = [];
  const oracleRegex = finding.exploit_oracle?.success_body_regex
    ? new RegExp(finding.exploit_oracle.success_body_regex, 'i')
    : null;

  for (let i = 0; i < mutants.length; i++) {
    const mutant = mutants[i];
    const req = mutant.request;

    // STEP 1: Effective-Mutant Oracle (Send directly to bare target)
    let isEffective = false;
    let directStatus = 0;
    try {
      const directResp = await fetch(`${targetUrl}${req.url}`, {
        method: req.method,
        headers: req.headers || {},
        body: req.body || null
      });
      directStatus = directResp.status;
      const directBody = await directResp.text();

      // Check if target was successfully exploited by this mutant
      const statusOk = directStatus === 200;
      const bodyOk = oracleRegex ? oracleRegex.test(directBody) : true;
      isEffective = statusOk && bodyOk;
    } catch {
      isEffective = false;
    }

    if (!isEffective) {
      invalidCount++;
      const resultCase = {
        name: mutant.id,
        mutator_id: mutant.mutator_id,
        mutator_name: mutant.mutator_name,
        expected: 'allow',
        outcome: 'invalid_mutant',
        details: { directStatus, reason: 'Mutant failed to exploit bare target' }
      };
      cases.push(resultCase);
      if (onCaseCompleted) onCaseCompleted(resultCase, i + 1, mutants.length);
      continue;
    }

    // Effective mutant confirmed!
    effectiveCount++;

    // STEP 2: Send via Proxy with Candidate Rule Verification Headers
    let proxiedStatus = 0;
    let proxiedDecision = 'allow';
    try {
      const proxyHeaders = {
        ...(req.headers || {}),
        'X-Shield-Verify-Patch': String(patch.id),
        'X-Shield-Verify-Token': internalToken
      };

      const proxiedResp = await fetch(`${proxyUrl}${req.url}`, {
        method: req.method,
        headers: proxyHeaders,
        body: req.body || null
      });
      proxiedStatus = proxiedResp.status;
      proxiedDecision = proxiedResp.headers.get('x-shield-decision') || (proxiedStatus === 403 ? 'block' : 'allow');
    } catch {
      proxiedStatus = 502;
    }

    const isBlocked = proxiedStatus === 403 || proxiedDecision === 'block';

    if (isBlocked) {
      blockedCount++;
    } else {
      bypassedCount++;
    }

    const resultCase = {
      name: mutant.id,
      mutator_id: mutant.mutator_id,
      mutator_name: mutant.mutator_name,
      expected: 'block',
      outcome: isBlocked ? 'pass' : 'fail', // pass means defense passed (blocked attack)
      details: {
        proxiedStatus,
        decision: isBlocked ? 'block' : 'bypass'
      }
    };
    cases.push(resultCase);
    if (onCaseCompleted) onCaseCompleted(resultCase, i + 1, mutants.length);
  }

  const bypassRate = effectiveCount > 0 ? Math.round((bypassedCount / effectiveCount) * 1000) / 1000 : 0;
  const ci95 = calculateWilsonCI(bypassedCount, effectiveCount);

  return {
    seed,
    mutation_budget: mutationBudget,
    total_mutants: mutants.length,
    effective: effectiveCount,
    blocked: blockedCount,
    bypassed: bypassedCount,
    invalid: invalidCount,
    bypass_rate: bypassRate,
    ci95,
    cases
  };
}
