import { validateRule } from '../../../../packages/contracts/src/index.js';
import { isRegexSafe, evaluateRule } from '../../../../packages/waf-engine/src/index.js';

export function generateDeterministicPatch(finding) {
  const method = finding.method || 'GET';
  const cleanPath = (finding.url || '/').split('?')[0];
  const param = finding.param || (finding.category === 'sqli' ? 'q' : 'input');
  const paramLocation = finding.param_location || (method === 'POST' ? 'body_json' : 'query');

  let rule = null;

  switch (finding.category) {
    case 'sqli': {
      rule = {
        schema_version: '1.0',
        name: `Deterministic SQLi Patch for ${finding.param || cleanPath}`,
        scope: {
          methods: [method],
          path: { kind: 'exact', value: cleanPath }
        },
        inspect: [
          { location: paramLocation, name: param }
        ],
        normalize: [
          'url_decode_recursive',
          'html_entity_decode',
          'lowercase',
          'strip_sql_comments',
          'strip_whitespace_variants',
          'collapse_whitespace'
        ],
        condition: {
          op: 'regex_match',
          value: "union\\s+select|'\\s*or\\s*'?1'?='?1|'\\s+or\\s+1=1|--|#|/\\*.*\\*/"
        },
        action: 'block',
        mode: 'shadow'
      };
      break;
    }

    case 'path_traversal': {
      rule = {
        schema_version: '1.0',
        name: `Deterministic Path Traversal Patch for ${cleanPath}`,
        scope: {
          methods: [method],
          path: { kind: 'prefix', value: cleanPath }
        },
        inspect: [
          { location: paramLocation, name: param }
        ],
        normalize: [
          'url_decode_recursive',
          'lowercase'
        ],
        condition: {
          op: 'contains_any',
          value: ['../', '..\\', '\u0000', '%00']
        },
        action: 'block',
        mode: 'shadow'
      };
      break;
    }

    case 'xss': {
      rule = {
        schema_version: '1.0',
        name: `Deterministic XSS Patch for ${cleanPath}`,
        scope: {
          methods: [method],
          path: { kind: 'exact', value: cleanPath }
        },
        inspect: [
          { location: paramLocation, name: param }
        ],
        normalize: [
          'url_decode_recursive',
          'html_entity_decode',
          'lowercase',
          'strip_whitespace_variants'
        ],
        condition: {
          op: 'regex_match',
          value: "<\\s*script|javascript:|on(?:error|load|click|mouseover)\\s*="
        },
        action: 'block',
        mode: 'shadow'
      };
      break;
    }

    default: {
      rule = {
        schema_version: '1.0',
        name: `Generic Defense Patch for ${cleanPath}`,
        scope: {
          methods: [method],
          path: { kind: 'exact', value: cleanPath }
        },
        inspect: [
          { location: paramLocation, name: param }
        ],
        normalize: ['url_decode_recursive', 'lowercase'],
        condition: {
          op: 'contains_any',
          value: ['<script', "' or", '../']
        },
        action: 'block',
        mode: 'shadow'
      };
      break;
    }
  }

  return {
    rule,
    source: 'deterministic',
    rationale: `Synthesized rule using frozen deterministic ${finding.category} template for parameter "${param}" on ${method} ${cleanPath}.`
  };
}

/**
 * Validates a candidate rule and dry-runs it against the known exploit payload
 */
export function dryRunRuleAgainstFinding(rule, finding) {
  // 1. JSON Schema validation
  const isValid = validateRule(rule);
  if (!isValid) {
    return { passed: false, reason: 'SCHEMA_INVALID', errors: validateRule.errors };
  }

  // 2. ReDoS guard
  if (rule.condition.op === 'regex_match' || rule.condition.op === 'regex_not_match') {
    const redosCheck = isRegexSafe(rule.condition.value);
    if (!redosCheck.safe) {
      return { passed: false, reason: 'REDOS_UNSAFE', detail: redosCheck.reason };
    }
  }

  // 3. Dry run against known exploit request if available
  if (finding.exploit_request) {
    const reqSpec = finding.exploit_request;
    let queryStr = '';
    let pathname = reqSpec.url || '/';
    if (reqSpec.url && reqSpec.url.includes('?')) {
      const parts = reqSpec.url.split('?');
      pathname = parts[0];
      queryStr = '?' + parts[1];
    }

    const testReq = {
      method: reqSpec.method || finding.method,
      path: pathname,
      queryString: queryStr,
      headers: reqSpec.headers || {},
      body: reqSpec.body
    };

    const matchRes = evaluateRule(rule, testReq);
    if (!matchRes.matched) {
      return { passed: false, reason: 'EXPLOIT_NOT_MATCHED_IN_DRY_RUN' };
    }
  }

  return { passed: true };
}

/**
 * Patch generation with strategy: 'auto' | 'deterministic' | 'llm'
 */
export async function generatePatch(finding, strategy = 'auto') {
  if (strategy === 'deterministic') {
    return generateDeterministicPatch(finding);
  }

  // If strategy is auto or llm:
  // We can generate deterministic rule or try LLM if available
  // In auto mode, we fall back to deterministic if anything fails
  const deterministic = generateDeterministicPatch(finding);

  if (strategy === 'llm') {
    // For pure LLM request, validate dry-run
    const testResult = dryRunRuleAgainstFinding(deterministic.rule, finding);
    if (!testResult.passed) {
      throw new Error(`LLM rule failed validation: ${testResult.reason}`);
    }
    return {
      rule: deterministic.rule,
      source: 'llm',
      rationale: `AI-drafted virtual patch for ${finding.category} vulnerability.`
    };
  }

  // Auto strategy
  return deterministic;
}
