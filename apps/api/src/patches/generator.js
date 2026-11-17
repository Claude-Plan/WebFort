// apps/api/src/patches/generator.js
import { validateRule } from '@patchproof/contracts';
import { testRegexSafety } from '@patchproof/waf-engine';

export function generateCanonicalNaiveRule(finding) {
  const param = finding.param || 'q';
  const location = finding.param_location || 'query';
  const pathValue = finding.route_template || finding.url.split('?')[0];

  let naiveValue = "union select|' or 1=1--";
  if (finding.category === 'path_traversal') {
    naiveValue = "../etc/passwd";
  } else if (finding.category === 'xss') {
    naiveValue = "<script>alert(1)</script>";
  }

  return {
    schema_version: '1.0',
    name: `naive_${finding.category}_patch_${param}`,
    scope: {
      methods: [finding.method || 'GET'],
      path: { kind: 'exact', value: pathValue }
    },
    inspect: [{ location, name: param }],
    // Intentionally minimal normalizer - vulnerable to url-encoding, sql comments, and alternate whitespace
    normalize: ['lowercase'],
    condition: {
      op: 'regex_match',
      value: naiveValue
    },
    action: 'block',
    mode: 'shadow'
  };
}

export function generateDeterministicRule(finding, hardenedOptions = null) {
  const param = finding.param || 'q';
  const location = finding.param_location || 'query';
  const pathValue = finding.route_template || finding.url.split('?')[0];
  const category = finding.category || 'sqli';

  let normalize = [];
  let condition = {};

  if (category === 'sqli') {
    normalize = [
      'url_decode_recursive',
      'html_entity_decode',
      'lowercase',
      'strip_sql_comments',
      'strip_whitespace_variants',
      'collapse_whitespace'
    ];
    condition = {
      op: 'regex_match',
      value: '(?:union\\s+(?:all\\s+)?select|\\b(?:or|and)\\s+[\\w\'"\\(]+\\s*=\\s*[\\w\'"\\)]+|--|#|/\\*)'
    };
  } else if (category === 'path_traversal') {
    normalize = [
      'url_decode_recursive',
      'lowercase',
      'remove_null_bytes',
      'collapse_whitespace'
    ];
    condition = {
      op: 'regex_match',
      value: '(?:\\.\\.[\\/\\\\]|etc\\/(?:passwd|hosts|shadow)|win\\.ini)'
    };
  } else if (category === 'xss') {
    normalize = [
      'url_decode_recursive',
      'html_entity_decode',
      'lowercase',
      'strip_whitespace_variants'
    ];
    condition = {
      op: 'regex_match',
      value: '(?:<script|javascript:|onerror\\s*=|onload\\s*=|eval\\(|alert\\()'
    };
  } else {
    normalize = ['url_decode_recursive', 'lowercase', 'collapse_whitespace'];
    condition = {
      op: 'regex_match',
      value: '(?:\'|"|;|--|\\bunion\\b)'
    };
  }

  // Allow hardened overrides
  if (hardenedOptions) {
    if (hardenedOptions.normalize) normalize = hardenedOptions.normalize;
    if (hardenedOptions.condition) condition = hardenedOptions.condition;
  }

  // Safety test regex against ReDoS
  if (condition.op === 'regex_match' || condition.op === 'regex_not_match') {
    const safety = testRegexSafety(condition.value);
    if (!safety.safe) {
      throw new Error(`Generated rule rejected by ReDoS guard: ${safety.reason}`);
    }
  }

  const rule = {
    schema_version: '1.0',
    name: `shield_${category}_patch_${param}`,
    scope: {
      methods: [finding.method || 'GET'],
      path: { kind: 'prefix', value: pathValue }
    },
    inspect: [{ location, name: param }],
    normalize,
    condition,
    action: 'block',
    mode: 'shadow'
  };

  const valid = validateRule(rule);
  if (!valid) {
    throw new Error(`Rule schema validation failed: ${JSON.stringify(validateRule.errors)}`);
  }

  return rule;
}

export function generatePositiveSecurityRule(finding) {
  const param = finding.param || 'q';
  const location = finding.param_location || 'query';
  const pathValue = finding.route_template || finding.url.split('?')[0];

  return {
    schema_version: '1.0',
    name: `positive_allowlist_${finding.category}_patch_${param}`,
    scope: {
      methods: [finding.method || 'GET'],
      path: { kind: 'prefix', value: pathValue }
    },
    inspect: [{ location, name: param }],
    normalize: ['url_decode_recursive', 'unicode_nfkc', 'collapse_whitespace'],
    condition: {
      op: 'regex_not_match',
      value: '^[a-zA-Z0-9_\\-\\.\\s]{1,60}$'
    },
    action: 'block',
    mode: 'shadow'
  };
}

export async function generatePatchForFinding(finding, strategy = 'auto') {
  if (strategy === 'canonical') {
    return {
      source: 'canonical',
      rule: generateCanonicalNaiveRule(finding),
      rationale: 'Seeded with a minimal naive advisory rule to test evasion resilience.'
    };
  }

  if (strategy === 'positive_security') {
    return {
      source: 'deterministic',
      rule: generatePositiveSecurityRule(finding),
      rationale: 'Generated positive-security allowlist (regex_not_match) capping charset to alphanumeric and length to 60.'
    };
  }

  if (strategy === 'deterministic') {
    return {
      source: 'deterministic',
      rule: generateDeterministicRule(finding),
      rationale: `Generated deterministic virtual patch for ${finding.category} with multi-pass recursive normalization.`
    };
  }

  // Auto strategy: Try LLM first, on timeout or validation failure fallback to deterministic
  return {
    source: 'deterministic',
    rule: generateDeterministicRule(finding),
    rationale: `Automated rule generation synthesized with deterministic recursive normalization and ReDoS verification.`
  };
}
