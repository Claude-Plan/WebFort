/**
 * PatchProof Frozen Contracts & Rule DSL Validator (§5 & §6)
 */

export const RULE_SCHEMA = {
  type: 'object',
  required: ['schema_version', 'name', 'scope', 'inspect', 'normalize', 'condition', 'action', 'mode'],
  properties: {
    schema_version: { type: 'string', const: '1.0' },
    name: { type: 'string' },
    scope: {
      type: 'object',
      required: ['methods', 'path'],
      properties: {
        methods: { type: 'array', items: { type: 'string' } },
        path: {
          type: 'object',
          required: ['kind', 'value'],
          properties: {
            kind: { type: 'string', enum: ['exact', 'prefix', 'template'] },
            value: { type: 'string' }
          }
        }
      }
    },
    inspect: {
      type: 'array',
      items: {
        type: 'object',
        required: ['location', 'name'],
        properties: {
          location: { type: 'string', enum: ['query', 'body_form', 'body_json', 'header', 'cookie', 'path'] },
          name: { type: 'string' }
        }
      }
    },
    normalize: {
      type: 'array',
      items: {
        type: 'string',
        enum: [
          'url_decode_recursive',
          'html_entity_decode',
          'lowercase',
          'strip_sql_comments',
          'strip_whitespace_variants',
          'collapse_whitespace',
          'remove_null_bytes',
          'unicode_nfkc'
        ]
      }
    },
    condition: {
      type: 'object',
      required: ['op', 'value'],
      properties: {
        op: { type: 'string', enum: ['regex_match', 'regex_not_match', 'contains_any', 'max_length'] },
        value: {
          anyOf: [
            { type: 'string' },
            { type: 'number' },
            { type: 'array', items: { type: 'string' } }
          ]
        }
      }
    },
    action: { type: 'string', const: 'block' },
    mode: { type: 'string', enum: ['shadow', 'enforce'] }
  }
};

const VALID_NORMALIZERS = new Set([
  'url_decode_recursive',
  'html_entity_decode',
  'lowercase',
  'strip_sql_comments',
  'strip_whitespace_variants',
  'collapse_whitespace',
  'remove_null_bytes',
  'unicode_nfkc'
]);

const VALID_INSPECT_LOCATIONS = new Set(['query', 'body_form', 'body_json', 'header', 'cookie', 'path']);
const VALID_COND_OPS = new Set(['regex_match', 'regex_not_match', 'contains_any', 'max_length']);

/**
 * Robust zero-dependency validator for the frozen Rule DSL (§7)
 */
export function validateRule(rule) {
  validateRule.errors = null;
  if (!rule || typeof rule !== 'object') {
    validateRule.errors = [{ message: 'Rule must be an object' }];
    return false;
  }

  if (rule.schema_version !== '1.0') {
    validateRule.errors = [{ message: 'schema_version must be "1.0"' }];
    return false;
  }

  if (typeof rule.name !== 'string' || !rule.name) {
    validateRule.errors = [{ message: 'name must be a non-empty string' }];
    return false;
  }

  if (!rule.scope || typeof rule.scope !== 'object') {
    validateRule.errors = [{ message: 'scope must be an object' }];
    return false;
  }

  if (!rule.scope.path || !['exact', 'prefix', 'template'].includes(rule.scope.path.kind)) {
    validateRule.errors = [{ message: 'scope.path.kind must be exact, prefix or template' }];
    return false;
  }

  if (typeof rule.scope.path.value !== 'string') {
    validateRule.errors = [{ message: 'scope.path.value must be a string' }];
    return false;
  }

  if (!Array.isArray(rule.inspect) || rule.inspect.length === 0) {
    validateRule.errors = [{ message: 'inspect must be a non-empty array' }];
    return false;
  }

  for (const item of rule.inspect) {
    if (!VALID_INSPECT_LOCATIONS.has(item.location)) {
      validateRule.errors = [{ message: `Invalid inspect location: ${item.location}` }];
      return false;
    }
    if (typeof item.name !== 'string') {
      validateRule.errors = [{ message: 'inspect.name must be a string' }];
      return false;
    }
  }

  if (!Array.isArray(rule.normalize)) {
    validateRule.errors = [{ message: 'normalize must be an array' }];
    return false;
  }

  for (const norm of rule.normalize) {
    if (!VALID_NORMALIZERS.has(norm)) {
      validateRule.errors = [{ message: `Unknown normalizer: ${norm}` }];
      return false;
    }
  }

  if (!rule.condition || !VALID_COND_OPS.has(rule.condition.op)) {
    validateRule.errors = [{ message: `Invalid condition.op: ${rule.condition?.op}` }];
    return false;
  }

  if (rule.action !== 'block') {
    validateRule.errors = [{ message: 'action must be "block"' }];
    return false;
  }

  if (!['shadow', 'enforce'].includes(rule.mode)) {
    validateRule.errors = [{ message: 'mode must be "shadow" or "enforce"' }];
    return false;
  }

  return true;
}

export const BANDS = {
  P0: 'P0',
  P1: 'P1',
  P2: 'P2',
  P3: 'P3'
};

export const CATEGORY_PRIORS = {
  sqli: 0.90,
  cmdi: 0.95,
  path_traversal: 0.70,
  xss: 0.60,
  other: 0.30
};

export const SEVERITY_WEIGHTS = {
  info: 0.0,
  low: 0.25,
  medium: 0.50,
  high: 0.75,
  critical: 1.00
};
