import Ajv from 'ajv';

export const RULE_SCHEMA = {
  type: 'object',
  required: ['schema_version', 'name', 'scope', 'inspect', 'normalize', 'condition', 'action', 'mode'],
  properties: {
    schema_version: { type: 'string', const: '1.0' },
    name: { type: 'string', minLength: 1 },
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
      minItems: 1,
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
        value: {}
      }
    },
    action: { type: 'string', enum: ['block'] },
    mode: { type: 'string', enum: ['shadow', 'enforce'] }
  }
};

const ajv = new Ajv({ allErrors: true });
export const validateRule = ajv.compile(RULE_SCHEMA);

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
  critical: 1.0
};

export function computePriorityScore({ scanner_risk, exploit_confirmed, category }) {
  const severity = SEVERITY_WEIGHTS[scanner_risk] ?? 0.5;
  const confirmed = exploit_confirmed ? 1.0 : 0.0;
  const category_prior = CATEGORY_PRIORS[category] ?? 0.3;

  // Formula: score = 100 * (0.40 * severity + 0.40 * confirmed + 0.20 * category_prior)
  const score = Math.round((100 * (0.40 * severity + 0.40 * confirmed + 0.20 * category_prior)) * 100) / 100;

  let priority_band = 'P3';
  if (score >= 75) priority_band = 'P0';
  else if (score >= 50) priority_band = 'P1';
  else if (score >= 25) priority_band = 'P2';

  const signals = [
    {
      id: 'severity',
      label: 'Scanner Severity',
      raw: scanner_risk,
      normalized: severity,
      weight: 0.40,
      contribution: Math.round(100 * 0.40 * severity * 100) / 100,
      applicable: true,
      evidence: `Scanner reported risk level: ${scanner_risk}`
    },
    {
      id: 'confirmed',
      label: 'Exploit Confirmation',
      raw: exploit_confirmed,
      normalized: confirmed,
      weight: 0.40,
      contribution: Math.round(100 * 0.40 * confirmed * 100) / 100,
      applicable: true,
      evidence: exploit_confirmed ? 'Active exploit confirmed directly on target endpoint' : 'No direct exploit confirmation recorded'
    },
    {
      id: 'category_prior',
      label: 'Vulnerability Category Prior',
      raw: category,
      normalized: category_prior,
      weight: 0.20,
      contribution: Math.round(100 * 0.20 * category_prior * 100) / 100,
      applicable: true,
      evidence: `Base exploitability prior weight for ${category} is ${category_prior}`
    }
  ];

  return { priority_score: score, priority_band, signals };
}

// Wilson 95% Confidence Interval for proportion p = x / n
export function calculateWilsonCI(successes, total, z = 1.96) {
  if (total === 0) return [0, 0];
  const p = successes / total;
  const denom = 1 + (z * z) / total;
  const center = (p + (z * z) / (2 * total)) / denom;
  const spread = (z * Math.sqrt((p * (1 - p) + (z * z) / (4 * total)) / total)) / denom;
  return [
    Math.max(0, Math.round((center - spread) * 1000) / 1000),
    Math.min(1, Math.round((center + spread) * 1000) / 1000)
  ];
}
