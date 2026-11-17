// packages/contracts/src/index.test.js
import { describe, it, expect } from 'vitest';
import {
  validateRule,
  computePriorityScore,
  calculateWilsonCI,
  CATEGORY_PRIORS,
  SEVERITY_WEIGHTS
} from './index.js';

describe('Contracts: Rule DSL Schema Validation', () => {
  const validRule = {
    schema_version: '1.0',
    name: 'test-sqli-block',
    scope: {
      methods: ['GET'],
      path: { kind: 'prefix', value: '/rest/products/search' }
    },
    inspect: [
      { location: 'query', name: 'q' }
    ],
    normalize: ['url_decode_recursive', 'lowercase', 'strip_sql_comments'],
    condition: {
      op: 'regex_match',
      value: "union.*select"
    },
    action: 'block',
    mode: 'enforce'
  };

  it('accepts a fully compliant Rule DSL object', () => {
    const valid = validateRule(validRule);
    expect(valid).toBe(true);
    expect(validateRule.errors).toBeNull();
  });

  it('rejects rules missing required properties', () => {
    const invalid = { schema_version: '1.0', name: 'bad-rule' };
    const valid = validateRule(invalid);
    expect(valid).toBe(false);
    expect(validateRule.errors.length).toBeGreaterThan(0);
  });

  it('rejects unrecognized normalizers', () => {
    const badNormalizer = {
      ...validRule,
      normalize: ['non_existent_normalizer']
    };
    const valid = validateRule(badNormalizer);
    expect(valid).toBe(false);
  });

  it('rejects invalid scope path kinds', () => {
    const badScope = {
      ...validRule,
      scope: {
        methods: ['GET'],
        path: { kind: 'wildcard_unsupported', value: '/*' }
      }
    };
    const valid = validateRule(badScope);
    expect(valid).toBe(false);
  });

  it('rejects invalid condition operators', () => {
    const badOp = {
      ...validRule,
      condition: { op: 'eval_js', value: '1 === 1' }
    };
    const valid = validateRule(badOp);
    expect(valid).toBe(false);
  });
});

describe('Contracts: Priority Scoring & Triage Waterfall', () => {
  it('elevates confirmed critical SQLi to P0 band (>= 75)', () => {
    const result = computePriorityScore({
      scanner_risk: 'high',
      exploit_confirmed: true,
      category: 'sqli'
    });
    // 0.40 * 0.75 + 0.40 * 1.0 + 0.20 * 0.90 = 0.30 + 0.40 + 0.18 = 0.88 -> 88.0
    expect(result.priority_score).toBe(88);
    expect(result.priority_band).toBe('P0');
    expect(result.signals).toHaveLength(3);
    expect(result.signals.find(s => s.id === 'confirmed').contribution).toBe(40);
  });

  it('demotes unconfirmed low severity finding to P2 or P3', () => {
    const result = computePriorityScore({
      scanner_risk: 'low',
      exploit_confirmed: false,
      category: 'other'
    });
    // 0.40 * 0.25 + 0.40 * 0.0 + 0.20 * 0.30 = 0.10 + 0.0 + 0.06 = 0.16 -> 16.0
    expect(result.priority_score).toBe(16);
    expect(result.priority_band).toBe('P3');
  });

  it('handles medium severity unconfirmed findings appropriately', () => {
    const result = computePriorityScore({
      scanner_risk: 'medium',
      exploit_confirmed: false,
      category: 'xss'
    });
    // 0.40 * 0.50 + 0.40 * 0.0 + 0.20 * 0.60 = 0.20 + 0.0 + 0.12 = 0.32 -> 32.0
    expect(result.priority_score).toBe(32);
    expect(result.priority_band).toBe('P2');
  });
});

describe('Contracts: Wilson 95% Confidence Interval', () => {
  it('returns [0, 0] for 0 trials', () => {
    const ci = calculateWilsonCI(0, 0);
    expect(ci).toEqual([0, 0]);
  });

  it('computes valid bounded CI for 0 bypasses out of 60 trials', () => {
    const [lower, upper] = calculateWilsonCI(0, 60);
    expect(lower).toBe(0);
    expect(upper).toBeGreaterThan(0);
    expect(upper).toBeLessThan(0.10); // Typically ~0.059
  });

  it('computes valid bounded CI for intermediate values', () => {
    const [lower, upper] = calculateWilsonCI(30, 60);
    expect(lower).toBeGreaterThan(0.35);
    expect(upper).toBeLessThan(0.65);
    expect(lower).toBeLessThan(upper);
  });

  it('stays strictly within [0, 1] bounds for 100% successes', () => {
    const [lower, upper] = calculateWilsonCI(60, 60);
    expect(lower).toBeGreaterThan(0.90);
    expect(upper).toBe(1);
  });
});
