// apps/api/src/gauntlet/gauntlet.test.js
import { describe, it, expect } from 'vitest';
import { MUTATORS } from './index.js';

describe('Mutation Gauntlet: Registry & Mutators', () => {
  it('contains at least 10 deterministic mutators (meets requirement >= 10)', () => {
    expect(MUTATORS.length).toBeGreaterThanOrEqual(10);
  });

  const baseReq = {
    method: 'GET',
    url: '/rest/products/search?q=qwert%27%20UNION%20SELECT%201%2C2--',
    headers: { 'host': 'localhost:3001' }
  };

  it('runs url_encode_double deterministically', () => {
    const mutator = MUTATORS.find(m => m.id === 'url_encode_double');
    expect(mutator).toBeDefined();
    const mutated = mutator.mutate(baseReq);
    expect(mutated).toHaveLength(1);
    expect(mutated[0].url).toContain('%25');
  });

  it('runs sql_inline_comment_space and replaces whitespace with /**/', () => {
    const mutator = MUTATORS.find(m => m.id === 'sql_inline_comment_space');
    expect(mutator).toBeDefined();
    const mutated = mutator.mutate(baseReq);
    expect(mutated[0].url).toContain('/**/');
  });

  it('runs sql_alt_whitespace and substitutes tabs or linefeeds', () => {
    const mutator = MUTATORS.find(m => m.id === 'sql_alt_whitespace');
    expect(mutator).toBeDefined();
    const mutated = mutator.mutate(baseReq, () => 0.1);
    expect(mutated[0].url).toMatch(/(%09|%0A|%0B|%0C|%A0)/);
  });

  it('runs unicode_fullwidth and transforms single quotes into fullwidth unicode', () => {
    const mutator = MUTATORS.find(m => m.id === 'unicode_fullwidth');
    expect(mutator).toBeDefined();
    const mutated = mutator.mutate(baseReq);
    // Fullwidth single quote is \uFF07 (＇)
    expect(mutated[0].url).toContain('\uFF07');
  });

  it('runs null_byte_variants and inserts null byte representations', () => {
    const mutator = MUTATORS.find(m => m.id === 'null_byte_variants');
    expect(mutator).toBeDefined();
    const mutated = mutator.mutate(baseReq, () => 0.0);
    expect(mutated[0].url).toContain('%00');
  });
});
