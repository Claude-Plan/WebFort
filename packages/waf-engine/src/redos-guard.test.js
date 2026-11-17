// packages/waf-engine/src/redos-guard.test.js
import { describe, it, expect } from 'vitest';
import { testRegexSafety } from './redos-guard.js';

describe('WAF Engine: ReDoS Guard', () => {
  it('allows safe, well-behaved regular expressions', () => {
    const result = testRegexSafety('union\\s+select', 'i', 20);
    expect(result.safe).toBe(true);
    expect(result.regex).toBeInstanceOf(RegExp);
  });

  it('detects and flags catastrophic backtracking patterns within 20ms timeout', () => {
    // Classic exponential catastrophic backtracking pattern: (a+)+$ on a string of 'a's ending in 'X'
    const dangerousPattern = '(a+)+$';
    const result = testRegexSafety(dangerousPattern, 'i', 20);
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('ReDoS detected');
  });

  it('rejects syntactically invalid regex strings cleanly without throwing uncaught exceptions', () => {
    const result = testRegexSafety('[invalid(regex', 'i', 20);
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('Invalid regex syntax');
  });
});
