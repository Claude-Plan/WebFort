/**
 * ReDoS Guard (§7):
 * Every regex from LLM or hardening loop is tested against two 10 KB
 * adversarial strings with a 20 ms execution limit before being accepted.
 */

const ADVERSARIAL_STRING_1 = 'a'.repeat(10000) + '!';
const ADVERSARIAL_STRING_2 = ("' or '" + ' '.repeat(5)).repeat(1000) + 'x';

export function isRegexSafe(pattern, flags = 'i', timeoutMs = 20) {
  if (typeof pattern !== 'string' || !pattern.trim()) {
    return { safe: false, reason: 'EMPTY_PATTERN' };
  }

  // Basic syntax validation
  let regex;
  try {
    regex = new RegExp(pattern, flags);
  } catch (err) {
    return { safe: false, reason: 'INVALID_SYNTAX: ' + err.message };
  }

  // Static checks for catastrophic backtracking structures (e.g., nested quantifiers (a+)+)
  const nestedQuantifierRegex = /(\([^\)]*[\+\*][^\)]*\)[\+\*])/;
  if (nestedQuantifierRegex.test(pattern)) {
    return { safe: false, reason: 'POTENTIAL_NESTED_QUANTIFIER' };
  }

  // Adversarial String 1 test
  try {
    const start1 = performance.now();
    regex.test(ADVERSARIAL_STRING_1);
    const duration1 = performance.now() - start1;
    if (duration1 > timeoutMs) {
      return { safe: false, reason: `TIMEOUT_EXCEEDED_ADVERSARIAL_1 (${duration1.toFixed(2)}ms > ${timeoutMs}ms)` };
    }
  } catch (err) {
    return { safe: false, reason: 'EXECUTION_ERROR_1: ' + err.message };
  }

  // Adversarial String 2 test
  try {
    const start2 = performance.now();
    regex.test(ADVERSARIAL_STRING_2);
    const duration2 = performance.now() - start2;
    if (duration2 > timeoutMs) {
      return { safe: false, reason: `TIMEOUT_EXCEEDED_ADVERSARIAL_2 (${duration2.toFixed(2)}ms > ${timeoutMs}ms)` };
    }
  } catch (err) {
    return { safe: false, reason: 'EXECUTION_ERROR_2: ' + err.message };
  }

  return { safe: true, regex };
}
