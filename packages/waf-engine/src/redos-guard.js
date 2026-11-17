// packages/waf-engine/src/redos-guard.js

export function testRegexSafety(patternStr, flags = 'i', timeoutMs = 20) {
  try {
    const re = new RegExp(patternStr, flags);

    // Adversarial test strings
    const str1 = 'a'.repeat(5000) + 'X' + 'a'.repeat(5000);
    const str2 = '/* ' + '1234567890 '.repeat(900) + ' */';

    const t0 = performance.now();
    re.test(str1);
    const d1 = performance.now() - t0;
    if (d1 > timeoutMs) return { safe: false, reason: `ReDoS detected on payload 1 (${Math.round(d1)}ms > ${timeoutMs}ms)` };

    const t1 = performance.now();
    re.test(str2);
    const d2 = performance.now() - t1;
    if (d2 > timeoutMs) return { safe: false, reason: `ReDoS detected on payload 2 (${Math.round(d2)}ms > ${timeoutMs}ms)` };

    return { safe: true, regex: re };
  } catch (err) {
    return { safe: false, reason: `Invalid regex syntax: ${err.message}` };
  }
}
