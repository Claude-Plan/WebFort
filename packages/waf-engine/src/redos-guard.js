// packages/waf-engine/src/redos-guard.js
import vm from 'node:vm';

export function testRegexSafety(patternStr, flags = 'i', timeoutMs = 20) {
  try {
    const re = new RegExp(patternStr, flags);

    // Adversarial test strings (designed to trigger catastrophic backtracking)
    const str1 = 'a'.repeat(5000) + 'X' + 'a'.repeat(5000);
    const str2 = '/* ' + '1234567890 '.repeat(900) + ' */';

    try {
      vm.runInNewContext('re.test(str1)', { re, str1 }, { timeout: timeoutMs });
      vm.runInNewContext('re.test(str2)', { re, str2 }, { timeout: timeoutMs });
    } catch (vmErr) {
      if (vmErr.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT' || vmErr.message.includes('timed out')) {
        return { safe: false, reason: `ReDoS detected: execution exceeded ${timeoutMs}ms timeout` };
      }
      throw vmErr;
    }

    return { safe: true, regex: re };
  } catch (err) {
    return { safe: false, reason: `Invalid regex syntax: ${err.message}` };
  }
}
