// apps/api/src/proof/proof.test.js
import { describe, it, expect } from 'vitest';
import { canonicalJsonStringify, signReport, verifyProofSignature } from './index.js';

describe('Signed Proof Report: Cryptographic Signatures & Tamper Detection', () => {
  it('canonicalJsonStringify recursively sorts object keys alphabetically', () => {
    const uncanonical = {
      z: 10,
      b: { d: 4, a: 1 },
      a: "hello",
      arr: [1, 2, { y: 2, x: 1 }]
    };
    const canonicalStr = canonicalJsonStringify(uncanonical);
    expect(canonicalStr).toBe('{"a":"hello","arr":[1,2,{"x":1,"y":2}],"b":{"a":1,"d":4},"z":10}');
  });

  it('signs report with ed25519 and successfully verifies authentic signature', () => {
    const report = {
      report_version: '1.0',
      finding: { id: 'f-1', title: 'SQLi Leak', category: 'sqli' },
      patch: { id: 'p-1', version: 3, source: 'hardened' },
      tests: {
        exploit_replay: { blocked: true },
        benign_replay: { n: 200, blocked: 0, false_positive_rate: 0 },
        mutation_exam: { effective: 42, blocked: 42, bypassed: 0, bypass_rate: 0 }
      },
      limitations: ['HTTP layer only', 'lab target only']
    };

    const signed = signReport(report);
    expect(signed.sha256).toBeDefined();
    expect(signed.signature).toBeDefined();
    expect(signed.public_key).toBeDefined();

    const verification = verifyProofSignature(report, signed.signature, signed.public_key);
    expect(verification.valid).toBe(true);
    expect(verification.sha256).toBe(signed.sha256);
  });

  it('tamper detection: modifying a single character in the report invalidates the signature', () => {
    const report = {
      report_version: '1.0',
      finding: { id: 'f-1', title: 'SQLi Leak' },
      tests: { exploit_replay: { blocked: true } }
    };

    const signed = signReport(report);

    // Tamper with report: flip blocked from true to false
    const tamperedReport = {
      ...report,
      tests: { exploit_replay: { blocked: false } }
    };

    const verification = verifyProofSignature(tamperedReport, signed.signature, signed.public_key);
    expect(verification.valid).toBe(false);
  });
});
