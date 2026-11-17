import crypto from 'node:crypto';

// Global demo keypair generated once at bootstrap
let demoKeyPair = null;

export function getDemoKeyPair() {
  if (!demoKeyPair) {
    demoKeyPair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
  }
  return demoKeyPair;
}

/**
 * Deterministic canonical JSON serialization (RFC 8785 subset)
 * Keys are sorted recursively; no arbitrary whitespace.
 */
export function canonicalJsonStringify(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJsonStringify).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  const parts = keys.map(k => `${JSON.stringify(k)}:${canonicalJsonStringify(obj[k])}`);
  return '{' + parts.join(',') + '}';
}

/**
 * Computes SHA-256 hash of a string
 */
export function sha256(content) {
  return crypto.createHash('sha256').update(content, 'utf-8').digest('hex');
}

/**
 * Signs canonical report payload with Ed25519 demo key
 */
export function signReport(report) {
  const { privateKey, publicKey } = getDemoKeyPair();
  const canonicalJson = canonicalJsonStringify(report);
  const hash = sha256(canonicalJson);

  const signature = crypto.sign(null, Buffer.from(hash, 'hex'), privateKey).toString('hex');

  return {
    report,
    sha256: hash,
    signature,
    public_key: publicKey,
    signer_label: 'DEMO SIGNING KEY — LAB VERIFICATION ONLY (NOT A TRUST ANCHOR)'
  };
}

/**
 * Verifies Ed25519 signature of a canonical report
 */
export function verifyReportSignature(report, signature, publicKeyPem) {
  try {
    const canonicalJson = canonicalJsonStringify(report);
    const hash = sha256(canonicalJson);
    const isValid = crypto.verify(
      null,
      Buffer.from(hash, 'hex'),
      publicKeyPem,
      Buffer.from(signature, 'hex')
    );
    return { valid: isValid, sha256: hash };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}
