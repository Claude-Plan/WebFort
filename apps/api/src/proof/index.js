// apps/api/src/proof/index.js
import crypto from 'node:crypto';

// Generate ed25519 keypair for demo signing
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

export const DEMO_PUBLIC_KEY = publicKey;

// Canonical JSON serializer (keys recursively sorted in alphabetical order)
export function canonicalJsonStringify(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJsonStringify).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJsonStringify(obj[k])).join(',') + '}';
}

export function signReport(report) {
  const canonicalStr = canonicalJsonStringify(report);
  const hash = crypto.createHash('sha256').update(canonicalStr).digest('hex');

  const signature = crypto.sign(null, Buffer.from(hash, 'hex'), privateKey).toString('base64');

  return {
    sha256: hash,
    signature,
    public_key: DEMO_PUBLIC_KEY
  };
}

export function verifyProofSignature(report, signature, pubKeyPem) {
  try {
    const canonicalStr = canonicalJsonStringify(report);
    const hash = crypto.createHash('sha256').update(canonicalStr).digest('hex');

    const isValid = crypto.verify(
      null,
      Buffer.from(hash, 'hex'),
      pubKeyPem || DEMO_PUBLIC_KEY,
      Buffer.from(signature, 'base64')
    );
    return { valid: isValid, sha256: hash };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}
