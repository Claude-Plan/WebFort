/**
 * WAF Normalizer implementations as per PatchProof frozen specification (§7)
 */

/**
 * 1. url_decode_recursive
 * Decodes URL-encoded strings iteratively to a fixed point, up to a maximum of 5 passes.
 */
export function urlDecodeRecursive(input, maxPasses = 5) {
  if (typeof input !== 'string') return '';
  let current = input;
  let passes = 0;

  while (passes < maxPasses) {
    try {
      const decoded = decodeURIComponent(current.replace(/\+/g, ' '));
      if (decoded === current) {
        break;
      }
      current = decoded;
      passes++;
    } catch {
      // If full decodeURIComponent fails on malformed sequences,
      // fallback to safe regex-based percent decoding
      const decoded = current.replace(/%([0-9a-fA-F]{2})/g, (match, hex) => {
        try {
          return String.fromCharCode(parseInt(hex, 16));
        } catch {
          return match;
        }
      });
      if (decoded === current) {
        break;
      }
      current = decoded;
      passes++;
    }
  }

  return current;
}

/**
 * 2. html_entity_decode
 * Decodes named, decimal, and hexadecimal HTML entities.
 */
const HTML_ENTITIES = {
  '&quot;': '"',
  '&apos;': "'",
  '&amp;': '&',
  '&lt;': '<',
  '&gt;': '>',
  '&nbsp;': ' ',
  '&copy;': '©',
  '&reg;': '®'
};

export function htmlEntityDecode(input) {
  if (typeof input !== 'string') return '';

  let output = input;

  // Named entities
  for (const [entity, replacement] of Object.entries(HTML_ENTITIES)) {
    output = output.replaceAll(entity, replacement);
  }

  // Hexadecimal entities: &#x...; or &#X...;
  output = output.replace(/&#[xX]([0-9a-fA-F]+);?/g, (match, hex) => {
    try {
      const code = parseInt(hex, 16);
      return String.fromCodePoint(code);
    } catch {
      return match;
    }
  });

  // Decimal entities: &#...;
  output = output.replace(/&#([0-9]+);?/g, (match, dec) => {
    try {
      const code = parseInt(dec, 10);
      return String.fromCodePoint(code);
    } catch {
      return match;
    }
  });

  return output;
}

/**
 * 3. lowercase
 */
export function lowercase(input) {
  if (typeof input !== 'string') return '';
  return input.toLowerCase();
}

/**
 * 4. strip_sql_comments
 * Strips C-style multi-line comments /* ... *\/ and single-line comments (-- or #)
 * Replaces with space to prevent concatenating adjacent tokens (e.g. UNION/**\/SELECT -> UNION SELECT)
 */
export function stripSqlComments(input) {
  if (typeof input !== 'string') return '';

  // Multi-line C-style comments
  let output = input.replace(/\/\*[\s\S]*?\*\//g, ' ');

  // Single-line SQL comments (-- or #)
  output = output.replace(/(?:--|#)[^\r\n]*/g, ' ');

  return output;
}

/**
 * 5. strip_whitespace_variants
 * Normalizes tab, newline, carriage return, vertical tab, form feed, non-breaking space,
 * and URL-encoded whitespace variants (%09, %0a, etc.) to standard spaces.
 */
export function stripWhitespaceVariants(input) {
  if (typeof input !== 'string') return '';

  return input
    .replace(/(?:%09|%0a|%0b|%0c|%0d|%a0)/gi, ' ')
    .replace(/[\t\r\n\v\f\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/g, ' ');
}

/**
 * 6. collapse_whitespace
 * Collapses multiple whitespace characters to a single space and trims.
 */
export function collapseWhitespace(input) {
  if (typeof input !== 'string') return '';
  return input.replace(/\s+/g, ' ').trim();
}

/**
 * 7. remove_null_bytes
 * Destructive: removes raw null bytes and null byte encodings.
 */
export function removeNullBytes(input) {
  if (typeof input !== 'string') return '';
  return input
    .replace(/\0/g, '')
    .replace(/%00/gi, '')
    .replace(/%2500/gi, '')
    .replace(/\\u0000/gi, '')
    .replace(/\\x00/gi, '');
}

/**
 * 8. unicode_nfkc
 * Applies Unicode Normalization Form KC (Compatibility Decomposition, Canonical Composition).
 */
export function unicodeNfkc(input) {
  if (typeof input !== 'string') return '';
  return input.normalize('NFKC');
}

/**
 * Registry of available normalizers
 */
export const NORMALIZERS = {
  url_decode_recursive: urlDecodeRecursive,
  html_entity_decode: htmlEntityDecode,
  lowercase: lowercase,
  strip_sql_comments: stripSqlComments,
  strip_whitespace_variants: stripWhitespaceVariants,
  collapse_whitespace: collapseWhitespace,
  remove_null_bytes: removeNullBytes,
  unicode_nfkc: unicodeNfkc
};

/**
 * Apply an ordered sequence of normalizers
 */
export function applyNormalizers(input, normalizerNames = []) {
  let result = input;
  for (const name of normalizerNames) {
    const fn = NORMALIZERS[name];
    if (typeof fn === 'function') {
      result = fn(result);
    }
  }
  return result;
}
