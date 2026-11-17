// packages/waf-engine/src/normalizers.js

export function urlDecodeRecursive(input, maxPasses = 5) {
  if (typeof input !== 'string') return input;
  let current = input;
  let passes = 0;
  while (passes < maxPasses) {
    try {
      const decoded = decodeURIComponent(current.replace(/\+/g, ' '));
      if (decoded === current) break;
      current = decoded;
      passes++;
    } catch {
      // If malformed URI component, attempt lenient decoding of individual %xx tokens
      const lenient = current.replace(/%([0-9a-fA-F]{2})/g, (_, hex) => {
        try {
          return String.fromCharCode(parseInt(hex, 16));
        } catch {
          return _;
        }
      });
      if (lenient === current) break;
      current = lenient;
      passes++;
    }
  }
  return current;
}

export function htmlEntityDecode(input) {
  if (typeof input !== 'string') return input;
  const named = {
    '&quot;': '"',
    '&apos;': "'",
    '&#x27;': "'",
    '&#39;': "'",
    '&amp;': '&',
    '&lt;': '<',
    '&gt;': '>',
    '&nbsp;': ' '
  };
  let res = input.replace(/&(?:quot|apos|#x27|#39|amp|lt|gt|nbsp);/gi, (match) => named[match.toLowerCase()] || match);
  // Decimal entities: &#123;
  res = res.replace(/&#(\d+);?/g, (_, dec) => {
    try {
      return String.fromCharCode(parseInt(dec, 10));
    } catch {
      return _;
    }
  });
  // Hex entities: &#x1f;
  res = res.replace(/&#x([0-9a-fA-F]+);?/g, (_, hex) => {
    try {
      return String.fromCharCode(parseInt(hex, 16));
    } catch {
      return _;
    }
  });
  return res;
}

export function lowercase(input) {
  return typeof input === 'string' ? input.toLowerCase() : input;
}

export function stripSqlComments(input) {
  if (typeof input !== 'string') return input;
  // Strip inline comments /* ... */
  let res = input.replace(/\/\*[\s\S]*?\*\//g, ' ');
  // Strip line comments -- ... or # ...
  res = res.replace(/(--|#)[^\r\n]*/g, ' ');
  return res;
}

export function stripWhitespaceVariants(input) {
  if (typeof input !== 'string') return input;
  // Replace tabs, line feeds, form feeds, vertical tabs, non-breaking spaces with space
  return input.replace(/[\t\r\n\v\f\u00A0\u2000-\u200B]/g, ' ');
}

export function collapseWhitespace(input) {
  if (typeof input !== 'string') return input;
  return input.replace(/\s+/g, ' ').trim();
}

export function removeNullBytes(input) {
  if (typeof input !== 'string') return input;
  return input.replace(/(\x00|%00|\u0000)/g, '');
}

export function unicodeNfkc(input) {
  if (typeof input !== 'string') return input;
  try {
    return input.normalize('NFKC');
  } catch {
    return input;
  }
}

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

export function applyNormalizers(val, normalizerNames = []) {
  let current = String(val ?? '');
  for (const name of normalizerNames) {
    const fn = NORMALIZERS[name];
    if (fn) {
      current = fn(current);
    }
  }
  return current;
}
