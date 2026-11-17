/**
 * Mutation Catalog for Mutation Gauntlet (§9.1)
 * Registry of deterministic mutators targeting WAF evasion techniques.
 */

// Helper to replace text within query string or body
function replacePayloadInUrl(url, targetParam, replacerFn) {
  if (!url || !url.includes('?')) return url;
  const [pathname, queryString] = url.split('?');
  const searchParams = new URLSearchParams(queryString);

  if (targetParam && searchParams.has(targetParam)) {
    const rawVal = searchParams.get(targetParam);
    const mutated = replacerFn(rawVal);
    searchParams.set(targetParam, mutated);
    return `${pathname}?${searchParams.toString()}`;
  }

  // Fallback: mutate all query param values
  for (const [key, val] of searchParams.entries()) {
    searchParams.set(key, replacerFn(val));
  }
  return `${pathname}?${searchParams.toString()}`;
}

export const MUTATORS = [
  // 1. url_encode_once
  {
    id: 'url_encode_once',
    name: 'Single URL Percent Encoding',
    family: 'encoding',
    mutate: (req, ctx) => {
      const replacer = (val) => {
        return val.replace(/'/g, '%27').replace(/ /g, '%20').replace(/=/g, '%3D');
      };
      return [{
        ...req,
        url: replacePayloadInUrl(req.url, ctx.param, replacer)
      }];
    }
  },

  // 2. url_encode_double
  {
    id: 'url_encode_double',
    name: 'Double URL Percent Encoding',
    family: 'encoding',
    mutate: (req, ctx) => {
      const replacer = (val) => {
        // Double encode quotes and spaces: %27 -> %2527, %20 -> %2520
        return val.replace(/'/g, '%2527').replace(/ /g, '%2520').replace(/=/g, '%253D');
      };
      return [{
        ...req,
        url: replacePayloadInUrl(req.url, ctx.param, replacer)
      }];
    }
  },

  // 3. mixed_case
  {
    id: 'mixed_case',
    name: 'Mixed Keyword Casing',
    family: 'casing',
    mutate: (req, ctx) => {
      const replacer = (val) => {
        return val
          .replace(/union/gi, 'uNiOn')
          .replace(/select/gi, 'SeLeCt')
          .replace(/from/gi, 'FrOm')
          .replace(/where/gi, 'WhErE')
          .replace(/or/gi, 'oR')
          .replace(/and/gi, 'aNd');
      };
      return [{
        ...req,
        url: replacePayloadInUrl(req.url, ctx.param, replacer)
      }];
    }
  },

  // 4. sql_inline_comment_space
  {
    id: 'sql_inline_comment_space',
    name: 'SQL Inline Comment Whitespace',
    family: 'comment',
    mutate: (req, ctx) => {
      const replacer = (val) => {
        return val.replace(/\s+/g, '/**/');
      };
      return [{
        ...req,
        url: replacePayloadInUrl(req.url, ctx.param, replacer)
      }];
    }
  },

  // 5. sql_alt_whitespace
  {
    id: 'sql_alt_whitespace',
    name: 'Alternative Whitespace (%09, %0a, %a0)',
    family: 'whitespace',
    mutate: (req, ctx) => {
      const replacer = (val) => {
        // Tab %09 and linefeed %0a are valid token separators in SQL
        return val.replace(/\s+/g, '%09');
      };
      return [{
        ...req,
        url: replacePayloadInUrl(req.url, ctx.param, replacer)
      }];
    }
  },

  // 6. json_unicode_escape
  {
    id: 'json_unicode_escape',
    name: 'JSON / String Unicode Escape',
    family: 'encoding',
    mutate: (req, ctx) => {
      if (req.body && typeof req.body === 'string') {
        const mutatedBody = req.body.replace(/'/g, '\\u0027').replace(/ /g, '\\u0020');
        return [{ ...req, body: mutatedBody }];
      }
      const replacer = (val) => val.replace(/'/g, '\\u0027');
      return [{ ...req, url: replacePayloadInUrl(req.url, ctx.param, replacer) }];
    }
  },

  // 7. html_entity
  {
    id: 'html_entity',
    name: 'HTML Entity Encoding',
    family: 'encoding',
    mutate: (req, ctx) => {
      const replacer = (val) => {
        return val.replace(/'/g, '&#x27;').replace(/"/g, '&quot;');
      };
      return [{
        ...req,
        url: replacePayloadInUrl(req.url, ctx.param, replacer)
      }];
    }
  },

  // 8. unicode_fullwidth
  {
    id: 'unicode_fullwidth',
    name: 'Unicode Fullwidth Characters',
    family: 'unicode',
    mutate: (req, ctx) => {
      const replacer = (val) => {
        // Replace single quote with fullwidth single quote ＇ (\uFF07)
        return val.replace(/'/g, '\uFF07').replace(/ /g, '\u3000');
      };
      return [{
        ...req,
        url: replacePayloadInUrl(req.url, ctx.param, replacer)
      }];
    }
  },

  // 9. null_byte_variants
  {
    id: 'null_byte_variants',
    name: 'Null Byte Injection (%00, %2500)',
    family: 'null_byte',
    mutate: (req, ctx) => {
      const replacer = (val) => {
        return `%00${val}`;
      };
      return [{
        ...req,
        url: replacePayloadInUrl(req.url, ctx.param, replacer)
      }];
    }
  },

  // 10. hpp_duplicate_param
  {
    id: 'hpp_duplicate_param',
    name: 'HTTP Parameter Pollution (HPP)',
    family: 'hpp',
    mutate: (req, ctx) => {
      if (!req.url || !req.url.includes('?')) return [req];
      const [pathname, queryString] = req.url.split('?');
      const param = ctx.param || 'q';
      // Put a benign param first and payload second, or vice-versa
      const pollutedUrl = `${pathname}?${param}=benign_fruit&${queryString}`;
      return [{
        ...req,
        url: pollutedUrl
      }];
    }
  },

  // 11. param_location_shift
  {
    id: 'param_location_shift',
    name: 'Parameter Location Shift (Query to Body)',
    family: 'location',
    mutate: (req, ctx) => {
      if (req.method === 'GET' && req.url.includes('?')) {
        const [pathname, queryString] = req.url.split('?');
        return [{
          ...req,
          method: 'POST',
          url: pathname,
          headers: {
            ...req.headers,
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: queryString
        }];
      }
      return [req];
    }
  },

  // 12. path_variants
  {
    id: 'path_variants',
    name: 'Path Canonicalization Anomalies (//, /./)',
    family: 'path',
    mutate: (req, ctx) => {
      if (!req.url) return [req];
      const mutatedUrl = req.url.replace('/rest/', '/rest//').replace('/search', '/./search');
      return [{
        ...req,
        url: mutatedUrl
      }];
    }
  }
];

export const MUTATORS_BY_ID = new Map(MUTATORS.map(m => [m.id, m]));
