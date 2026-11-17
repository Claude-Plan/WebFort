// packages/waf-engine/src/normalizers.test.js
import { describe, it, expect } from 'vitest';
import {
  urlDecodeRecursive,
  htmlEntityDecode,
  lowercase,
  stripSqlComments,
  stripWhitespaceVariants,
  collapseWhitespace,
  removeNullBytes,
  unicodeNfkc,
  applyNormalizers
} from './normalizers.js';

describe('WAF Engine: Normalizers', () => {
  describe('urlDecodeRecursive', () => {
    it('decodes single percent encoding', () => {
      expect(urlDecodeRecursive('%27%20UNION')).toBe("' UNION");
    });

    it('decodes double percent encoding (%2527 -> %27 -> \')', () => {
      expect(urlDecodeRecursive('%2527')).toBe("'");
    });

    it('decodes triple percent encoding (%252527 -> \')', () => {
      expect(urlDecodeRecursive('%252527')).toBe("'");
    });

    it('handles plus sign as space', () => {
      expect(urlDecodeRecursive('union+select')).toBe('union select');
    });

    it('recovers gracefully from malformed URI sequences', () => {
      expect(urlDecodeRecursive('%zz%27')).toBe('%zz\'');
    });
  });

  describe('htmlEntityDecode', () => {
    it('decodes common named HTML entities', () => {
      expect(htmlEntityDecode('&quot;hello&quot; &amp; &apos;world&apos;')).toBe('"hello" & \'world\'');
    });

    it('decodes decimal and hex entities', () => {
      expect(htmlEntityDecode('&#39; &#x27; &#60;script&#62;')).toBe("' ' <script>");
    });
  });

  describe('lowercase', () => {
    it('lowercases mixed-case SQL keywords', () => {
      expect(lowercase('UnIoN SeLeCt 1, 2, 3')).toBe('union select 1, 2, 3');
    });
  });

  describe('stripSqlComments', () => {
    it('replaces inline SQL comments with spaces', () => {
      expect(stripSqlComments("1'/**/UNION/**/SELECT/**/1--")).toBe("1' UNION SELECT 1 ");
    });

    it('replaces single-line comments with spaces', () => {
      expect(stripSqlComments("admin'-- rest of query\nline2")).toBe("admin' \nline2");
      expect(stripSqlComments("admin'# mysql comment")).toBe("admin' ");
    });
  });

  describe('stripWhitespaceVariants', () => {
    it('converts tabs, form feeds, and non-breaking spaces into standard space', () => {
      const input = "union\tselect\u00A0*\rfrom\vusers";
      const output = stripWhitespaceVariants(input);
      expect(output).toBe("union select * from users");
    });
  });

  describe('collapseWhitespace', () => {
    it('collapses multiple whitespace runs into a single space and trims', () => {
      expect(collapseWhitespace("   union     select      1   ")).toBe("union select 1");
    });
  });

  describe('removeNullBytes', () => {
    it('removes raw null bytes and encoded %00', () => {
      expect(removeNullBytes("file.php\x00.jpg")).toBe("file.php.jpg");
      expect(removeNullBytes("union%00select")).toBe("unionselect");
    });
  });

  describe('unicodeNfkc', () => {
    it('normalizes fullwidth unicode characters to ASCII equivalents', () => {
      // ＵＮＩＯＮ -> UNION
      const fullwidth = "\uFF35\uFF2E\uFF29\uFF2F\uFF2E";
      expect(unicodeNfkc(fullwidth)).toBe("UNION");
    });
  });

  describe('applyNormalizers (Pipeline Order)', () => {
    it('correctly executes full chain: double encoded + comments + mixed case', () => {
      // %2527%252F%252A%252A%252FuNiOn%2520sElEcT
      // url_decode -> '/**/uNiOn sElEcT
      // strip_sql_comments -> ' uNiOn sElEcT
      // lowercase -> ' union select
      // collapse_whitespace -> ' union select
      const raw = "%2527%252F%252A%252A%252FuNiOn%2520sElEcT";
      const normalized = applyNormalizers(raw, [
        'url_decode_recursive',
        'strip_sql_comments',
        'lowercase',
        'collapse_whitespace'
      ]);
      expect(normalized).toBe("' union select");
    });
  });
});
