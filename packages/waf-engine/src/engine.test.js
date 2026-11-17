// packages/waf-engine/src/engine.test.js
import { describe, it, expect } from 'vitest';
import { matchPath, extractValues, evaluateCondition, evaluateRule } from './engine.js';

describe('WAF Engine: Core Engine & Evaluation', () => {
  describe('matchPath', () => {
    it('matches exact paths correctly', () => {
      const scope = { kind: 'exact', value: '/rest/products/search' };
      expect(matchPath(scope, '/rest/products/search')).toBe(true);
      expect(matchPath(scope, '/rest/products/search?q=apple')).toBe(true);
      expect(matchPath(scope, '/rest/products/search/extra')).toBe(false);
    });

    it('matches prefix paths correctly', () => {
      const scope = { kind: 'prefix', value: '/rest/products' };
      expect(matchPath(scope, '/rest/products/search')).toBe(true);
      expect(matchPath(scope, '/rest/products/123')).toBe(true);
      expect(matchPath(scope, '/rest/user/login')).toBe(false);
    });

    it('matches template paths with parameters', () => {
      const scope = { kind: 'template', value: '/api/users/{id}' };
      expect(matchPath(scope, '/api/users/42')).toBe(true);
      expect(matchPath(scope, '/api/users/abc-def')).toBe(true);
      expect(matchPath(scope, '/api/users/42/details')).toBe(false);
    });
  });

  describe('extractValues', () => {
    it('extracts query parameters including HPP duplicates', () => {
      const req = {
        query: { q: ['apple', 'banana'] },
        rawQuery: 'q=apple&q=banana'
      };
      const values = extractValues(req, { location: 'query', name: 'q' });
      expect(values).toContain('apple');
      expect(values).toContain('banana');
    });

    it('extracts JSON body parameters', () => {
      const req = {
        body: { email: "admin@juice-sh.op' or 1=1--" }
      };
      const values = extractValues(req, { location: 'body_json', name: 'email' });
      expect(values).toEqual(["admin@juice-sh.op' or 1=1--"]);
    });

    it('extracts headers case-insensitively', () => {
      const req = {
        headers: { 'x-forwarded-for': '127.0.0.1' }
      };
      const values = extractValues(req, { location: 'header', name: 'X-Forwarded-For' });
      expect(values).toEqual(['127.0.0.1']);
    });
  });

  describe('evaluateCondition', () => {
    it('evaluates regex_match correctly', () => {
      expect(evaluateCondition({ op: 'regex_match', value: "union.*select" }, "qwert' union select 1,2")).toBe(true);
      expect(evaluateCondition({ op: 'regex_match', value: "union.*select" }, "apple juice")).toBe(false);
    });

    it('evaluates regex_not_match (positive security allowlist)', () => {
      // Allowlist: only alphanumeric and spaces, max length 50
      const allowlistCond = { op: 'regex_not_match', value: "^[a-zA-Z0-9 ]{1,50}$" };
      // Benign search matches allowlist regex -> NOT_MATCH condition is FALSE (not blocked)
      expect(evaluateCondition(allowlistCond, "apple juice")).toBe(false);
      // Exploit payload has special characters -> NOT_MATCH condition is TRUE (blocked!)
      expect(evaluateCondition(allowlistCond, "apple' UNION SELECT")).toBe(true);
    });

    it('evaluates contains_any', () => {
      const cond = { op: 'contains_any', value: ["<script>", "javascript:", "onload="] };
      expect(evaluateCondition(cond, "test <script>alert(1)</script>")).toBe(true);
      expect(evaluateCondition(cond, "benign text")).toBe(false);
    });
  });

  describe('evaluateRule (End-to-End WAF Decision)', () => {
    const testRule = {
      id: 'rule-test-1',
      version: 1,
      name: 'SQLi Block',
      scope: {
        methods: ['GET'],
        path: { kind: 'exact', value: '/rest/products/search' }
      },
      inspect: [{ location: 'query', name: 'q' }],
      normalize: ['url_decode_recursive', 'lowercase', 'strip_sql_comments', 'collapse_whitespace'],
      condition: {
        op: 'regex_match',
        value: "union select"
      },
      action: 'block',
      mode: 'enforce'
    };

    it('enforces HTTP 403 block when exploit matches normalized condition', () => {
      const attackReq = {
        method: 'GET',
        path: '/rest/products/search',
        query: { q: "%27%2F%2A%2A%2FuNiOn%2F%2A%2A%2FsElEcT" }, // '/**/uNiOn/**/sElEcT
        headers: {}
      };

      const result = evaluateRule(testRule, attackReq);
      expect(result.match).toBe(true);
      expect(result.decision).toBe('block');
      expect(result.would_block).toBe(true);
    });

    it('permits benign requests without blocking', () => {
      const benignReq = {
        method: 'GET',
        path: '/rest/products/search',
        query: { q: "orange juice" },
        headers: {}
      };

      const result = evaluateRule(testRule, benignReq);
      expect(result.match).toBe(false);
      expect(result.decision).toBe('allow');
      expect(result.would_block).toBe(false);
    });

    it('observes and logs in shadow mode without blocking traffic', () => {
      const shadowRule = { ...testRule, mode: 'shadow' };
      const attackReq = {
        method: 'GET',
        path: '/rest/products/search',
        query: { q: "union select 1,2" },
        headers: {}
      };

      const result = evaluateRule(shadowRule, attackReq);
      expect(result.match).toBe(true);
      expect(result.decision).toBe('allow'); // shadow mode allows request through
      expect(result.would_block).toBe(true); // but flags that it would block in enforce
    });
  });
});
