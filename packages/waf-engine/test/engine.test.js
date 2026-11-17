import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  urlDecodeRecursive,
  htmlEntityDecode,
  stripSqlComments,
  stripWhitespaceVariants,
  collapseWhitespace,
  removeNullBytes,
  unicodeNfkc,
  isRegexSafe,
  WafEngine,
  evaluateRule
} from '../src/index.js';

describe('Normalizers', () => {
  it('url_decode_recursive terminates within 5 passes and handles double encoding', () => {
    assert.equal(urlDecodeRecursive('%27'), "'");
    assert.equal(urlDecodeRecursive('%2527'), "'");
    assert.equal(urlDecodeRecursive('%252527'), "'");
  });

  it('html_entity_decode decodes named, decimal, and hex entities', () => {
    assert.equal(htmlEntityDecode('&quot;union&#x27;select&lt;&gt;'), '"union\'select<>');
    assert.equal(htmlEntityDecode('&#117;&#110;&#105;&#111;&#110;'), 'union');
  });

  it('strip_sql_comments removes inline block comments and line comments preserving token separation', () => {
    assert.ok(stripSqlComments('UNION/**/SELECT').includes('UNION SELECT'));
    assert.ok(stripSqlComments("admin'-- rest of query").includes("admin' "));
    assert.ok(stripSqlComments('admin# comment').includes('admin '));
  });

  it('strip_whitespace_variants handles tabs, newlines, and url-encoded variants', () => {
    assert.equal(stripWhitespaceVariants('UNION%09SELECT%0aFROM'), 'UNION SELECT FROM');
  });

  it('collapse_whitespace cleans up excess spaces', () => {
    assert.equal(collapseWhitespace('  UNION    SELECT   *  '), 'UNION SELECT *');
  });

  it('remove_null_bytes strips raw and encoded null bytes', () => {
    assert.equal(removeNullBytes('foo%00bar\0baz%2500qux\\u0000'), 'foobarbazqux');
  });

  it('unicode_nfkc normalizes compatibility characters', () => {
    assert.equal(unicodeNfkc('ﬂ'), 'fl');
  });
});

describe('ReDoS Guard', () => {
  it('detects nested quantifiers as unsafe', () => {
    const result = isRegexSafe('(a+)+$');
    assert.equal(result.safe, false);
  });

  it('allows safe regex patterns', () => {
    const result = isRegexSafe('union\\s+select');
    assert.equal(result.safe, true);
  });
});

describe('WAF Rule Engine', () => {
  const sqliRule = {
    id: 'rule-sqli-01',
    schema_version: '1.0',
    name: 'Block SQL Injection Search',
    scope: {
      methods: ['GET'],
      path: { kind: 'exact', value: '/rest/products/search' }
    },
    inspect: [
      { location: 'query', name: 'q' }
    ],
    normalize: [
      'url_decode_recursive',
      'html_entity_decode',
      'lowercase',
      'strip_sql_comments',
      'strip_whitespace_variants',
      'collapse_whitespace'
    ],
    condition: {
      op: 'regex_match',
      value: "union\\s+select|'\\s+or\\s+'1'='1"
    },
    action: 'block',
    mode: 'enforce'
  };

  it('blocks SQL injection in query string', () => {
    const engine = new WafEngine();
    engine.setRules([sqliRule]);

    const reqData = {
      method: 'GET',
      path: '/rest/products/search',
      queryString: 'q=apple%27%20UNION/**/SELECT%201,2,3--',
      headers: {}
    };

    const evalResult = engine.evaluate(reqData);
    assert.equal(evalResult.decision, 'block');
    assert.equal(evalResult.rule_id, 'rule-sqli-01');
    assert.equal(evalResult.would_block, true);
    assert.ok(evalResult.latency_ms < 5, `Expected latency < 5ms, got ${evalResult.latency_ms}ms`);
  });

  it('allows benign search queries', () => {
    const engine = new WafEngine();
    engine.setRules([sqliRule]);

    const reqData = {
      method: 'GET',
      path: '/rest/products/search',
      queryString: 'q=apple%20juice',
      headers: {}
    };

    const evalResult = engine.evaluate(reqData);
    assert.equal(evalResult.decision, 'allow');
    assert.equal(evalResult.would_block, false);
  });

  it('handles shadow mode correctly by allowing request with would_block: true', () => {
    const shadowRule = { ...sqliRule, mode: 'shadow' };
    const engine = new WafEngine();
    engine.setRules([shadowRule]);

    const reqData = {
      method: 'GET',
      path: '/rest/products/search',
      queryString: 'q=apple%27%20UNION/**/SELECT%201,2,3--',
      headers: {}
    };

    const evalResult = engine.evaluate(reqData);
    assert.equal(evalResult.decision, 'log_only');
    assert.equal(evalResult.would_block, true);
  });

  it('inspects duplicate parameters (HTTP Parameter Pollution)', () => {
    const engine = new WafEngine();
    engine.setRules([sqliRule]);

    // First q is benign, second q contains SQLi
    const reqData = {
      method: 'GET',
      path: '/rest/products/search',
      queryString: 'q=safe_first&q=union/**/select',
      headers: {}
    };

    const evalResult = engine.evaluate(reqData);
    assert.equal(evalResult.decision, 'block');
    assert.equal(evalResult.would_block, true);
  });

  it('inspects JSON body parameters', () => {
    const loginRule = {
      id: 'rule-login-01',
      schema_version: '1.0',
      name: 'Block SQLi Login',
      scope: {
        methods: ['POST'],
        path: { kind: 'exact', value: '/rest/user/login' }
      },
      inspect: [
        { location: 'body_json', name: 'email' }
      ],
      normalize: [
        'url_decode_recursive',
        'lowercase',
        'strip_sql_comments',
        'collapse_whitespace'
      ],
      condition: {
        op: 'regex_match',
        value: "'\\s+or\\s+1=1"
      },
      action: 'block',
      mode: 'enforce'
    };

    const engine = new WafEngine();
    engine.setRules([loginRule]);

    const reqData = {
      method: 'POST',
      path: '/rest/user/login',
      queryString: '',
      body: JSON.stringify({ email: "' or 1=1--", password: "x" }),
      headers: { 'content-type': 'application/json' }
    };

    const evalResult = engine.evaluate(reqData);
    assert.equal(evalResult.decision, 'block');
    assert.equal(evalResult.would_block, true);
  });

  it('fails open when error occurs if failMode=open', () => {
    const engine = new WafEngine({ failMode: 'open' });
    const evalResult = engine.evaluate(null);
    assert.equal(evalResult.decision, 'allow');
    assert.equal(evalResult.is_error, true);
  });
});
