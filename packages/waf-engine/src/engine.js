import { applyNormalizers } from './normalizers.js';
import { isRegexSafe } from './redos.js';

/**
 * Compiles a path template into a RegExp
 * Template segments like {x} or :x match [^/]+
 */
function compileTemplateToRegex(template) {
  const pattern = template
    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&') // escape regex chars except braces
    .replace(/\\\{[^/]+\\\}/g, '([^/]+)') // replace \{param\} with capture group
    .replace(/:[a-zA-Z0-9_]+/g, '([^/]+)');
  return new RegExp(`^${pattern}$`);
}

/**
 * Checks if request method and path match the rule scope
 */
export function matchesScope(ruleScope, method, path) {
  if (!ruleScope) return true;

  // 1. Method check
  if (ruleScope.methods && Array.isArray(ruleScope.methods) && ruleScope.methods.length > 0) {
    const uppercaseMethod = (method || 'GET').toUpperCase();
    const allowed = ruleScope.methods.map(m => m.toUpperCase());
    if (!allowed.includes(uppercaseMethod)) {
      return false;
    }
  }

  // 2. Path check
  if (ruleScope.path) {
    const { kind, value } = ruleScope.path;
    const cleanPath = (path || '/').split('?')[0];

    if (kind === 'exact') {
      if (cleanPath !== value) return false;
    } else if (kind === 'prefix') {
      if (!cleanPath.startsWith(value)) return false;
    } else if (kind === 'template') {
      const regex = compileTemplateToRegex(value);
      if (!regex.test(cleanPath)) return false;
    }
  }

  return true;
}

/**
 * Parses raw query string and collects all occurrences of each parameter name
 */
export function parseQueryStringAll(queryString) {
  const result = new Map();
  if (!queryString) return result;

  const pairs = queryString.replace(/^\?/, '').split('&');
  for (const pair of pairs) {
    if (!pair) continue;
    const [rawKey, ...rawValueParts] = pair.split('=');
    const rawValue = rawValueParts.join('=');
    try {
      const key = decodeURIComponent(rawKey);
      const val = decodeURIComponent(rawValue);
      if (!result.has(key)) {
        result.set(key, []);
      }
      result.get(key).push(val);
    } catch {
      if (!result.has(rawKey)) {
        result.set(rawKey, []);
      }
      result.get(rawKey).push(rawValue);
    }
  }
  return result;
}

/**
 * Parses Cookie header into map of key -> string[]
 */
export function parseCookiesAll(cookieHeader) {
  const result = new Map();
  if (!cookieHeader) return result;

  const pairs = cookieHeader.split(';');
  for (const pair of pairs) {
    const trimmed = pair.trim();
    if (!trimmed) continue;
    const [rawKey, ...rawValueParts] = trimmed.split('=');
    const key = rawKey.trim();
    const val = rawValueParts.join('=').trim();
    if (!result.has(key)) {
      result.set(key, []);
    }
    result.get(key).push(val);
  }
  return result;
}

/**
 * Recursively inspects a JSON object/array to find all values for a given key name
 */
function findInJsonObject(obj, targetKey, collected = []) {
  if (obj === null || obj === undefined) return collected;

  if (Array.isArray(obj)) {
    for (const item of obj) {
      findInJsonObject(item, targetKey, collected);
    }
  } else if (typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      if (k.toLowerCase() === targetKey.toLowerCase()) {
        if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
          collected.push(String(v));
        } else if (Array.isArray(v)) {
          for (const elem of v) {
            collected.push(typeof elem === 'object' ? JSON.stringify(elem) : String(elem));
          }
        } else if (typeof v === 'object' && v !== null) {
          collected.push(JSON.stringify(v));
        }
      }
      // Also search nested
      if (typeof v === 'object' && v !== null) {
        findInJsonObject(v, targetKey, collected);
      }
    }
  }
  return collected;
}

/**
 * Extracts all values matching an inspect target from the HTTP request
 */
export function extractInspectValues(target, reqData) {
  const { location, name } = target;
  const values = [];

  switch (location) {
    case 'query': {
      const qMap = parseQueryStringAll(reqData.queryString || '');
      for (const [k, list] of qMap.entries()) {
        if (k.toLowerCase() === name.toLowerCase()) {
          values.push(...list);
        }
      }
      break;
    }
    case 'body_form': {
      if (typeof reqData.body === 'string') {
        const formMap = parseQueryStringAll(reqData.body);
        for (const [k, list] of formMap.entries()) {
          if (k.toLowerCase() === name.toLowerCase()) {
            values.push(...list);
          }
        }
      } else if (typeof reqData.body === 'object' && reqData.body !== null) {
        findInJsonObject(reqData.body, name, values);
      }
      break;
    }
    case 'body_json': {
      if (typeof reqData.body === 'object' && reqData.body !== null) {
        findInJsonObject(reqData.body, name, values);
      } else if (typeof reqData.body === 'string') {
        try {
          const parsed = JSON.parse(reqData.body);
          findInJsonObject(parsed, name, values);
        } catch {
          // If body is not valid JSON, cannot extract JSON params
        }
      }
      break;
    }
    case 'header': {
      if (reqData.headers) {
        const targetHeader = name.toLowerCase();
        for (const [k, v] of Object.entries(reqData.headers)) {
          if (k.toLowerCase() === targetHeader) {
            if (Array.isArray(v)) {
              values.push(...v.map(String));
            } else if (v !== undefined && v !== null) {
              values.push(String(v));
            }
          }
        }
      }
      break;
    }
    case 'cookie': {
      const cookieHeader = reqData.headers?.cookie || reqData.headers?.Cookie;
      const cMap = parseCookiesAll(cookieHeader);
      for (const [k, list] of cMap.entries()) {
        if (k.toLowerCase() === name.toLowerCase()) {
          values.push(...list);
        }
      }
      break;
    }
    case 'path': {
      values.push(reqData.path || '/');
      break;
    }
  }

  return values;
}

/**
 * Evaluates a condition against a normalized value
 */
export function evaluateCondition(condition, normalizedValue) {
  if (!condition || typeof normalizedValue !== 'string') return false;

  const { op, value } = condition;

  switch (op) {
    case 'regex_match': {
      try {
        const regex = new RegExp(value, 'is');
        return regex.test(normalizedValue);
      } catch {
        return false;
      }
    }
    case 'regex_not_match': {
      try {
        const regex = new RegExp(value, 'is');
        return !regex.test(normalizedValue);
      } catch {
        return false;
      }
    }
    case 'contains_any': {
      if (Array.isArray(value)) {
        return value.some(sub => normalizedValue.includes(sub));
      }
      if (typeof value === 'string') {
        return normalizedValue.includes(value);
      }
      return false;
    }
    case 'max_length': {
      const maxLen = Number(value);
      return !isNaN(maxLen) && normalizedValue.length > maxLen;
    }
    default:
      return false;
  }
}

/**
 * Evaluates a single rule against a request representation
 */
export function evaluateRule(rule, reqData) {
  if (!rule || typeof rule !== 'object') {
    return { matched: false };
  }
  const { scope, inspect, normalize = [], condition, mode = 'enforce' } = rule;

  // 1. Check scope
  if (!matchesScope(scope, reqData.method, reqData.path)) {
    return { matched: false };
  }

  // 2. Inspect targets and extract values
  const inspectTargets = Array.isArray(inspect) ? inspect : [inspect];

  for (const target of inspectTargets) {
    const rawValues = extractInspectValues(target, reqData);

    for (const rawVal of rawValues) {
      // 3. Apply normalizers in exact order
      const normalized = applyNormalizers(rawVal, normalize);

      // 4. Evaluate condition
      if (evaluateCondition(condition, normalized)) {
        return {
          matched: true,
          rule_id: rule.id || rule.name,
          mode: mode,
          action: rule.action || 'block',
          matched_target: target,
          matched_raw: rawVal,
          matched_normalized: normalized
        };
      }
    }
  }

  return { matched: false };
}

/**
 * WAF Engine: evaluates a list of rules against a request
 */
export class WafEngine {
  constructor(options = {}) {
    this.failMode = options.failMode || 'open';
    this.rules = [];
  }

  setRules(rules) {
    // Validate rules and ReDoS safety of any regex
    const validRules = [];
    for (const rule of rules) {
      if (rule.condition && (rule.condition.op === 'regex_match' || rule.condition.op === 'regex_not_match')) {
        const check = isRegexSafe(rule.condition.value);
        if (!check.safe) {
          console.warn(`[WAF Engine] Rule "${rule.name || rule.id}" failed ReDoS check: ${check.reason}`);
          continue;
        }
      }
      validRules.push(rule);
    }
    this.rules = validRules;
  }

  /**
   * Process an inbound HTTP request
   * @param {Object} reqData - { method, path, queryString, headers, body }
   * @param {Object} [overrideRule] - Optional candidate rule for verification mode
   * @returns {Object} { decision: 'allow'|'block'|'log_only'|'error', rule_id, mode, latency_ms }
   */
  evaluate(reqData, overrideRule = null) {
    const start = performance.now();

    try {
      if (!reqData || typeof reqData !== 'object') {
        throw new Error('Invalid request data provided to WAF Engine');
      }

      const activeRules = overrideRule ? [overrideRule] : this.rules;

      for (const rule of activeRules) {
        const result = evaluateRule(rule, reqData);
        if (result.matched) {
          const latency = performance.now() - start;
          const isEnforce = result.mode === 'enforce';

          return {
            decision: isEnforce ? 'block' : 'log_only',
            would_block: true,
            rule_id: result.rule_id,
            mode: result.mode,
            action: result.action,
            matched_raw: result.matched_raw,
            latency_ms: Number(latency.toFixed(3))
          };
        }
      }

      const latency = performance.now() - start;
      return {
        decision: 'allow',
        would_block: false,
        latency_ms: Number(latency.toFixed(3))
      };
    } catch (err) {
      const latency = performance.now() - start;
      return {
        decision: this.failMode === 'open' ? 'allow' : 'block',
        error: err.message,
        is_error: true,
        would_block: false,
        latency_ms: Number(latency.toFixed(3))
      };
    }
  }
}
