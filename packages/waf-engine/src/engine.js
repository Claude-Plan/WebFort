// packages/waf-engine/src/engine.js
import { applyNormalizers } from './normalizers.js';
import { testRegexSafety } from './redos-guard.js';

export function matchPath(scopePath, reqPath) {
  if (!scopePath || !scopePath.value) return true;
  const cleanReq = reqPath.split('?')[0];
  const { kind, value } = scopePath;

  if (kind === 'exact') {
    return cleanReq === value;
  }
  if (kind === 'prefix') {
    return cleanReq.startsWith(value);
  }
  if (kind === 'template') {
    // Template segments {x} match [^/]+
    const regexStr = '^' + value.replace(/\{[^}]+\}/g, '[^/]+') + '$';
    try {
      const re = new RegExp(regexStr);
      return re.test(cleanReq);
    } catch {
      return false;
    }
  }
  return true;
}

export function extractValues(req, inspectRule) {
  const { location, name } = inspectRule;
  const values = [];

  if (location === 'query') {
    if (req.query) {
      if (Array.isArray(req.query[name])) {
        values.push(...req.query[name]);
      } else if (req.query[name] !== undefined) {
        values.push(req.query[name]);
      }
    }
    // Also parse raw query string to catch duplicates if framework collapsed them
    if (req.rawQuery) {
      const sp = new URLSearchParams(req.rawQuery);
      const all = sp.getAll(name);
      for (const v of all) {
        if (!values.includes(v)) values.push(v);
      }
    }
  } else if (location === 'body_form' || location === 'body_json') {
    let body = req.body;
    if (typeof body === 'string') {
      try {
        body = JSON.parse(body);
      } catch {
        // May be form encoded
        try {
          const sp = new URLSearchParams(body);
          const all = sp.getAll(name);
          values.push(...all);
        } catch {}
      }
    }
    if (body && typeof body === 'object') {
      if (Array.isArray(body[name])) {
        values.push(...body[name]);
      } else if (body[name] !== undefined) {
        values.push(body[name]);
      }
    }
  } else if (location === 'header') {
    const hdr = req.headers?.[name.toLowerCase()];
    if (hdr !== undefined) {
      if (Array.isArray(hdr)) values.push(...hdr);
      else values.push(hdr);
    }
  } else if (location === 'cookie') {
    if (req.cookies && req.cookies[name] !== undefined) {
      values.push(req.cookies[name]);
    } else if (req.headers?.cookie) {
      const pairs = req.headers.cookie.split(';');
      for (const p of pairs) {
        const [k, ...v] = p.trim().split('=');
        if (k === name) values.push(v.join('='));
      }
    }
  } else if (location === 'path') {
    const cleanPath = (req.path || req.url || '').split('?')[0];
    values.push(cleanPath);
  }

  return values;
}

export function evaluateCondition(condition, normalizedValue) {
  const { op, value } = condition;

  if (op === 'regex_match') {
    try {
      const re = new RegExp(value, 'i');
      return re.test(normalizedValue);
    } catch {
      return false;
    }
  }

  if (op === 'regex_not_match') {
    try {
      const re = new RegExp(value, 'i');
      // Fires if value DOES NOT match the allowlist pattern
      return !re.test(normalizedValue);
    } catch {
      return false;
    }
  }

  if (op === 'contains_any') {
    const list = Array.isArray(value) ? value : [value];
    for (const item of list) {
      if (normalizedValue.includes(item)) return true;
    }
    return false;
  }

  if (op === 'max_length') {
    const max = Number(value);
    return normalizedValue.length > max;
  }

  return false;
}

export function evaluateRule(rule, request) {
  const t0 = performance.now();

  // 1. Check scope
  if (rule.scope?.methods && rule.scope.methods.length > 0) {
    const reqMethod = (request.method || 'GET').toUpperCase();
    const allowed = rule.scope.methods.map(m => m.toUpperCase());
    if (!allowed.includes(reqMethod)) {
      return { match: false, decision: 'allow', latency_ms: performance.now() - t0 };
    }
  }

  if (!matchPath(rule.scope?.path, request.path || request.url || '/')) {
    return { match: false, decision: 'allow', latency_ms: performance.now() - t0 };
  }

  // 2. Extract values across all inspect targets
  const inspectedValues = [];
  for (const inspectTarget of rule.inspect || []) {
    const vals = extractValues(request, inspectTarget);
    for (const val of vals) {
      inspectedValues.push({
        target: inspectTarget,
        raw: val,
        normalized: applyNormalizers(val, rule.normalize || [])
      });
    }
  }

  // 3. Evaluate condition across inspected values
  for (const item of inspectedValues) {
    const triggered = evaluateCondition(rule.condition, item.normalized);
    if (triggered) {
      const latency_ms = performance.now() - t0;
      const isEnforce = rule.mode === 'enforce';
      return {
        match: true,
        rule_name: rule.name,
        decision: isEnforce ? 'block' : 'allow',
        would_block: true,
        mode: rule.mode,
        matched_target: item.target,
        matched_value: item.raw,
        normalized_value: item.normalized,
        latency_ms: Math.round(latency_ms * 100) / 100
      };
    }
  }

  return {
    match: false,
    decision: 'allow',
    would_block: false,
    latency_ms: Math.round((performance.now() - t0) * 100) / 100
  };
}

export class WafEngine {
  constructor(rules = []) {
    this.rules = rules;
  }

  setRules(rules) {
    this.rules = rules || [];
  }

  inspectRequest(req) {
    const t0 = performance.now();
    let wouldBlockAny = false;
    let blockingResult = null;

    for (const rule of this.rules) {
      const res = evaluateRule(rule, req);
      if (res.would_block) {
        wouldBlockAny = true;
      }
      if (res.match && res.decision === 'block') {
        blockingResult = {
          ...res,
          rule_id: rule.id || rule.name,
          latency_ms: Math.round((performance.now() - t0) * 100) / 100
        };
        break; // First blocking rule terminates evaluation
      }
    }

    if (blockingResult) {
      return blockingResult;
    }

    return {
      match: false,
      decision: 'allow',
      would_block: wouldBlockAny,
      latency_ms: Math.round((performance.now() - t0) * 100) / 100
    };
  }
}
