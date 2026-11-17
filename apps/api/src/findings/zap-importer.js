import { computeDedupeKey } from '../recipes/index.js';

function mapRiskCode(riskcode, riskdesc) {
  const code = String(riskcode || '').trim();
  const desc = String(riskdesc || '').toLowerCase();

  if (code === '3' || desc.includes('high')) return 'high';
  if (code === '2' || desc.includes('medium')) return 'medium';
  if (code === '1' || desc.includes('low')) return 'low';
  if (desc.includes('critical')) return 'critical';
  return 'info';
}

function inferCategory(alertName, pluginId) {
  const name = String(alertName || '').toLowerCase();
  const id = String(pluginId || '');

  if (name.includes('sql') || id === '40018') return 'sqli';
  if (name.includes('cross site scripting') || name.includes('xss') || id === '40012') return 'xss';
  if (name.includes('command') || name.includes('cmdi') || id === '90020') return 'cmdi';
  if (name.includes('path traversal') || name.includes('directory browsing') || id === '40028') return 'path_traversal';
  return 'other';
}

/**
 * Parses OWASP ZAP baseline scan JSON and extracts standardized findings
 */
export function parseZapReport(zapJson, targetId) {
  const findings = [];
  let rawAlerts = [];

  if (Array.isArray(zapJson)) {
    rawAlerts = zapJson;
  } else if (zapJson?.site && Array.isArray(zapJson.site)) {
    for (const site of zapJson.site) {
      if (Array.isArray(site.alerts)) {
        rawAlerts.push(...site.alerts);
      }
    }
  } else if (Array.isArray(zapJson?.alerts)) {
    rawAlerts = zapJson.alerts;
  }

  for (const alert of rawAlerts) {
    const instances = Array.isArray(alert.instances) && alert.instances.length > 0
      ? alert.instances
      : [{ uri: alert.url || '/rest/products/search', method: alert.method || 'GET', param: alert.param || '' }];

    for (const inst of instances) {
      const urlStr = inst.uri || alert.url || '/';
      let pathname = '/';
      try {
        pathname = new URL(urlStr, 'http://localhost').pathname;
      } catch {
        pathname = urlStr.split('?')[0];
      }

      const method = (inst.method || alert.method || 'GET').toUpperCase();
      const param = inst.param || alert.param || '';
      const category = inferCategory(alert.alert || alert.name, alert.pluginId);
      const scannerRisk = mapRiskCode(alert.riskcode, alert.riskdesc);
      const dedupeKey = computeDedupeKey(method, pathname, param);

      findings.push({
        target_id: targetId,
        title: alert.alert || alert.name || 'Discovered Vulnerability',
        category,
        scanner_risk: scannerRisk,
        method,
        url: pathname,
        route_template: pathname,
        param: param || null,
        param_location: param ? 'query' : null,
        evidence: (inst.evidence || alert.evidence || alert.description || '').slice(0, 1500),
        exploit_request: null,
        exploit_oracle: null,
        exploit_confirmed: false, // Non-negotiable: scanner alone is never exploit_confirmed
        status: 'open',
        dedupe_key: dedupeKey,
        provenance: 'real_scan'
      });
    }
  }

  return findings;
}
