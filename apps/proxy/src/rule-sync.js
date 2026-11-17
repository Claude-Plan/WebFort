/**
 * Rule Synchronization for Proxy Data Plane (§6)
 * - Polls GET /internal/v1/rules/active every 2s
 * - Handles ETag and 304 Not Modified
 * - Never crashes if API is temporarily unavailable
 * - Caches candidate rules for verification runs (X-Shield-Verify-Patch)
 */

export class RuleSynchronizer {
  constructor(options = {}) {
    this.apiUrl = (options.apiUrl || 'http://localhost:4000').replace(/\/$/, '');
    this.internalToken = options.internalToken || 'patchproof_secret_internal_token_2026';
    this.targetId = options.targetId || null;
    this.pollIntervalMs = options.pollIntervalMs || 2000;
    this.onRulesUpdated = options.onRulesUpdated || (() => {});

    this.currentEtag = null;
    this.activeRules = [];
    this.candidateCache = new Map(); // patchId -> { rule, cachedAt }
    this.timer = null;
    this.isPolling = false;
  }

  async fetchActiveRules() {
    try {
      const url = new URL(`${this.apiUrl}/internal/v1/rules/active`);
      if (this.targetId) {
        url.searchParams.set('target_id', this.targetId);
      }

      const headers = {
        'X-Internal-Token': this.internalToken
      };
      if (this.currentEtag) {
        headers['If-None-Match'] = this.currentEtag;
      }

      const res = await fetch(url.toString(), {
        method: 'GET',
        headers,
        signal: AbortSignal.timeout(3000)
      });

      if (res.status === 304) {
        // Not modified - active rules are unchanged
        return this.activeRules;
      }

      if (res.ok) {
        const data = await res.json();
        const newEtag = res.headers.get('ETag') || res.headers.get('etag');
        if (newEtag) {
          this.currentEtag = newEtag;
        }

        const rules = data.rules || (Array.isArray(data) ? data : []);
        this.activeRules = rules;
        this.onRulesUpdated(rules);
        return rules;
      }
    } catch (err) {
      // Graceful error handling: API may be booting or temporarily offline
      // Keep existing rules, do not crash
    }

    return this.activeRules;
  }

  /**
   * Fetches a candidate rule for verification requests
   */
  async fetchCandidateRule(patchId) {
    if (!patchId) return null;

    // Check candidate cache (cache for 10 seconds)
    const cached = this.candidateCache.get(patchId);
    if (cached && (Date.now() - cached.cachedAt < 10000)) {
      return cached.rule;
    }

    try {
      const url = `${this.apiUrl}/internal/v1/rules/candidate/${encodeURIComponent(patchId)}`;
      const res = await fetch(url, {
        method: 'GET',
        headers: {
          'X-Internal-Token': this.internalToken
        },
        signal: AbortSignal.timeout(3000)
      });

      if (res.ok) {
        const body = await res.json();
        const rule = body.rule || (body.data && body.data.rule) || body;
        if (rule) {
          this.candidateCache.set(patchId, { rule, cachedAt: Date.now() });
          return rule;
        }
      }
    } catch {
      // Return cached if available, else null
    }

    return cached ? cached.rule : null;
  }

  start() {
    if (this.timer) return;
    this.fetchActiveRules();
    this.timer = setInterval(() => {
      this.fetchActiveRules();
    }, this.pollIntervalMs);
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}
