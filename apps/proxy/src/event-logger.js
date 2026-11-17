/**
 * Fire-and-forget asynchronous event logger for proxy decisions
 */

export class ProxyEventLogger {
  constructor(options = {}) {
    this.apiUrl = (options.apiUrl || 'http://localhost:4000').replace(/\/$/, '');
    this.internalToken = options.internalToken || 'patchproof_secret_internal_token_2026';
    this.batchSize = options.batchSize || 20;
    this.flushIntervalMs = options.flushIntervalMs || 500;
    this.queue = [];
    this.timer = null;
  }

  log(event) {
    const enrichedEvent = {
      ts: event.ts || new Date().toISOString(),
      target_id: event.target_id || null,
      method: event.method || 'GET',
      path: event.path || '/',
      route_template: event.route_template || event.path || '/',
      decision: event.decision || 'allow',
      rule_id: event.rule_id || null,
      patch_id: event.patch_id || null,
      latency_ms: event.latency_ms !== undefined ? Number(event.latency_ms) : null,
      status_code: event.status_code || 200,
      meta: event.meta || {}
    };

    this.queue.push(enrichedEvent);

    if (this.queue.length >= this.batchSize) {
      this.flush();
    }
  }

  start() {
    if (this.timer) return;
    this.timer = setInterval(() => {
      this.flush();
    }, this.flushIntervalMs);
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.flush();
  }

  async flush() {
    if (this.queue.length === 0) return;

    const eventsToSend = [...this.queue];
    this.queue = [];

    try {
      // Fire and forget POST to internal events endpoint
      fetch(`${this.apiUrl}/internal/v1/events`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Internal-Token': this.internalToken
        },
        body: JSON.stringify({ events: eventsToSend }),
        signal: AbortSignal.timeout(2000)
      }).catch(() => {
        // Silently ignore network drop to maintain non-blocking behavior
      });
    } catch {
      // Ignore
    }
  }
}
