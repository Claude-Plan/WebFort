import { randomUUID } from 'node:crypto';
import { dbQuery, memoryDb } from './index.js';

export const Repository = {
  // --- TARGETS ---
  async createTarget(data) {
    const id = data.id || randomUUID();
    const createdAt = new Date().toISOString();
    const target = {
      id,
      name: data.name,
      base_url: data.base_url,
      proxy_url: data.proxy_url,
      mode: data.mode || 'protect',
      created_at: createdAt
    };

    memoryDb.targets.set(id, target);

    await dbQuery(
      `INSERT INTO targets (id, name, base_url, proxy_url, mode, created_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (id) DO UPDATE SET name = $2, base_url = $3, proxy_url = $4, mode = $5`,
      [id, target.name, target.base_url, target.proxy_url, target.mode, createdAt]
    );

    return target;
  },

  async listTargets() {
    const pgRes = await dbQuery('SELECT * FROM targets ORDER BY created_at DESC');
    if (pgRes && pgRes.rows.length > 0) {
      return pgRes.rows;
    }
    return Array.from(memoryDb.targets.values());
  },

  async getTargetById(id) {
    const pgRes = await dbQuery('SELECT * FROM targets WHERE id = $1', [id]);
    if (pgRes && pgRes.rows[0]) {
      return pgRes.rows[0];
    }
    return memoryDb.targets.get(id) || null;
  },

  async getOrCreateDefaultTarget() {
    const targets = await this.listTargets();
    if (targets.length > 0) return targets[0];

    return await this.createTarget({
      name: 'OWASP Juice Shop (Lab)',
      base_url: process.env.TARGET_URL || 'http://localhost:3001',
      proxy_url: process.env.PROXY_URL || 'http://localhost:8080',
      mode: 'protect'
    });
  },

  // --- FINDINGS ---
  async upsertFinding(data) {
    const existing = await this.getFindingByDedupeKey(data.dedupe_key);
    const id = existing?.id || data.id || randomUUID();
    const createdAt = existing?.created_at || new Date().toISOString();

    const finding = {
      id,
      target_id: data.target_id,
      title: data.title,
      category: data.category,
      scanner_risk: data.scanner_risk,
      method: data.method,
      url: data.url,
      route_template: data.route_template || data.url.split('?')[0],
      param: data.param || null,
      param_location: data.param_location || null,
      evidence: data.evidence || '',
      exploit_request: data.exploit_request || null,
      exploit_oracle: data.exploit_oracle || null,
      exploit_confirmed: Boolean(data.exploit_confirmed),
      status: data.status || 'open',
      dedupe_key: data.dedupe_key,
      provenance: data.provenance || 'real_scan',
      created_at: createdAt
    };

    memoryDb.findings.set(id, finding);

    await dbQuery(
      `INSERT INTO findings (
        id, target_id, title, category, scanner_risk, method, url, route_template,
        param, param_location, evidence, exploit_request, exploit_oracle,
        exploit_confirmed, status, dedupe_key, provenance, created_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
      ON CONFLICT (dedupe_key) DO UPDATE SET
        title = EXCLUDED.title,
        category = EXCLUDED.category,
        scanner_risk = EXCLUDED.scanner_risk,
        evidence = EXCLUDED.evidence,
        exploit_request = EXCLUDED.exploit_request,
        exploit_oracle = EXCLUDED.exploit_oracle,
        exploit_confirmed = EXCLUDED.exploit_confirmed,
        status = EXCLUDED.status`,
      [
        id, finding.target_id, finding.title, finding.category, finding.scanner_risk,
        finding.method, finding.url, finding.route_template, finding.param,
        finding.param_location, finding.evidence, JSON.stringify(finding.exploit_request),
        JSON.stringify(finding.exploit_oracle), finding.exploit_confirmed,
        finding.status, finding.dedupe_key, finding.provenance, createdAt
      ]
    );

    return finding;
  },

  async getFindingById(id) {
    const pgRes = await dbQuery('SELECT * FROM findings WHERE id = $1', [id]);
    if (pgRes && pgRes.rows[0]) {
      const row = pgRes.rows[0];
      return {
        ...row,
        exploit_request: typeof row.exploit_request === 'string' ? JSON.parse(row.exploit_request) : row.exploit_request,
        exploit_oracle: typeof row.exploit_oracle === 'string' ? JSON.parse(row.exploit_oracle) : row.exploit_oracle
      };
    }
    return memoryDb.findings.get(id) || null;
  },

  async getFindingByDedupeKey(dedupeKey) {
    const pgRes = await dbQuery('SELECT * FROM findings WHERE dedupe_key = $1', [dedupeKey]);
    if (pgRes && pgRes.rows[0]) {
      return pgRes.rows[0];
    }
    for (const f of memoryDb.findings.values()) {
      if (f.dedupe_key === dedupeKey) return f;
    }
    return null;
  },

  async listFindings(targetId = null) {
    let pgRes;
    if (targetId) {
      pgRes = await dbQuery('SELECT * FROM findings WHERE target_id = $1 ORDER BY created_at DESC', [targetId]);
    } else {
      pgRes = await dbQuery('SELECT * FROM findings ORDER BY created_at DESC');
    }

    if (pgRes && pgRes.rows.length > 0) {
      return pgRes.rows.map(row => ({
        ...row,
        exploit_request: typeof row.exploit_request === 'string' ? JSON.parse(row.exploit_request) : row.exploit_request,
        exploit_oracle: typeof row.exploit_oracle === 'string' ? JSON.parse(row.exploit_oracle) : row.exploit_oracle
      }));
    }

    const all = Array.from(memoryDb.findings.values());
    if (targetId) {
      return all.filter(f => f.target_id === targetId);
    }
    return all;
  },

  // --- TRIAGE RESULTS ---
  async upsertTriageResult(data) {
    const existing = await this.getTriageByFindingId(data.finding_id);
    const id = existing?.id || data.id || randomUUID();
    const createdAt = existing?.created_at || new Date().toISOString();

    const triage = {
      id,
      finding_id: data.finding_id,
      priority_score: Number(data.priority_score),
      priority_band: data.priority_band,
      signals: data.signals || [],
      llm_explanation: data.llm_explanation || null,
      llm_status: data.llm_status || 'skipped',
      created_at: createdAt
    };

    memoryDb.triage_results.set(data.finding_id, triage);

    await dbQuery(
      `INSERT INTO triage_results (id, finding_id, priority_score, priority_band, signals, llm_explanation, llm_status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (finding_id) DO UPDATE SET
         priority_score = EXCLUDED.priority_score,
         priority_band = EXCLUDED.priority_band,
         signals = EXCLUDED.signals,
         llm_explanation = EXCLUDED.llm_explanation,
         llm_status = EXCLUDED.llm_status`,
      [
        id, triage.finding_id, triage.priority_score, triage.priority_band,
        JSON.stringify(triage.signals), JSON.stringify(triage.llm_explanation),
        triage.llm_status, createdAt
      ]
    );

    return triage;
  },

  async getTriageByFindingId(findingId) {
    const pgRes = await dbQuery('SELECT * FROM triage_results WHERE finding_id = $1', [findingId]);
    if (pgRes && pgRes.rows[0]) {
      const row = pgRes.rows[0];
      return {
        ...row,
        priority_score: Number(row.priority_score),
        signals: typeof row.signals === 'string' ? JSON.parse(row.signals) : row.signals,
        llm_explanation: typeof row.llm_explanation === 'string' ? JSON.parse(row.llm_explanation) : row.llm_explanation
      };
    }
    return memoryDb.triage_results.get(findingId) || null;
  },

  // --- PATCHES ---
  async createPatch(data) {
    const id = data.id || randomUUID();
    const createdAt = new Date().toISOString();

    const patch = {
      id,
      finding_id: data.finding_id,
      version: data.version || 1,
      parent_patch_id: data.parent_patch_id || null,
      source: data.source || 'deterministic',
      rule: data.rule || null,
      mode: data.mode || 'shadow',
      status: data.status || 'draft',
      rationale: data.rationale || '',
      meta: data.meta || {},
      created_at: createdAt,
      deployed_at: data.deployed_at || null
    };

    memoryDb.patches.set(id, patch);

    await dbQuery(
      `INSERT INTO patches (id, finding_id, version, parent_patch_id, source, rule, mode, status, rationale, meta, created_at, deployed_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        id, patch.finding_id, patch.version, patch.parent_patch_id,
        patch.source, JSON.stringify(patch.rule), patch.mode, patch.status,
        patch.rationale, JSON.stringify(patch.meta), createdAt, patch.deployed_at
      ]
    );

    return patch;
  },

  async updatePatch(id, updates) {
    const patch = await this.getPatchById(id);
    if (!patch) return null;

    Object.assign(patch, updates);
    memoryDb.patches.set(id, patch);

    await dbQuery(
      `UPDATE patches SET
         rule = COALESCE($2, rule),
         mode = COALESCE($3, mode),
         status = COALESCE($4, status),
         rationale = COALESCE($5, rationale),
         meta = COALESCE($6, meta),
         deployed_at = COALESCE($7, deployed_at)
       WHERE id = $1`,
      [
        id,
        updates.rule !== undefined ? JSON.stringify(updates.rule) : null,
        updates.mode,
        updates.status,
        updates.rationale,
        updates.meta ? JSON.stringify(updates.meta) : null,
        updates.deployed_at
      ]
    );

    return patch;
  },

  async getPatchById(id) {
    const pgRes = await dbQuery('SELECT * FROM patches WHERE id = $1', [id]);
    if (pgRes && pgRes.rows[0]) {
      const row = pgRes.rows[0];
      return {
        ...row,
        rule: typeof row.rule === 'string' ? JSON.parse(row.rule) : row.rule,
        meta: typeof row.meta === 'string' ? JSON.parse(row.meta) : row.meta
      };
    }
    return memoryDb.patches.get(id) || null;
  },

  async listPatchesByFinding(findingId) {
    const pgRes = await dbQuery('SELECT * FROM patches WHERE finding_id = $1 ORDER BY version DESC', [findingId]);
    if (pgRes && pgRes.rows.length > 0) {
      return pgRes.rows.map(row => ({
        ...row,
        rule: typeof row.rule === 'string' ? JSON.parse(row.rule) : row.rule,
        meta: typeof row.meta === 'string' ? JSON.parse(row.meta) : row.meta
      }));
    }
    return Array.from(memoryDb.patches.values()).filter(p => p.finding_id === findingId);
  },

  async listActiveDeployedRules(targetId = null) {
    const pgRes = await dbQuery(
      `SELECT p.* FROM patches p
       JOIN findings f ON p.finding_id = f.id
       WHERE p.status = 'deployed' ${targetId ? 'AND f.target_id = $1' : ''}
       ORDER BY p.deployed_at DESC`,
      targetId ? [targetId] : []
    );

    if (pgRes && pgRes.rows.length > 0) {
      return pgRes.rows.map(row => ({
        ...row,
        rule: typeof row.rule === 'string' ? JSON.parse(row.rule) : row.rule,
        meta: typeof row.meta === 'string' ? JSON.parse(row.meta) : row.meta
      }));
    }

    return Array.from(memoryDb.patches.values())
      .filter(p => p.status === 'deployed' && p.rule);
  },

  // --- VERIFICATIONS ---
  async createVerification(data) {
    const id = data.id || randomUUID();
    const startedAt = new Date().toISOString();
    const verification = {
      id,
      patch_id: data.patch_id,
      status: data.status || 'running',
      summary: data.summary || {},
      started_at: startedAt,
      finished_at: null
    };

    memoryDb.verifications.set(id, verification);

    await dbQuery(
      `INSERT INTO verifications (id, patch_id, status, summary, started_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [id, verification.patch_id, verification.status, JSON.stringify(verification.summary), startedAt]
    );

    return verification;
  },

  async updateVerification(id, updates) {
    const ver = memoryDb.verifications.get(id);
    if (ver) {
      Object.assign(ver, updates);
    }

    await dbQuery(
      `UPDATE verifications SET
         status = COALESCE($2, status),
         summary = COALESCE($3, summary),
         finished_at = COALESCE($4, finished_at)
       WHERE id = $1`,
      [
        id,
        updates.status,
        updates.summary ? JSON.stringify(updates.summary) : null,
        updates.finished_at || (updates.status !== 'running' ? new Date().toISOString() : null)
      ]
    );

    return ver;
  },

  async getLatestVerificationForPatch(patchId) {
    const pgRes = await dbQuery(
      'SELECT * FROM verifications WHERE patch_id = $1 ORDER BY started_at DESC LIMIT 1',
      [patchId]
    );
    if (pgRes && pgRes.rows[0]) {
      const row = pgRes.rows[0];
      return {
        ...row,
        summary: typeof row.summary === 'string' ? JSON.parse(row.summary) : row.summary
      };
    }
    const matching = Array.from(memoryDb.verifications.values()).filter(v => v.patch_id === patchId);
    return matching[matching.length - 1] || null;
  },

  // --- PROXY EVENTS ---
  async insertProxyEvents(events) {
    if (!Array.isArray(events) || events.length === 0) return;

    for (const ev of events) {
      memoryDb.proxy_events.unshift(ev);
    }
    // Keep in-memory queue to max 500 events
    if (memoryDb.proxy_events.length > 500) {
      memoryDb.proxy_events = memoryDb.proxy_events.slice(0, 500);
    }

    for (const ev of events) {
      await dbQuery(
        `INSERT INTO proxy_events (ts, target_id, method, path, route_template, decision, rule_id, patch_id, latency_ms, status_code, meta)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [
          ev.ts || new Date().toISOString(),
          ev.target_id || null,
          ev.method,
          ev.path,
          ev.route_template || ev.path,
          ev.decision,
          ev.rule_id || null,
          ev.patch_id || null,
          ev.latency_ms !== null ? Number(ev.latency_ms) : null,
          ev.status_code || 200,
          JSON.stringify(ev.meta || {})
        ]
      );
    }
  },

  async getRecentProxyEvents(limit = 100) {
    const pgRes = await dbQuery('SELECT * FROM proxy_events ORDER BY ts DESC LIMIT $1', [limit]);
    if (pgRes && pgRes.rows.length > 0) {
      return pgRes.rows.map(row => ({
        ...row,
        latency_ms: row.latency_ms !== null ? Number(row.latency_ms) : null,
        meta: typeof row.meta === 'string' ? JSON.parse(row.meta) : row.meta
      }));
    }
    return memoryDb.proxy_events.slice(0, limit);
  },

  // --- HARDENING RUNS ---
  async createHardeningRun(data) {
    const id = data.id || randomUUID();
    const createdAt = new Date().toISOString();
    const record = {
      id,
      patch_id: data.patch_id,
      status: data.status || 'completed',
      start_mode: data.start_mode || 'current',
      max_iterations: data.max_iterations || 5,
      mutation_budget: data.mutation_budget || 60,
      seed: data.seed || 12345,
      iterations: data.iterations || [],
      exam: data.exam || null,
      best_patch_id: data.best_patch_id || data.patch_id,
      created_at: createdAt
    };

    memoryDb.hardening_runs.set(id, record);

    await dbQuery(
      `INSERT INTO hardening_runs (id, patch_id, status, start_mode, max_iterations, mutation_budget, seed, iterations, exam, best_patch_id, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [
        id, record.patch_id, record.status, record.start_mode,
        record.max_iterations, record.mutation_budget, record.seed,
        JSON.stringify(record.iterations), JSON.stringify(record.exam),
        record.best_patch_id, createdAt
      ]
    );

    return record;
  },

  async getHardeningRunById(id) {
    const pgRes = await dbQuery('SELECT * FROM hardening_runs WHERE id = $1', [id]);
    if (pgRes && pgRes.rows[0]) {
      const row = pgRes.rows[0];
      return {
        ...row,
        iterations: typeof row.iterations === 'string' ? JSON.parse(row.iterations) : row.iterations,
        exam: typeof row.exam === 'string' ? JSON.parse(row.exam) : row.exam
      };
    }
    return memoryDb.hardening_runs.get(id) || null;
  },

  // --- PROOF REPORTS ---
  async createProofReportRecord(data) {
    const id = data.id || randomUUID();
    const createdAt = new Date().toISOString();
    const record = {
      id,
      patch_id: data.patch_id,
      report: data.report,
      sha256: data.sha256,
      signature: data.signature,
      public_key: data.public_key,
      created_at: createdAt
    };

    memoryDb.proof_reports.set(data.patch_id, record);

    await dbQuery(
      `INSERT INTO proof_reports (id, patch_id, report, sha256, signature, public_key, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [id, record.patch_id, JSON.stringify(record.report), record.sha256, record.signature, record.public_key, createdAt]
    );

    return record;
  },

  async getProofReportByPatchId(patchId) {
    const pgRes = await dbQuery('SELECT * FROM proof_reports WHERE patch_id = $1 ORDER BY created_at DESC LIMIT 1', [patchId]);
    if (pgRes && pgRes.rows[0]) {
      const row = pgRes.rows[0];
      return {
        ...row,
        report: typeof row.report === 'string' ? JSON.parse(row.report) : row.report
      };
    }
    return memoryDb.proof_reports.get(patchId) || null;
  },

  // --- BENCHMARK RUNS ---
  async createBenchmarkRunRecord(data) {
    const id = data.id || randomUUID();
    const createdAt = new Date().toISOString();
    const record = {
      id,
      target_id: data.target_id || null,
      config: data.config || {},
      results: data.results || {},
      status: data.status || 'completed',
      created_at: createdAt
    };

    memoryDb.benchmark_runs.set(id, record);

    await dbQuery(
      `INSERT INTO benchmark_runs (id, target_id, config, results, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [id, record.target_id, JSON.stringify(record.config), JSON.stringify(record.results), record.status, createdAt]
    );

    return record;
  },

  async getBenchmarkRunById(id) {
    const pgRes = await dbQuery('SELECT * FROM benchmark_runs WHERE id = $1', [id]);
    if (pgRes && pgRes.rows[0]) {
      const row = pgRes.rows[0];
      return {
        ...row,
        config: typeof row.config === 'string' ? JSON.parse(row.config) : row.config,
        results: typeof row.results === 'string' ? JSON.parse(row.results) : row.results
      };
    }
    return memoryDb.benchmark_runs.get(id) || null;
  },

  async getLatestBenchmarkRun() {
    const pgRes = await dbQuery('SELECT * FROM benchmark_runs ORDER BY created_at DESC LIMIT 1');
    if (pgRes && pgRes.rows[0]) {
      const row = pgRes.rows[0];
      return {
        ...row,
        config: typeof row.config === 'string' ? JSON.parse(row.config) : row.config,
        results: typeof row.results === 'string' ? JSON.parse(row.results) : row.results
      };
    }
    const all = Array.from(memoryDb.benchmark_runs.values());
    return all[all.length - 1] || null;
  }
};
