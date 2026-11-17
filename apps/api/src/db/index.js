import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const databaseUrl = process.env.DATABASE_URL || 'postgres://patchproof:patchproof@localhost:5432/patchproof';

let pool = null;
let isPgConnected = false;
let pgModule = null;

// Dynamically load pg if available
async function loadPg() {
  if (!pgModule) {
    try {
      pgModule = await import('pg');
    } catch {
      pgModule = null;
    }
  }
  return pgModule?.default || pgModule;
}

// In-memory fallback repository for graceful degradation and offline lab environments
class MemoryDatabase {
  constructor() {
    this.targets = new Map();
    this.findings = new Map();
    this.triage_results = new Map();
    this.patches = new Map();
    this.verifications = new Map();
    this.verification_cases = new Map();
    this.traffic_corpus = new Map();
    this.proxy_events = [];
    this.hardening_runs = new Map();
    this.proof_reports = new Map();
    this.benchmark_runs = new Map();
  }

  reset() {
    this.targets.clear();
    this.findings.clear();
    this.triage_results.clear();
    this.patches.clear();
    this.verifications.clear();
    this.verification_cases.clear();
    this.traffic_corpus.clear();
    this.proxy_events = [];
    this.hardening_runs.clear();
    this.proof_reports.clear();
    this.benchmark_runs.clear();
  }
}

export const memoryDb = new MemoryDatabase();

export async function getPool() {
  if (!pool) {
    const pg = await loadPg();
    if (!pg) return null;

    try {
      pool = new pg.Pool({
        connectionString: databaseUrl,
        connectionTimeoutMillis: 2500,
        idleTimeoutMillis: 10000
      });

      pool.on('error', (err) => {
        console.warn('[DB] PostgreSQL pool background error:', err.message);
        isPgConnected = false;
      });
    } catch {
      pool = null;
    }
  }
  return pool;
}

export async function checkDbHealth() {
  try {
    const p = await getPool();
    if (p) {
      const res = await p.query('SELECT 1 as ping');
      if (res.rows[0]?.ping === 1) {
        isPgConnected = true;
        return { connected: true, driver: 'postgresql' };
      }
    }
  } catch (err) {
    isPgConnected = false;
    return { connected: false, driver: 'in_memory_fallback', error: err.message };
  }
  return { connected: false, driver: 'in_memory_fallback' };
}

export async function runMigrations() {
  try {
    const p = await getPool();
    if (p) {
      const sqlPath = path.resolve(__dirname, '001_core.sql');
      if (fs.existsSync(sqlPath)) {
        const sql = fs.readFileSync(sqlPath, 'utf-8');
        await p.query(sql);
        isPgConnected = true;
        console.log('[DB] PostgreSQL schema migrations applied successfully.');
        return { success: true, driver: 'postgresql' };
      }
    }
  } catch (err) {
    console.warn(`[DB] PostgreSQL migration note (${err.message}). Using unified data layer.`);
    isPgConnected = false;
    return { success: false, driver: 'in_memory_fallback', error: err.message };
  }
  return { success: true, driver: 'in_memory_fallback' };
}

export async function dbQuery(text, params = []) {
  if (isPgConnected) {
    try {
      const p = await getPool();
      if (p) {
        return await p.query(text, params);
      }
    } catch (err) {
      console.warn(`[DB] Query failed on PostgreSQL, checking connection: ${err.message}`);
      isPgConnected = false;
    }
  }
  return null;
}
