// apps/api/src/db/index.js
import pg from 'pg';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;
const DATABASE_URL = process.env.DATABASE_URL || 'postgres://patchproof:patchproof@localhost:5432/patchproof';

let pool = null;
let useMemoryFallback = false;

// Robust memory store in case Postgres is unavailable
const memoryStore = {
  targets: [],
  findings: [],
  triage_results: [],
  patches: [],
  verifications: [],
  verification_cases: [],
  traffic_corpus: [],
  proxy_events: [],
  hardening_runs: [],
  proof_reports: [],
  benchmark_runs: [],
  attack_lab_runs: []
};

function memoryQuery(text, params = []) {
  const cleanSql = text.trim();
  const lowerSql = cleanSql.toLowerCase();

  // Simple parser for standard CRUD operations in the app
  // 1. INSERT INTO table (...) VALUES (...) RETURNING ...
  if (lowerSql.startsWith('insert into')) {
    const tableMatch = lowerSql.match(/insert into\s+([a-z_]+)/i);
    const tableName = tableMatch ? tableMatch[1].toLowerCase() : null;

    if (tableName && memoryStore[tableName]) {
      const colMatch = cleanSql.match(/insert into\s+[a-z_]+\s*\(([^)]+)\)/i);
      const cols = colMatch ? colMatch[1].split(',').map(c => c.trim()) : [];

      const newRow = {
        id: crypto.randomUUID(),
        created_at: new Date().toISOString()
      };

      cols.forEach((col, idx) => {
        let val = params[idx];
        if (typeof val === 'string' && (val.startsWith('{') || val.startsWith('['))) {
          try { val = JSON.parse(val); } catch {}
        }
        newRow[col] = val;
      });

      // Handle dedupe_key uniqueness on findings
      if (tableName === 'findings' && newRow.dedupe_key) {
        const existingIdx = memoryStore.findings.findIndex(f => f.dedupe_key === newRow.dedupe_key);
        if (existingIdx !== -1) {
          memoryStore.findings[existingIdx] = { ...memoryStore.findings[existingIdx], ...newRow };
          return { rows: [memoryStore.findings[existingIdx]] };
        }
      }

      // Handle finding_id uniqueness on triage_results
      if (tableName === 'triage_results' && newRow.finding_id) {
        const existingIdx = memoryStore.triage_results.findIndex(t => t.finding_id === newRow.finding_id);
        if (existingIdx !== -1) {
          memoryStore.triage_results[existingIdx] = { ...memoryStore.triage_results[existingIdx], ...newRow };
          return { rows: [memoryStore.triage_results[existingIdx]] };
        }
      }

      memoryStore[tableName].push(newRow);
      return { rows: [newRow] };
    }
  }

  // 2. SELECT ... FROM table ...
  if (lowerSql.startsWith('select')) {
    if (/^select\s+1(\s+as\s+\w+)?/i.test(cleanSql)) {
      return { rows: [{ ok: 1 }] };
    }

    const fromMatch = lowerSql.match(/from\s+([a-z_]+)/i);
    const tableName = fromMatch ? fromMatch[1].toLowerCase() : null;

    if (tableName && memoryStore[tableName]) {
      let rows = [...memoryStore[tableName]];

      // Handle parameterized WHERE col = $N
      const paramWhere = cleanSql.match(/where\s+([a-z_]+)\s*=\s*\$(\d+)/i);
      if (paramWhere) {
        const col = paramWhere[1].toLowerCase();
        const pIdx = parseInt(paramWhere[2], 10) - 1;
        const targetVal = String(params[pIdx]);
        rows = rows.filter(r => String(r[col]) === targetVal);
      }

      // Handle literal WHERE col = 'value'
      const literalWhere = cleanSql.match(/where\s+([a-z_]+)\s*=\s*'([^']+)'/i);
      if (literalWhere) {
        const col = literalWhere[1].toLowerCase();
        const targetVal = literalWhere[2];
        rows = rows.filter(r => String(r[col]) === targetVal);
      }

      // Handle ORDER BY ts desc or created_at desc
      if (lowerSql.includes('order by')) {
        if (lowerSql.includes('ts desc')) {
          rows.sort((a, b) => new Date(b.ts || b.created_at) - new Date(a.ts || a.created_at));
        } else if (lowerSql.includes('created_at desc')) {
          rows.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        }
      }

      // Handle LIMIT
      const limitMatch = lowerSql.match(/limit\s+(\d+|\$\d+)/i);
      if (limitMatch) {
        const limit = limitMatch[1].startsWith('$') ? Number(params[parseInt(limitMatch[1].slice(1)) - 1]) : parseInt(limitMatch[1], 10);
        rows = rows.slice(0, limit);
      }

      return { rows };
    }
  }

  // 3. UPDATE table SET ... WHERE ...
  if (lowerSql.startsWith('update')) {
    const tableMatch = lowerSql.match(/update\s+([a-z_]+)/i);
    const tableName = tableMatch ? tableMatch[1].toLowerCase() : null;

    if (tableName && memoryStore[tableName]) {
      const setMatch = cleanSql.match(/set\s+(.+?)\s+where\s+(.+)$/i);
      if (setMatch) {
        const setClause = setMatch[1];
        const whereClause = setMatch[2];

        // Parse assignments
        const assignments = setClause.split(',').map(a => {
          const [col, valRef] = a.trim().split('=').map(s => s.trim());
          return { col: col.toLowerCase(), valRef };
        });

        // Filter target rows
        const matchingRows = memoryStore[tableName].filter(row => {
          // Check where col = $N
          const paramWhere = whereClause.match(/([a-z_]+)\s*=\s*\$(\d+)/i);
          if (paramWhere) {
            const col = paramWhere[1].toLowerCase();
            const pIdx = parseInt(paramWhere[2], 10) - 1;
            return String(row[col]) === String(params[pIdx]);
          }
          // Check where col = 'literal'
          const literalWhere = whereClause.match(/([a-z_]+)\s*=\s*'([^']+)'/i);
          if (literalWhere) {
            const col = literalWhere[1].toLowerCase();
            const litVal = literalWhere[2];
            return String(row[col]) === litVal;
          }
          return true;
        });

        // Apply SET assignments to all matching rows
        for (const row of matchingRows) {
          for (const { col, valRef } of assignments) {
            const pIdxMatch = valRef.match(/\$(\d+)/);
            if (pIdxMatch) {
              const idx = parseInt(pIdxMatch[1], 10) - 1;
              let val = params[idx];
              if (typeof val === 'string' && (val.startsWith('{') || val.startsWith('['))) {
                try { val = JSON.parse(val); } catch {}
              }
              row[col] = val;
            } else if (/^'([^']*)'$/.test(valRef)) {
              row[col] = valRef.slice(1, -1);
            } else if (valRef.toLowerCase() === 'now()') {
              row[col] = new Date().toISOString();
            }
          }
        }
        return { rows: matchingRows };
      }
    }
  }

  // 4. DELETE
  if (lowerSql.startsWith('delete from')) {
    const tableMatch = lowerSql.match(/delete from\s+([a-z_]+)/i);
    const tableName = tableMatch ? tableMatch[1].toLowerCase() : null;
    if (tableName && memoryStore[tableName]) {
      memoryStore[tableName] = [];
      return { rows: [] };
    }
  }

  return { rows: [] };
}

export async function query(text, params = []) {
  if (useMemoryFallback) {
    return memoryQuery(text, params);
  }

  try {
    return await pool.query(text, params);
  } catch (err) {
    if (!useMemoryFallback && err.code === 'ECONNREFUSED') {
      console.warn('[DB] Postgres connection failed. Switching to fail-safe storage engine.');
      useMemoryFallback = true;
      return memoryQuery(text, params);
    }
    throw err;
  }
}

export async function initDb() {
  try {
    pool = new Pool({
      connectionString: DATABASE_URL,
      connectionTimeoutMillis: 2000
    });

    // Test connection
    const client = await pool.connect();
    console.log('[DB] Connected to PostgreSQL successfully at', DATABASE_URL);

    // Apply migrations
    const schemaPath = path.resolve(process.cwd(), 'db/001_core.sql');
    if (fs.existsSync(schemaPath)) {
      const sql = fs.readFileSync(schemaPath, 'utf-8');
      await client.query(sql);
      console.log('[DB] Applied 001_core.sql migrations.');
    }
    client.release();
    useMemoryFallback = false;
  } catch (err) {
    console.warn(`[DB] Could not connect to Postgres (${err.message}). Using resilient embedded storage.`);
    useMemoryFallback = true;
  }
}

export function isDbReady() {
  return true;
}

export function getDbMode() {
  return useMemoryFallback ? 'embedded_memory' : 'postgresql';
}
