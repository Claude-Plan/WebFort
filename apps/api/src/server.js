import http from 'node:http';
import { URL } from 'node:url';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { Repository } from './db/repository.js';
import { checkDbHealth } from './db/index.js';
import { checkOllamaHealth, explainFinding } from './llm/ollama-client.js';
import { executeRecipe, RECIPES, computeDedupeKey } from './recipes/index.js';
import { parseZapReport } from './findings/zap-importer.js';
import { calculateTriageScore } from './triage/index.js';
import { generatePatch } from './patches/generator.js';
import { runVerification } from './patches/verifier.js';
import { runMutationGauntlet } from './gauntlet/runner.js';
import { runAutoTighten } from './harden/engine.js';
import { createProofReport } from './proof/report-generator.js';
import { verifyReportSignature, getDemoKeyPair } from './proof/signer.js';
import { runBenchmark } from './benchmark/runner.js';

function sendJson(res, statusCode, data) {
  const jsonStr = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Internal-Token, X-Shield-Verify-Patch, X-Shield-Verify-Token, If-None-Match',
    'Content-Length': Buffer.byteLength(jsonStr)
  });
  res.end(jsonStr);
}

// Active SSE client connections
const sseClients = new Set();

export function emitSse(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(msg);
    } catch {
      sseClients.delete(client);
    }
  }
}

export function createApiServer() {
  const server = http.createServer(async (req, res) => {
    // 1. CORS Preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Internal-Token, X-Shield-Verify-Patch, X-Shield-Verify-Token, If-None-Match'
      });
      res.end();
      return;
    }

    const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = reqUrl.pathname;
    const method = req.method.toUpperCase();

    // 2. SSE Stream Endpoint (§6 & §9.1)
    if ((pathname === '/stream' || pathname === '/api/v1/stream') && method === 'GET') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*'
      });
      res.write(': stream connected\n\n');
      sseClients.add(res);

      req.on('close', () => {
        sseClients.delete(res);
      });
      return;
    }

    // 3. Buffer request body
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));

    req.on('end', async () => {
      let body = {};
      const rawBody = Buffer.concat(chunks).toString('utf-8');
      if (rawBody && (req.headers['content-type'] || '').includes('application/json')) {
        try {
          body = JSON.parse(rawBody);
        } catch {
          // malformed JSON handled per route
        }
      }

      try {
        // --- ROUTE: GET / -> Serve Security Console HTML ---
        if ((pathname === '/' || pathname === '/index.html') && method === 'GET') {
          const staticHtmlPath = new URL('./static/index.html', import.meta.url);
          if (fs.existsSync(staticHtmlPath)) {
            const html = fs.readFileSync(staticHtmlPath, 'utf-8');
            res.writeHead(200, {
              'Content-Type': 'text/html; charset=utf-8',
              'Access-Control-Allow-Origin': '*'
            });
            res.end(html);
          } else {
            sendJson(res, 200, { message: 'PatchProof API Server Running' });
          }
          return;
        }

        // --- ROUTE: GET /health or /api/v1/health ---
        if ((pathname === '/health' || pathname === '/api/v1/health') && method === 'GET') {
          const dbHealth = await checkDbHealth();
          const ollamaHealth = await checkOllamaHealth();

          let targetReachable = false;
          try {
            const targetUrl = process.env.TARGET_URL || 'http://localhost:3001';
            const tRes = await fetch(targetUrl, { method: 'HEAD', signal: AbortSignal.timeout(1500) });
            targetReachable = tRes.ok || tRes.status < 500;
          } catch {
            targetReachable = false;
          }

          let proxyReachable = false;
          try {
            const proxyUrl = process.env.PROXY_URL || 'http://localhost:8080';
            const pRes = await fetch(proxyUrl, { method: 'HEAD', signal: AbortSignal.timeout(1500) });
            proxyReachable = pRes.ok || pRes.status < 500;
          } catch {
            proxyReachable = false;
          }

          const allUp = dbHealth.connected && targetReachable && proxyReachable;
          return sendJson(res, 200, {
            status: allUp ? 'ok' : 'degraded',
            services: {
              db: dbHealth,
              ollama: ollamaHealth,
              proxy: { connected: proxyReachable, url: process.env.PROXY_URL || 'http://localhost:8080' },
              target: { connected: targetReachable, url: process.env.TARGET_URL || 'http://localhost:3001' }
            }
          });
        }

        // --- ROUTE: /api/v1/targets ---
        if (pathname === '/api/v1/targets' || pathname === '/targets') {
          if (method === 'GET') {
            const targets = await Repository.listTargets();
            if (targets.length === 0) {
              const def = await Repository.getOrCreateDefaultTarget();
              return sendJson(res, 200, { data: [def] });
            }
            return sendJson(res, 200, { data: targets });
          }

          if (method === 'POST') {
            const { name, base_url, proxy_url, mode } = body;
            if (!name || !base_url) {
              return sendJson(res, 400, { error: { code: 'VALIDATION_ERROR', message: 'Name and base_url are required' } });
            }
            const target = await Repository.createTarget({
              name,
              base_url,
              proxy_url: proxy_url || 'http://localhost:8080',
              mode: mode || 'protect'
            });
            return sendJson(res, 201, { data: target });
          }
        }

        // --- ROUTE: POST /api/v1/scans/import ---
        if ((pathname === '/api/v1/scans/import' || pathname === '/scans/import') && method === 'POST') {
          const target = await Repository.getOrCreateDefaultTarget();
          const parsedFindings = parseZapReport(body, target.id);
          const savedFindings = [];
          for (const f of parsedFindings) {
            const saved = await Repository.upsertFinding(f);
            savedFindings.push(saved);
          }
          return sendJson(res, 201, { data: savedFindings, meta: { count: savedFindings.length } });
        }

        // --- ROUTE: POST /api/v1/recipes/run ---
        if ((pathname === '/api/v1/recipes/run' || pathname === '/recipes/run') && method === 'POST') {
          const { recipe_id = 'R1', target_id } = body;
          const recipe = RECIPES[recipe_id];
          if (!recipe) {
            return sendJson(res, 400, { error: { code: 'INVALID_RECIPE', message: `Unknown recipe ${recipe_id}. Choose R1 or R2.` } });
          }

          const target = target_id ? await Repository.getTargetById(target_id) : await Repository.getOrCreateDefaultTarget();
          const execResult = await executeRecipe(recipe_id, target.base_url);
          const dedupeKey = computeDedupeKey(recipe.method, recipe.path, recipe.param);

          const finding = await Repository.upsertFinding({
            target_id: target.id,
            title: recipe.title,
            category: recipe.category,
            scanner_risk: recipe.severity,
            method: recipe.method,
            url: recipe.path,
            route_template: recipe.path,
            param: recipe.param,
            param_location: recipe.param_location,
            evidence: execResult.evidence,
            exploit_request: execResult.exploit_request,
            exploit_oracle: execResult.exploit_oracle,
            exploit_confirmed: execResult.confirmed,
            status: 'open',
            dedupe_key: dedupeKey,
            provenance: 'real_capture'
          });

          return sendJson(res, 201, {
            data: {
              finding,
              recipe_run: execResult
            }
          });
        }

        // --- ROUTE: /api/v1/findings ---
        if (pathname === '/api/v1/findings' || pathname === '/findings') {
          if (method === 'GET') {
            const targetId = reqUrl.searchParams.get('target_id');
            const findings = await Repository.listFindings(targetId);
            const enriched = await Promise.all(findings.map(async (f) => {
              const triage = await Repository.getTriageByFindingId(f.id);
              const patches = await Repository.listPatchesByFinding(f.id);
              return {
                ...f,
                triage: triage || null,
                patches: patches || []
              };
            }));

            enriched.sort((a, b) => {
              const scoreA = a.triage ? a.triage.priority_score : -1;
              const scoreB = b.triage ? b.triage.priority_score : -1;
              return scoreB - scoreA;
            });

            return sendJson(res, 200, { data: enriched });
          }
        }

        // --- ROUTE: GET /api/v1/findings/:id ---
        const findingMatch = pathname.match(/^\/(?:api\/v1\/)?findings\/([0-9a-fA-F-]+)$/);
        if (findingMatch && method === 'GET') {
          const findingId = findingMatch[1];
          const finding = await Repository.getFindingById(findingId);
          if (!finding) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Finding not found' } });
          }
          const triage = await Repository.getTriageByFindingId(finding.id);
          const patches = await Repository.listPatchesByFinding(finding.id);
          return sendJson(res, 200, { data: { ...finding, triage, patches } });
        }

        // --- ROUTE: POST /api/v1/triage/run ---
        if ((pathname === '/api/v1/triage/run' || pathname === '/triage/run') && method === 'POST') {
          const { finding_ids } = body;
          let targetFindings = [];

          if (Array.isArray(finding_ids) && finding_ids.length > 0) {
            for (const fid of finding_ids) {
              const f = await Repository.getFindingById(fid);
              if (f) targetFindings.push(f);
            }
          } else {
            targetFindings = await Repository.listFindings();
          }

          const triageResults = [];
          for (const finding of targetFindings) {
            const calc = calculateTriageScore(finding);
            const explanation = await explainFinding(finding, calc);

            const triageRecord = await Repository.upsertTriageResult({
              finding_id: finding.id,
              priority_score: calc.score,
              priority_band: calc.band,
              signals: calc.signals,
              llm_explanation: explanation,
              llm_status: explanation.status
            });

            await Repository.upsertFinding({ ...finding, status: 'triaged' });
            triageResults.push(triageRecord);
          }

          return sendJson(res, 200, { data: triageResults });
        }

        // --- ROUTE: GET /api/v1/findings/:id/triage ---
        const triageMatch = pathname.match(/^\/(?:api\/v1\/)?findings\/([0-9a-fA-F-]+)\/triage$/);
        if (triageMatch && method === 'GET') {
          const findingId = triageMatch[1];
          const triage = await Repository.getTriageByFindingId(findingId);
          if (!triage) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Triage not found' } });
          }
          return sendJson(res, 200, { data: triage });
        }

        // --- ROUTE: POST /api/v1/findings/:id/patches ---
        const createPatchMatch = pathname.match(/^\/(?:api\/v1\/)?findings\/([0-9a-fA-F-]+)\/patches$/);
        if (createPatchMatch && method === 'POST') {
          const findingId = createPatchMatch[1];
          const finding = await Repository.getFindingById(findingId);
          if (!finding) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Finding not found' } });
          }

          const strategy = body.strategy || 'auto';
          const existing = await Repository.listPatchesByFinding(finding.id);
          const nextVersion = existing.length + 1;

          const patchGen = await generatePatch(finding, strategy);
          const patch = await Repository.createPatch({
            finding_id: finding.id,
            version: nextVersion,
            parent_patch_id: existing[0]?.id || null,
            source: patchGen.source,
            rule: patchGen.rule,
            mode: 'shadow',
            status: 'draft',
            rationale: patchGen.rationale
          });

          return sendJson(res, 201, { data: patch });
        }

        // --- ROUTE: GET /api/v1/patches ---
        if ((pathname === '/api/v1/patches' || pathname === '/patches') && method === 'GET') {
          const findingId = reqUrl.searchParams.get('finding_id');
          let patches = [];
          if (findingId) {
            patches = await Repository.listPatchesByFinding(findingId);
          } else {
            const findings = await Repository.listFindings();
            for (const f of findings) {
              const list = await Repository.listPatchesByFinding(f.id);
              patches.push(...list);
            }
          }

          const enriched = await Promise.all(patches.map(async p => {
            const ver = await Repository.getLatestVerificationForPatch(p.id);
            return { ...p, latest_verification: ver || null };
          }));

          return sendJson(res, 200, { data: enriched });
        }

        // --- ROUTE: GET /api/v1/patches/:id ---
        const patchDetailMatch = pathname.match(/^\/(?:api\/v1\/)?patches\/([0-9a-fA-F-]+)$/);
        if (patchDetailMatch && method === 'GET') {
          const patchId = patchDetailMatch[1];
          const patch = await Repository.getPatchById(patchId);
          if (!patch) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Patch not found' } });
          }
          const verification = await Repository.getLatestVerificationForPatch(patch.id);
          return sendJson(res, 200, { data: { ...patch, latest_verification: verification } });
        }

        // --- ROUTE: POST /api/v1/patches/:id/verify ---
        const verifyMatch = pathname.match(/^\/(?:api\/v1\/)?patches\/([0-9a-fA-F-]+)\/verify$/);
        if (verifyMatch && method === 'POST') {
          const patchId = verifyMatch[1];
          const patch = await Repository.getPatchById(patchId);
          if (!patch) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Patch not found' } });
          }
          const finding = await Repository.getFindingById(patch.finding_id);
          if (!finding) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Finding not found' } });
          }

          const verRecord = await Repository.createVerification({
            patch_id: patch.id,
            status: 'running',
            summary: {}
          });

          const runResult = await runVerification(patch, finding, body);

          await Repository.updateVerification(verRecord.id, {
            status: runResult.status,
            summary: runResult.summary
          });

          const updatedPatch = await Repository.updatePatch(patch.id, {
            status: runResult.status === 'passed' ? 'verified' : 'failed'
          });

          return sendJson(res, 200, {
            data: {
              verification: {
                id: verRecord.id,
                patch_id: patch.id,
                status: runResult.status,
                summary: runResult.summary
              },
              patch: updatedPatch
            }
          });
        }

        // --- ROUTE: POST /api/v1/patches/:id/deploy ---
        const deployMatch = pathname.match(/^\/(?:api\/v1\/)?patches\/([0-9a-fA-F-]+)\/deploy$/);
        if (deployMatch && method === 'POST') {
          const patchId = deployMatch[1];
          const patch = await Repository.getPatchById(patchId);
          if (!patch) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Patch not found' } });
          }

          const mode = body.mode || 'enforce';
          const deployedPatch = await Repository.updatePatch(patch.id, {
            mode,
            status: 'deployed',
            deployed_at: new Date().toISOString()
          });

          return sendJson(res, 200, { data: deployedPatch });
        }

        // --- ROUTE: POST /api/v1/patches/:id/rollback ---
        const rollbackMatch = pathname.match(/^\/(?:api\/v1\/)?patches\/([0-9a-fA-F-]+)\/rollback$/);
        if (rollbackMatch && method === 'POST') {
          const patchId = rollbackMatch[1];
          const patch = await Repository.getPatchById(patchId);
          if (!patch) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Patch not found' } });
          }

          const rolledBack = await Repository.updatePatch(patch.id, { status: 'rolled_back' });
          return sendJson(res, 200, { data: rolledBack });
        }

        // --- ROUTE: GET /api/v1/events ---
        if ((pathname === '/api/v1/events' || pathname === '/events') && method === 'GET') {
          const limit = Math.min(Number(reqUrl.searchParams.get('limit')) || 100, 500);
          const events = await Repository.getRecentProxyEvents(limit);
          return sendJson(res, 200, { data: events });
        }

        // ==================== P3 ROUTES ====================

        // --- ROUTE: POST /api/v1/patches/:id/gauntlet (§9.1) ---
        const gauntletMatch = pathname.match(/^\/(?:api\/v1\/)?patches\/([0-9a-fA-F-]+)\/gauntlet$/);
        if (gauntletMatch && method === 'POST') {
          const patchId = gauntletMatch[1];
          const patch = await Repository.getPatchById(patchId);
          if (!patch) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Patch not found' } });
          }
          const finding = await Repository.getFindingById(patch.finding_id);
          if (!finding) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Finding not found' } });
          }

          const result = await runMutationGauntlet(patch, finding, {
            budget: body.mutation_budget || 60,
            seed: body.seed !== undefined ? body.seed : 12345,
            sseEmitter: emitSse
          });

          return sendJson(res, 200, { data: result });
        }

        // --- ROUTE: POST /api/v1/patches/:id/harden (§9.2) ---
        const hardenMatch = pathname.match(/^\/(?:api\/v1\/)?patches\/([0-9a-fA-F-]+)\/harden$/);
        if (hardenMatch && method === 'POST') {
          const patchId = hardenMatch[1];
          const patch = await Repository.getPatchById(patchId);
          if (!patch) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Patch not found' } });
          }
          const finding = await Repository.getFindingById(patch.finding_id);
          if (!finding) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Finding not found' } });
          }

          const run = await runAutoTighten(patch, finding, {
            maxIterations: body.max_iterations || 5,
            mutationBudget: body.mutation_budget || 60,
            seed: body.seed !== undefined ? body.seed : 42,
            start: body.start || 'current',
            sseEmitter: emitSse
          });

          const savedRun = await Repository.createHardeningRun(run);
          return sendJson(res, 200, { data: savedRun });
        }

        // --- ROUTE: GET /api/v1/hardening-runs/:id (§6) ---
        const getHardenMatch = pathname.match(/^\/(?:api\/v1\/)?hardening-runs\/([0-9a-fA-F-]+)$/);
        if (getHardenMatch && method === 'GET') {
          const runId = getHardenMatch[1];
          const run = await Repository.getHardeningRunById(runId);
          if (!run) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Hardening run not found' } });
          }
          return sendJson(res, 200, { data: run });
        }

        // --- ROUTE: POST /api/v1/patches/:id/proof (§9.3) ---
        const proofCreateMatch = pathname.match(/^\/(?:api\/v1\/)?patches\/([0-9a-fA-F-]+)\/proof$/);
        if (proofCreateMatch && method === 'POST') {
          const patchId = proofCreateMatch[1];
          const patch = await Repository.getPatchById(patchId);
          if (!patch) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Patch not found' } });
          }
          const finding = await Repository.getFindingById(patch.finding_id);
          if (!finding) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Finding not found' } });
          }

          const verification = await Repository.getLatestVerificationForPatch(patch.id);
          const proof = createProofReport(patch, finding, verification);
          const record = await Repository.createProofReportRecord(proof);

          return sendJson(res, 201, { data: record });
        }

        // --- ROUTE: GET /api/v1/patches/:id/proof (§9.3) ---
        const proofGetMatch = pathname.match(/^\/(?:api\/v1\/)?patches\/([0-9a-fA-F-]+)\/proof$/);
        if (proofGetMatch && method === 'GET') {
          const patchId = proofGetMatch[1];
          const record = await Repository.getProofReportByPatchId(patchId);
          if (!record) {
            // Auto-generate if not yet persisted
            const patch = await Repository.getPatchById(patchId);
            if (!patch) return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Patch not found' } });
            const finding = await Repository.getFindingById(patch.finding_id);
            const verification = await Repository.getLatestVerificationForPatch(patch.id);
            const proof = createProofReport(patch, finding, verification);
            const saved = await Repository.createProofReportRecord(proof);
            return sendJson(res, 200, { data: saved });
          }
          return sendJson(res, 200, { data: record });
        }

        // --- ROUTE: POST /api/v1/proof/verify (§9.3) ---
        if ((pathname === '/api/v1/proof/verify' || pathname === '/proof/verify') && method === 'POST') {
          const { report, signature, public_key } = body;
          if (!report || !signature || !public_key) {
            return sendJson(res, 400, { error: { code: 'VALIDATION_ERROR', message: 'report, signature and public_key are required' } });
          }
          const verification = verifyReportSignature(report, signature, public_key);
          return sendJson(res, 200, { data: verification });
        }

        // --- ROUTE: POST /api/v1/benchmarks/run (§9.4) ---
        if ((pathname === '/api/v1/benchmarks/run' || pathname === '/benchmarks/run') && method === 'POST') {
          const findingId = body.finding_id;
          let finding = null;
          if (findingId) {
            finding = await Repository.getFindingById(findingId);
          } else {
            const allFindings = await Repository.listFindings();
            finding = allFindings[0];
          }

          if (!finding) {
            return sendJson(res, 400, { error: { code: 'NO_FINDINGS', message: 'Cannot run benchmark without findings' } });
          }

          const bmResult = await runBenchmark(finding, body);
          const record = await Repository.createBenchmarkRunRecord({
            target_id: finding.target_id,
            config: body,
            results: bmResult
          });

          return sendJson(res, 201, { data: record });
        }

        // --- ROUTE: GET /api/v1/benchmarks/:id (§9.4) ---
        const bmMatch = pathname.match(/^\/(?:api\/v1\/)?benchmarks\/([0-9a-fA-F-]+|latest)$/);
        if (bmMatch && method === 'GET') {
          const id = bmMatch[1];
          const record = id === 'latest' ? await Repository.getLatestBenchmarkRun() : await Repository.getBenchmarkRunById(id);
          if (!record) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Benchmark not found' } });
          }
          return sendJson(res, 200, { data: record });
        }

        // --- INTERNAL ROUTE: GET /internal/v1/rules/active ---
        if (pathname === '/internal/v1/rules/active' && method === 'GET') {
          const internalToken = req.headers['x-internal-token'];
          const expected = process.env.INTERNAL_TOKEN || 'patchproof_secret_internal_token_2026';
          if (!internalToken || internalToken !== expected) {
            return sendJson(res, 401, { error: { code: 'UNAUTHORIZED', message: 'Invalid internal token' } });
          }

          const targetId = reqUrl.searchParams.get('target_id');
          const deployedPatches = await Repository.listActiveDeployedRules(targetId);
          const rules = deployedPatches.map(p => ({
            ...p.rule,
            id: p.id,
            mode: p.mode
          }));

          const jsonStr = JSON.stringify(rules);
          const etag = `"${createHash('md5').update(jsonStr).digest('hex')}"`;

          if (req.headers['if-none-match'] === etag) {
            res.writeHead(304, { 'Access-Control-Allow-Origin': '*' });
            res.end();
            return;
          }

          res.writeHead(200, {
            'Content-Type': 'application/json',
            'ETag': etag,
            'Access-Control-Allow-Origin': '*'
          });
          res.end(JSON.stringify({ etag, rules }));
          return;
        }

        // --- INTERNAL ROUTE: GET /internal/v1/rules/candidate/:patch_id ---
        const candidateMatch = pathname.match(/^\/internal\/v1\/rules\/candidate\/([0-9a-fA-F-]+)$/);
        if (candidateMatch && method === 'GET') {
          const patchId = candidateMatch[1];
          const patch = await Repository.getPatchById(patchId);
          if (!patch || !patch.rule) {
            return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Candidate rule not found' } });
          }
          return sendJson(res, 200, { rule: { ...patch.rule, id: patch.id, mode: patch.mode } });
        }

        // --- INTERNAL ROUTE: POST /internal/v1/events ---
        if (pathname === '/internal/v1/events' && method === 'POST') {
          const internalToken = req.headers['x-internal-token'];
          const expected = process.env.INTERNAL_TOKEN || 'patchproof_secret_internal_token_2026';
          if (!internalToken || internalToken !== expected) {
            return sendJson(res, 401, { error: { code: 'UNAUTHORIZED', message: 'Invalid internal token' } });
          }

          const events = body.events || (Array.isArray(body) ? body : [body]);
          await Repository.insertProxyEvents(events);
          return sendJson(res, 202, { received: events.length });
        }

        // Fallthrough 404
        return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: `Route ${method} ${pathname} not found` } });
      } catch (err) {
        console.error('[API Server Error]', err);
        return sendJson(res, 500, { error: { code: 'INTERNAL_SERVER_ERROR', message: err.message } });
      }
    });
  });

  return {
    server,
    listen: (port, cb) => server.listen(port, cb),
    close: (cb) => server.close(cb)
  };
}
