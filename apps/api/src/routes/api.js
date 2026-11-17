import express from 'express';
import { createHash } from 'node:crypto';
import { Repository } from '../db/repository.js';
import { checkDbHealth } from '../db/index.js';
import { checkOllamaHealth, explainFinding } from '../llm/ollama-client.js';
import { executeRecipe, RECIPES, computeDedupeKey } from '../recipes/index.js';
import { parseZapReport } from '../findings/zap-importer.js';
import { calculateTriageScore } from '../triage/index.js';
import { generatePatch } from '../patches/generator.js';
import { runVerification } from '../patches/verifier.js';

export const router = express.Router();

// Helper for standard API responses
const success = (res, data, meta = {}, status = 200) => {
  return res.status(status).json({ data, meta });
};

const error = (res, code, message, status = 400) => {
  return res.status(status).json({ error: { code, message } });
};

// 1. GET /health
router.get('/health', async (req, res) => {
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
  const status = allUp ? 'ok' : 'degraded';

  return res.json({
    status,
    services: {
      db: dbHealth,
      ollama: ollamaHealth,
      proxy: { connected: proxyReachable, url: process.env.PROXY_URL || 'http://localhost:8080' },
      target: { connected: targetReachable, url: process.env.TARGET_URL || 'http://localhost:3001' }
    }
  });
});

// 2. TARGETS
router.get('/targets', async (req, res) => {
  const targets = await Repository.listTargets();
  if (targets.length === 0) {
    const def = await Repository.getOrCreateDefaultTarget();
    return success(res, [def]);
  }
  return success(res, targets);
});

router.post('/targets', async (req, res) => {
  const { name, base_url, proxy_url, mode } = req.body;
  if (!name || !base_url) {
    return error(res, 'VALIDATION_ERROR', 'Name and base_url are required.');
  }
  const target = await Repository.createTarget({
    name,
    base_url,
    proxy_url: proxy_url || 'http://localhost:8080',
    mode: mode || 'protect'
  });
  return success(res, target, {}, 201);
});

// 3. SCAN IMPORT (OWASP ZAP JSON)
router.post('/scans/import', async (req, res) => {
  const target = await Repository.getOrCreateDefaultTarget();
  const rawData = req.body;

  const parsedFindings = parseZapReport(rawData, target.id);
  const savedFindings = [];

  for (const f of parsedFindings) {
    const saved = await Repository.upsertFinding(f);
    savedFindings.push(saved);
  }

  return success(res, savedFindings, { count: savedFindings.length }, 201);
});

// 4. RECIPES RUN (R1 / R2)
router.post('/recipes/run', async (req, res) => {
  const { recipe_id = 'R1', target_id } = req.body;
  const recipe = RECIPES[recipe_id];
  if (!recipe) {
    return error(res, 'INVALID_RECIPE', `Unknown recipe ID: ${recipe_id}. Choose R1 or R2.`);
  }

  const target = target_id ? await Repository.getTargetById(target_id) : await Repository.getOrCreateDefaultTarget();
  const execResult = await executeRecipe(recipe_id, target.base_url);

  const dedupeKey = computeDedupeKey(recipe.method, recipe.path, recipe.param);

  const findingData = {
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
  };

  const finding = await Repository.upsertFinding(findingData);

  return success(res, {
    finding,
    recipe_run: execResult
  }, {}, 201);
});

// 5. FINDINGS
router.get('/findings', async (req, res) => {
  const { target_id } = req.query;
  const findings = await Repository.listFindings(target_id);

  // Attach triage and patches
  const enriched = await Promise.all(findings.map(async (f) => {
    const triage = await Repository.getTriageByFindingId(f.id);
    const patches = await Repository.listPatchesByFinding(f.id);
    return {
      ...f,
      triage: triage || null,
      patches: patches || []
    };
  }));

  // Sort by priority score if available
  enriched.sort((a, b) => {
    const scoreA = a.triage ? a.triage.priority_score : -1;
    const scoreB = b.triage ? b.triage.priority_score : -1;
    return scoreB - scoreA;
  });

  return success(res, enriched);
});

router.get('/findings/:id', async (req, res) => {
  const finding = await Repository.getFindingById(req.params.id);
  if (!finding) {
    return error(res, 'NOT_FOUND', 'Finding not found', 404);
  }

  const triage = await Repository.getTriageByFindingId(finding.id);
  const patches = await Repository.listPatchesByFinding(finding.id);

  return success(res, {
    ...finding,
    triage,
    patches
  });
});

// 6. TRIAGE RUN
router.post('/triage/run', async (req, res) => {
  const { finding_ids } = req.body;
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
    // Deterministic formula
    const calc = calculateTriageScore(finding);

    // AI explanation with automatic fallback
    const explanation = await explainFinding(finding, calc);

    const triageRecord = await Repository.upsertTriageResult({
      finding_id: finding.id,
      priority_score: calc.score,
      priority_band: calc.band,
      signals: calc.signals,
      llm_explanation: explanation,
      llm_status: explanation.status
    });

    await Repository.upsertFinding({
      ...finding,
      status: 'triaged'
    });

    triageResults.push(triageRecord);
  }

  return success(res, triageResults);
});

router.get('/findings/:id/triage', async (req, res) => {
  const triage = await Repository.getTriageByFindingId(req.params.id);
  if (!triage) {
    return error(res, 'NOT_FOUND', 'Triage not calculated for this finding', 404);
  }
  return success(res, triage);
});

// 7. PATCHES
router.post('/findings/:id/patches', async (req, res) => {
  const finding = await Repository.getFindingById(req.params.id);
  if (!finding) {
    return error(res, 'NOT_FOUND', 'Finding not found', 404);
  }

  const { strategy = 'auto' } = req.body;
  const existingPatches = await Repository.listPatchesByFinding(finding.id);
  const nextVersion = existingPatches.length + 1;

  const patchGen = await generatePatch(finding, strategy);

  const patch = await Repository.createPatch({
    finding_id: finding.id,
    version: nextVersion,
    parent_patch_id: existingPatches[0]?.id || null,
    source: patchGen.source,
    rule: patchGen.rule,
    mode: 'shadow',
    status: 'draft',
    rationale: patchGen.rationale
  });

  return success(res, patch, {}, 201);
});

router.get('/patches', async (req, res) => {
  const { finding_id } = req.query;
  let patches = [];
  if (finding_id) {
    patches = await Repository.listPatchesByFinding(finding_id);
  } else {
    const findings = await Repository.listFindings();
    for (const f of findings) {
      const list = await Repository.listPatchesByFinding(f.id);
      patches.push(...list);
    }
  }

  // Attach latest verification
  const enriched = await Promise.all(patches.map(async p => {
    const ver = await Repository.getLatestVerificationForPatch(p.id);
    return { ...p, latest_verification: ver || null };
  }));

  return success(res, enriched);
});

router.get('/patches/:id', async (req, res) => {
  const patch = await Repository.getPatchById(req.params.id);
  if (!patch) {
    return error(res, 'NOT_FOUND', 'Patch not found', 404);
  }
  const verification = await Repository.getLatestVerificationForPatch(patch.id);
  return success(res, { ...patch, latest_verification: verification });
});

// 8. VERIFY PATCH
router.post('/patches/:id/verify', async (req, res) => {
  const patch = await Repository.getPatchById(req.params.id);
  if (!patch) {
    return error(res, 'NOT_FOUND', 'Patch not found', 404);
  }
  const finding = await Repository.getFindingById(patch.finding_id);
  if (!finding) {
    return error(res, 'NOT_FOUND', 'Associated finding not found', 404);
  }

  const verRecord = await Repository.createVerification({
    patch_id: patch.id,
    status: 'running',
    summary: {}
  });

  const runResult = await runVerification(patch, finding, req.body || {});

  await Repository.updateVerification(verRecord.id, {
    status: runResult.status,
    summary: runResult.summary
  });

  const updatedPatch = await Repository.updatePatch(patch.id, {
    status: runResult.status === 'passed' ? 'verified' : 'failed'
  });

  return success(res, {
    verification: {
      id: verRecord.id,
      patch_id: patch.id,
      status: runResult.status,
      summary: runResult.summary
    },
    patch: updatedPatch
  });
});

// 9. DEPLOY PATCH
router.post('/patches/:id/deploy', async (req, res) => {
  const patch = await Repository.getPatchById(req.params.id);
  if (!patch) {
    return error(res, 'NOT_FOUND', 'Patch not found', 404);
  }

  const { mode = 'enforce' } = req.body;
  if (!['shadow', 'enforce'].includes(mode)) {
    return error(res, 'INVALID_MODE', 'Mode must be shadow or enforce');
  }

  const deployedPatch = await Repository.updatePatch(patch.id, {
    mode,
    status: 'deployed',
    deployed_at: new Date().toISOString()
  });

  return success(res, deployedPatch);
});

// 10. ROLLBACK PATCH
router.post('/patches/:id/rollback', async (req, res) => {
  const patch = await Repository.getPatchById(req.params.id);
  if (!patch) {
    return error(res, 'NOT_FOUND', 'Patch not found', 404);
  }

  const rolledBack = await Repository.updatePatch(patch.id, {
    status: 'rolled_back'
  });

  return success(res, rolledBack);
});

// 11. EVENTS
router.get('/events', async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 100, 500);
  const events = await Repository.getRecentProxyEvents(limit);
  return success(res, events);
});

// --- INTERNAL ROUTES (X-Internal-Token guarded) ---
function verifyInternalToken(req, res, next) {
  const token = req.headers['x-internal-token'];
  const expected = process.env.INTERNAL_TOKEN || 'patchproof_secret_internal_token_2026';
  if (!token || token !== expected) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid internal token' } });
  }
  next();
}

// GET /internal/v1/rules/active?target_id=
router.get('/internal/v1/rules/active', verifyInternalToken, async (req, res) => {
  const { target_id } = req.query;
  const deployedPatches = await Repository.listActiveDeployedRules(target_id);
  const rules = deployedPatches.map(p => ({
    ...p.rule,
    id: p.id,
    mode: p.mode
  }));

  const jsonStr = JSON.stringify(rules);
  const etag = `"${createHash('md5').update(jsonStr).digest('hex')}"`;

  if (req.headers['if-none-match'] === etag) {
    return res.status(304).end();
  }

  res.setHeader('ETag', etag);
  return res.json({ etag, rules });
});

// GET /internal/v1/rules/candidate/:patch_id
router.get('/internal/v1/rules/candidate/:patch_id', verifyInternalToken, async (req, res) => {
  const patch = await Repository.getPatchById(req.params.patch_id);
  if (!patch || !patch.rule) {
    return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Candidate patch or rule not found' } });
  }

  return res.json({
    rule: {
      ...patch.rule,
      id: patch.id,
      mode: patch.mode
    }
  });
});

// POST /internal/v1/events
router.post('/internal/v1/events', verifyInternalToken, async (req, res) => {
  const events = req.body.events || (Array.isArray(req.body) ? req.body : [req.body]);
  await Repository.insertProxyEvents(events);
  return res.status(202).json({ received: events.length });
});
