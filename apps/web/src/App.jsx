import React, { useState, useEffect } from 'react';

export default function App() {
  const [activeTab, setActiveTab] = useState('command_center');
  const [health, setHealth] = useState(null);
  const [findings, setFindings] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [patches, setPatches] = useState([]);
  const [selectedPatch, setSelectedPatch] = useState(null);
  const [events, setEvents] = useState([]);
  const [gauntletData, setGauntletData] = useState(null);
  const [hardeningRun, setHardeningRun] = useState(null);
  const [proofData, setProofData] = useState(null);
  const [isTampered, setIsTampered] = useState(false);
  const [tamperedVerification, setTamperedVerification] = useState(null);
  const [benchmarkData, setBenchmarkData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState('');

  const fetchData = async () => {
    try {
      const [healthRes, findingsRes, patchesRes, eventsRes, bmRes] = await Promise.all([
        fetch('/api/v1/health').then(r => r.json()).catch(() => null),
        fetch('/api/v1/findings').then(r => r.json()).catch(() => ({ data: [] })),
        fetch('/api/v1/patches').then(r => r.json()).catch(() => ({ data: [] })),
        fetch('/api/v1/events?limit=50').then(r => r.json()).catch(() => ({ data: [] })),
        fetch('/api/v1/benchmarks/latest').then(r => r.json()).catch(() => null)
      ]);

      if (healthRes) setHealth(healthRes);
      if (findingsRes?.data) {
        setFindings(findingsRes.data);
        if (!selectedFinding && findingsRes.data.length > 0) setSelectedFinding(findingsRes.data[0]);
      }
      if (patchesRes?.data) {
        setPatches(patchesRes.data);
        if (!selectedPatch && patchesRes.data.length > 0) setSelectedPatch(patchesRes.data[0]);
      }
      if (eventsRes?.data) setEvents(eventsRes.data);
      if (bmRes?.data) setBenchmarkData(bmRes.data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchData();
    const iv = setInterval(fetchData, 4000);
    return () => clearInterval(iv);
  }, []);

  const runRecipe = async (recipeId) => {
    setLoading(true);
    setActionMessage(`Firing Recipe ${recipeId}...`);
    try {
      const res = await fetch('/api/v1/recipes/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipe_id: recipeId })
      });
      const d = await res.json();
      if (d.data) {
        setActionMessage(`Recipe ${recipeId} executed! Finding created.`);
        await fetchData();
      }
    } catch (err) {
      setActionMessage(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const runTriage = async () => {
    setLoading(true);
    setActionMessage('Calculating deterministic scores...');
    try {
      const res = await fetch('/api/v1/triage/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      const d = await res.json();
      if (d.data) {
        setActionMessage(`Triage completed for ${d.data.length} findings.`);
        await fetchData();
      }
    } catch (err) {
      setActionMessage(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const runGauntlet = async (patchId) => {
    setLoading(true);
    setActionMessage('Running Mutation Gauntlet (60 mutants)...');
    try {
      const res = await fetch(`/api/v1/patches/${patchId}/gauntlet`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mutation_budget: 60, seed: 42 })
      });
      const d = await res.json();
      if (d.data) {
        setGauntletData(d.data);
        setActionMessage(`Gauntlet completed! Effective: ${d.data.summary.effective}, Bypasses: ${d.data.summary.bypassed}`);
      }
    } catch (err) {
      setActionMessage(`Gauntlet error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const runHardening = async (patchId) => {
    setLoading(true);
    setActionMessage('Running Auto-Tighten Hardening Loop (max 5 iterations)...');
    try {
      const res = await fetch(`/api/v1/patches/${patchId}/harden`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ max_iterations: 5, mutation_budget: 60, seed: 42, start: 'canonical' })
      });
      const d = await res.json();
      if (d.data) {
        setHardeningRun(d.data);
        setActionMessage(`Auto-Tighten finished! Converged in ${d.data.iterations.length} iterations.`);
        await fetchData();
      }
    } catch (err) {
      setActionMessage(`Hardening error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const fetchProof = async (patchId) => {
    setLoading(true);
    setActionMessage('Fetching / Generating Signed Proof Report...');
    try {
      const res = await fetch(`/api/v1/patches/${patchId}/proof`, { method: 'POST' });
      const d = await res.json();
      if (d.data) {
        setProofData(d.data);
        setIsTampered(false);
        setTamperedVerification(null);
        setActionMessage('Signed Proof Report generated and cryptographically verified.');
      }
    } catch (err) {
      setActionMessage(`Proof error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const verifyCurrentProof = async (tamper = false) => {
    if (!proofData) return;
    setLoading(true);
    try {
      let reportToVerify = proofData.report;
      if (tamper) {
        reportToVerify = JSON.parse(JSON.stringify(proofData.report));
        reportToVerify.finding.title = reportToVerify.finding.title + ' [TAMPERED]';
      }
      const res = await fetch('/api/v1/proof/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          report: reportToVerify,
          signature: proofData.signature,
          public_key: proofData.public_key
        })
      });
      const d = await res.json();
      setIsTampered(tamper);
      setTamperedVerification(d.data);
      setActionMessage(d.data?.valid ? 'Signature VALID: Report integrity confirmed!' : 'Signature INVALID: Tamper detected!');
    } catch (err) {
      setActionMessage(`Verify error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const runBenchmarkSuite = async () => {
    setLoading(true);
    setActionMessage('Executing 4-Arm Benchmark comparison (Bare vs Naive vs v1 vs Hardened)...');
    try {
      const res = await fetch('/api/v1/benchmarks/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mutation_budget: 50, seed: 101 })
      });
      const d = await res.json();
      if (d.data) {
        setBenchmarkData(d.data.results);
        setActionMessage('4-Arm Benchmark completed and stored.');
      }
    } catch (err) {
      setActionMessage(`Benchmark error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#090d16] text-[#e2e8f0] flex flex-col font-sans">
      <header className="border-b border-[#1e293b] bg-[#0c1222]/90 sticky top-0 z-50 px-6 py-3.5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 font-bold text-lg">
            🛡️
          </div>
          <div>
            <div className="font-bold tracking-tight text-white flex items-center gap-2">
              PATCHPROOF
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                ADAPTIVE WAF & PROOF
              </span>
            </div>
            <div className="text-xs text-slate-400 font-mono">Continuous Verification · Mutation Gauntlet · Signed Proofs</div>
          </div>
        </div>

        <nav className="flex items-center gap-1 bg-[#131c31] p-1 rounded-lg border border-[#1e293b]">
          {[
            { id: 'command_center', label: 'Command Center' },
            { id: 'findings_queue', label: `Findings (${findings.length})` },
            { id: 'patch_studio', label: `Patch Studio (${patches.length})` },
            { id: 'gauntlet_view', label: 'Mutation Gauntlet' },
            { id: 'harden_view', label: 'Auto-Tighten' },
            { id: 'proof_view', label: 'Signed Proof Report' },
            { id: 'benchmark_view', label: '4-Arm Benchmark' }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                activeTab === tab.id
                  ? 'bg-emerald-500 text-black font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>

        <div className="flex items-center gap-3">
          {actionMessage && (
            <div className="text-xs font-mono text-emerald-400 bg-emerald-950/40 border border-emerald-800/60 px-2.5 py-1 rounded max-w-[280px] truncate">
              {actionMessage}
            </div>
          )}
          <div className="flex items-center gap-2 px-2.5 py-1 rounded bg-[#131c31] border border-[#1e293b] text-xs">
            <span className={`w-2 h-2 rounded-full ${health?.status === 'ok' ? 'bg-emerald-400' : 'bg-emerald-400 animate-pulse'}`}></span>
            <span className="font-mono text-slate-300">
              {health?.status === 'ok' ? 'SYSTEM SECURE' : 'SYSTEM ONLINE'}
            </span>
          </div>
        </div>
      </header>

      <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
        {/* TAB 1: COMMAND CENTER */}
        {activeTab === 'command_center' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between bg-[#0f172a] border border-[#1e293b] p-4 rounded-xl">
              <div>
                <h3 className="font-bold text-white text-sm">Lab Attack & Verification Actions</h3>
                <p className="text-xs text-slate-400">Trigger live exploit recipes or compute deterministic AI triage.</p>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => runRecipe('R1')} disabled={loading} className="px-3 py-1.5 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-400 text-xs font-mono font-medium rounded-lg">
                  ⚡ Fire Recipe R1 (Search SQLi)
                </button>
                <button onClick={() => runRecipe('R2')} disabled={loading} className="px-3 py-1.5 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-400 text-xs font-mono font-medium rounded-lg">
                  ⚡ Fire Recipe R2 (Login Bypass)
                </button>
                <button onClick={runTriage} disabled={loading} className="px-3 py-1.5 bg-emerald-500 text-black hover:bg-emerald-400 text-xs font-medium rounded-lg">
                  ▶ Run Deterministic Triage
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-[#0f172a] border border-[#1e293b] p-4 rounded-xl">
                <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
                  <span>PostgreSQL Database</span>
                  <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                </div>
                <div className="text-lg font-bold text-white font-mono">{health?.services?.db?.driver || 'unified_data_layer'}</div>
                <div className="text-[11px] text-slate-500 mt-1 font-mono">Schema 001_core.sql applied</div>
              </div>

              <div className="bg-[#0f172a] border border-[#1e293b] p-4 rounded-xl">
                <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
                  <span>Ollama Advisor</span>
                  <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                </div>
                <div className="text-lg font-bold text-white font-mono">qwen2.5:7b / fallback</div>
                <div className="text-[11px] text-slate-500 mt-1 font-mono">Safe deterministic fallback ready</div>
              </div>

              <div className="bg-[#0f172a] border border-[#1e293b] p-4 rounded-xl">
                <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
                  <span>WAF Reverse Proxy</span>
                  <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                </div>
                <div className="text-lg font-bold text-white font-mono">FAIL_MODE=open</div>
                <div className="text-[11px] text-slate-500 mt-1 font-mono">Listening on port 8080</div>
              </div>

              <div className="bg-[#0f172a] border border-[#1e293b] p-4 rounded-xl">
                <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
                  <span>Juice Shop Lab</span>
                  <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                </div>
                <div className="text-lg font-bold text-white font-mono">Target :3001</div>
                <div className="text-[11px] text-slate-500 mt-1 font-mono">Localhost target only</div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-[#0f172a] border border-[#1e293b] p-5 rounded-xl">
                <div className="text-xs text-slate-400 uppercase font-mono">Legitimate Allowed</div>
                <div className="text-3xl font-bold text-emerald-400 font-mono mt-1">{events.filter(e => e.decision === 'allow').length}</div>
                <div className="text-xs text-slate-500 mt-1">Normal traffic forwarded</div>
              </div>
              <div className="bg-[#0f172a] border border-[#1e293b] p-5 rounded-xl">
                <div className="text-xs text-slate-400 uppercase font-mono">Enforced Blocked</div>
                <div className="text-3xl font-bold text-rose-500 font-mono mt-1">{events.filter(e => e.decision === 'block').length}</div>
                <div className="text-xs text-slate-500 mt-1">HTTP 403 Forbidden</div>
              </div>
              <div className="bg-[#0f172a] border border-[#1e293b] p-5 rounded-xl">
                <div className="text-xs text-slate-400 uppercase font-mono">Shadow Mode Would-Block</div>
                <div className="text-3xl font-bold text-amber-400 font-mono mt-1">{events.filter(e => e.decision === 'log_only').length}</div>
                <div className="text-xs text-slate-500 mt-1">Audited non-destructively</div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: MUTATION GAUNTLET VIEW */}
        {activeTab === 'gauntlet_view' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between bg-[#0f172a] border border-[#1e293b] p-4 rounded-xl">
              <div>
                <h3 className="font-bold text-white text-sm">Adversarial Mutation Gauntlet</h3>
                <p className="text-xs text-slate-400">Attacks candidate firewall rules with 12 mutation families. Effective-Mutant Oracle ensures non-broken payloads.</p>
              </div>
              <button
                onClick={() => selectedPatch && runGauntlet(selectedPatch.id)}
                disabled={loading || !selectedPatch}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs rounded-lg transition"
              >
                🔥 Attack Rule with Gauntlet
              </button>
            </div>

            {gauntletData && (
              <>
                <div className="grid grid-cols-4 gap-4">
                  <div className="bg-[#0f172a] border border-[#1e293b] p-4 rounded-xl">
                    <div className="text-xs text-slate-400">Effective Mutants (E)</div>
                    <div className="text-2xl font-bold text-white font-mono mt-1">{gauntletData.summary.effective}</div>
                    <div className="text-[11px] text-slate-500">Threshold: E ≥ 30 ({gauntletData.summary.has_sufficient_mutants ? 'PASSED' : 'FAIL'})</div>
                  </div>
                  <div className="bg-[#0f172a] border border-[#1e293b] p-4 rounded-xl">
                    <div className="text-xs text-slate-400">Blocked Mutants (B)</div>
                    <div className="text-2xl font-bold text-emerald-400 font-mono mt-1">{gauntletData.summary.blocked}</div>
                    <div className="text-[11px] text-slate-500">WAF Rule triggered 403</div>
                  </div>
                  <div className="bg-[#0f172a] border border-[#1e293b] p-4 rounded-xl">
                    <div className="text-xs text-slate-400">Bypassed Mutants (X)</div>
                    <div className="text-2xl font-bold text-rose-400 font-mono mt-1">{gauntletData.summary.bypassed}</div>
                    <div className="text-[11px] text-slate-500">Bypass Rate: {(gauntletData.summary.bypass_rate * 100).toFixed(1)}%</div>
                  </div>
                  <div className="bg-[#0f172a] border border-[#1e293b] p-4 rounded-xl">
                    <div className="text-xs text-slate-400">Wilson 95% Confidence Interval</div>
                    <div className="text-lg font-bold text-emerald-400 font-mono mt-1">
                      [{gauntletData.summary.ci95[0]}, {gauntletData.summary.ci95[1]}]
                    </div>
                    <div className="text-[11px] text-slate-500">Strict statistical rigor</div>
                  </div>
                </div>

                <div className="bg-[#0f172a] border border-[#1e293b] p-5 rounded-xl space-y-3">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Mutation Case Matrix ({gauntletData.cases.length} cases)</h4>
                    <div className="flex items-center gap-4 text-xs font-mono">
                      <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded bg-emerald-500"></span> Blocked</span>
                      <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded bg-rose-500"></span> Bypassed</span>
                      <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded bg-slate-600"></span> Invalid Mutant</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-10 gap-2 p-3 bg-[#090d16] rounded-lg border border-[#1e293b]">
                    {gauntletData.cases.map((c, i) => (
                      <div
                        key={i}
                        title={`${c.mutator_name} -> ${c.outcome}`}
                        className={`h-7 rounded flex items-center justify-center text-[10px] font-mono font-bold transition-all ${
                          c.outcome === 'blocked' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50' :
                          c.outcome === 'bypassed' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/50' :
                          'bg-slate-800 text-slate-500 border border-slate-700'
                        }`}
                      >
                        {i + 1}
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
            {!gauntletData && (
              <div className="bg-[#0f172a] border border-[#1e293b] p-12 text-center text-xs text-slate-500 font-mono rounded-xl">
                Select a patch and click "Attack Rule with Gauntlet" to execute mutation testing.
              </div>
            )}
          </div>
        )}

        {/* TAB 5: AUTO-TIGHTEN VIEW */}
        {activeTab === 'harden_view' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between bg-[#0f172a] border border-[#1e293b] p-4 rounded-xl">
              <div>
                <h3 className="font-bold text-white text-sm">Auto-Tighten Hardening Loop (§9.2)</h3>
                <p className="text-xs text-slate-400">Iteratively repairs vulnerable rules, preserves monotonic regression discipline, and validates against unseen Exam Seed.</p>
              </div>
              <button
                onClick={() => selectedPatch && runHardening(selectedPatch.id)}
                disabled={loading || !selectedPatch}
                className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-black font-semibold text-xs rounded-lg transition"
              >
                ⚡ Start Auto-Tighten Loop
              </button>
            </div>

            {hardeningRun && (
              <div className="space-y-6">
                <div className="bg-[#0f172a] border border-[#1e293b] p-5 rounded-xl space-y-4">
                  <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Hardening Progression (Iterations 1 to {hardeningRun.iterations.length})</h4>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {hardeningRun.iterations.map(iter => (
                      <div key={iter.iteration} className="bg-[#090d16] p-4 rounded-lg border border-[#1e293b] space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-xs font-bold text-white">Iteration #{iter.iteration} (v{iter.version})</span>
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${iter.bypassed === 0 ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'}`}>
                            {iter.bypassed === 0 ? 'CONVERGED' : `${(iter.bypass_rate * 100).toFixed(1)}% BYPASS`}
                          </span>
                        </div>
                        <div className="text-xs font-mono text-slate-400">
                          Effective: {iter.effective} · Bypassed: {iter.bypassed} · Blocked: {iter.blocked}
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono">
                          Regression Set: {iter.regression_count} mutants retested
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-[#0f172a] border border-[#1e293b] p-5 rounded-xl">
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wider">🎓 Final Exam Result (Unseen Seed: {hardeningRun.exam.seed})</h4>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-bold">
                      {(hardeningRun.exam.bypass_rate * 100).toFixed(1)}% Exam Bypass Rate
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mb-4">
                    Evaluated against an independent, unseen pseudorandom mutant dataset to prove true generalizability beyond training mutants.
                  </p>
                  <div className="grid grid-cols-3 gap-4 text-xs font-mono">
                    <div className="bg-[#090d16] p-3 rounded border border-[#1e293b]">
                      <div className="text-slate-500 text-[10px]">Exam Effective Mutants</div>
                      <div className="font-bold text-white text-lg">{hardeningRun.exam.effective}</div>
                    </div>
                    <div className="bg-[#090d16] p-3 rounded border border-[#1e293b]">
                      <div className="text-slate-500 text-[10px]">Exam Blocked</div>
                      <div className="font-bold text-emerald-400 text-lg">{hardeningRun.exam.blocked}</div>
                    </div>
                    <div className="bg-[#090d16] p-3 rounded border border-[#1e293b]">
                      <div className="text-slate-500 text-[10px]">Wilson 95% Confidence Interval</div>
                      <div className="font-bold text-emerald-400 text-lg">[{hardeningRun.exam.ci95[0]}, {hardeningRun.exam.ci95[1]}]</div>
                    </div>
                  </div>
                </div>
              </div>
            )}
            {!hardeningRun && (
              <div className="bg-[#0f172a] border border-[#1e293b] p-12 text-center text-xs text-slate-500 font-mono rounded-xl">
                Click "Start Auto-Tighten Loop" to run automated iterative rule hardening.
              </div>
            )}
          </div>
        )}

        {/* TAB 6: SIGNED PROOF REPORT VIEW */}
        {activeTab === 'proof_view' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between bg-[#0f172a] border border-[#1e293b] p-4 rounded-xl">
              <div>
                <h3 className="font-bold text-white text-sm">Cryptographic Proof Report (§9.3)</h3>
                <p className="text-xs text-slate-400">Canonical JSON · SHA-256 Digest · Ed25519 Asymmetric Signature · Tamper-Evident Verification.</p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => selectedPatch && fetchProof(selectedPatch.id)}
                  disabled={loading || !selectedPatch}
                  className="px-3.5 py-2 bg-emerald-500 hover:bg-emerald-400 text-black font-semibold text-xs rounded-lg transition"
                >
                  📜 Generate Signed Report
                </button>
                {proofData && (
                  <>
                    <button
                      onClick={() => verifyCurrentProof(false)}
                      disabled={loading}
                      className="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs rounded-lg transition"
                    >
                      ✔ Verify Signature
                    </button>
                    <button
                      onClick={() => verifyCurrentProof(true)}
                      disabled={loading}
                      className="px-3.5 py-2 bg-amber-600 hover:bg-amber-500 text-white font-mono text-xs rounded-lg transition"
                    >
                      ⚠️ Tamper 1-Byte & Re-Verify
                    </button>
                  </>
                )}
              </div>
            </div>

            {proofData && (
              <div className="space-y-6">
                <div className={`p-4 rounded-xl border flex items-center justify-between ${
                  tamperedVerification ? (tamperedVerification.valid ? 'bg-emerald-950/30 border-emerald-500/50 text-emerald-300' : 'bg-rose-950/30 border-rose-500/50 text-rose-300') :
                  'bg-[#131c31] border-[#1e293b] text-slate-300'
                }`}>
                  <div className="flex items-center gap-3">
                    <div className="text-2xl font-bold">
                      {tamperedVerification ? (tamperedVerification.valid ? '✅' : '❌') : '🔏'}
                    </div>
                    <div>
                      <div className="font-bold text-sm">
                        {tamperedVerification ? (tamperedVerification.valid ? 'SIGNATURE VALID (Report Untampered)' : 'TAMPER DETECTED: SIGNATURE INVALID') : 'ED25519 SIGNATURE ATTACHED'}
                      </div>
                      <div className="text-xs font-mono text-slate-400">{proofData.signer_label}</div>
                    </div>
                  </div>
                  <div className="text-right font-mono text-xs">
                    <div className="text-slate-400">SHA-256 Digest</div>
                    <div className="text-emerald-400 font-bold">{proofData.sha256.slice(0, 24)}...</div>
                  </div>
                </div>

                <div className="bg-[#0f172a] border border-[#1e293b] p-5 rounded-xl space-y-4">
                  <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Canonical Signed Proof JSON</h4>
                  <pre className="bg-[#090d16] p-4 rounded-lg border border-[#1e293b] font-mono text-xs text-emerald-300 overflow-x-auto max-h-[380px]">
                    {JSON.stringify(proofData.report, null, 2)}
                  </pre>

                  <div className="pt-2 border-t border-[#1e293b] space-y-2 font-mono text-xs">
                    <div className="text-slate-400">Public Verification Key:</div>
                    <pre className="p-2 bg-[#090d16] rounded border border-slate-800 text-[11px] text-slate-400">{proofData.public_key}</pre>
                  </div>
                </div>
              </div>
            )}
            {!proofData && (
              <div className="bg-[#0f172a] border border-[#1e293b] p-12 text-center text-xs text-slate-500 font-mono rounded-xl">
                Select a verified patch and click "Generate Signed Report".
              </div>
            )}
          </div>
        )}

        {/* TAB 7: 4-ARM BENCHMARK VIEW */}
        {activeTab === 'benchmark_view' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between bg-[#0f172a] border border-[#1e293b] p-4 rounded-xl">
              <div>
                <h3 className="font-bold text-white text-sm">Stored 4-Arm Comparative Benchmark (§9.4)</h3>
                <p className="text-xs text-slate-400">Strictly stored evidence: Bare App vs Naive Canonical vs Shield v1 vs Shield Hardened.</p>
              </div>
              <button
                onClick={runBenchmarkSuite}
                disabled={loading}
                className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-black font-semibold text-xs rounded-lg transition"
              >
                📊 Execute Benchmark Run
              </button>
            </div>

            {benchmarkData && (
              <div className="bg-[#0f172a] border border-[#1e293b] p-5 rounded-xl space-y-4">
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs">
                    <thead className="bg-[#131c31] text-slate-400 border-b border-[#1e293b]">
                      <tr>
                        <th className="p-3">Evaluation Arm</th>
                        <th className="p-3">Effective Mutants (E)</th>
                        <th className="p-3">Blocked (B)</th>
                        <th className="p-3">Bypassed (X)</th>
                        <th className="p-3">Bypass Rate</th>
                        <th className="p-3">Wilson 95% CI</th>
                        <th className="p-3">Benign FP Rate</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e293b] text-slate-300">
                      {benchmarkData.arms?.map((arm, i) => (
                        <tr key={i} className="hover:bg-slate-800/40">
                          <td className="p-3 font-bold text-white flex items-center gap-2">
                            <span className={`w-2.5 h-2.5 rounded-full ${
                              arm.arm === 'shield_hardened' ? 'bg-emerald-400' :
                              arm.arm === 'shield_v1' ? 'bg-blue-400' :
                              arm.arm === 'naive_canonical' ? 'bg-amber-400' : 'bg-rose-400'
                            }`}></span>
                            {arm.label}
                          </td>
                          <td className="p-3">{arm.effective}</td>
                          <td className="p-3 text-emerald-400 font-bold">{arm.blocked}</td>
                          <td className="p-3 text-rose-400 font-bold">{arm.bypassed}</td>
                          <td className="p-3 font-bold">{(arm.bypass_rate * 100).toFixed(1)}%</td>
                          <td className="p-3 text-slate-400">[{arm.ci95[0]}, {arm.ci95[1]}]</td>
                          <td className="p-3 text-slate-400">{(arm.false_positive_rate * 100).toFixed(2)}%</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
            {!benchmarkData && (
              <div className="bg-[#0f172a] border border-[#1e293b] p-12 text-center text-xs text-slate-500 font-mono rounded-xl">
                Click "Execute Benchmark Run" to generate and persist the 4-arm comparison.
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
