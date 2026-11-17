import React, { useState } from 'react';
import { Shield, Play, RefreshCw, CheckCircle2, XCircle, AlertTriangle, Cpu, Terminal, ArrowRight, Activity, Zap } from 'lucide-react';

export default function PatchStudio({
  patches,
  selectedPatch,
  setSelectedPatch,
  onVerifyPatch,
  onDeployPatch,
  onRollbackPatch,
  onRunGauntlet,
  onRunHarden,
  findings
}) {
  const [verifying, setVerifying] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [runningGauntlet, setRunningGauntlet] = useState(false);
  const [runningHarden, setRunningHarden] = useState(false);
  const [gauntletResult, setGauntletResult] = useState(null);
  const [hardenResult, setHardenResult] = useState(null);
  const [startMode, setStartMode] = useState('canonical');

  const patch = selectedPatch || patches[0];

  const handleVerify = async () => {
    if (!patch) return;
    setVerifying(true);
    try {
      await onVerifyPatch(patch.id);
    } finally {
      setVerifying(false);
    }
  };

  const handleDeploy = async (mode) => {
    if (!patch) return;
    setDeploying(true);
    try {
      await onDeployPatch(patch.id, mode);
    } finally {
      setDeploying(false);
    }
  };

  const handleRollback = async () => {
    if (!patch) return;
    await onRollbackPatch(patch.id);
  };

  const handleGauntlet = async () => {
    if (!patch) return;
    setRunningGauntlet(true);
    try {
      const res = await onRunGauntlet(patch.id, 60, 42);
      setGauntletResult(res);
    } finally {
      setRunningGauntlet(false);
    }
  };

  const handleHarden = async () => {
    if (!patch) return;
    setRunningHarden(true);
    try {
      const res = await onRunHarden(patch.id, 5, 60, 42, startMode);
      setHardenResult(res);
      if (res?.best_patch) setSelectedPatch(res.best_patch);
    } finally {
      setRunningHarden(false);
    }
  };

  if (!patch) {
    return (
      <div className="rounded-lg bg-[#11151f] border border-[#1f2638] p-12 text-center text-xs font-mono text-slate-400">
        No patches created yet. Select a vulnerability finding from the Triage Queue and click "Synthesize Virtual Patch".
      </div>
    );
  }

  const rule = patch.rule || {};

  return (
    <div className="space-y-6">
      {/* Header and Version Selector */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-[#1f2638] gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-emerald-400" />
            VIRTUAL PATCH STUDIO
          </h2>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Deterministic Rule DSL · Multi-Pass Normalization · Mutation Verification & Auto-Tighten
          </p>
        </div>

        {/* Patch Version Switcher */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-mono text-slate-400">Version Lineage:</span>
          {patches.map(p => (
            <button
              key={p.id}
              onClick={() => setSelectedPatch(p)}
              className={`px-3 py-1 rounded text-xs font-mono font-semibold transition flex items-center gap-1.5 ${
                p.id === patch.id
                  ? 'bg-emerald-500 text-black shadow-md shadow-emerald-500/20'
                  : 'bg-[#11151f] text-slate-300 border border-[#1f2638] hover:border-slate-500'
              }`}
            >
              <span>v{p.version}</span>
              <span className={`text-[10px] px-1 rounded ${p.source === 'canonical' ? 'bg-amber-900/50 text-amber-200' : 'bg-black/30'}`}>
                {p.source}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Main Studio Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Rule Inspector & Deployment (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="rounded-lg bg-[#11151f] border border-[#1f2638] p-4 space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-[#1f2638]">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold text-white uppercase">{rule.name || 'WAF Rule'}</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                  patch.status === 'deployed' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                  patch.status === 'verified' ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' :
                  patch.status === 'rolled_back' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                  'bg-slate-800 text-slate-400'
                }`}>
                  {patch.status} ({patch.mode})
                </span>
              </div>
              <span className="text-[10px] font-mono text-slate-400">Schema 1.0</span>
            </div>

            {/* Normalizers Applied List */}
            <div className="space-y-1.5">
              <span className="text-xs font-mono text-slate-400 uppercase">Ordered Normalizer Pipeline:</span>
              <div className="flex flex-wrap gap-1.5">
                {(rule.normalize || []).map((norm, i) => (
                  <span key={i} className="px-2 py-0.5 rounded bg-[#090b10] border border-[#1f2638] text-[11px] font-mono text-emerald-400 flex items-center gap-1">
                    <span className="text-slate-500 text-[9px]">{i + 1}.</span> {norm}
                  </span>
                ))}
                {(!rule.normalize || rule.normalize.length === 0) && (
                  <span className="text-xs text-amber-400 font-mono">None (Vulnerable to encoding bypass)</span>
                )}
              </div>
            </div>

            {/* Condition & Scope */}
            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-2.5 rounded bg-[#090b10] border border-[#1f2638] space-y-1">
                <span className="text-slate-400 uppercase text-[10px]">Scope</span>
                <div className="text-white truncate">{rule.scope?.methods?.join(', ')} {rule.scope?.path?.value}</div>
              </div>
              <div className="p-2.5 rounded bg-[#090b10] border border-[#1f2638] space-y-1">
                <span className="text-slate-400 uppercase text-[10px]">Inspect Target</span>
                <div className="text-white truncate">
                  {rule.inspect?.map(ins => `${ins.location}:${ins.name}`).join(', ') || 'q'}
                </div>
              </div>
            </div>

            {/* Rule JSON display */}
            <div className="space-y-1">
              <span className="text-xs font-mono text-slate-400 uppercase">Frozen Rule DSL:</span>
              <pre className="p-3 rounded bg-[#090b10] border border-[#1f2638] text-[11px] font-mono text-slate-300 max-h-48 overflow-y-auto">
                {JSON.stringify(rule, null, 2)}
              </pre>
            </div>

            {/* Action Buttons */}
            <div className="pt-2 space-y-2">
              <div className="grid grid-cols-2 gap-2">
                <button
                  onClick={handleVerify}
                  disabled={verifying}
                  className="py-2 px-3 rounded bg-[#1f2638] hover:bg-slate-700 text-white font-mono text-xs transition flex items-center justify-center gap-1.5"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin text-emerald-400' : ''}`} />
                  {verifying ? 'Verifying...' : 'Verify Gate'}
                </button>

                {patch.mode === 'enforce' && patch.status === 'deployed' ? (
                  <button
                    onClick={handleRollback}
                    className="py-2 px-3 rounded bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 font-mono text-xs transition"
                  >
                    Rollback Rule
                  </button>
                ) : (
                  <button
                    onClick={() => handleDeploy('enforce')}
                    disabled={deploying}
                    className="py-2 px-3 rounded bg-emerald-500 hover:bg-emerald-400 text-black font-bold font-mono text-xs transition flex items-center justify-center gap-1.5 shadow-md shadow-emerald-500/20"
                  >
                    <Shield className="w-3.5 h-3.5" />
                    Deploy Enforce (403)
                  </button>
                )}
              </div>

              <button
                onClick={() => handleDeploy('shadow')}
                className="w-full py-1.5 rounded bg-[#090b10] hover:bg-[#1f2638] text-amber-400 border border-amber-500/30 font-mono text-[11px] transition"
              >
                Deploy in Shadow Mode (Log & Would-Block Only)
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Mutation Gauntlet & Auto-Tighten Loop (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {/* Gauntlet Runner Strip */}
          <div className="rounded-lg bg-[#11151f] border border-[#1f2638] p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-[#1f2638] gap-2">
              <div>
                <h3 className="text-sm font-bold tracking-wide text-white uppercase font-mono flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-purple-400" />
                  ADVERSARIAL MUTATION GAUNTLET
                </h3>
                <span className="text-[11px] text-slate-400 font-mono">
                  12 Attack Mutators · Effective-Mutant Oracle Filtering
                </span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleGauntlet}
                  disabled={runningGauntlet}
                  className="px-4 py-2 rounded bg-purple-600 hover:bg-purple-500 text-white font-mono text-xs font-bold transition flex items-center gap-1.5 shadow-lg shadow-purple-600/20"
                >
                  <Play className={`w-3.5 h-3.5 ${runningGauntlet ? 'animate-spin' : ''}`} />
                  {runningGauntlet ? 'Attacking Rule...' : 'Run Gauntlet (60 Mutants)'}
                </button>
              </div>
            </div>

            {/* Live Mutant Grid */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">Mutant Execution Matrix (Live Oracle Grid):</span>
                <div className="flex items-center gap-3">
                  <span className="flex items-center gap-1 text-emerald-400">
                    <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500 inline-block"></span> Blocked
                  </span>
                  <span className="flex items-center gap-1 text-red-400">
                    <span className="w-2.5 h-2.5 rounded-sm bg-red-500 inline-block"></span> Bypassed
                  </span>
                  <span className="flex items-center gap-1 text-slate-500">
                    <span className="w-2.5 h-2.5 rounded-sm bg-slate-700 inline-block"></span> Invalid Mutant
                  </span>
                </div>
              </div>

              {/* Grid Tiles */}
              <div className="p-3 rounded-lg bg-[#090b10] border border-[#1f2638] grid grid-cols-10 sm:grid-cols-12 md:grid-cols-15 gap-1.5 min-h-[100px]">
                {gauntletResult?.cases?.map((c, idx) => (
                  <div
                    key={idx}
                    title={`${c.name} (${c.mutator_name}): ${c.outcome}`}
                    className={`h-5 rounded-sm flex items-center justify-center text-[9px] font-mono font-bold transition-all ${
                      c.outcome === 'pass' ? 'bg-emerald-500 text-black shadow-sm shadow-emerald-500/30' :
                      c.outcome === 'fail' ? 'bg-red-500 text-white animate-pulse shadow-sm shadow-red-500/50' :
                      'bg-slate-800 text-slate-500'
                    }`}
                  >
                    {idx + 1}
                  </div>
                ))}

                {(!gauntletResult || gauntletResult.cases?.length === 0) && (
                  <div className="col-span-full py-8 text-center text-xs font-mono text-slate-500">
                    Grid idle. Click "Run Gauntlet" to systematically attack this rule with mutated SQLi payloads.
                  </div>
                )}
              </div>
            </div>

            {/* Metrics: Wilson 95% Confidence Interval */}
            {gauntletResult && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3 rounded bg-[#090b10] border border-[#1f2638] text-xs font-mono">
                <div>
                  <div className="text-slate-500 text-[10px]">EFFECTIVE (E)</div>
                  <div className="text-white text-base font-bold">{gauntletResult.effective}</div>
                  <div className="text-slate-500 text-[10px]">{gauntletResult.invalid} invalid ignored</div>
                </div>
                <div>
                  <div className="text-slate-500 text-[10px]">BLOCKED (B)</div>
                  <div className="text-emerald-400 text-base font-bold">{gauntletResult.blocked}</div>
                </div>
                <div>
                  <div className="text-slate-500 text-[10px]">BYPASSED (X)</div>
                  <div className="text-red-400 text-base font-bold">{gauntletResult.bypassed}</div>
                </div>
                <div>
                  <div className="text-slate-500 text-[10px]">BYPASS RATE + WILSON 95% CI</div>
                  <div className="text-white text-base font-bold">{(gauntletResult.bypass_rate * 100).toFixed(1)}%</div>
                  <div className="text-cyan-400 text-[10px]">
                    CI: [{(gauntletResult.ci95[0] * 100).toFixed(1)}%, {(gauntletResult.ci95[1] * 100).toFixed(1)}%]
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Auto-Tighten Hardening Loop Strip */}
          <div className="rounded-lg bg-[#11151f] border border-[#1f2638] p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-[#1f2638] gap-2">
              <div>
                <h3 className="text-sm font-bold tracking-wide text-white uppercase font-mono flex items-center gap-2">
                  <Zap className="w-4 h-4 text-emerald-400" />
                  AUTO-TIGHTEN LOOP (ADAPTIVE RE-SYNTHESIS)
                </h3>
                <span className="text-[11px] text-slate-400 font-mono">
                  Iterative Normalizer Addition · Monotonic Regression Set · Fresh Exam Verification
                </span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleHarden}
                  disabled={runningHarden}
                  className="px-4 py-2 rounded bg-emerald-500 hover:bg-emerald-400 text-black font-mono text-xs font-bold transition flex items-center gap-1.5 shadow-lg shadow-emerald-500/20"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${runningHarden ? 'animate-spin' : ''}`} />
                  {runningHarden ? 'Tightening Rule...' : 'Auto-Tighten (5 Iterations)'}
                </button>
              </div>
            </div>

            {/* Hardening Progression Chart */}
            {hardenResult ? (
              <div className="space-y-4">
                <div className="p-3 rounded bg-[#090b10] border border-[#1f2638] space-y-3">
                  <span className="text-xs font-mono text-slate-400 uppercase">Monotonic Convergence Across Iterations:</span>
                  <div className="space-y-2">
                    {hardenResult.iterations?.map((iter) => (
                      <div key={iter.iteration} className="flex items-center justify-between text-xs font-mono gap-4">
                        <span className="w-24 text-slate-300 font-semibold">Iteration {iter.iteration} (v{iter.version})</span>
                        <div className="flex-1 h-3 bg-[#11151f] rounded-full overflow-hidden flex">
                          <div
                            className="bg-red-500 transition-all duration-500"
                            style={{ width: `${iter.stats.bypass_rate * 100}%` }}
                            title={`Bypass rate: ${(iter.stats.bypass_rate * 100).toFixed(1)}%`}
                          />
                          <div
                            className="bg-emerald-500 transition-all duration-500"
                            style={{ width: `${(1 - iter.stats.bypass_rate) * 100}%` }}
                            title={`Blocked rate: ${((1 - iter.stats.bypass_rate) * 100).toFixed(1)}%`}
                          />
                        </div>
                        <span className="w-20 text-right text-slate-200 font-bold">
                          {(iter.stats.bypass_rate * 100).toFixed(1)}% bypass
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Fresh Exam Score (Unseen Seed) */}
                <div className="p-3.5 rounded bg-gradient-to-r from-emerald-950/40 to-[#090b10] border border-emerald-500/30 flex items-center justify-between">
                  <div>
                    <div className="text-xs font-mono font-bold text-emerald-400 uppercase flex items-center gap-1.5">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      UNSEEN EXAM VERIFICATION (SEED: {hardenResult.exam?.seed})
                    </div>
                    <div className="text-[11px] text-slate-300 mt-1 font-mono">
                      Graded on completely fresh unseen mutations to prevent overfitting.
                    </div>
                  </div>
                  <div className="text-right font-mono">
                    <div className="text-lg font-bold text-white">
                      {(hardenResult.exam?.bypass_rate * 100).toFixed(1)}% Bypass
                    </div>
                    <div className="text-[10px] text-emerald-400">
                      Blocked {hardenResult.exam?.blocked} of {hardenResult.exam?.effective} Effective Mutants
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-6 rounded bg-[#090b10] border border-[#1f2638] text-center text-xs font-mono text-slate-500">
                Auto-Tighten loop not yet executed. Run Auto-Tighten to see rule self-mutate until all adversarial bypasses are eliminated.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
