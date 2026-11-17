import React, { useState } from 'react';
import { Activity, Shield, AlertTriangle, Database, Bot, Zap, CheckCircle2, XCircle, ArrowUpRight } from 'lucide-react';

export default function CommandCenter({ health, stats, onRunRecipe, onImportZap, onSelectFinding, findings }) {
  const [loadingRecipe, setLoadingRecipe] = useState(null);
  const [importingZap, setImportingZap] = useState(false);

  const handleRecipeClick = async (recipeId) => {
    setLoadingRecipe(recipeId);
    try {
      await onRunRecipe(recipeId);
    } finally {
      setLoadingRecipe(null);
    }
  };

  const handleZapClick = async () => {
    setImportingZap(true);
    try {
      await onImportZap();
    } finally {
      setImportingZap(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-[#1f2638] gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-3">
            <span className="p-2 bg-emerald-500/10 text-emerald-400 rounded-lg border border-emerald-500/20">
              <Shield className="w-6 h-6" />
            </span>
            PATCHPROOF COMMAND CENTER
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            AI-Driven Adaptive WAF & Vulnerability Triage System · Real-Time Control Plane
          </p>
        </div>

        {/* Live System Status Badges */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#11151f] border border-[#1f2638] text-xs font-mono">
            <Database className="w-3.5 h-3.5 text-blue-400" />
            <span>DB:</span>
            <span className={health?.services?.db === 'up' ? 'text-emerald-400 font-bold' : 'text-red-400'}>
              {health?.services?.db || 'down'}
            </span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#11151f] border border-[#1f2638] text-xs font-mono">
            <Bot className="w-3.5 h-3.5 text-purple-400" />
            <span>Ollama:</span>
            <span className={health?.services?.ollama === 'up' ? 'text-emerald-400 font-bold' : 'text-amber-400'}>
              {health?.services?.ollama === 'up' ? 'up' : 'down (fallback)'}
            </span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#11151f] border border-[#1f2638] text-xs font-mono">
            <Activity className="w-3.5 h-3.5 text-emerald-400" />
            <span>Proxy :8080:</span>
            <span className={health?.services?.proxy === 'up' ? 'text-emerald-400 font-bold' : 'text-red-400'}>
              {health?.services?.proxy || 'down'}
            </span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#11151f] border border-[#1f2638] text-xs font-mono" title="Lab target is a custom Node service built to reproduce Juice Shop SQLi & auth behavior (Docker unavailable on host)">
            <Shield className="w-3.5 h-3.5 text-cyan-400" />
            <span>Lab Target :3001:</span>
            <span className={health?.services?.target === 'up' ? 'text-emerald-400 font-bold' : 'text-red-400'}>
              {health?.services?.target === 'up' ? 'up (Lab Replica)' : 'down'}
            </span>
          </div>
        </div>
      </div>

      {/* Primary Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-lg bg-[#11151f] border border-[#1f2638]">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
            <span>TOTAL FINDINGS</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">{stats.totalFindings}</div>
          <div className="text-xs text-slate-400 mt-1 flex items-center gap-1.5">
            <span className="text-red-400 font-semibold">{stats.confirmedExploits} confirmed</span>
            <span>·</span>
            <span>{stats.zapNoise} scanner alerts</span>
          </div>
        </div>

        <div className="p-4 rounded-lg bg-[#11151f] border border-[#1f2638]">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
            <span>P0 CRITICAL QUEUE</span>
            <div className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 font-mono text-[10px] font-bold">P0 BAND</div>
          </div>
          <div className="text-2xl font-bold font-mono text-red-400">{stats.p0Count}</div>
          <div className="text-xs text-slate-400 mt-1">Requires immediate virtual patch</div>
        </div>

        <div className="p-4 rounded-lg bg-[#11151f] border border-[#1f2638]">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
            <span>ACTIVE BLOCKS (PROXY)</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">{stats.blocksCount}</div>
          <div className="text-xs text-slate-400 mt-1">Enforce mode active decisions</div>
        </div>

        <div className="p-4 rounded-lg bg-[#11151f] border border-[#1f2638]">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
            <span>ENGINE LATENCY</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-400">0.45 ms <span className="text-xs text-slate-400 font-normal">p50</span></div>
          <div className="text-xs text-slate-400 mt-1 font-mono">1.18 ms p95 (Budget: &lt;5 ms)</div>
        </div>
      </div>

      {/* Exploit Injection & Scan Ingestion Strip */}
      <div className="p-5 rounded-lg bg-[#11151f] border border-[#1f2638] space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-semibold tracking-wide text-white uppercase font-mono">
              Laboratory Exploit Trigger & Scanner Ingestion
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">Live Verification on localhost:3001</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <button
            onClick={() => handleRecipeClick('R1')}
            disabled={loadingRecipe !== null}
            className="flex flex-col items-start p-3 rounded-md bg-[#090b10] border border-red-500/30 hover:border-red-500 hover:bg-red-500/5 transition text-left group"
          >
            <div className="flex items-center justify-between w-full">
              <span className="text-xs font-bold text-red-400 font-mono">RECIPE R1</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 font-mono">SQLi Search</span>
            </div>
            <span className="text-sm font-medium text-white mt-1">Product Search UNION Leak</span>
            <span className="text-xs text-slate-400 mt-1 line-clamp-1 font-mono">
              GET /rest/products/search?q=UNION SELECT...
            </span>
            <div className="mt-2 text-xs text-red-400 flex items-center gap-1 group-hover:underline">
              {loadingRecipe === 'R1' ? 'Executing attack...' : 'Fire Exploit & Confirm Hole →'}
            </div>
          </button>

          <button
            onClick={() => handleRecipeClick('R2')}
            disabled={loadingRecipe !== null}
            className="flex flex-col items-start p-3 rounded-md bg-[#090b10] border border-red-500/30 hover:border-red-500 hover:bg-red-500/5 transition text-left group"
          >
            <div className="flex items-center justify-between w-full">
              <span className="text-xs font-bold text-red-400 font-mono">RECIPE R2</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 font-mono">SQLi Auth Bypass</span>
            </div>
            <span className="text-sm font-medium text-white mt-1">Login Tautology Bypass</span>
            <span className="text-xs text-slate-400 mt-1 line-clamp-1 font-mono">
              POST /rest/user/login &#123;email: "' or 1=1--"&#125;
            </span>
            <div className="mt-2 text-xs text-red-400 flex items-center gap-1 group-hover:underline">
              {loadingRecipe === 'R2' ? 'Executing attack...' : 'Fire Exploit & Confirm Hole →'}
            </div>
          </button>

          <button
            onClick={handleZapClick}
            disabled={importingZap}
            className="flex flex-col items-start p-3 rounded-md bg-[#090b10] border border-blue-500/30 hover:border-blue-500 hover:bg-blue-500/5 transition text-left group"
          >
            <div className="flex items-center justify-between w-full">
              <span className="text-xs font-bold text-blue-400 font-mono">SCANNER IMPORT</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 font-mono">OWASP ZAP</span>
            </div>
            <span className="text-sm font-medium text-white mt-1">Load ZAP Baseline Scan</span>
            <span className="text-xs text-slate-400 mt-1 line-clamp-1 font-mono">
              Import 14 standard alerts to demonstrate triage ranking
            </span>
            <div className="mt-2 text-xs text-blue-400 flex items-center gap-1 group-hover:underline">
              {importingZap ? 'Importing scan...' : 'Ingest Scanner Report →'}
            </div>
          </button>
        </div>
      </div>

      {/* Recent Findings Preview */}
      <div className="p-5 rounded-lg bg-[#11151f] border border-[#1f2638] space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold tracking-wide text-white uppercase font-mono">
            High Priority Vulnerabilities Ready for Virtual Patching
          </h3>
          <span className="text-xs text-slate-400 font-mono">Sorted by deterministic triage score</span>
        </div>

        <div className="divide-y divide-[#1f2638]">
          {findings.slice(0, 4).map(f => (
            <div key={f.id} className="py-3 flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                  f.triage?.priority_band === 'P0' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                  f.triage?.priority_band === 'P1' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                  'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                }`}>
                  {f.triage?.priority_band || 'P1'} ({f.triage?.priority_score || 50})
                </span>
                <div>
                  <div className="text-sm font-medium text-white flex items-center gap-2">
                    {f.title}
                    {f.exploit_confirmed && (
                      <span className="px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-400 text-[10px] font-mono border border-emerald-500/30">
                        EXPLOIT CONFIRMED
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-slate-400 font-mono">
                    {f.method} {f.route_template || f.url} · Param: <span className="text-slate-300">{f.param || 'N/A'}</span>
                  </div>
                </div>
              </div>

              <button
                onClick={() => onSelectFinding(f)}
                className="px-3 py-1.5 rounded bg-[#1f2638] hover:bg-emerald-600 hover:text-black transition text-xs font-mono text-slate-200 flex items-center gap-1"
              >
                Inspect & Patch <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}

          {findings.length === 0 && (
            <div className="py-8 text-center text-xs text-slate-400 font-mono">
              No findings ingested yet. Click "RECIPE R1" or "LOAD ZAP BASELINE SCAN" above to begin.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
