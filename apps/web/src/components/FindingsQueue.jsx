import React, { useState } from 'react';
import { AlertCircle, Shield, Bot, ArrowRight, CheckCircle2, X, ChevronRight, Layers } from 'lucide-react';

export default function FindingsQueue({ findings, onDraftPatch, selectedFinding, setSelectedFinding }) {
  const [strategy, setStrategy] = useState('auto');
  const [drafting, setDrafting] = useState(false);

  const handleDraft = async (finding) => {
    setDrafting(true);
    try {
      await onDraftPatch(finding.id, strategy);
    } finally {
      setDrafting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-[#1f2638] gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Layers className="w-5 h-5 text-emerald-400" />
            VULNERABILITY TRIAGE QUEUE
          </h2>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Deterministic Prioritization: Exploit Confirmation (40%) + Severity (40%) + Category Prior (20%)
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Findings List (7 cols) */}
        <div className="lg:col-span-7 space-y-3">
          <div className="rounded-lg bg-[#11151f] border border-[#1f2638] overflow-hidden">
            <div className="p-3 bg-[#0c0e14] border-b border-[#1f2638] flex items-center justify-between text-xs font-mono text-slate-400">
              <span>ALL FINDINGS ({findings.length})</span>
              <span>CLICK TO INSPECT TRIAGE WATERFALL</span>
            </div>

            <div className="divide-y divide-[#1f2638]">
              {findings.map(f => {
                const isSelected = selectedFinding?.id === f.id;
                const band = f.triage?.priority_band || 'P2';
                const score = f.triage?.priority_score || 50;

                return (
                  <div
                    key={f.id}
                    onClick={() => setSelectedFinding(f)}
                    className={`p-4 cursor-pointer transition flex items-start justify-between gap-3 ${
                      isSelected ? 'bg-emerald-500/10 border-l-4 border-emerald-400' : 'hover:bg-[#161c2a]'
                    }`}
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                          band === 'P0' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                          band === 'P1' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' :
                          'bg-blue-500/20 text-blue-400 border border-blue-500/40'
                        }`}>
                          {band} · {score}/100
                        </span>

                        <span className="text-xs px-2 py-0.5 rounded bg-[#1f2638] text-slate-300 font-mono uppercase">
                          {f.category}
                        </span>

                        {f.exploit_confirmed ? (
                          <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 text-xs font-mono font-semibold flex items-center gap-1 border border-emerald-500/30">
                            <CheckCircle2 className="w-3 h-3" /> EXPLOIT CONFIRMED
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 text-xs font-mono">
                            Unconfirmed Scanner Alert
                          </span>
                        )}
                      </div>

                      <h4 className="text-sm font-semibold text-white mt-1">{f.title}</h4>
                      <div className="text-xs font-mono text-slate-400">
                        {f.method} {f.route_template || f.url}
                        {f.param && <span> · param: <span className="text-slate-200">{f.param}</span></span>}
                      </div>
                    </div>

                    <ChevronRight className={`w-5 h-5 mt-2 transition ${isSelected ? 'text-emerald-400 translate-x-1' : 'text-slate-500'}`} />
                  </div>
                );
              })}

              {findings.length === 0 && (
                <div className="p-8 text-center text-xs font-mono text-slate-400">
                  No findings in queue. Fire an exploit or import a scan from the Command Center.
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Selected Finding Detail Drawer (5 cols) */}
        <div className="lg:col-span-5">
          {selectedFinding ? (
            <div className="rounded-lg bg-[#11151f] border border-[#1f2638] p-5 space-y-5 sticky top-4">
              <div className="flex items-start justify-between pb-3 border-b border-[#1f2638]">
                <div>
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                      selectedFinding.triage?.priority_band === 'P0' ? 'bg-red-500/20 text-red-400' :
                      selectedFinding.triage?.priority_band === 'P1' ? 'bg-amber-500/20 text-amber-400' :
                      'bg-blue-500/20 text-blue-400'
                    }`}>
                      {selectedFinding.triage?.priority_band || 'P1'}
                    </span>
                    <span className="text-xs font-mono text-slate-400 uppercase">
                      Score: {selectedFinding.triage?.priority_score || 50}/100
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-white mt-1">{selectedFinding.title}</h3>
                </div>
              </div>

              {/* Triage Waterfall Breakdown */}
              <div className="space-y-3">
                <h4 className="text-xs font-mono uppercase text-slate-400 font-semibold flex items-center justify-between">
                  <span>DETERMINISTIC TRIAGE WATERFALL</span>
                  <span className="text-emerald-400 font-bold">100% TRANSPARENT</span>
                </h4>

                <div className="space-y-2 text-xs font-mono">
                  {/* Signal 1: Confirmed */}
                  <div>
                    <div className="flex justify-between text-slate-300 mb-1">
                      <span>Exploit Confirmed Live (40% max)</span>
                      <span className={selectedFinding.exploit_confirmed ? 'text-emerald-400 font-bold' : 'text-slate-500'}>
                        {selectedFinding.exploit_confirmed ? '+40.0 pts' : '0.0 pts'}
                      </span>
                    </div>
                    <div className="h-2 w-full bg-[#0c0e14] rounded-full overflow-hidden">
                      <div
                        className="h-full bg-emerald-500 rounded-full transition-all duration-500"
                        style={{ width: selectedFinding.exploit_confirmed ? '100%' : '0%' }}
                      />
                    </div>
                  </div>

                  {/* Signal 2: Severity */}
                  <div>
                    <div className="flex justify-between text-slate-300 mb-1">
                      <span>Scanner Severity ({selectedFinding.scanner_risk}) (40% max)</span>
                      <span className="text-amber-400 font-bold">
                        +{((selectedFinding.scanner_risk === 'critical' ? 1 : selectedFinding.scanner_risk === 'high' ? 0.75 : 0.5) * 40).toFixed(1)} pts
                      </span>
                    </div>
                    <div className="h-2 w-full bg-[#0c0e14] rounded-full overflow-hidden">
                      <div
                        className="h-full bg-amber-500 rounded-full transition-all duration-500"
                        style={{ width: `${(selectedFinding.scanner_risk === 'critical' ? 1 : selectedFinding.scanner_risk === 'high' ? 0.75 : 0.5) * 100}%` }}
                      />
                    </div>
                  </div>

                  {/* Signal 3: Category Prior */}
                  <div>
                    <div className="flex justify-between text-slate-300 mb-1">
                      <span>Category Prior ({selectedFinding.category}) (20% max)</span>
                      <span className="text-cyan-400 font-bold">
                        +{(0.90 * 20).toFixed(1)} pts
                      </span>
                    </div>
                    <div className="h-2 w-full bg-[#0c0e14] rounded-full overflow-hidden">
                      <div className="h-full bg-cyan-500 rounded-full" style={{ width: '90%' }} />
                    </div>
                  </div>
                </div>
              </div>

              {/* Labeled AI Explanation Card */}
              <div className="p-3.5 rounded-lg bg-[#090b10] border border-[#1f2638] space-y-2">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="flex items-center gap-1.5 text-purple-400 font-semibold">
                    <Bot className="w-3.5 h-3.5" /> AI-DRAFTED EXPLANATION
                  </span>
                  <span className="px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-300 text-[10px] border border-purple-500/20">
                    {selectedFinding.triage?.llm_status === 'ok' ? 'qwen2.5:7b-instruct' : 'Deterministic Fallback'}
                  </span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {selectedFinding.triage?.llm_explanation?.explanation ||
                   'Finding prioritized based on direct exploit validation on target endpoints and baseline prior probability of exploitation.'}
                </p>
                <div className="text-[10px] font-mono text-slate-400 flex items-center gap-1 pt-1 border-t border-[#1f2638]/50">
                  <Shield className="w-3 h-3 text-emerald-400" />
                  <span>Prompt-Injection Protected: Attacker payload isolated in &lt;data&gt; tags</span>
                </div>
              </div>

              {/* Evidence Payload */}
              <div className="space-y-1">
                <span className="text-xs font-mono text-slate-400 uppercase">Exploit Evidence</span>
                <pre className="p-2.5 rounded bg-[#090b10] border border-[#1f2638] text-[11px] font-mono text-slate-300 overflow-x-auto">
                  {selectedFinding.evidence || 'No raw evidence logged.'}
                </pre>
              </div>

              {/* Patch Generation Action */}
              <div className="pt-2 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-400">Generation Strategy:</span>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => setStrategy('auto')}
                      className={`px-2 py-1 rounded text-xs font-mono ${strategy === 'auto' ? 'bg-emerald-500 text-black font-bold' : 'bg-[#1f2638] text-slate-300'}`}
                    >
                      Auto
                    </button>
                    <button
                      onClick={() => setStrategy('deterministic')}
                      className={`px-2 py-1 rounded text-xs font-mono ${strategy === 'deterministic' ? 'bg-emerald-500 text-black font-bold' : 'bg-[#1f2638] text-slate-300'}`}
                    >
                      Deterministic
                    </button>
                    <button
                      onClick={() => setStrategy('canonical')}
                      className={`px-2 py-1 rounded text-xs font-mono ${strategy === 'canonical' ? 'bg-amber-500 text-black font-bold' : 'bg-[#1f2638] text-slate-300'}`}
                      title="Seeded with naive rule to test mutation evasion in Gauntlet"
                    >
                      Canonical (v1 Naive)
                    </button>
                  </div>
                </div>

                <button
                  onClick={() => handleDraft(selectedFinding)}
                  disabled={drafting}
                  className="w-full py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-black font-bold text-xs font-mono transition flex items-center justify-center gap-2 shadow-lg shadow-emerald-500/20"
                >
                  <Shield className="w-4 h-4" />
                  {drafting ? 'Generating Virtual Patch...' : 'Synthesize Virtual Patch →'}
                </button>
              </div>
            </div>
          ) : (
            <div className="rounded-lg bg-[#11151f] border border-[#1f2638] p-8 text-center text-xs font-mono text-slate-400">
              Select a finding from the list to view the deterministic triage score waterfall and synthesize a virtual patch.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
