import React, { useState, useEffect } from 'react';
import { BarChart3, Activity, Shield, CheckCircle2, XCircle, Clock } from 'lucide-react';

export default function BenchmarkEvents() {
  const [benchmark, setBenchmark] = useState(null);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchBenchmark();
    fetchEvents();
    const interval = setInterval(fetchEvents, 2500);
    return () => clearInterval(interval);
  }, []);

  const fetchBenchmark = async () => {
    try {
      const res = await fetch('/api/v1/benchmarks');
      if (res.ok) {
        const data = await res.json();
        const latest = data.data?.[0];
        if (latest) {
          const results = typeof latest.results === 'string' ? JSON.parse(latest.results) : latest.results;
          setBenchmark(results);
        }
      }
    } catch (err) {
      console.error('Failed to load benchmark:', err);
    }
  };

  const fetchEvents = async () => {
    try {
      const res = await fetch('/api/v1/events');
      if (res.ok) {
        const data = await res.json();
        setEvents(data.data || []);
      }
    } catch (err) {}
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-[#1f2638] gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-emerald-400" />
            BENCHMARK EVALUATION & PROXY TELEMETRY
          </h2>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Rigorous 4-Arm Comparison with Wilson 95% CIs · Live Request Stream
          </p>
        </div>
      </div>

      {/* 4-Arm Benchmark Strip */}
      <div className="p-5 rounded-lg bg-[#11151f] border border-[#1f2638] space-y-5">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold uppercase font-mono text-white flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-400" />
            Adversarial Mutation Bypass Rate Across 4 Arms
          </h3>
          <span className="text-xs font-mono text-slate-400">
            Stored Run (Seed: {benchmark?.config?.seed || 42}, Budget: {benchmark?.config?.mutation_budget || 60})
          </span>
        </div>

        {/* Arms Comparison Grid */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {benchmark?.arms?.map((arm) => (
            <div key={arm.arm} className="p-4 rounded-lg bg-[#090b10] border border-[#1f2638] space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-slate-200">{arm.name}</span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                  arm.bypass_rate === 0 ? 'bg-emerald-500/20 text-emerald-400' :
                  arm.bypass_rate > 0.5 ? 'bg-red-500/20 text-red-400' :
                  'bg-amber-500/20 text-amber-400'
                }`}>
                  {(arm.bypass_rate * 100).toFixed(1)}% Bypass
                </span>
              </div>

              {/* Progress bar */}
              <div className="h-3 w-full bg-[#11151f] rounded-full overflow-hidden flex">
                <div
                  className="bg-red-500 transition-all duration-500"
                  style={{ width: `${arm.bypass_rate * 100}%` }}
                />
                <div
                  className="bg-emerald-500 transition-all duration-500"
                  style={{ width: `${(1 - arm.bypass_rate) * 100}%` }}
                />
              </div>

              <div className="space-y-1 text-xs font-mono text-slate-400">
                <div className="flex justify-between">
                  <span>Effective Mutants:</span>
                  <span className="text-white">{arm.effective_mutants}</span>
                </div>
                <div className="flex justify-between">
                  <span>Blocked:</span>
                  <span className="text-emerald-400 font-bold">{arm.blocked}</span>
                </div>
                <div className="flex justify-between">
                  <span>Wilson 95% CI:</span>
                  <span className="text-cyan-400">
                    [{(arm.ci95[0] * 100).toFixed(1)}%, {(arm.ci95[1] * 100).toFixed(1)}%]
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Benign False Pos:</span>
                  <span className="text-emerald-400">{arm.benign_blocked} of {arm.benign_tested}</span>
                </div>
                <div className="flex justify-between">
                  <span>Latency p95:</span>
                  <span className="text-slate-300">{arm.latency_p95_ms} ms</span>
                </div>
              </div>
            </div>
          ))}

          {!benchmark && (
            <div className="col-span-full py-8 text-center text-xs font-mono text-slate-500">
              Loading benchmark run data...
            </div>
          )}
        </div>
      </div>

      {/* Live Proxy Event Stream */}
      <div className="p-5 rounded-lg bg-[#11151f] border border-[#1f2638] space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold uppercase font-mono text-white">
              Live Data-Plane Proxy Decision Stream (:8080)
            </h3>
          </div>
          <span className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            Streaming Real Telemetry
          </span>
        </div>

        <div className="rounded-lg bg-[#090b10] border border-[#1f2638] overflow-hidden">
          <div className="grid grid-cols-12 gap-2 p-3 bg-[#0c0e14] border-b border-[#1f2638] text-[11px] font-mono text-slate-400 uppercase">
            <span className="col-span-2">Timestamp</span>
            <span className="col-span-1">Method</span>
            <span className="col-span-4">Path</span>
            <span className="col-span-2">Decision</span>
            <span className="col-span-2">Rule / Reason</span>
            <span className="col-span-1 text-right">Latency</span>
          </div>

          <div className="divide-y divide-[#1f2638] max-h-80 overflow-y-auto text-xs font-mono">
            {events.map((ev, i) => (
              <div key={i} className="grid grid-cols-12 gap-2 p-2.5 items-center hover:bg-[#161c2a] transition">
                <span className="col-span-2 text-slate-500 text-[10px] truncate">
                  {new Date(ev.ts).toLocaleTimeString()}
                </span>
                <span className="col-span-1 text-slate-300 font-bold">{ev.method}</span>
                <span className="col-span-4 text-slate-200 truncate">{ev.path}</span>
                <span className="col-span-2">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    ev.decision === 'block' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                    ev.decision === 'allow' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' :
                    'bg-amber-500/20 text-amber-400'
                  }`}>
                    {ev.decision} ({ev.status_code})
                  </span>
                </span>
                <span className="col-span-2 text-slate-400 text-[11px] truncate">
                  {ev.rule_id || (ev.decision === 'allow' ? 'clean_forward' : 'error')}
                </span>
                <span className="col-span-1 text-right text-slate-400 text-[11px]">
                  {ev.latency_ms ? `${ev.latency_ms}ms` : '<1ms'}
                </span>
              </div>
            ))}

            {events.length === 0 && (
              <div className="p-8 text-center text-xs text-slate-500">
                No proxy traffic recorded yet. Requests passing through proxy :8080 appear here live.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
