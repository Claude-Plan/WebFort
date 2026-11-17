import React, { useState, useEffect } from 'react';
import { Shield, LayoutDashboard, Layers, Cpu, Award, BarChart3, AlertTriangle, Activity } from 'lucide-react';
import CommandCenter from './components/CommandCenter';
import FindingsQueue from './components/FindingsQueue';
import PatchStudio from './components/PatchStudio';
import ProofPage from './components/ProofPage';
import BenchmarkEvents from './components/BenchmarkEvents';

export default function App() {
  const [activeTab, setActiveTab] = useState('command');
  const [health, setHealth] = useState(null);
  const [findings, setFindings] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [patches, setPatches] = useState([]);
  const [selectedPatch, setSelectedPatch] = useState(null);
  const [stats, setStats] = useState({
    totalFindings: 0,
    confirmedExploits: 0,
    zapNoise: 0,
    p0Count: 0,
    blocksCount: 0
  });

  useEffect(() => {
    fetchHealth();
    fetchFindings();
    fetchPatches();
    fetchEvents();

    const healthInterval = setInterval(fetchHealth, 5000);
    const findingsInterval = setInterval(fetchFindings, 4000);
    const eventsInterval = setInterval(fetchEvents, 3000);

    // Setup SSE listener for live gauntlet and hardening updates
    const sse = new EventSource('/stream');
    sse.addEventListener('gauntlet.case', (e) => {
      // Handled inside PatchStudio via state if active
    });
    sse.addEventListener('hardening.progress', (e) => {
      // Handled inside PatchStudio
    });

    return () => {
      clearInterval(healthInterval);
      clearInterval(findingsInterval);
      clearInterval(eventsInterval);
      sse.close();
    };
  }, []);

  const fetchHealth = async () => {
    try {
      const res = await fetch('/api/v1/health');
      if (res.ok) {
        const body = await res.json();
        setHealth(body.data);
      }
    } catch {}
  };

  const fetchFindings = async () => {
    try {
      const res = await fetch('/api/v1/findings');
      if (res.ok) {
        const body = await res.json();
        const list = body.data || [];
        setFindings(list);
        if (!selectedFinding && list.length > 0) {
          setSelectedFinding(list[0]);
        }

        // Compute aggregate stats
        const confirmed = list.filter(f => f.exploit_confirmed).length;
        const p0s = list.filter(f => f.triage?.priority_band === 'P0').length;
        setStats(prev => ({
          ...prev,
          totalFindings: list.length,
          confirmedExploits: confirmed,
          zapNoise: list.length - confirmed,
          p0Count: p0s
        }));
      }
    } catch {}
  };

  const fetchPatches = async () => {
    try {
      const res = await fetch('/api/v1/patches');
      if (res.ok) {
        const body = await res.json();
        const list = body.data || [];
        setPatches(list);
        if (!selectedPatch && list.length > 0) {
          setSelectedPatch(list[0]);
        }
      }
    } catch {}
  };

  const fetchEvents = async () => {
    try {
      const res = await fetch('/api/v1/events');
      if (res.ok) {
        const body = await res.json();
        const list = body.data || [];
        const blocks = list.filter(e => e.decision === 'block').length;
        setStats(prev => ({ ...prev, blocksCount: blocks }));
      }
    } catch {}
  };

  const handleRunRecipe = async (recipeId) => {
    const res = await fetch('/api/v1/recipes/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipe_id: recipeId })
    });
    if (res.ok) {
      await fetchFindings();
      setActiveTab('findings');
    }
  };

  const handleImportZap = async () => {
    // Standard OWASP ZAP Baseline alert report simulation
    const zapSample = {
      site: [{
        alerts: [
          { alert: 'SQL Injection - Generic Error Based', riskcode: '3', pluginId: '40018', uri: '/rest/products/search', instances: [{ uri: '/rest/products/search?q=test', method: 'GET', param: 'q' }] },
          { alert: 'Cross Site Scripting (Reflected)', riskcode: '3', pluginId: '40012', uri: '/#/search', instances: [{ uri: '/#/search?q=<script>', method: 'GET', param: 'q' }] },
          { alert: 'Directory Browsing / Path Traversal', riskcode: '2', pluginId: '10045', uri: '/ftp', instances: [{ uri: '/ftp', method: 'GET' }] },
          { alert: 'Missing Anti-clickjacking Header', riskcode: '1', pluginId: '10020', uri: '/', instances: [{ uri: '/', method: 'GET' }] },
          { alert: 'Strict-Transport-Security Header Not Set', riskcode: '1', pluginId: '10035', uri: '/', instances: [{ uri: '/', method: 'GET' }] },
          { alert: 'Content Security Policy (CSP) Header Not Set', riskcode: '2', pluginId: '10038', uri: '/', instances: [{ uri: '/', method: 'GET' }] },
          { alert: 'Cookie Without Secure Flag', riskcode: '1', pluginId: '10011', uri: '/', instances: [{ uri: '/', method: 'GET' }] },
          { alert: 'Vulnerable JS Library (Outdated Angular)', riskcode: '2', pluginId: '10003', uri: '/main.js', instances: [{ uri: '/main.js', method: 'GET' }] },
          { alert: 'X-Content-Type-Options Header Missing', riskcode: '1', pluginId: '10021', uri: '/', instances: [{ uri: '/', method: 'GET' }] },
          { alert: 'Server Leaks Version Information via Header', riskcode: '0', pluginId: '10036', uri: '/', instances: [{ uri: '/', method: 'GET' }] }
        ]
      }]
    };

    const res = await fetch('/api/v1/scans/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(zapSample)
    });
    if (res.ok) {
      await fetchFindings();
      setActiveTab('findings');
    }
  };

  const handleDraftPatch = async (findingId, strategy) => {
    const res = await fetch(`/api/v1/findings/${findingId}/patches`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ strategy })
    });
    if (res.ok) {
      const body = await res.json();
      await fetchPatches();
      setSelectedPatch(body.data);
      setActiveTab('studio');
    }
  };

  const handleVerifyPatch = async (patchId) => {
    const res = await fetch(`/api/v1/patches/${patchId}/verify`, { method: 'POST' });
    if (res.ok) {
      await fetchPatches();
      await fetchEvents();
    }
  };

  const handleDeployPatch = async (patchId, mode) => {
    const res = await fetch(`/api/v1/patches/${patchId}/deploy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode })
    });
    if (res.ok) {
      await fetchPatches();
    }
  };

  const handleRollbackPatch = async (patchId) => {
    const res = await fetch(`/api/v1/patches/${patchId}/rollback`, { method: 'POST' });
    if (res.ok) {
      await fetchPatches();
    }
  };

  const handleRunGauntlet = async (patchId, budget, seed) => {
    const res = await fetch(`/api/v1/patches/${patchId}/gauntlet`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mutation_budget: budget, seed })
    });
    if (res.ok) {
      const body = await res.json();
      await fetchEvents();
      return body.data;
    }
    return null;
  };

  const handleRunHarden = async (patchId, maxIter, budget, seed, start) => {
    const res = await fetch(`/api/v1/patches/${patchId}/harden`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ max_iterations: maxIter, mutation_budget: budget, seed, start })
    });
    if (res.ok) {
      const body = await res.json();
      await fetchPatches();
      await fetchEvents();
      return body.data;
    }
    return null;
  };

  return (
    <div className="min-h-screen bg-[#090b10] text-[#e2e8f0] flex flex-col">
      {/* Top Navigation Bar */}
      <header className="border-b border-[#1f2638] bg-[#0c0e14]/90 backdrop-blur sticky top-0 z-50 px-4 lg:px-8 py-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-bold">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-black tracking-wider text-white text-base">PATCHPROOF</span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  PS3 ADAPTIVE WAF
                </span>
              </div>
              <div className="text-[10px] text-slate-500 font-mono">
                Continuous Firewall Verification & Vulnerability Triage
              </div>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex items-center gap-1 bg-[#11151f] p-1 rounded-lg border border-[#1f2638]">
            <button
              onClick={() => setActiveTab('command')}
              className={`px-3 py-1.5 rounded-md text-xs font-mono font-semibold transition flex items-center gap-1.5 ${
                activeTab === 'command'
                  ? 'bg-emerald-500 text-black shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-[#1f2638]/60'
              }`}
            >
              <LayoutDashboard className="w-3.5 h-3.5" />
              <span>Command Center</span>
            </button>

            <button
              onClick={() => setActiveTab('findings')}
              className={`px-3 py-1.5 rounded-md text-xs font-mono font-semibold transition flex items-center gap-1.5 ${
                activeTab === 'findings'
                  ? 'bg-emerald-500 text-black shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-[#1f2638]/60'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Triage Queue</span>
              {stats.p0Count > 0 && (
                <span className={`px-1 py-0.2 text-[9px] rounded-full font-bold ${
                  activeTab === 'findings' ? 'bg-black text-emerald-400' : 'bg-red-500 text-white'
                }`}>
                  {stats.p0Count}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('studio')}
              className={`px-3 py-1.5 rounded-md text-xs font-mono font-semibold transition flex items-center gap-1.5 ${
                activeTab === 'studio'
                  ? 'bg-emerald-500 text-black shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-[#1f2638]/60'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>Patch Studio</span>
            </button>

            <button
              onClick={() => setActiveTab('proof')}
              className={`px-3 py-1.5 rounded-md text-xs font-mono font-semibold transition flex items-center gap-1.5 ${
                activeTab === 'proof'
                  ? 'bg-emerald-500 text-black shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-[#1f2638]/60'
              }`}
            >
              <Award className="w-3.5 h-3.5" />
              <span>Proof Report</span>
            </button>

            <button
              onClick={() => setActiveTab('benchmark')}
              className={`px-3 py-1.5 rounded-md text-xs font-mono font-semibold transition flex items-center gap-1.5 ${
                activeTab === 'benchmark'
                  ? 'bg-emerald-500 text-black shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-[#1f2638]/60'
              }`}
            >
              <BarChart3 className="w-3.5 h-3.5" />
              <span>Benchmark & Events</span>
            </button>
          </nav>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 lg:p-8">
        {activeTab === 'command' && (
          <CommandCenter
            health={health}
            stats={stats}
            onRunRecipe={handleRunRecipe}
            onImportZap={handleImportZap}
            onSelectFinding={(f) => {
              setSelectedFinding(f);
              setActiveTab('findings');
            }}
            findings={findings}
          />
        )}

        {activeTab === 'findings' && (
          <FindingsQueue
            findings={findings}
            onDraftPatch={handleDraftPatch}
            selectedFinding={selectedFinding}
            setSelectedFinding={setSelectedFinding}
          />
        )}

        {activeTab === 'studio' && (
          <PatchStudio
            patches={patches}
            selectedPatch={selectedPatch}
            setSelectedPatch={setSelectedPatch}
            onVerifyPatch={handleVerifyPatch}
            onDeployPatch={handleDeployPatch}
            onRollbackPatch={handleRollbackPatch}
            onRunGauntlet={handleRunGauntlet}
            onRunHarden={handleRunHarden}
            findings={findings}
          />
        )}

        {activeTab === 'proof' && (
          <ProofPage
            patches={patches}
            selectedPatch={selectedPatch}
          />
        )}

        {activeTab === 'benchmark' && (
          <BenchmarkEvents />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-[#1f2638] bg-[#0c0e14] py-3 px-8 text-xs font-mono text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block"></span>
          <span>PatchProof Engine v1.0 · RNSIT CSE Hackathon · 17 Nov 2026</span>
        </div>
        <div>
          <span>Local Lab Defense Architecture (Postgres + Juice Shop Target + ed25519)</span>
        </div>
      </footer>
    </div>
  );
}
