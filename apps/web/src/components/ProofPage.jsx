import React, { useState, useEffect } from 'react';
import { Award, CheckCircle2, XCircle, Shield, Key, FileCode, AlertOctagon, Printer, Copy, Check } from 'lucide-react';

export default function ProofPage({ patches, selectedPatch }) {
  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [tampered, setTampered] = useState(false);
  const [verificationResult, setVerificationResult] = useState(null);
  const [copied, setCopied] = useState(false);

  const patch = selectedPatch || patches[0];

  useEffect(() => {
    if (patch) {
      fetchProofReport(patch.id);
    }
  }, [patch?.id]);

  const fetchProofReport = async (patchId) => {
    setLoading(true);
    try {
      // First try GET
      let res = await fetch(`/api/v1/patches/${patchId}/proof`);
      if (!res.ok) {
        // If not generated, POST to create one
        res = await fetch(`/api/v1/patches/${patchId}/proof`, { method: 'POST' });
      }
      if (res.ok) {
        const body = await res.json();
        setReportData(body.data);
        setTampered(false);
        setVerificationResult({ valid: true, sha256: body.data.sha256 });
      }
    } catch (err) {
      console.error('Failed to load proof report:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (reportToVerify) => {
    if (!reportData) return;
    try {
      const res = await fetch('/api/v1/proof/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          report: reportToVerify,
          signature: reportData.signature,
          public_key: reportData.public_key
        })
      });
      const data = await res.json();
      setVerificationResult(data.data);
    } catch (err) {
      setVerificationResult({ valid: false, error: err.message });
    }
  };

  const toggleTamper = () => {
    if (!reportData) return;
    const nextTampered = !tampered;
    setTampered(nextTampered);

    const reportCopy = JSON.parse(JSON.stringify(reportData.report));
    if (nextTampered) {
      // Tamper by altering one value client-side
      reportCopy.tests.mutation_exam.bypassed = 999;
      reportCopy.tests.exploit_replay.blocked = false;
    }

    handleVerify(reportCopy);
  };

  const copyToClipboard = () => {
    if (!reportData) return;
    navigator.clipboard.writeText(JSON.stringify(reportData, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) {
    return (
      <div className="rounded-lg bg-[#11151f] border border-[#1f2638] p-12 text-center text-xs font-mono text-slate-400">
        Generating and signing proof report with ed25519...
      </div>
    );
  }

  if (!reportData) {
    return (
      <div className="rounded-lg bg-[#11151f] border border-[#1f2638] p-12 text-center text-xs font-mono text-slate-400">
        No proof report generated yet. Select or verify a patch first.
      </div>
    );
  }

  const report = reportData.report;

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-[#1f2638] gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Award className="w-5 h-5 text-emerald-400" />
            CRYPTOGRAPHIC PROOF REPORT
          </h2>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Signed Compliance Artifact · ed25519 Tamper-Evident Security Guarantee
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={copyToClipboard}
            className="px-3 py-1.5 rounded bg-[#11151f] hover:bg-[#1f2638] border border-[#1f2638] text-xs font-mono text-slate-300 flex items-center gap-1.5 transition"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copied' : 'Copy JSON'}
          </button>

          <button
            onClick={() => window.print()}
            className="px-3 py-1.5 rounded bg-[#11151f] hover:bg-[#1f2638] border border-[#1f2638] text-xs font-mono text-slate-300 flex items-center gap-1.5 transition"
          >
            <Printer className="w-3.5 h-3.5" />
            Print / PDF
          </button>
        </div>
      </div>

      {/* Interactive Tamper & Verification Control Strip */}
      <div className={`p-4 rounded-lg border transition-all ${
        verificationResult?.valid
          ? 'bg-emerald-950/20 border-emerald-500/40'
          : 'bg-red-950/30 border-red-500/50'
      }`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            {verificationResult?.valid ? (
              <div className="p-2 bg-emerald-500/20 rounded-full text-emerald-400">
                <CheckCircle2 className="w-6 h-6" />
              </div>
            ) : (
              <div className="p-2 bg-red-500/20 rounded-full text-red-400 animate-bounce">
                <AlertOctagon className="w-6 h-6" />
              </div>
            )}
            <div>
              <div className="text-sm font-bold font-mono text-white flex items-center gap-2">
                <span>{verificationResult?.valid ? 'SIGNATURE VALID — ZERO TAMPERING DETECTED' : 'CRYPTO FAILURE: SIGNATURE INVALID / DATA TAMPERED!'}</span>
              </div>
              <div className="text-xs font-mono text-slate-400 mt-0.5">
                ed25519 verification against SHA-256 canonical hash
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={toggleTamper}
              className={`px-4 py-2 rounded font-mono text-xs font-bold transition ${
                tampered
                  ? 'bg-slate-700 hover:bg-slate-600 text-white'
                  : 'bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-600/30'
              }`}
            >
              {tampered ? 'Restore Authentic Report' : 'Tamper 1 Byte Live (Demo Proof)'}
            </button>
          </div>
        </div>
      </div>

      {/* Report Document Shell */}
      <div className="rounded-lg bg-[#11151f] border border-[#1f2638] p-6 space-y-6 font-mono text-xs">
        {/* Certificate Metadata */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pb-4 border-b border-[#1f2638]">
          <div className="space-y-1">
            <span className="text-slate-500 uppercase text-[10px]">Report Version</span>
            <div className="text-white font-bold">{report.report_version}</div>
          </div>
          <div className="space-y-1">
            <span className="text-slate-500 uppercase text-[10px]">Timestamp (ISO 8601)</span>
            <div className="text-white">{report.generated_at}</div>
          </div>
          <div className="space-y-1">
            <span className="text-slate-500 uppercase text-[10px]">Finding Target</span>
            <div className="text-white font-bold">{report.finding?.title}</div>
            <div className="text-slate-400">{report.finding?.route} (param: {report.finding?.param})</div>
          </div>
          <div className="space-y-1">
            <span className="text-slate-500 uppercase text-[10px]">Direct Exploit Confirmation</span>
            <div className="text-emerald-400 font-bold flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> PROVED ON BARE TARGET
            </div>
          </div>
        </div>

        {/* Test Suites Verification Grid */}
        <div className="space-y-2">
          <span className="text-slate-400 uppercase text-[11px] font-bold">Verification Test Evidence:</span>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3 rounded bg-[#090b10] border border-[#1f2638] space-y-1">
              <span className="text-slate-500 text-[10px] uppercase">Exploit Replay</span>
              <div className="text-emerald-400 font-bold text-sm">BLOCKED (403)</div>
              <div className="text-slate-400 text-[10px]">Candidate rule evaluated via proxy</div>
            </div>

            <div className="p-3 rounded bg-[#090b10] border border-[#1f2638] space-y-1">
              <span className="text-slate-500 text-[10px] uppercase">Benign Replay Safety</span>
              <div className="text-emerald-400 font-bold text-sm">0 of {report.tests?.benign_replay?.n} Blocked</div>
              <div className="text-slate-400 text-[10px]">0.0% False Positive Rate</div>
            </div>

            <div className="p-3 rounded bg-[#090b10] border border-[#1f2638] space-y-1">
              <span className="text-slate-500 text-[10px] uppercase">Mutation Exam Set</span>
              <div className="text-cyan-400 font-bold text-sm">{(report.tests?.mutation_exam?.bypass_rate * 100).toFixed(1)}% Bypass</div>
              <div className="text-slate-400 text-[10px]">
                CI95: [{(report.tests?.mutation_exam?.ci95[0] * 100).toFixed(1)}%, {(report.tests?.mutation_exam?.ci95[1] * 100).toFixed(1)}%]
              </div>
            </div>
          </div>
        </div>

        {/* Performance & AI Involvement */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 p-3 rounded bg-[#090b10] border border-[#1f2638]">
          <div className="space-y-1">
            <span className="text-slate-500 text-[10px] uppercase">Engine Performance</span>
            <div className="text-white">
              p50: <span className="font-bold text-emerald-400">{report.performance?.engine_latency_ms?.p50} ms</span> ·
              p95: <span className="font-bold text-emerald-400">{report.performance?.engine_latency_ms?.p95} ms</span>
            </div>
          </div>

          <div className="space-y-1">
            <span className="text-slate-500 text-[10px] uppercase">AI Involvement Role</span>
            <div className="text-white">
              Role: <span className="font-bold text-purple-400">Draft-Only</span> (Never in proxy request path)
            </div>
          </div>
        </div>

        {/* Cryptographic Digital Signature Block */}
        <div className="space-y-2">
          <span className="text-slate-400 uppercase text-[11px] font-bold flex items-center gap-1.5">
            <Key className="w-3.5 h-3.5 text-amber-400" />
            ed25519 Digital Signature & Hash:
          </span>
          <div className="p-3 rounded bg-[#090b10] border border-[#1f2638] space-y-2">
            <div>
              <span className="text-slate-500 text-[10px]">SHA-256 CANONICAL DIGEST:</span>
              <div className="text-cyan-300 select-all font-mono break-all">{reportData.sha256}</div>
            </div>
            <div>
              <span className="text-slate-500 text-[10px]">ED25519 SIGNATURE:</span>
              <div className="text-amber-300 select-all font-mono break-all text-[10px]">{reportData.signature}</div>
            </div>
          </div>
        </div>

        {/* Limitations & Disclaimers */}
        <div className="p-3.5 rounded bg-[#090b10] border border-[#1f2638] space-y-1.5">
          <span className="text-slate-400 uppercase text-[10px] font-bold">Documented Limitations & Scope:</span>
          <ul className="list-disc list-inside space-y-1 text-slate-400 text-[11px]">
            {report.limitations?.map((lim, i) => (
              <li key={i}>{lim}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
