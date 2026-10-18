"use client";

import React, { useEffect, useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import {
  Radar,
  Play,
  XCircle,
  CheckCircle2,
  Clock,
  ArrowRight,
  Flame,
  AlertTriangle,
  RotateCcw,
  GitCompare,
  Layers,
  ChevronRight,
  RefreshCw,
} from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { SeverityPill } from "@/components/ui/SeverityPill";
import { FindingDrawer } from "@/components/findings/FindingDrawer";
import { api } from "@/lib/api";
import { wsClient } from "@/lib/ws";

function ScansContent() {
  const searchParams = useSearchParams();
  const queryScanId = searchParams.get("scan_id");

  const [scans, setScans] = useState<any[]>([]);
  const [activeScan, setActiveScan] = useState<any | null>(null);
  const [activeScanFindings, setActiveScanFindings] = useState<any[]>([]);
  const [progress, setProgress] = useState<{ step: string; percent: number }>({
    step: "Ready",
    percent: 0,
  });
  const [selectedFinding, setSelectedFinding] = useState<any | null>(null);
  const [diffData, setDiffData] = useState<any | null>(null);

  const stepsList = [
    { key: "iam", label: "IAM & Credentials" },
    { key: "storage", label: "S3 Buckets & Access" },
    { key: "network", label: "Security Groups & VPC" },
    { key: "logging", label: "CloudTrail & Auditing" },
    { key: "encryption", label: "KMS & Volume Encryption" },
    { key: "backup", label: "Snapshots & Retention" },
    { key: "scoring", label: "Contextual Risk Scoring" },
  ];

  const loadScans = async () => {
    try {
      const list = await api.getScans();
      setScans(list);

      const targetId = queryScanId ? parseInt(queryScanId) : list.length > 0 ? list[0].id : null;
      if (targetId) {
        loadScanDetail(targetId);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const loadScanDetail = async (id: number) => {
    try {
      const scanData = await api.getScan(id);
      setActiveScan(scanData);
      const findingsData = await api.getFindings({ scan_id: id });
      setActiveScanFindings(findingsData.items || findingsData || []);

      if (scanData.status === "completed") {
        setProgress({ step: "Scan Completed", percent: 100 });
      } else if (scanData.status === "running") {
        setProgress({ step: "Scanning in progress...", percent: 45 });
      }

      // Load comparison diff if available
      try {
        const compare = await api.compareScan(id);
        setDiffData(compare);
      } catch {
        setDiffData(null);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadScans();

    // WebSocket real-time progress listeners
    const unsubProgress = wsClient.on("scan.progress", (data: any) => {
      setProgress({ step: data.step, percent: data.percent });
    });

    const unsubNewFinding = wsClient.on("finding.new", (newFinding: any) => {
      setActiveScanFindings((prev) => [newFinding, ...prev]);
    });

    const unsubCompleted = wsClient.on("scan.completed", (data: any) => {
      setProgress({ step: "Scan Completed", percent: 100 });
      loadScans();
    });

    return () => {
      unsubProgress();
      unsubNewFinding();
      unsubCompleted();
    };
  }, [queryScanId]);

  const handleCancelScan = async () => {
    if (!activeScan) return;
    try {
      await api.cancelScan(activeScan.id);
      loadScanDetail(activeScan.id);
    } catch (err: any) {
      alert(err.message || "Failed to cancel scan");
    }
  };

  const isRunning = activeScan?.status === "running";

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
              <Radar className="w-6 h-6 text-cyan-400" />
              Posture Scan Console & History
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Live inspection progress, CIS control validation, and historical scan comparison.
            </p>
          </div>
        </div>

        {/* Live Scan Execution Card */}
        {activeScan && (
          <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-6 space-y-6 shadow-xl">
            <div className="flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2.5">
                  <h2 className="text-lg font-bold text-white">
                    Scan #{activeScan.id}
                  </h2>
                  <span
                    className={`text-xs font-bold px-2.5 py-0.5 rounded-full uppercase border ${
                      isRunning
                        ? "bg-blue-950/80 text-blue-400 border-blue-700 animate-pulse"
                        : activeScan.status === "completed"
                        ? "bg-emerald-950/80 text-emerald-400 border-emerald-700"
                        : "bg-red-950/80 text-red-400 border-red-700"
                    }`}
                  >
                    {activeScan.status}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Started: {activeScan.started_at ? new Date(activeScan.started_at).toLocaleString() : "Just now"}
                </p>
              </div>

              {isRunning && (
                <button
                  onClick={handleCancelScan}
                  className="px-3 py-1.5 bg-red-950/40 hover:bg-red-900/60 text-red-400 text-xs font-semibold rounded-lg border border-red-800 transition flex items-center gap-1.5"
                >
                  <XCircle className="w-3.5 h-3.5" />
                  Cancel Scan
                </button>
              )}
            </div>

            {/* Progress Bar */}
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-semibold">
                <span className="text-slate-300 flex items-center gap-2">
                  {isRunning && <RefreshCw className="w-3.5 h-3.5 text-cyan-400 animate-spin" />}
                  {progress.step}
                </span>
                <span className="text-cyan-400 font-mono">{progress.percent}%</span>
              </div>
              <div className="w-full h-3 bg-[#090f1b] rounded-full overflow-hidden border border-[#24324D]">
                <div
                  style={{ width: `${progress.percent}%` }}
                  className="h-full bg-gradient-to-r from-blue-600 via-cyan-400 to-emerald-400 rounded-full transition-all duration-300 shadow-lg shadow-cyan-500/20"
                />
              </div>
            </div>

            {/* Step Timeline */}
            <div className="grid grid-cols-2 md:grid-cols-7 gap-2">
              {stepsList.map((step, idx) => {
                const stepPct = ((idx + 1) / stepsList.length) * 100;
                const isPast = progress.percent >= stepPct;
                const isCurrent = progress.percent >= (idx / stepsList.length) * 100 && !isPast;

                return (
                  <div
                    key={step.key}
                    className={`p-2.5 rounded-xl border text-center transition ${
                      isPast
                        ? "bg-emerald-950/20 border-emerald-800/60 text-emerald-300"
                        : isCurrent
                        ? "bg-blue-950/30 border-blue-600 text-cyan-300 shadow-sm shadow-blue-500/20"
                        : "bg-[#090f1b] border-[#1e2d48] text-slate-500"
                    }`}
                  >
                    <div className="text-[10px] font-mono font-bold uppercase">
                      {isPast ? "✓ Done" : isCurrent ? "⚡ Scanning" : `0${idx + 1}`}
                    </div>
                    <div className="text-[11px] font-semibold mt-1 truncate">
                      {step.label}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Diff Comparison Badge Banner */}
            {diffData && (
              <div className="p-3 bg-[#090f1b] border border-[#24324D] rounded-xl flex items-center justify-between text-xs">
                <div className="flex items-center gap-2 text-slate-300 font-medium">
                  <GitCompare className="w-4 h-4 text-cyan-400" />
                  <span>Comparison with Previous Scan #{diffData.previous_scan_id}:</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-red-400 font-semibold font-mono">
                    +{diffData.new_findings || 0} New
                  </span>
                  <span className="text-emerald-400 font-semibold font-mono">
                    -{diffData.fixed_findings || 0} Remediated
                  </span>
                  <span className="text-slate-400 font-semibold font-mono">
                    {diffData.unchanged_findings || 0} Unchanged
                  </span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Live Discovered Findings During Scan */}
        <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Discovered Findings ({activeScanFindings.length})
            </h3>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[#24324D] text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                  <th className="py-2.5 px-3">Score</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Finding Title</th>
                  <th className="py-2.5 px-3">Resource ID</th>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d48]">
                {activeScanFindings.slice(0, 30).map((f: any) => (
                  <tr key={f.id} className="hover:bg-[#162238] transition cursor-pointer" onClick={() => setSelectedFinding(f)}>
                    <td className="py-2.5 px-3 font-mono font-bold text-red-400">
                      {f.risk_score}
                    </td>
                    <td className="py-2.5 px-3">
                      <SeverityPill severity={f.severity} size="sm" />
                    </td>
                    <td className="py-2.5 px-3 font-semibold text-white truncate max-w-sm">
                      {f.title}
                    </td>
                    <td className="py-2.5 px-3 text-cyan-300 font-mono truncate max-w-[200px]">
                      {f.resource_id}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">{f.category}</td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFinding(f);
                        }}
                        className="text-xs text-blue-400 hover:text-cyan-300 font-medium"
                      >
                        Inspect →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Scan History Table */}
        <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Clock className="w-4 h-4 text-slate-400" />
            Historical Scan Runs
          </h3>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[#24324D] text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                  <th className="py-2.5 px-3">Scan ID</th>
                  <th className="py-2.5 px-3">Started</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Resources</th>
                  <th className="py-2.5 px-3">Findings</th>
                  <th className="py-2.5 px-3">Risk Score</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d48]">
                {scans.length > 0 ? (
                  scans.map((s) => (
                    <tr key={s.id} className="hover:bg-[#162238] transition">
                      <td className="py-2.5 px-3 font-mono font-bold text-slate-200">
                        #{s.id}
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">
                        {s.started_at ? new Date(s.started_at).toLocaleString() : "Unknown"}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="font-semibold text-slate-200 uppercase text-[11px]">
                          {s.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300 font-mono">
                        {s.total_resources}
                      </td>
                      <td className="py-2.5 px-3 font-mono font-bold text-red-400">
                        {s.total_findings}
                      </td>
                      <td className="py-2.5 px-3 font-mono font-extrabold text-white">
                        {s.account_risk_score} / 100
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => loadScanDetail(s.id)}
                          className="px-2.5 py-1 bg-[#090f1b] hover:bg-blue-600 hover:text-white text-blue-400 rounded-lg text-xs font-semibold border border-[#24324D] transition"
                        >
                          View Scan
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-slate-400 text-xs">
                      No posture scans recorded yet. Connect an AWS account and run a scan to inspect CIS controls.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Drawer */}
      <FindingDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onStatusUpdated={() => {
          setSelectedFinding(null);
          if (activeScan) loadScanDetail(activeScan.id);
        }}
      />
    </AppShell>
  );
}

export default function ScansPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[#0B1220] flex items-center justify-center text-slate-400">Loading scan console...</div>}>
      <ScansContent />
    </Suspense>
  );
}
