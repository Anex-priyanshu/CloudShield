"use client";

import React, { useState } from "react";
import {
  FileCode2,
  Upload,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Play,
  FileCheck,
  Flame,
  Code2,
  Sparkles,
  ArrowRight,
} from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { SeverityPill } from "@/components/ui/SeverityPill";
import { api } from "@/lib/api";

export default function IacScannerPage() {
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState<any | null>(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [highlightedLine, setHighlightedLine] = useState<number | null>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      setSelectedFiles(Array.from(e.target.files));
      setErrorMsg("");
    }
  };

  const handleRunScan = async () => {
    if (selectedFiles.length === 0) return;
    setLoading(true);
    setErrorMsg("");
    try {
      const res = await api.scanIacFiles(selectedFiles);
      setScanResult(res);
      setHighlightedLine(res.findings?.[0]?.line_start || null);
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to analyze files");
    } finally {
      setLoading(false);
    }
  };

  const handleLoadSample = async (sampleType: "insecure" | "secure") => {
    setLoading(true);
    setErrorMsg("");
    try {
      const res = await api.scanIacSample(sampleType);
      setScanResult(res);
      setHighlightedLine(res.findings?.[0]?.line_start || null);
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to load sample");
    } finally {
      setLoading(false);
    }
  };

  const codeLines = (scanResult?.raw_code || "").split("\n");

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
              <FileCode2 className="w-6 h-6 text-cyan-400" />
              Infrastructure as Code (IaC) Scanner
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Shift-left security assessment: scan Terraform (.tf) and CloudFormation files before deployment to prevent cloud misconfigurations.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => handleLoadSample("insecure")}
              disabled={loading}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-red-950/40 hover:bg-red-900/60 text-red-300 border border-red-800/80 rounded-xl text-xs font-bold transition"
            >
              <Sparkles className="w-3.5 h-3.5 text-red-400" />
              <span>Load Insecure Sample (FAIL Gate)</span>
            </button>

            <button
              onClick={() => handleLoadSample("secure")}
              disabled={loading}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-300 border border-emerald-800/80 rounded-xl text-xs font-bold transition"
            >
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span>Load Secure Sample (PASS Gate)</span>
            </button>
          </div>
        </div>

        {/* Upload Dropzone */}
        <div className="bg-[#111B2E] border-2 border-dashed border-[#24324D] hover:border-blue-500/60 rounded-2xl p-6 text-center transition space-y-4">
          <Upload className="w-10 h-10 text-cyan-400 mx-auto" />
          <div>
            <h3 className="text-sm font-bold text-white">
              Upload Terraform or CloudFormation Files
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Supports <code className="text-cyan-300 font-mono">.tf</code>,{" "}
              <code className="text-cyan-300 font-mono">.json</code>,{" "}
              <code className="text-cyan-300 font-mono">.yaml</code> (Max 5MB each)
            </p>
          </div>

          <div className="flex items-center justify-center gap-3">
            <label className="cursor-pointer px-4 py-2 bg-[#090f1b] hover:bg-[#162238] border border-[#24324D] text-slate-200 text-xs font-semibold rounded-xl transition">
              <span>Choose Files...</span>
              <input
                type="file"
                multiple
                accept=".tf,.json,.yaml,.yml"
                onChange={handleFileUpload}
                className="hidden"
              />
            </label>

            {selectedFiles.length > 0 && (
              <button
                onClick={handleRunScan}
                disabled={loading}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold rounded-xl transition shadow-lg shadow-blue-600/25 disabled:opacity-50"
              >
                {loading ? "Analyzing..." : `Scan ${selectedFiles.length} File(s)`}
              </button>
            )}
          </div>

          {selectedFiles.length > 0 && (
            <div className="flex flex-wrap justify-center gap-2 pt-2">
              {selectedFiles.map((f, i) => (
                <span
                  key={i}
                  className="text-xs font-mono text-cyan-300 bg-[#090f1b] border border-[#24324D] px-2.5 py-1 rounded-lg"
                >
                  {f.name} ({Math.round(f.size / 1024)} KB)
                </span>
              ))}
            </div>
          )}

          {errorMsg && (
            <div className="text-xs text-red-400 bg-red-950/40 border border-red-800 p-2.5 rounded-xl max-w-md mx-auto">
              {errorMsg}
            </div>
          )}
        </div>

        {/* Scan Results & Deployment Gate */}
        {scanResult && (
          <div className="space-y-6">
            {/* Gate Verdict Banner */}
            <div
              className={`p-6 rounded-2xl border flex flex-col md:flex-row md:items-center justify-between gap-4 ${
                scanResult.verdict === "PASS"
                  ? "bg-emerald-950/30 border-emerald-800/80 text-emerald-300"
                  : "bg-red-950/30 border-red-800/80 text-red-300"
              }`}
            >
              <div className="flex items-center gap-4">
                <div
                  className={`w-14 h-14 rounded-2xl flex items-center justify-center font-extrabold text-2xl font-mono shadow-xl ${
                    scanResult.verdict === "PASS"
                      ? "bg-emerald-600 text-white shadow-emerald-500/20"
                      : "bg-red-600 text-white shadow-red-500/20 animate-pulse"
                  }`}
                >
                  {scanResult.verdict}
                </div>
                <div>
                  <h2 className="text-xl font-extrabold text-white">
                    Deployment Gate: {scanResult.verdict === "PASS" ? "PASSED" : "FAILED (BLOCKED)"}
                  </h2>
                  <p className="text-xs text-slate-300 mt-1">
                    {scanResult.summary?.gate_reason}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-4 text-xs font-mono">
                <div className="text-center px-3 py-1.5 bg-[#090f1b]/60 rounded-xl border border-slate-700">
                  <div className="text-[10px] text-slate-400">CRITICAL</div>
                  <div className="text-base font-bold text-red-400">
                    {scanResult.summary?.critical || 0}
                  </div>
                </div>
                <div className="text-center px-3 py-1.5 bg-[#090f1b]/60 rounded-xl border border-slate-700">
                  <div className="text-[10px] text-slate-400">HIGH</div>
                  <div className="text-base font-bold text-orange-400">
                    {scanResult.summary?.high || 0}
                  </div>
                </div>
                <div className="text-center px-3 py-1.5 bg-[#090f1b]/60 rounded-xl border border-slate-700">
                  <div className="text-[10px] text-slate-400">MEDIUM</div>
                  <div className="text-base font-bold text-amber-400">
                    {scanResult.summary?.medium || 0}
                  </div>
                </div>
                <div className="text-center px-3 py-1.5 bg-[#090f1b]/60 rounded-xl border border-slate-700">
                  <div className="text-[10px] text-slate-400">LOW</div>
                  <div className="text-base font-bold text-blue-400">
                    {scanResult.summary?.low || 0}
                  </div>
                </div>
              </div>
            </div>

            {/* Two Column: Findings List (left) · Source Code Viewer (right) */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
              {/* Findings */}
              <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-5 space-y-4">
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  IaC Misconfigurations ({scanResult.findings?.length || 0})
                </h3>

                <div className="space-y-3 max-h-[550px] overflow-y-auto pr-1">
                  {scanResult.findings?.length > 0 ? (
                    scanResult.findings.map((f: any, idx: number) => (
                      <div
                        key={idx}
                        onClick={() => setHighlightedLine(f.line_start)}
                        className={`p-3.5 rounded-xl border transition cursor-pointer space-y-2 ${
                          highlightedLine === f.line_start
                            ? "bg-blue-950/40 border-cyan-500 shadow-md"
                            : "bg-[#090f1b] border-[#1e2d48] hover:border-slate-500"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <SeverityPill severity={f.severity} size="sm" />
                          <span className="font-mono text-xs font-bold text-red-400">
                            Risk: {f.risk_score}
                          </span>
                        </div>

                        <div className="text-xs font-bold text-white leading-tight">
                          {f.check_name}
                        </div>

                        <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                          <span>Lines: {f.line_start}-{f.line_end}</span>
                          <span className="text-cyan-300">{f.resource}</span>
                        </div>

                        <p className="text-[11px] text-slate-400 italic">
                          {f.guideline}
                        </p>
                      </div>
                    ))
                  ) : (
                    <div className="py-16 text-center text-xs text-emerald-400 font-semibold">
                      ✓ No infrastructure misconfigurations detected!
                    </div>
                  )}
                </div>
              </div>

              {/* Source Code Viewer with Line Highlights */}
              <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-5 space-y-3">
                <div className="flex items-center justify-between border-b border-[#24324D] pb-2">
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                    <Code2 className="w-4 h-4 text-cyan-400" />
                    Source Code Viewer
                  </h3>
                  <span className="text-xs text-slate-400 font-mono">
                    {codeLines.length} lines
                  </span>
                </div>

                <div className="bg-[#090f1b] border border-[#1e2d48] rounded-xl p-3 font-mono text-xs max-h-[550px] overflow-y-auto leading-relaxed">
                  {codeLines.map((line: string, i: number) => {
                    const lineNum = i + 1;
                    const isFailing = scanResult.findings?.some(
                      (f: any) => lineNum >= f.line_start && lineNum <= f.line_end
                    );
                    const isHighlighted = highlightedLine === lineNum;

                    return (
                      <div
                        key={i}
                        className={`flex py-0.5 px-2 rounded ${
                          isHighlighted
                            ? "bg-cyan-950/80 border-l-2 border-cyan-400 text-white"
                            : isFailing
                            ? "bg-red-950/30 text-red-200"
                            : "text-slate-400 hover:bg-slate-900"
                        }`}
                      >
                        <span className="w-8 select-none text-slate-600 text-right pr-3 shrink-0">
                          {lineNum}
                        </span>
                        <span className="whitespace-pre overflow-x-auto">{line}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
