"use client";

import React, { useEffect, useState } from "react";
import {
  FileText,
  Download,
  FileCode,
  FileSpreadsheet,
  Clock,
  Shield,
  CheckCircle,
  ExternalLink,
  Loader2,
} from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { api } from "@/lib/api";

export default function ReportsPage() {
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloadingId, setDownloadingId] = useState<number | null>(null);

  const loadReports = async () => {
    try {
      const data = await api.getReports();
      setReports(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReports();
  }, []);

  const handleDownloadPdf = async (scanId: number) => {
    setDownloadingId(scanId);
    try {
      const blob = await api.downloadPdf(scanId);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `CloudShield_Assessment_Scan_${scanId}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err: any) {
      alert(err.message || "Failed to download PDF report");
    } finally {
      setDownloadingId(null);
    }
  };

  const handleDownloadCsv = async (scanId: number) => {
    try {
      const blob = await api.downloadCsv(scanId);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `CloudShield_Findings_Scan_${scanId}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err: any) {
      alert(err.message || "Failed to export CSV");
    }
  };

  const handleDownloadJson = async (scanId: number) => {
    try {
      const json = await api.downloadJson(scanId);
      const blob = new Blob([JSON.stringify(json, null, 2)], {
        type: "application/json",
      });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `CloudShield_Scan_${scanId}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err: any) {
      alert(err.message || "Failed to export JSON");
    }
  };

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
              <FileText className="w-6 h-6 text-cyan-400" />
              Security Posture Audit Reports
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Download formal PDF executive assessment reports, CSV raw findings, and full JSON audit logs.
            </p>
          </div>
        </div>

        {/* Reports Table Card */}
        <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-5 space-y-4 shadow-xl">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Generated Scan Reports ({reports.length})
            </h3>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[#24324D] text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-3">Scan ID</th>
                  <th className="py-3 px-3">Account Name</th>
                  <th className="py-3 px-3">Scan Date</th>
                  <th className="py-3 px-3">Risk Score</th>
                  <th className="py-3 px-3">Total Findings</th>
                  <th className="py-3 px-3 text-right">Downloads</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d48]">
                {reports.length > 0 ? (
                  reports.map((r) => (
                    <tr key={r.scan_id} className="hover:bg-[#162238] transition">
                      <td className="py-3 px-3 font-mono font-bold text-white">
                        #{r.scan_id}
                      </td>
                      <td className="py-3 px-3">
                        <div className="font-semibold text-slate-200">
                          {r.account_name}
                        </div>
                        <span className="text-[10px] text-slate-400 font-mono">
                          {r.provider?.toUpperCase()} • {r.region}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-slate-400">
                        {r.finished_at ? new Date(r.finished_at).toLocaleString() : "Recent"}
                      </td>
                      <td className="py-3 px-3">
                        <span className="font-mono font-extrabold px-2 py-0.5 rounded bg-red-950/80 text-red-300 border border-red-800/80">
                          {r.account_risk_score} / 100
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono font-semibold text-slate-300">
                        {r.total_findings} findings
                      </td>
                      <td className="py-3 px-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleDownloadPdf(r.scan_id)}
                            disabled={downloadingId === r.scan_id}
                            className="px-3 py-1.5 bg-red-950/40 hover:bg-red-900/60 text-red-300 border border-red-800/80 rounded-lg text-xs font-bold transition flex items-center gap-1.5"
                          >
                            {downloadingId === r.scan_id ? (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                              <FileText className="w-3.5 h-3.5 text-red-400" />
                            )}
                            <span>PDF Report</span>
                          </button>

                          <button
                            onClick={() => handleDownloadCsv(r.scan_id)}
                            className="px-2.5 py-1.5 bg-[#090f1b] hover:bg-[#162238] border border-[#24324D] text-slate-300 rounded-lg text-xs font-semibold transition flex items-center gap-1"
                            title="Download CSV"
                          >
                            <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
                            <span>CSV</span>
                          </button>

                          <button
                            onClick={() => handleDownloadJson(r.scan_id)}
                            className="px-2.5 py-1.5 bg-[#090f1b] hover:bg-[#162238] border border-[#24324D] text-slate-300 rounded-lg text-xs font-semibold transition flex items-center gap-1"
                            title="Download JSON"
                          >
                            <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                            <span>JSON</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-slate-400 text-xs">
                      {loading ? "Loading reports..." : "No completed scans found. Run a scan to generate PDF reports."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
