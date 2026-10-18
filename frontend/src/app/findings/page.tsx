"use client";

import React, { useEffect, useState } from "react";
import {
  AlertOctagon,
  Search,
  Filter,
  Download,
  CheckSquare,
  Square,
  Flame,
  ArrowUpDown,
  SlidersHorizontal,
  ChevronRight,
  HelpCircle,
  X,
} from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { SeverityPill } from "@/components/ui/SeverityPill";
import { FindingDrawer } from "@/components/findings/FindingDrawer";
import { api } from "@/lib/api";

export default function FindingsPage() {
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState<any | null>(null);

  // Filters
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [sortBy, setSortBy] = useState<"risk_score" | "severity">("risk_score");
  const [showComparisonModal, setShowComparisonModal] = useState(false);

  // Bulk actions
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [bulkStatus, setBulkStatus] = useState("acknowledged");
  const [bulkLoading, setBulkLoading] = useState(false);

  const fetchFindings = async () => {
    setLoading(true);
    try {
      const data = await api.getFindings({
        q: search,
        severity: severityFilter,
        category: categoryFilter,
        status: statusFilter,
        sort: sortBy === "risk_score" ? "risk_score_desc" : "severity_desc",
      });
      setFindings(data.items || data || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [severityFilter, categoryFilter, statusFilter, sortBy]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchFindings();
  };

  const toggleSelectAll = () => {
    if (selectedIds.length === findings.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(findings.map((f) => f.id));
    }
  };

  const toggleSelectOne = (id: number) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
    );
  };

  const handleBulkUpdate = async () => {
    if (selectedIds.length === 0) return;
    setBulkLoading(true);
    try {
      await api.bulkUpdateFindings(selectedIds, bulkStatus, "Bulk update from findings console");
      setSelectedIds([]);
      fetchFindings();
    } catch (err: any) {
      alert(err.message || "Failed to update findings");
    } finally {
      setBulkLoading(false);
    }
  };

  const handleExportCsv = async () => {
    try {
      // Find latest scan id from findings or default to 1
      const scanId = findings[0]?.scan_id || 1;
      const blob = await api.downloadCsv(scanId);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `CloudShield_Findings_${Date.now()}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err) {
      console.error("Export error", err);
    }
  };

  const categories = ["IAM", "Storage", "Network", "Logging", "Encryption", "Backup"];

  // Sort comparison list for the demo proof
  const rawSeveritySorted = [...findings].sort((a, b) => b.severity - a.severity);
  const riskScoreSorted = [...findings].sort((a, b) => b.risk_score - a.risk_score);

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
              <AlertOctagon className="w-6 h-6 text-red-400" />
              Security Findings & Misconfigurations
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Contextually scored findings prioritized by actual attack surface exposure and data classification.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowComparisonModal(true)}
              className="flex items-center gap-1.5 px-3 py-2 bg-[#111B2E] hover:bg-[#162238] border border-cyan-500/30 text-cyan-400 text-xs font-semibold rounded-xl transition"
            >
              <HelpCircle className="w-4 h-4" />
              <span>Why Risk Score? (Prioritisation Proof)</span>
            </button>

            <button
              onClick={handleExportCsv}
              className="flex items-center gap-2 px-3.5 py-2 bg-[#111B2E] hover:bg-[#162238] border border-[#24324D] text-slate-300 text-xs font-semibold rounded-xl transition"
            >
              <Download className="w-4 h-4" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        {/* Filter Toolbar */}
        <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-4 space-y-3">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            {/* Search Input */}
            <form onSubmit={handleSearchSubmit} className="flex-1 relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by title, resource ARN, or check ID..."
                className="w-full bg-[#090f1b] border border-[#24324D] rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </form>

            {/* Dropdown Filters */}
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="bg-[#090f1b] border border-[#24324D] rounded-xl px-3 py-2 text-slate-300 focus:outline-none"
              >
                <option value="">All Categories</option>
                {categories.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-[#090f1b] border border-[#24324D] rounded-xl px-3 py-2 text-slate-300 focus:outline-none"
              >
                <option value="">All Severities</option>
                <option value="5">Critical (5)</option>
                <option value="4">High (4)</option>
                <option value="3">Medium (3)</option>
                <option value="2">Low (2)</option>
              </select>

              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-[#090f1b] border border-[#24324D] rounded-xl px-3 py-2 text-slate-300 focus:outline-none"
              >
                <option value="">All Statuses</option>
                <option value="open">Open</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="fixed">Fixed</option>
                <option value="false_positive">False Positive</option>
              </select>

              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                className="bg-[#090f1b] border border-[#24324D] rounded-xl px-3 py-2 text-cyan-400 font-semibold focus:outline-none"
              >
                <option value="risk_score">Sort: Risk Score (High → Low)</option>
                <option value="severity">Sort: Raw Severity</option>
              </select>
            </div>
          </div>

          {/* Bulk Selection Actions Bar */}
          {selectedIds.length > 0 && (
            <div className="p-2.5 bg-blue-950/40 border border-blue-800/60 rounded-xl flex items-center justify-between text-xs">
              <span className="text-blue-300 font-semibold">
                {selectedIds.length} finding{selectedIds.length > 1 ? "s" : ""} selected
              </span>
              <div className="flex items-center gap-2">
                <select
                  value={bulkStatus}
                  onChange={(e) => setBulkStatus(e.target.value)}
                  className="bg-[#090f1b] border border-[#24324D] rounded-lg px-2 py-1 text-slate-200 text-xs"
                >
                  <option value="acknowledged">Set to Acknowledged</option>
                  <option value="fixed">Set to Fixed</option>
                  <option value="false_positive">Set to False Positive</option>
                  <option value="open">Reopen</option>
                </select>
                <button
                  onClick={handleBulkUpdate}
                  disabled={bulkLoading}
                  className="px-3 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-bold text-xs transition"
                >
                  {bulkLoading ? "Updating..." : "Apply Bulk Action"}
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Findings Table */}
        <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[#24324D] bg-[#0d1627] text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-3 w-8">
                    <button onClick={toggleSelectAll} className="text-slate-400 hover:text-white">
                      {selectedIds.length === findings.length && findings.length > 0 ? (
                        <CheckSquare className="w-4 h-4 text-blue-500" />
                      ) : (
                        <Square className="w-4 h-4" />
                      )}
                    </button>
                  </th>
                  <th className="py-3 px-3">Risk Score</th>
                  <th className="py-3 px-3">Severity</th>
                  <th className="py-3 px-3">Title & Rule</th>
                  <th className="py-3 px-3">Resource Target</th>
                  <th className="py-3 px-3">Category</th>
                  <th className="py-3 px-3">Status</th>
                  <th className="py-3 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d48]">
                {findings.length > 0 ? (
                  findings.map((f) => {
                    const isSelected = selectedIds.includes(f.id);
                    return (
                      <tr
                        key={f.id}
                        onClick={() => setSelectedFinding(f)}
                        className={`hover:bg-[#162238] transition cursor-pointer ${
                          isSelected ? "bg-blue-950/20" : ""
                        }`}
                      >
                        <td className="py-3 px-3" onClick={(e) => e.stopPropagation()}>
                          <button onClick={() => toggleSelectOne(f.id)}>
                            {isSelected ? (
                              <CheckSquare className="w-4 h-4 text-blue-500" />
                            ) : (
                              <Square className="w-4 h-4 text-slate-500" />
                            )}
                          </button>
                        </td>
                        <td className="py-3 px-3">
                          <span className="font-mono font-extrabold px-2 py-0.5 rounded bg-red-950/80 text-red-300 border border-red-800/80">
                            {f.risk_score}
                          </span>
                        </td>
                        <td className="py-3 px-3">
                          <SeverityPill severity={f.severity} size="sm" />
                        </td>
                        <td className="py-3 px-3">
                          <div className="font-semibold text-white truncate max-w-md">
                            {f.title}
                          </div>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span className="text-[10px] text-slate-400 font-mono">
                              {f.check_id}
                            </span>
                            {f.cis_control && (
                              <span className="text-[10px] text-emerald-400 font-mono">
                                CIS {f.cis_control}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-3 font-mono text-cyan-300 truncate max-w-[180px]">
                          {f.resource_id}
                        </td>
                        <td className="py-3 px-3 text-slate-300">{f.category}</td>
                        <td className="py-3 px-3">
                          <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold uppercase bg-slate-900 border border-slate-700 text-slate-300">
                            {f.status}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedFinding(f);
                            }}
                            className="px-2.5 py-1 bg-blue-600/20 text-blue-400 hover:bg-blue-600 hover:text-white rounded-md text-xs font-semibold border border-blue-500/30 transition"
                          >
                            Remediate
                          </button>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={8} className="py-12 text-center text-slate-400 text-xs">
                      {loading ? "Loading findings..." : "No findings match the current filters."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Prioritisation Proof Modal ("Why Risk Score?") */}
      {showComparisonModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in">
          <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl max-w-4xl w-full p-6 space-y-5 shadow-2xl relative max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-[#24324D] pb-3">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <Flame className="w-5 h-5 text-red-400" />
                  Prioritisation Proof: Raw Severity vs CloudShield Risk Score
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Demonstrates why treating every Severity 5 equally causes alert fatigue.
                </p>
              </div>
              <button
                onClick={() => setShowComparisonModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Traditional scanner view */}
              <div className="bg-[#090f1b] p-4 rounded-xl border border-[#24324D] space-y-3">
                <div className="border-b border-[#24324D] pb-2">
                  <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">
                    Traditional Generic Scanner
                  </span>
                  <p className="text-[11px] text-slate-400">
                    Sorts purely by static check severity. Empty buckets and customer-PII buckets look identical.
                  </p>
                </div>

                <div className="space-y-2 text-xs">
                  {rawSeveritySorted.slice(0, 5).map((f, i) => (
                    <div key={i} className="p-2.5 rounded-lg bg-[#111B2E] border border-[#24324D]">
                      <div className="flex justify-between font-semibold text-white">
                        <span className="truncate pr-2">{f.title}</span>
                        <SeverityPill severity={f.severity} size="sm" />
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono mt-1 truncate">
                        {f.resource_id}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* CloudShield Contextual Risk Score */}
              <div className="bg-[#090f1b] p-4 rounded-xl border border-cyan-500/30 space-y-3">
                <div className="border-b border-cyan-500/30 pb-2">
                  <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">
                    CloudShield Risk Prioritisation
                  </span>
                  <p className="text-[11px] text-cyan-300/80">
                    Calculates Risk = Severity × Exposure × Data Sensitivity. Most dangerous comes first.
                  </p>
                </div>

                <div className="space-y-2 text-xs">
                  {riskScoreSorted.slice(0, 5).map((f, i) => (
                    <div key={i} className="p-2.5 rounded-lg bg-[#111B2E] border border-cyan-900/40">
                      <div className="flex justify-between font-semibold text-white">
                        <span className="truncate pr-2">{f.title}</span>
                        <span className="font-mono font-extrabold px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-800">
                          Score: {f.risk_score}
                        </span>
                      </div>
                      <div className="text-[11px] text-cyan-300 font-mono mt-1 truncate">
                        {f.resource_id}
                      </div>
                      <div className="text-[10px] text-slate-400 mt-1">
                        Sev {f.severity} × Exp {f.exposure} × Sens {f.data_sensitivity}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="p-3 bg-blue-950/30 border border-blue-800/40 rounded-xl text-xs text-slate-300">
              💡 <strong>College Presentation Takeaway:</strong> CloudShield's context-aware formula ensures engineers don't waste 4 hours auditing an empty test bucket while confidential customer data is exposed to 0.0.0.0/0.
            </div>
          </div>
        </div>
      )}

      {/* Slide-in Detail Drawer */}
      <FindingDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onStatusUpdated={() => {
          setSelectedFinding(null);
          fetchFindings();
        }}
      />
    </AppShell>
  );
}
