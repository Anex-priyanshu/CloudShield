"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  Flame,
  AlertTriangle,
  AlertCircle,
  Info,
  Activity,
  ArrowUpRight,
  TrendingDown,
  CheckCircle2,
  Clock,
  Layers,
  ChevronRight,
  Sparkles,
} from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { RiskGauge } from "@/components/ui/RiskGauge";
import { SeverityPill } from "@/components/ui/SeverityPill";
import { FindingDrawer } from "@/components/findings/FindingDrawer";
import { api } from "@/lib/api";
import { wsClient } from "@/lib/ws";
import { useAuth } from "@/lib/auth";

export default function DashboardPage() {
  const { user, loading: authLoading } = useAuth();
  const [selectedAccount, setSelectedAccount] = useState<any>(null);
  const [summary, setSummary] = useState<any>(null);
  const [trend, setTrend] = useState<any[]>([]);
  const [liveAlerts, setLiveAlerts] = useState<any[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchDashboardData = async (accountId?: number) => {
    try {
      const summaryData = await api.getDashboardSummary(accountId);
      setSummary(summaryData && typeof summaryData === "object" ? summaryData : {});
      const trendData = await api.getDashboardTrend(accountId);
      setTrend(Array.isArray(trendData) ? trendData : []);
      const alertsData = await api.getAlerts({ limit: 8, account_id: accountId });
      setLiveAlerts(Array.isArray(alertsData?.items) ? alertsData.items : Array.isArray(alertsData) ? alertsData : []);
    } catch (err) {
      console.error("Dashboard data load error", err);
      setTrend([]);
      setLiveAlerts([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!authLoading && user) {
      fetchDashboardData(selectedAccount?.id);
    }

    // WebSocket real-time updates for scan completion & new alerts
    const unsubScan = wsClient.on("scan.completed", () => {
      fetchDashboardData(selectedAccount?.id);
    });

    const unsubAlert = wsClient.on("alert.new", (newAlert: any) => {
      setLiveAlerts((prev) => [newAlert, ...prev.slice(0, 7)]);
    });

    return () => {
      unsubScan();
      unsubAlert();
    };
  }, [selectedAccount?.id, user, authLoading]);

  const severityCounts = {
    critical: summary?.critical ?? summary?.severity_counts?.critical ?? 0,
    high: summary?.high ?? summary?.severity_counts?.high ?? 0,
    medium: summary?.medium ?? summary?.severity_counts?.medium ?? 0,
    low: summary?.low ?? summary?.severity_counts?.low ?? 0,
  };

  const rawScore = summary?.account_risk_score ?? summary?.last_scan?.account_risk_score ?? 0;
  const displayScore = Math.round(rawScore);
  const evaluatedResources = summary?.last_scan?.total_resources ?? summary?.total_resources ?? (summary?.total_open ? summary.total_open + 10 : 0);
  const categoryCounts: Record<string, number> = summary?.by_category ?? summary?.category_counts ?? {};

  const topRisks = summary?.top5_risks || summary?.top_risks || [];
  const complianceCategories = summary?.compliance_pct || summary?.compliance_snapshot?.categories || {
    IAM: 100,
    Storage: 100,
    Network: 100,
    Logging: 100,
    Encryption: 100,
    Backup: 100,
  };
  const categoryVals: number[] = Object.values(complianceCategories);
  const overallPercent = summary?.compliance_snapshot?.overall_percent ?? 
    (categoryVals.length > 0 ? Math.round(categoryVals.reduce((a: number, b: number) => a + b, 0) / categoryVals.length) : 100);

  const compliance = {
    overall_percent: overallPercent,
    categories: complianceCategories,
  };

  return (
    <AppShell onAccountChange={(acc) => setSelectedAccount(acc)}>
      <div className="space-y-6">
        {/* Page Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
              Security Posture Dashboard
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Real-time posture assessment, contextual risk prioritisation (Severity × Exposure × Sensitivity), and live CloudTrail threat detection.
            </p>
          </div>

          {summary?.last_scan && (
            <div className="flex items-center gap-3 text-xs bg-[#111B2E] border border-[#24324D] px-3.5 py-2 rounded-xl text-slate-300">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span>
                Last Scan: <strong className="text-white">{summary.last_scan.finished_at ? new Date(summary.last_scan.finished_at).toLocaleString() : "Just now"}</strong>
              </span>
              <span className="text-slate-400">|</span>
              <span>{summary.last_scan.total_findings} findings</span>
            </div>
          )}
        </div>

        {/* Connect Account Prompt if no active account */}
        {!selectedAccount && !loading && (
          <div className="bg-gradient-to-r from-blue-900/40 via-[#111B2E] to-cyan-900/30 border border-blue-500/30 rounded-2xl p-6 flex flex-col md:flex-row items-center justify-between gap-4 shadow-xl">
            <div className="space-y-1">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-cyan-400" />
                Connect Your AWS Cloud Environment
              </h3>
              <p className="text-xs text-slate-300">
                CloudShield assesses your live cloud posture against 25 CIS AWS Foundations Benchmark controls and streams CloudTrail threat detections in real time using secure, read-only IAM credentials or Assume Role.
              </p>
            </div>
            <Link
              href="/accounts"
              className="shrink-0 px-4 py-2.5 bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 text-white font-bold text-xs rounded-xl shadow-lg shadow-blue-500/25 transition"
            >
              + Connect AWS Account
            </Link>
          </div>
        )}

        {/* Top Row: 4 Severity Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-[#111B2E] border border-[#24324D] rounded-xl p-4 flex items-center justify-between shadow-sm relative overflow-hidden group hover:border-red-800/80 transition">
            <div className="absolute top-0 left-0 w-1 h-full bg-red-600" />
            <div>
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Critical Risks
              </span>
              <div className="text-3xl font-extrabold text-red-400 font-mono mt-1">
                {severityCounts.critical}
              </div>
              <span className="text-[11px] text-red-500/80 font-medium">Immediate action</span>
            </div>
            <div className="w-11 h-11 rounded-xl bg-red-950/50 border border-red-800/60 flex items-center justify-center text-red-400">
              <Flame className="w-5 h-5" />
            </div>
          </div>

          <div className="bg-[#111B2E] border border-[#24324D] rounded-xl p-4 flex items-center justify-between shadow-sm relative overflow-hidden group hover:border-orange-800/80 transition">
            <div className="absolute top-0 left-0 w-1 h-full bg-orange-600" />
            <div>
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                High Risks
              </span>
              <div className="text-3xl font-extrabold text-orange-400 font-mono mt-1">
                {severityCounts.high}
              </div>
              <span className="text-[11px] text-orange-500/80 font-medium">Elevated exposure</span>
            </div>
            <div className="w-11 h-11 rounded-xl bg-orange-950/50 border border-orange-800/60 flex items-center justify-center text-orange-400">
              <AlertTriangle className="w-5 h-5" />
            </div>
          </div>

          <div className="bg-[#111B2E] border border-[#24324D] rounded-xl p-4 flex items-center justify-between shadow-sm relative overflow-hidden group hover:border-amber-800/80 transition">
            <div className="absolute top-0 left-0 w-1 h-full bg-amber-500" />
            <div>
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Medium Risks
              </span>
              <div className="text-3xl font-extrabold text-amber-400 font-mono mt-1">
                {severityCounts.medium}
              </div>
              <span className="text-[11px] text-amber-500/80 font-medium">Needs hardening</span>
            </div>
            <div className="w-11 h-11 rounded-xl bg-amber-950/50 border border-amber-800/60 flex items-center justify-center text-amber-400">
              <AlertCircle className="w-5 h-5" />
            </div>
          </div>

          <div className="bg-[#111B2E] border border-[#24324D] rounded-xl p-4 flex items-center justify-between shadow-sm relative overflow-hidden group hover:border-blue-800/80 transition">
            <div className="absolute top-0 left-0 w-1 h-full bg-blue-600" />
            <div>
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Low Risks
              </span>
              <div className="text-3xl font-extrabold text-blue-400 font-mono mt-1">
                {severityCounts.low}
              </div>
              <span className="text-[11px] text-blue-500/80 font-medium">Best practice</span>
            </div>
            <div className="w-11 h-11 rounded-xl bg-blue-950/50 border border-blue-800/60 flex items-center justify-center text-blue-400">
              <Info className="w-5 h-5" />
            </div>
          </div>
        </div>

        {/* Second Row: Risk Gauge (left) · Risk Trend (middle) · Category Chart (right) */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Risk Gauge */}
          <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Account Posture Score
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Normalized aggregate risk (0-100)
                </p>
              </div>
            </div>

            <div className="py-2">
              <RiskGauge score={displayScore} size={200} />
            </div>

            <div className="bg-[#090f1b] p-3 rounded-xl border border-[#1e2d48] text-xs text-slate-400 flex items-center justify-between">
              <span>Evaluated Resources:</span>
              <strong className="text-white font-mono">{evaluatedResources}</strong>
            </div>
          </div>

          {/* Risk Trend Over Scans */}
          <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Risk Posture Trend
                </h3>
                <span className="text-xs text-cyan-400 flex items-center gap-1">
                  <TrendingDown className="w-3.5 h-3.5" />
                  Last 10 Scans
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Historical score progression over time
              </p>
            </div>

            {/* Simple sparkline / bar visual for trend */}
            <div className="h-44 flex items-end gap-2.5 pt-4 pb-2 px-2 border-b border-[#24324D]">
              {trend.length > 0 ? (
                trend.map((t, idx) => {
                  const s = t.account_risk_score ?? t.score ?? 0;
                  const h = Math.max(15, Math.min(100, Math.round(s)));
                  const isCrit = s >= 70;
                  return (
                    <div key={idx} className="flex-1 flex flex-col items-center gap-1.5 group">
                      <span className="text-[10px] font-mono text-slate-400 opacity-0 group-hover:opacity-100 transition">
                        {Math.round(s)}
                      </span>
                      <div
                        style={{ height: `${h}%` }}
                        className={`w-full rounded-t-md transition-all ${
                          isCrit ? "bg-red-500 hover:bg-red-400" : "bg-blue-500 hover:bg-blue-400"
                        }`}
                      />
                      <span className="text-[10px] text-slate-400 font-mono">
                        #{t.scan_id}
                      </span>
                    </div>
                  );
                })
              ) : (
                <div className="w-full h-full flex items-center justify-center text-xs text-slate-400">
                  Run multiple scans to view trend history.
                </div>
              )}
            </div>

            <div className="text-[11px] text-slate-400 flex justify-between mt-2">
              <span>Higher score = Higher risk</span>
              <span className="text-emerald-400 font-medium">Target: &lt; 20</span>
            </div>
          </div>

          {/* Category Distribution */}
          <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-5 flex flex-col justify-between">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Findings by Category
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Misconfigurations across security domains
              </p>
            </div>

            <div className="space-y-2.5 my-3">
              {Object.keys(categoryCounts).length > 0 ? (
                Object.entries(categoryCounts).map(([cat, count]: [string, any]) => {
                  const maxVal = Math.max(...Object.values(categoryCounts));
                  const pct = Math.max(10, Math.min(100, Math.round((count / (maxVal || 1)) * 100)));
                  return (
                    <div key={cat} className="space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className="text-slate-300 font-medium">{cat}</span>
                        <span className="font-mono text-slate-400 font-semibold">{count}</span>
                      </div>
                      <div className="w-full h-2 bg-[#090f1b] rounded-full overflow-hidden">
                        <div
                          style={{ width: `${pct}%` }}
                          className="h-full bg-gradient-to-r from-blue-600 to-cyan-400 rounded-full"
                        />
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="py-6 text-center text-xs text-slate-400">
                  No categorical findings yet.
                </div>
              )}
            </div>

            <Link
              href="/findings"
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center justify-between p-2 rounded-lg bg-[#090f1b] border border-[#1e2d48] transition"
            >
              <span>Explore all findings</span>
              <ChevronRight className="w-4 h-4" />
            </Link>
          </div>
        </div>

        {/* Third Row: Top 5 Prioritised Risks (left) · Live Alert Feed (right) */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Top 5 Prioritised Risks Table */}
          <div className="lg:col-span-2 bg-[#111B2E] border border-[#24324D] rounded-2xl p-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Flame className="w-4 h-4 text-red-500" />
                  Top Prioritised Risks (Fix First)
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Ranked by Risk Score = Severity × Exposure × Data Sensitivity
                </p>
              </div>
              <Link
                href="/findings"
                className="text-xs text-blue-400 hover:text-blue-300 font-medium flex items-center gap-1"
              >
                <span>View All</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </Link>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-[#24324D] text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                    <th className="py-2.5 px-3">Score</th>
                    <th className="py-2.5 px-3">Finding</th>
                    <th className="py-2.5 px-3">Category</th>
                    <th className="py-2.5 px-3">Resource</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d48] text-xs">
                  {topRisks.length > 0 ? (
                    topRisks.map((item: any) => (
                      <tr key={item.id} className="hover:bg-[#162238] transition">
                        <td className="py-3 px-3">
                          <span className="font-mono font-bold px-2 py-0.5 rounded bg-red-950/80 text-red-300 border border-red-800">
                            {item.risk_score}
                          </span>
                        </td>
                        <td className="py-3 px-3">
                          <div className="font-semibold text-white truncate max-w-xs">
                            {item.title}
                          </div>
                          <span className="text-[10px] text-slate-400 font-mono">
                            {item.check_id}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-slate-300">{item.category}</td>
                        <td className="py-3 px-3 text-cyan-400 font-mono truncate max-w-[150px]">
                          {item.resource_id}
                        </td>
                        <td className="py-3 px-3 text-right">
                          <button
                            onClick={() => setSelectedFinding(item)}
                            className="px-2.5 py-1 bg-blue-600/20 text-blue-400 hover:bg-blue-600 hover:text-white rounded-md text-xs font-semibold border border-blue-500/30 transition"
                          >
                            Fix
                          </button>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-slate-400 text-xs">
                        No critical findings found. Cloud account is healthy!
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Live CloudTrail Alert Feed */}
          <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  Live CloudTrail Alerts
                </h3>
                <span className="flex items-center gap-1.5 text-[11px] font-bold text-emerald-400">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse-live" />
                  STREAMING
                </span>
              </div>
              <p className="text-xs text-slate-400 mb-3">
                Near real-time threat detection from CloudTrail audit logs
              </p>
            </div>

            <div className="space-y-2.5 overflow-y-auto max-h-72 pr-1">
              {liveAlerts.length > 0 ? (
                liveAlerts.map((alert: any, idx: number) => (
                  <div
                    key={alert.id || idx}
                    className="p-3 bg-[#090f1b] border border-[#24324D] rounded-xl hover:border-slate-600 transition"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <SeverityPill severity={alert.severity} size="sm" />
                      <span className="text-[10px] text-slate-400 font-mono">
                        {alert.created_at ? new Date(alert.created_at).toLocaleTimeString() : "Just now"}
                      </span>
                    </div>
                    <div className="text-xs font-semibold text-white leading-tight">
                      {alert.title}
                    </div>
                    <div className="text-[10px] text-slate-400 mt-1 flex items-center gap-2">
                      <span>Rule: <strong className="text-slate-300">{alert.rule_id}</strong></span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="py-12 text-center text-xs text-slate-400">
                  Monitoring CloudTrail audit stream...
                </div>
              )}
            </div>

            <Link
              href="/monitor"
              className="mt-3 block text-center py-2 text-xs font-semibold text-cyan-400 hover:text-cyan-300 bg-[#090f1b] border border-[#1e2d48] rounded-xl transition"
            >
              Open Live Monitor Console →
            </Link>
          </div>
        </div>

        {/* Bottom Row: CIS Benchmark Compliance Snapshot */}
        <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                CIS Benchmark Compliance Snapshot
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Pass rate across CIS AWS Foundations Benchmark controls
              </p>
            </div>
            <div className="text-right">
              <span className="text-xs text-slate-400">Overall Compliance: </span>
              <strong className="text-sm font-mono text-emerald-400">
                {compliance.overall_percent}%
              </strong>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
            {Object.entries(compliance.categories).map(([cat, pct]: [string, any]) => (
              <div key={cat} className="bg-[#090f1b] p-3 rounded-xl border border-[#1e2d48] space-y-1.5">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-300 font-medium">{cat}</span>
                  <span className="font-mono text-cyan-400 font-bold">{pct}%</span>
                </div>
                <div className="w-full h-1.5 bg-[#162238] rounded-full overflow-hidden">
                  <div
                    style={{ width: `${pct}%` }}
                    className={`h-full rounded-full ${
                      pct >= 75 ? "bg-emerald-500" : pct >= 50 ? "bg-amber-500" : "bg-red-500"
                    }`}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Slide-in Finding Drawer */}
      <FindingDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onStatusUpdated={() => {
          setSelectedFinding(null);
          fetchDashboardData(selectedAccount?.id);
        }}
      />
    </AppShell>
  );
}
