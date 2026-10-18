"use client";

import React, { useEffect, useState } from "react";
import {
  Activity,
  Radio,
  Pause,
  Play,
  Filter,
  CheckCircle2,
  AlertCircle,
  ShieldAlert,
  Flame,
  Terminal,
  Clock,
  User,
  Globe,
  XCircle,
} from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { SeverityPill } from "@/components/ui/SeverityPill";
import { api } from "@/lib/api";
import { wsClient } from "@/lib/ws";

export default function LiveMonitorPage() {
  const [events, setEvents] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [isPaused, setIsPaused] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("");
  const [selectedAlert, setSelectedAlert] = useState<any | null>(null);

  const loadInitialData = async () => {
    try {
      const recentEvents = await api.getEvents(undefined, 40);
      setEvents(recentEvents);
      const recentAlerts = await api.getAlerts({ limit: 30 });
      setAlerts(recentAlerts.items || recentAlerts || []);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadInitialData();
    setIsConnected(wsClient.isConnected);

    const unsubStatus = wsClient.on("ws.status", (d: any) => {
      setIsConnected(d?.connected ?? false);
    });

    const unsubEvent = wsClient.on("event.new", (newEvent: any) => {
      if (!isPaused) {
        setEvents((prev) => [newEvent, ...prev.slice(0, 50)]);
      }
    });

    const unsubAlert = wsClient.on("alert.new", (newAlert: any) => {
      if (!isPaused) {
        setAlerts((prev) => [newAlert, ...prev.slice(0, 50)]);
      }
    });

    return () => {
      unsubStatus();
      unsubEvent();
      unsubAlert();
    };
  }, [isPaused]);

  const handleAlertStatus = async (id: number, status: string) => {
    try {
      await api.updateAlert(id, status);
      setAlerts((prev) =>
        prev.map((a) => (a.id === id ? { ...a, status } : a))
      );
      if (selectedAlert?.id === id) {
        setSelectedAlert((prev: any) => ({ ...prev, status }));
      }
    } catch (err: any) {
      alert(err.message || "Failed to update alert");
    }
  };

  const filteredAlerts = alerts.filter((a) => {
    if (!severityFilter) return true;
    return a.severity?.toLowerCase() === severityFilter.toLowerCase();
  });

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header & Controls */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
                <Activity className="w-6 h-6 text-cyan-400" />
                Live CloudTrail Threat Monitor
              </h1>
              <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#111B2E] border border-[#24324D] text-xs font-semibold">
                <span
                  className={`w-2.5 h-2.5 rounded-full ${
                    isConnected ? "bg-emerald-500 animate-pulse-live" : "bg-red-500"
                  }`}
                />
                <span className={isConnected ? "text-emerald-400" : "text-red-400"}>
                  {isConnected ? "LIVE STREAM CONNECTED" : "RECONNECTING..."}
                </span>
              </div>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Watches CloudTrail audit events in near real-time, executing detection rules for unauthorized IAM privilege escalation, root logins, and public bucket leaks.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsPaused(!isPaused)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-bold border transition ${
                isPaused
                  ? "bg-amber-600/20 text-amber-400 border-amber-600/40"
                  : "bg-[#111B2E] text-slate-300 border-[#24324D] hover:bg-[#162238]"
              }`}
            >
              {isPaused ? <Play className="w-3.5 h-3.5 fill-amber-400" /> : <Pause className="w-3.5 h-3.5" />}
              <span>{isPaused ? "Resume Live Feed" : "Pause Feed"}</span>
            </button>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-[#111B2E] border border-[#24324D] rounded-xl px-3 py-1.5 text-xs text-slate-300 focus:outline-none"
            >
              <option value="">All Alert Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>

        {/* Two-Column Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
          {/* Left Column: CloudTrail Audit Stream */}
          <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#24324D] pb-3">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  CloudTrail Event Stream
                </h3>
                <span className="text-[11px] text-slate-400">
                  Showing latest audit logs from API activity
                </span>
              </div>
              <span className="text-xs font-mono text-cyan-400 font-bold">
                {events.length} events
              </span>
            </div>

            <div className="space-y-2.5 max-h-[650px] overflow-y-auto pr-1">
              {events.length > 0 ? (
                events.map((ev, i) => (
                  <div
                    key={ev.id || i}
                    className="p-3 bg-[#090f1b] border border-[#1e2d48] rounded-xl hover:border-slate-600 transition font-mono text-xs space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-cyan-300">{ev.event_name}</span>
                      <span className="text-[10px] text-slate-400">
                        {ev.event_time ? new Date(ev.event_time).toLocaleTimeString() : "Just now"}
                      </span>
                    </div>

                    <div className="flex items-center gap-3 text-[11px] text-slate-400">
                      <span className="flex items-center gap-1">
                        <User className="w-3 h-3 text-slate-400" />
                        {ev.username || "Unknown"}
                      </span>
                      <span className="flex items-center gap-1">
                        <Globe className="w-3 h-3 text-slate-400" />
                        {ev.source_ip || "127.0.0.1"}
                      </span>
                      <span>{ev.region}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="py-24 text-center text-xs text-slate-400">
                  Awaiting CloudTrail API events...
                </div>
              )}
            </div>
          </div>

          {/* Right Column: Triggered Security Alerts */}
          <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#24324D] pb-3">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-red-400" />
                  Active Security Alerts ({filteredAlerts.length})
                </h3>
                <span className="text-[11px] text-slate-400">
                  Triggered by 10 real-time detection rules
                </span>
              </div>
            </div>

            <div className="space-y-3 max-h-[650px] overflow-y-auto pr-1">
              {filteredAlerts.length > 0 ? (
                filteredAlerts.map((alert) => (
                  <div
                    key={alert.id}
                    onClick={() => setSelectedAlert(alert)}
                    className="p-4 bg-[#090f1b] border border-[#24324D] rounded-xl hover:border-slate-500 transition cursor-pointer space-y-2.5"
                  >
                    <div className="flex items-center justify-between">
                      <SeverityPill severity={alert.severity} size="sm" />
                      <span className="text-xs font-mono font-bold text-cyan-400">
                        {alert.rule_id}
                      </span>
                    </div>

                    <h4 className="text-sm font-bold text-white leading-tight">
                      {alert.title}
                    </h4>

                    <div className="flex items-center justify-between pt-2 border-t border-[#1e2d48] text-xs">
                      <span className="text-slate-400">
                        Status: <strong className="text-slate-200 uppercase text-[10px]">{alert.status}</strong>
                      </span>

                      <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                        {alert.status === "new" && (
                          <button
                            onClick={() => handleAlertStatus(alert.id, "investigating")}
                            className="px-2 py-0.5 bg-blue-600/20 text-blue-400 hover:bg-blue-600 hover:text-white rounded text-[11px] font-semibold transition"
                          >
                            Investigate
                          </button>
                        )}
                        {alert.status !== "resolved" && (
                          <button
                            onClick={() => handleAlertStatus(alert.id, "resolved")}
                            className="px-2 py-0.5 bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600 hover:text-white rounded text-[11px] font-semibold transition"
                          >
                            Resolve
                          </button>
                        )}
                        <button
                          onClick={() => handleAlertStatus(alert.id, "false_positive")}
                          className="px-2 py-0.5 bg-slate-800 text-slate-400 hover:text-white rounded text-[11px] transition"
                        >
                          False Positive
                        </button>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="py-24 text-center text-xs text-slate-400">
                  No alerts detected under current filter.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in">
          <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl relative">
            <div className="flex items-start justify-between border-b border-[#24324D] pb-3">
              <div>
                <SeverityPill severity={selectedAlert.severity} size="md" />
                <h3 className="text-base font-bold text-white mt-2">
                  {selectedAlert.title}
                </h3>
              </div>
              <button onClick={() => setSelectedAlert(null)} className="text-slate-400 hover:text-white">
                ✕
              </button>
            </div>

            <div className="space-y-2 text-xs text-slate-300">
              <p><strong>Rule Triggered:</strong> <span className="font-mono text-cyan-400">{selectedAlert.rule_id}</span></p>
              <p><strong>Status:</strong> <span className="uppercase text-slate-200 font-semibold">{selectedAlert.status}</span></p>
              <p><strong>Detected At:</strong> {selectedAlert.created_at ? new Date(selectedAlert.created_at).toLocaleString() : "Just now"}</p>
            </div>

            <div className="p-3 bg-[#090f1b] rounded-xl border border-[#24324D] text-xs text-slate-400">
              <strong>Recommended Action:</strong> Verify with the respective IAM identity owner or revoke active sessions immediately if anomalous behavior is suspected.
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => {
                  handleAlertStatus(selectedAlert.id, "resolved");
                  setSelectedAlert(null);
                }}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold transition"
              >
                Mark as Resolved
              </button>
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}
