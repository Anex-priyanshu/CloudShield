"use client";

import React, { useEffect, useState } from "react";
import {
  Settings,
  Sliders,
  ShieldCheck,
  Bell,
  Lock,
  Save,
  RotateCcw,
  CheckCircle2,
  Info,
  Flame,
} from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";

export default function SettingsPage() {
  const { isAdmin } = useAuth();
  const [activeTab, setActiveTab] = useState<"risk" | "rules" | "password">("risk");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState("");

  // Settings values
  const [riskBands, setRiskBands] = useState({
    critical_min: 91,
    high_min: 51,
    medium_min: 21,
  });
  const [defaultSensitivity, setDefaultSensitivity] = useState(3);
  const [pollInterval, setPollInterval] = useState(30);

  // Checks and rules
  const [availableChecks, setAvailableChecks] = useState<any[]>([]);
  const [availableRules, setAvailableRules] = useState<any[]>([]);

  // Password change
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [passError, setPassError] = useState("");
  const [passSuccess, setPassSuccess] = useState("");

  const loadSettings = async () => {
    try {
      const data = await api.getSettings();
      if (data.settings?.risk_bands) {
        setRiskBands(data.settings.risk_bands);
      }
      if (data.settings?.default_data_sensitivity) {
        setDefaultSensitivity(data.settings.default_data_sensitivity);
      }
      if (data.settings?.log_poll_interval) {
        setPollInterval(data.settings.log_poll_interval);
      }
      setAvailableChecks(data.available_checks || []);
      setAvailableRules(data.available_rules || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const handleSaveRiskSettings = async () => {
    setSaving(true);
    setMsg("");
    try {
      await api.updateSettings({
        risk_bands: riskBands,
        default_data_sensitivity: defaultSensitivity,
        log_poll_interval: pollInterval,
      });
      setMsg("Settings saved successfully!");
      setTimeout(() => setMsg(""), 3000);
    } catch (err: any) {
      setMsg(err.message || "Failed to update settings");
    } finally {
      setSaving(false);
    }
  };

  const handleRecalculate = async () => {
    setSaving(true);
    try {
      const res = await api.recalculateScores();
      setMsg(`Recalculated ${res.recalculated_findings} findings with updated thresholds!`);
      setTimeout(() => setMsg(""), 4000);
    } catch (err: any) {
      setMsg(err.message || "Recalculation failed");
    } finally {
      setSaving(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPassError("");
    setPassSuccess("");
    try {
      await api.changePassword(currentPassword, newPassword);
      setPassSuccess("Password updated successfully!");
      setCurrentPassword("");
      setNewPassword("");
    } catch (err: any) {
      setPassError(err.message || "Failed to change password");
    }
  };

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
              <Settings className="w-6 h-6 text-cyan-400" />
              Platform Settings & Risk Tuning
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Configure risk scoring formula weights, severity bands, enabled CIS checks, and account preferences.
            </p>
          </div>
        </div>

        {msg && (
          <div className="p-3 bg-emerald-950/40 border border-emerald-800 text-xs text-emerald-300 rounded-xl flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>{msg}</span>
          </div>
        )}

        {/* Tabs */}
        <div className="flex p-1 bg-[#111B2E] rounded-xl border border-[#24324D] max-w-md">
          <button
            onClick={() => setActiveTab("risk")}
            className={`flex-1 py-2 text-xs font-bold rounded-lg transition ${
              activeTab === "risk"
                ? "bg-blue-600 text-white shadow"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            ⚖️ Risk Scoring & Bands
          </button>
          <button
            onClick={() => setActiveTab("rules")}
            className={`flex-1 py-2 text-xs font-bold rounded-lg transition ${
              activeTab === "rules"
                ? "bg-blue-600 text-white shadow"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            🛡️ Checks & Detections
          </button>
          <button
            onClick={() => setActiveTab("password")}
            className={`flex-1 py-2 text-xs font-bold rounded-lg transition ${
              activeTab === "password"
                ? "bg-blue-600 text-white shadow"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            🔒 Security & Auth
          </button>
        </div>

        {/* TAB 1: Risk Scoring */}
        {activeTab === "risk" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 bg-[#111B2E] border border-[#24324D] rounded-2xl p-6 space-y-5">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Sliders className="w-4 h-4 text-cyan-400" />
                Risk Band Thresholds (Score: 1 - 125)
              </h3>

              <div className="grid grid-cols-3 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-red-400 block">
                    Critical Band Min Score
                  </label>
                  <input
                    type="number"
                    min="1"
                    max="125"
                    value={riskBands.critical_min}
                    onChange={(e) =>
                      setRiskBands({ ...riskBands, critical_min: parseInt(e.target.value) || 91 })
                    }
                    className="w-full bg-[#090f1b] border border-[#24324D] rounded-xl px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-red-500"
                  />
                  <span className="text-[10px] text-slate-400">Default: 91 - 125</span>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-orange-400 block">
                    High Band Min Score
                  </label>
                  <input
                    type="number"
                    min="1"
                    max="125"
                    value={riskBands.high_min}
                    onChange={(e) =>
                      setRiskBands({ ...riskBands, high_min: parseInt(e.target.value) || 51 })
                    }
                    className="w-full bg-[#090f1b] border border-[#24324D] rounded-xl px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-orange-500"
                  />
                  <span className="text-[10px] text-slate-400">Default: 51 - 90</span>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-amber-400 block">
                    Medium Band Min Score
                  </label>
                  <input
                    type="number"
                    min="1"
                    max="125"
                    value={riskBands.medium_min}
                    onChange={(e) =>
                      setRiskBands({ ...riskBands, medium_min: parseInt(e.target.value) || 21 })
                    }
                    className="w-full bg-[#090f1b] border border-[#24324D] rounded-xl px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-amber-500"
                  />
                  <span className="text-[10px] text-slate-400">Default: 21 - 50</span>
                </div>
              </div>

              <div className="pt-2 border-t border-[#24324D] grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">
                    Default Data Sensitivity Heuristic
                  </label>
                  <select
                    value={defaultSensitivity}
                    onChange={(e) => setDefaultSensitivity(parseInt(e.target.value))}
                    className="w-full bg-[#090f1b] border border-[#24324D] rounded-xl px-3 py-2 text-xs text-slate-200"
                  >
                    <option value="1">1 - Public / Non-critical</option>
                    <option value="2">2 - Internal Testing</option>
                    <option value="3">3 - Default Standard (Recommended)</option>
                    <option value="4">4 - Confidential / PII</option>
                    <option value="5">5 - Restricted / Secret</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">
                    CloudTrail Polling Frequency
                  </label>
                  <select
                    value={pollInterval}
                    onChange={(e) => setPollInterval(parseInt(e.target.value))}
                    className="w-full bg-[#090f1b] border border-[#24324D] rounded-xl px-3 py-2 text-xs text-slate-200"
                  >
                    <option value="15">Every 15 seconds (High frequency)</option>
                    <option value="30">Every 30 seconds (Default)</option>
                    <option value="60">Every 60 seconds (Cost-optimized)</option>
                  </select>
                </div>
              </div>

              {isAdmin && (
                <div className="pt-4 border-t border-[#24324D] flex items-center justify-between">
                  <button
                    onClick={handleRecalculate}
                    disabled={saving}
                    className="px-4 py-2 bg-[#090f1b] hover:bg-[#162238] border border-[#24324D] text-cyan-400 text-xs font-bold rounded-xl transition flex items-center gap-1.5"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Recalculate All Existing Findings</span>
                  </button>

                  <button
                    onClick={handleSaveRiskSettings}
                    disabled={saving}
                    className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold rounded-xl shadow-lg shadow-blue-600/25 transition flex items-center gap-1.5"
                  >
                    <Save className="w-3.5 h-3.5" />
                    <span>Save Risk Settings</span>
                  </button>
                </div>
              )}
            </div>

            {/* Formula Explanation documentation card */}
            <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-5 space-y-3">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Info className="w-4 h-4 text-cyan-400" />
                How the Score is Calculated
              </h3>
              <div className="text-xs text-slate-300 space-y-2 leading-relaxed">
                <p>
                  <strong>Finding Risk Score (1 to 125):</strong>
                </p>
                <pre className="p-2.5 bg-[#090f1b] border border-[#1e2d48] rounded-lg text-cyan-300 font-mono text-[11px]">
                  Risk Score = Severity × Exposure × Sensitivity
                </pre>
                <ul className="list-disc pl-4 space-y-1 text-slate-400 text-[11px]">
                  <li><strong>Severity (1-5):</strong> Inherent technical severity of the misconfiguration.</li>
                  <li><strong>Exposure (1-5):</strong> 5 = 0.0.0.0/0 public internet; 1 = internal VPC only.</li>
                  <li><strong>Data Sensitivity (1-5):</strong> Read from tags or regex heuristics (e.g. prod, pii, customer = 4).</li>
                </ul>

                <p className="pt-2">
                  <strong>Account Risk Score (0 to 100):</strong>
                </p>
                <pre className="p-2.5 bg-[#090f1b] border border-[#1e2d48] rounded-lg text-cyan-300 font-mono text-[11px]">
                  Account Score = min(100, round((Sum of Open Findings / (Resources × 25)) × 100))
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: Checks & Detections Toggle */}
        {activeTab === "rules" && (
          <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-6 space-y-5">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Active Security Checks ({availableChecks.length}) & Detection Rules ({availableRules.length})
            </h3>
            <p className="text-xs text-slate-400">
              All 25 CIS posture checks and 10 CloudTrail detection rules are active by default.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-cyan-400 uppercase">Posture Checks</h4>
                <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                  {availableChecks.map((c) => (
                    <div key={c.id} className="p-2.5 bg-[#090f1b] border border-[#1e2d48] rounded-xl flex items-center justify-between text-xs">
                      <div>
                        <span className="font-bold text-white">{c.title}</span>
                        <div className="text-[10px] text-slate-400 font-mono">{c.id} • {c.category}</div>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                        ENABLED
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="space-y-2">
                <h4 className="text-xs font-bold text-cyan-400 uppercase">CloudTrail Detection Rules</h4>
                <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                  {availableRules.map((r) => (
                    <div key={r.id} className="p-2.5 bg-[#090f1b] border border-[#1e2d48] rounded-xl flex items-center justify-between text-xs">
                      <div>
                        <span className="font-bold text-white">{r.title}</span>
                        <div className="text-[10px] text-slate-400 font-mono">{r.id}</div>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                        ACTIVE
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: Change Password */}
        {activeTab === "password" && (
          <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-6 max-w-md space-y-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Lock className="w-4 h-4 text-cyan-400" />
              Update Account Password
            </h3>

            {passSuccess && (
              <div className="p-3 bg-emerald-950/40 border border-emerald-800 text-xs text-emerald-300 rounded-xl">
                {passSuccess}
              </div>
            )}
            {passError && (
              <div className="p-3 bg-red-950/40 border border-red-800 text-xs text-red-300 rounded-xl">
                {passError}
              </div>
            )}

            <form onSubmit={handleChangePassword} className="space-y-3.5">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Current Password
                </label>
                <input
                  type="password"
                  required
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  className="w-full bg-[#090f1b] border border-[#24324D] rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  New Password (min 8 characters)
                </label>
                <input
                  type="password"
                  required
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full bg-[#090f1b] border border-[#24324D] rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <button
                type="submit"
                className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl text-xs transition"
              >
                Update Password
              </button>
            </form>
          </div>
        )}
      </div>
    </AppShell>
  );
}
