"use client";

import React, { useState } from "react";
import {
  X,
  Copy,
  Check,
  ShieldAlert,
  Terminal,
  FileText,
  AlertTriangle,
  Flame,
  ArrowRight,
  Save,
} from "lucide-react";
import { SeverityPill } from "@/lib/../components/ui/SeverityPill";
import { api } from "@/lib/api";

interface FindingDrawerProps {
  finding: any | null;
  onClose: () => void;
  onStatusUpdated?: () => void;
}

export function FindingDrawer({ finding, onClose, onStatusUpdated }: FindingDrawerProps) {
  const [copiedCli, setCopiedCli] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);
  const [status, setStatus] = useState<string>(finding?.status || "open");
  const [note, setNote] = useState<string>(finding?.note || "");
  const [saving, setSaving] = useState(false);

  if (!finding) return null;

  const copyToClipboard = (text: string, setCopied: (v: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSaveStatus = async () => {
    setSaving(true);
    try {
      await api.updateFinding(finding.id, { status, note });
      onStatusUpdated?.();
    } catch (err) {
      console.error("Failed to update finding status", err);
    } finally {
      setSaving(false);
    }
  };

  const evidenceJson = typeof finding.evidence_json === "string"
    ? finding.evidence_json
    : JSON.stringify(finding.evidence_json || {}, null, 2);

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex justify-end bg-black/60 backdrop-blur-sm transition-opacity">
      <div className="w-full max-w-2xl bg-[#0d1627] border-l border-[#24324D] h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-200">
        {/* Header */}
        <div className="p-5 border-b border-[#24324D] flex items-start justify-between bg-[#111B2E]">
          <div className="pr-4">
            <div className="flex items-center gap-2 mb-2">
              <SeverityPill severity={finding.severity} size="md" />
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-950/60 text-blue-400 border border-blue-800/50">
                {finding.check_id}
              </span>
              {finding.cis_control && (
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/50">
                  CIS {finding.cis_control}
                </span>
              )}
            </div>
            <h2 className="text-lg font-bold text-white leading-tight">
              {finding.title}
            </h2>
            <p className="text-xs font-mono text-slate-400 mt-1 break-all">
              Resource: <span className="text-cyan-300">{finding.resource_id}</span>
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white hover:bg-slate-800/50 rounded-lg transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Risk Score Breakdown (S × E × D) */}
          <div className="bg-[#111B2E] border border-[#24324D] rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                Contextual Risk Score Breakdown
              </span>
              <span className="text-sm font-extrabold text-white font-mono px-2.5 py-0.5 bg-red-950/80 text-red-300 border border-red-800/80 rounded-md">
                {finding.risk_score} / 125 ({finding.band?.toUpperCase()})
              </span>
            </div>

            {/* Formula visualization */}
            <div className="grid grid-cols-3 gap-3 text-center my-3">
              <div className="bg-[#090f1b] p-2.5 rounded-lg border border-[#1e2d48]">
                <div className="text-[11px] text-slate-400 uppercase font-medium">Severity</div>
                <div className="text-lg font-mono font-bold text-red-400 mt-1">{finding.severity}</div>
                <div className="text-[10px] text-slate-400 mt-0.5">Scale 1-5</div>
              </div>
              <div className="bg-[#090f1b] p-2.5 rounded-lg border border-[#1e2d48]">
                <div className="text-[11px] text-slate-400 uppercase font-medium">Exposure</div>
                <div className="text-lg font-mono font-bold text-orange-400 mt-1">{finding.exposure}</div>
                <div className="text-[10px] text-slate-400 mt-0.5">Reachable: {finding.exposure === 5 ? "Public Internet" : "Internal"}</div>
              </div>
              <div className="bg-[#090f1b] p-2.5 rounded-lg border border-[#1e2d48]">
                <div className="text-[11px] text-slate-400 uppercase font-medium">Data Sensitivity</div>
                <div className="text-lg font-mono font-bold text-cyan-400 mt-1">{finding.data_sensitivity}</div>
                <div className="text-[10px] text-slate-400 mt-0.5">Class: {finding.data_sensitivity >= 4 ? "Confidential/PII" : "Internal"}</div>
              </div>
            </div>

            <p className="text-xs text-slate-300 bg-[#090f1b] p-2.5 rounded-lg border border-[#1e2d48]">
              <strong>Formula:</strong> Severity ({finding.severity}) × Exposure ({finding.exposure}) × Data Sensitivity ({finding.data_sensitivity}) = <span className="text-red-400 font-bold">{finding.risk_score}</span>.
              This prioritize action items where sensitive data or wide public exposure coincide.
            </p>
          </div>

          {/* Why It Matters */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              Why It Matters
            </h3>
            <p className="text-sm text-slate-300 bg-[#111B2E] p-3.5 rounded-lg border border-[#24324D] leading-relaxed">
              {finding.remediation ? finding.remediation.split(".")[0] + "." : "Misconfiguration in cloud resources can lead to unauthorized data access, privilege escalation, or lateral movement."}
            </p>
          </div>

          {/* Remediation Steps */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <FileText className="w-3.5 h-3.5 text-blue-400" />
              Remediation Instructions
            </h3>
            <div className="text-sm text-slate-300 bg-[#111B2E] p-3.5 rounded-lg border border-[#24324D] space-y-2 leading-relaxed">
              <p>{finding.remediation || "Review the resource configuration in the AWS Management Console or apply infrastructure-as-code updates."}</p>
            </div>
          </div>

          {/* AWS CLI Fix Command */}
          {finding.cli_fix && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  AWS CLI Fix Command <span className="text-[10px] text-slate-400 lowercase">(display only, not executed)</span>
                </h3>
                <button
                  onClick={() => copyToClipboard(finding.cli_fix, setCopiedCli)}
                  className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition"
                >
                  {copiedCli ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedCli ? "Copied" : "Copy"}</span>
                </button>
              </div>
              <div className="relative">
                <pre className="p-3.5 bg-[#090f1b] border border-[#24324D] rounded-lg text-xs font-mono text-cyan-300 overflow-x-auto whitespace-pre-wrap">
                  {finding.cli_fix}
                </pre>
              </div>
            </div>
          )}

          {/* Evidence JSON */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                Evaluation Evidence (JSON)
              </h3>
              <button
                onClick={() => copyToClipboard(evidenceJson, setCopiedJson)}
                className="text-xs text-slate-400 hover:text-white flex items-center gap-1 transition"
              >
                {copiedJson ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedJson ? "Copied" : "Copy JSON"}</span>
              </button>
            </div>
            <pre className="p-3 bg-[#090f1b] border border-[#24324D] rounded-lg text-xs font-mono text-slate-300 max-h-48 overflow-y-auto">
              {evidenceJson}
            </pre>
          </div>

          {/* Status & Note Updates */}
          <div className="bg-[#111B2E] border border-[#24324D] rounded-xl p-4 space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Manage Finding Status
            </h3>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-slate-400 mb-1 block">Status</label>
                <select
                  value={status}
                  onChange={(e) => setStatus(e.target.value)}
                  className="w-full bg-[#090f1b] border border-[#24324D] rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                >
                  <option value="open">Open (Unresolved)</option>
                  <option value="acknowledged">Acknowledged (Risk Accepted)</option>
                  <option value="fixed">Fixed (Remediated)</option>
                  <option value="false_positive">False Positive</option>
                </select>
              </div>
              <div>
                <label className="text-xs text-slate-400 mb-1 block">Audit Note</label>
                <input
                  type="text"
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  placeholder="Optional justification note..."
                  className="w-full bg-[#090f1b] border border-[#24324D] rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>

            <button
              onClick={handleSaveStatus}
              disabled={saving}
              className="mt-2 w-full flex items-center justify-center gap-2 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-bold transition disabled:opacity-50"
            >
              <Save className="w-3.5 h-3.5" />
              <span>{saving ? "Saving Changes..." : "Update Finding Status"}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
