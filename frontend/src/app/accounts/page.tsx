"use client";

import React, { useEffect, useState } from "react";
import {
  Cloud,
  Plus,
  Play,
  Trash2,
  CheckCircle,
  AlertCircle,
  Copy,
  Check,
  Shield,
  Sparkles,
  Lock,
  ExternalLink,
  RefreshCw,
} from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";

export default function AccountsPage() {
  const { isAdmin } = useAuth();
  const [accounts, setAccounts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [activeTab, setActiveTab] = useState<"demo" | "aws">("demo");
  const [copiedPolicy, setCopiedPolicy] = useState(false);
  const [testResult, setTestResult] = useState<{ id: number; message: string; ok: boolean } | null>(null);
  const [testingId, setTestingId] = useState<number | null>(null);

  // Form states
  const [name, setName] = useState("");
  const [region, setRegion] = useState("us-east-1");
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secretAccessKey, setSecretAccessKey] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState("");

  const loadAccounts = async () => {
    try {
      const data = await api.getAccounts();
      setAccounts(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAccounts();
  }, []);

  const handleTestConnection = async (id: number) => {
    setTestingId(id);
    setTestResult(null);
    try {
      const res = await api.testAccount(id);
      setTestResult({
        id,
        ok: res.status === "ok",
        message: res.status === "ok" ? `Connection successful! AWS Account ID: ${res.account_id}` : res.error,
      });
      loadAccounts();
    } catch (err: any) {
      setTestResult({ id, ok: false, message: err.message || "Connection failed" });
    } finally {
      setTestingId(null);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Are you sure you want to remove this cloud account? Stored encrypted credentials will be purged.")) {
      return;
    }
    try {
      await api.deleteAccount(id);
      loadAccounts();
    } catch (err: any) {
      alert(err.message || "Failed to delete account");
    }
  };

  const handleCreateDemo = async () => {
    setSubmitting(true);
    setFormError("");
    try {
      await api.createDemoAccount();
      setShowModal(false);
      loadAccounts();
    } catch (err: any) {
      setFormError(err.message || "Failed to create demo account");
    } finally {
      setSubmitting(false);
    }
  };

  const handleCreateAws = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setFormError("");
    try {
      await api.createAccount({
        name,
        provider: "aws",
        region,
        access_key_id: accessKeyId,
        secret_access_key: secretAccessKey,
      });
      setShowModal(false);
      setName("");
      setAccessKeyId("");
      setSecretAccessKey("");
      loadAccounts();
    } catch (err: any) {
      setFormError(err.message || "Failed to connect AWS account");
    } finally {
      setSubmitting(false);
    }
  };

  const READ_ONLY_POLICY_TEXT = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudShieldReadOnlyAudit",
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "iam:GenerateCredentialReport",
        "s3:GetBucket*",
        "s3:List*",
        "ec2:Describe*",
        "rds:Describe*",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:LookupEvents",
        "kms:List*",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    }
  ]
}`;

  const copyPolicy = () => {
    navigator.clipboard.writeText(READ_ONLY_POLICY_TEXT);
    setCopiedPolicy(true);
    setTimeout(() => setCopiedPolicy(false), 2000);
  };

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
              Connected Cloud Accounts
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Connect target AWS accounts with read-only permissions or explore using simulated demo environments.
            </p>
          </div>

          {isAdmin && (
            <button
              onClick={() => setShowModal(true)}
              className="flex items-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold rounded-xl shadow-lg shadow-blue-600/25 transition"
            >
              <Plus className="w-4 h-4" />
              <span>Connect New Account</span>
            </button>
          )}
        </div>

        {/* Ethical / Legal Warning Banner */}
        <div className="p-4 bg-[#111B2E] border border-amber-500/30 rounded-xl flex items-start gap-3 text-xs text-amber-300/90">
          <Shield className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="leading-relaxed">
            <strong className="text-amber-300">Authorised Assessment Policy:</strong> Scan only cloud accounts you own or are explicitly authorised to audit. CloudShield operates exclusively using non-intrusive, read-only AWS APIs (Describe/List/LookupEvents). No cloud resource will be modified or created.
          </div>
        </div>

        {/* Account Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {accounts.map((acc) => (
            <div
              key={acc.id}
              className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-5 flex flex-col justify-between hover:border-slate-600 transition shadow-sm"
            >
              <div>
                <div className="flex items-start justify-between mb-3">
                  <div className="w-10 h-10 rounded-xl bg-blue-950/60 border border-blue-800/60 flex items-center justify-center text-cyan-400">
                    <Cloud className="w-5 h-5" />
                  </div>
                  {acc.is_demo ? (
                    <span className="text-[11px] font-bold px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/30">
                      DEMO SANDBOX
                    </span>
                  ) : (
                    <span className="text-[11px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                      CONNECTED
                    </span>
                  )}
                </div>

                <h3 className="text-base font-bold text-white truncate">{acc.name}</h3>
                <div className="text-xs font-mono text-slate-400 mt-1 space-y-0.5">
                  <p>Provider: <span className="text-slate-300 font-semibold">{acc.provider?.toUpperCase()}</span></p>
                  <p>Region: <span className="text-slate-300 font-semibold">{acc.region}</span></p>
                  {acc.account_id && <p>AWS ID: <span className="text-cyan-400 font-semibold">{acc.account_id}</span></p>}
                </div>

                {testResult && testResult.id === acc.id && (
                  <div className={`mt-3 p-2.5 rounded-lg text-xs border ${
                    testResult.ok ? "bg-emerald-950/40 text-emerald-300 border-emerald-800" : "bg-red-950/40 text-red-300 border-red-800"
                  }`}>
                    {testResult.message}
                  </div>
                )}
              </div>

              <div className="mt-5 pt-4 border-t border-[#24324D] flex items-center justify-between">
                <button
                  onClick={() => handleTestConnection(acc.id)}
                  disabled={testingId === acc.id}
                  className="text-xs font-semibold px-3 py-1.5 bg-[#090f1b] hover:bg-[#162238] border border-[#24324D] rounded-lg text-slate-300 transition flex items-center gap-1.5"
                >
                  {testingId === acc.id ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle className="w-3.5 h-3.5 text-cyan-400" />}
                  <span>{testingId === acc.id ? "Testing..." : "Test STS"}</span>
                </button>

                {isAdmin && (
                  <button
                    onClick={() => handleDelete(acc.id)}
                    className="p-2 text-slate-400 hover:text-red-400 hover:bg-red-950/30 rounded-lg transition"
                    title="Remove Account"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>
          ))}

          {accounts.length === 0 && !loading && (
            <div className="col-span-full py-12 bg-[#111B2E] border border-[#24324D] rounded-2xl text-center space-y-3 p-6">
              <Cloud className="w-12 h-12 text-slate-500 mx-auto" />
              <h3 className="text-base font-bold text-white">No Cloud Accounts Connected</h3>
              <p className="text-xs text-slate-400 max-w-sm mx-auto">
                Connect your AWS account using read-only IAM credentials or spin up a simulated demo sandbox in one click.
              </p>
              <button
                onClick={() => setShowModal(true)}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-bold transition inline-flex items-center gap-2"
              >
                <Plus className="w-4 h-4" />
                Connect First Account
              </button>
            </div>
          )}
        </div>

        {/* Read-Only Policy Reference Box */}
        <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Lock className="w-4 h-4 text-cyan-400" />
                Required Read-Only IAM Policy
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Attach AWS managed policies <code className="text-cyan-300 bg-[#090f1b] px-1 py-0.5 rounded">SecurityAudit</code> and <code className="text-cyan-300 bg-[#090f1b] px-1 py-0.5 rounded">ViewOnlyAccess</code> to a dedicated user <code className="text-slate-300 font-mono">cloudshield-readonly</code>, or use the custom minimal JSON below:
              </p>
            </div>
            <button
              onClick={copyPolicy}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold px-3 py-1.5 bg-[#090f1b] border border-[#24324D] rounded-lg flex items-center gap-1.5 transition"
            >
              {copiedPolicy ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedPolicy ? "Copied Policy" : "Copy Policy JSON"}</span>
            </button>
          </div>

          <pre className="p-3 bg-[#090f1b] border border-[#24324D] rounded-xl text-xs font-mono text-slate-300 max-h-44 overflow-y-auto">
            {READ_ONLY_POLICY_TEXT}
          </pre>
        </div>
      </div>

      {/* Add Account Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in">
          <div className="bg-[#111B2E] border border-[#24324D] rounded-2xl max-w-lg w-full p-6 space-y-5 shadow-2xl relative">
            <div className="flex items-center justify-between border-b border-[#24324D] pb-4">
              <h2 className="text-lg font-bold text-white">Connect Cloud Account</h2>
              <button
                onClick={() => setShowModal(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            {formError && (
              <div className="p-3 bg-red-950/40 border border-red-800 rounded-xl text-xs text-red-300">
                {formError}
              </div>
            )}

            {/* Tab switch */}
            <div className="flex p-1 bg-[#090f1b] rounded-xl border border-[#24324D]">
              <button
                type="button"
                onClick={() => setActiveTab("demo")}
                className={`flex-1 py-2 text-xs font-bold rounded-lg transition ${
                  activeTab === "demo"
                    ? "bg-blue-600 text-white shadow"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                ⚡ Instant Demo Mode (One-Click)
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("aws")}
                className={`flex-1 py-2 text-xs font-bold rounded-lg transition ${
                  activeTab === "aws"
                    ? "bg-blue-600 text-white shadow"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                ☁️ Real AWS Account
              </button>
            </div>

            {activeTab === "demo" ? (
              <div className="space-y-4 py-2">
                <div className="p-4 rounded-xl bg-blue-950/30 border border-blue-800/40 text-xs text-slate-300 space-y-2">
                  <p className="font-semibold text-cyan-300 flex items-center gap-1.5">
                    <Sparkles className="w-4 h-4" />
                    Simulated Insecure Cloud Environment
                  </p>
                  <p>
                    Creates a realistic sandbox with 6 S3 buckets (including public & unencrypted), 8 IAM users (admin with *:* and missing MFA), 5 security groups (SSH & DB ports open to 0.0.0.0/0), unencrypted EBS and RDS instances.
                  </p>
                  <p className="text-[11px] text-slate-400">
                    Runs through the exact same check engine and risk prioritisation formulas. Zero AWS setup or cost required.
                  </p>
                </div>

                <button
                  type="button"
                  onClick={handleCreateDemo}
                  disabled={submitting}
                  className="w-full py-3 bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 text-white font-bold rounded-xl text-xs shadow-lg shadow-blue-600/30 transition disabled:opacity-50"
                >
                  {submitting ? "Creating Demo Sandbox..." : "Create Simulated Demo Account"}
                </button>
              </div>
            ) : (
              <form onSubmit={handleCreateAws} className="space-y-3.5">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    Account Name / Alias
                  </label>
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. Production-Sandbox-Audit"
                    className="w-full bg-[#090f1b] border border-[#24324D] rounded-xl px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    Default Region
                  </label>
                  <input
                    type="text"
                    required
                    value={region}
                    onChange={(e) => setRegion(e.target.value)}
                    placeholder="us-east-1"
                    className="w-full bg-[#090f1b] border border-[#24324D] rounded-xl px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    AWS Access Key ID
                  </label>
                  <input
                    type="text"
                    required
                    value={accessKeyId}
                    onChange={(e) => setAccessKeyId(e.target.value)}
                    placeholder="AKIA..."
                    className="w-full bg-[#090f1b] border border-[#24324D] rounded-xl px-3 py-2 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    AWS Secret Access Key
                  </label>
                  <input
                    type="password"
                    required
                    value={secretAccessKey}
                    onChange={(e) => setSecretAccessKey(e.target.value)}
                    placeholder="••••••••••••••••••••••••"
                    className="w-full bg-[#090f1b] border border-[#24324D] rounded-xl px-3 py-2 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500"
                  />
                  <span className="text-[10px] text-slate-400 mt-1 block">
                    Credentials are encrypted with Fernet (AES-128-CBC) and never exposed via API.
                  </span>
                </div>

                <button
                  type="submit"
                  disabled={submitting}
                  className="w-full mt-2 py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl text-xs shadow-lg shadow-blue-600/30 transition disabled:opacity-50"
                >
                  {submitting ? "Validating & Encrypting..." : "Save and Verify Connection"}
                </button>
              </form>
            )}
          </div>
        </div>
      )}
    </AppShell>
  );
}
