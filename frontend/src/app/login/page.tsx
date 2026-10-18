"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Lock, Mail, ArrowRight, AlertCircle, KeyRound } from "lucide-react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";

export default function LoginPage() {
  const router = useRouter();
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setError("Please fill in both email and password.");
      return;
    }
    setError("");
    setLoading(true);

    try {
      const data = await api.login(email, password);
      login(data.access_token, data.user);
      router.push("/");
    } catch (err: any) {
      setError(err.message || "Invalid credentials. Please verify and try again.");
    } finally {
      setLoading(false);
    }
  };

  const fillDemoCreds = () => {
    setEmail("admin@cloudshield.local");
    setPassword("Admin@12345!");
    setError("");
  };

  return (
    <div className="min-h-screen bg-[#0B1220] flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background radial glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-10 right-10 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md bg-[#111B2E] border border-[#24324D] rounded-2xl p-8 shadow-2xl relative z-10">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-blue-600 to-cyan-400 flex items-center justify-center shadow-lg shadow-blue-500/25 mb-4">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">
            CloudShield
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Cloud Security Posture & Risk-Prioritised Assessment Platform
          </p>
        </div>

        {error && (
          <div className="mb-6 p-3.5 bg-red-950/40 border border-red-800/80 rounded-xl flex items-center gap-2.5 text-xs text-red-300">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">
              Email Address
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="name@organization.com"
                className="w-full bg-[#090f1b] border border-[#24324D] rounded-xl pl-10 pr-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">
              Password
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-[#090f1b] border border-[#24324D] rounded-xl pl-10 pr-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-2 py-3 bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 text-white font-bold rounded-xl text-sm shadow-lg shadow-blue-600/30 flex items-center justify-center gap-2 transition disabled:opacity-50"
          >
            <span>{loading ? "Authenticating..." : "Sign In to CloudShield"}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        {/* Quick Demo Credentials shortcut */}
        <div className="mt-6 pt-5 border-t border-[#24324D] flex flex-col items-center">
          <button
            type="button"
            onClick={fillDemoCreds}
            className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 font-medium bg-[#162238] border border-[#24324D] px-3 py-1.5 rounded-lg transition"
          >
            <KeyRound className="w-3.5 h-3.5" />
            Fill Default Admin Credentials (Demo)
          </button>
          <span className="text-[11px] text-slate-500 mt-2">
            admin@cloudshield.local • Admin@12345!
          </span>
        </div>
      </div>
    </div>
  );
}
