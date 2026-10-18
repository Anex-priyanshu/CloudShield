"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Play,
  Cloud,
  ChevronDown,
  Sparkles,
  AlertCircle,
  RefreshCw,
  Plus,
} from "lucide-react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";

interface Account {
  id: number;
  name: string;
  provider: string;
  region: string;
  status: string;
}

interface TopBarProps {
  onAccountChange?: (account: Account | null) => void;
  selectedAccountId?: number;
}

export function TopBar({ onAccountChange, selectedAccountId }: TopBarProps) {
  const router = useRouter();
  const { isAdmin } = useAuth();
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [currentAccount, setCurrentAccount] = useState<Account | null>(null);
  const [scanning, setScanning] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  const loadAccounts = async () => {
    try {
      const data = await api.getAccounts();
      setAccounts(data);
      if (data.length > 0) {
        const found = selectedAccountId ? data.find((a: Account) => a.id === selectedAccountId) : data[0];
        const active = found || data[0];
        setCurrentAccount(active);
        onAccountChange?.(active);
      } else {
        setCurrentAccount(null);
        onAccountChange?.(null);
      }
    } catch (e: any) {
      console.warn("Could not load accounts", e);
    }
  };

  useEffect(() => {
    loadAccounts();
  }, [selectedAccountId]);

  const handleSelectAccount = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const id = parseInt(e.target.value);
    const acc = accounts.find((a) => a.id === id) || null;
    setCurrentAccount(acc);
    onAccountChange?.(acc);
  };

  const handleStartScan = async () => {
    if (!currentAccount) return;
    setScanning(true);
    setErrorMsg("");
    try {
      const scanRes = await api.startScan(currentAccount.id);
      router.push(`/scans?scan_id=${scanRes.id}`);
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to trigger scan");
      setTimeout(() => setErrorMsg(""), 5000);
    } finally {
      setScanning(false);
    }
  };

  return (
    <header className="h-16 bg-[#0B1220] border-b border-[#24324D] px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Left: Account Selector */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 bg-[#111B2E] border border-[#24324D] rounded-lg px-3 py-1.5 shadow-sm">
          <Cloud className="w-4 h-4 text-cyan-400" />
          {accounts.length > 0 ? (
            <select
              value={currentAccount?.id || ""}
              onChange={handleSelectAccount}
              className="bg-transparent text-sm font-medium text-slate-200 focus:outline-none cursor-pointer pr-2"
            >
              {accounts.map((acc) => (
                <option key={acc.id} value={acc.id} className="bg-[#111B2E] text-slate-200">
                  {acc.name} ({acc.provider.toUpperCase()} - {acc.region})
                </option>
              ))}
            </select>
          ) : (
            <span className="text-xs text-slate-400">No account connected</span>
          )}
        </div>

        {accounts.length === 0 && (
          <button
            onClick={() => router.push("/accounts")}
            className="text-xs font-semibold px-2.5 py-1.5 bg-cyan-600/20 text-cyan-400 hover:bg-cyan-600/30 border border-cyan-500/30 rounded-lg flex items-center gap-1.5 transition"
          >
            <Plus className="w-3.5 h-3.5" />
            Connect AWS Account
          </button>
        )}

        {errorMsg && (
          <div className="flex items-center gap-1.5 text-xs text-red-400 bg-red-950/40 px-3 py-1 rounded border border-red-800">
            <AlertCircle className="w-3.5 h-3.5" />
            {errorMsg}
          </div>
        )}
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-3">
        {isAdmin && currentAccount && (
          <button
            onClick={handleStartScan}
            disabled={scanning}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold rounded-lg shadow-lg shadow-blue-600/25 transition disabled:opacity-50"
          >
            {scanning ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4 fill-white" />
            )}
            <span>{scanning ? "Starting..." : "Start Scan"}</span>
          </button>
        )}
      </div>
    </header>
  );
}
