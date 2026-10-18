"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
  LayoutDashboard,
  Cloud,
  Radar,
  AlertOctagon,
  Activity,
  FileCode2,
  FileText,
  Settings,
  LogOut,
  ChevronRight,
  Radio,
} from "lucide-react";
import { useAuth } from "@/lib/auth";
import { wsClient } from "@/lib/ws";

interface NavItem {
  name: string;
  href: string;
  icon: any;
  badge?: number | string;
}

export function Sidebar() {
  const pathname = usePathname();
  const { user, logout, isAdmin } = useAuth();
  const [alertCount, setAlertCount] = useState<number>(0);
  const [isLive, setIsLive] = useState<boolean>(false);

  useEffect(() => {
    // Listen to real-time alerts to update badge
    const unsubscribeAlert = wsClient.on("alert.new", () => {
      setAlertCount((prev) => prev + 1);
    });

    const unsubscribeStatus = wsClient.on("ws.status", (data: any) => {
      setIsLive(data?.connected ?? false);
    });

    return () => {
      unsubscribeAlert();
      unsubscribeStatus();
    };
  }, []);

  const navItems: NavItem[] = [
    { name: "Dashboard", href: "/", icon: LayoutDashboard },
    { name: "Cloud Accounts", href: "/accounts", icon: Cloud },
    { name: "Scans", href: "/scans", icon: Radar },
    { name: "Findings", href: "/findings", icon: AlertOctagon },
    {
      name: "Live Monitor",
      href: "/monitor",
      icon: Activity,
      badge: alertCount > 0 ? alertCount : undefined,
    },
    { name: "IaC Scanner", href: "/iac", icon: FileCode2 },
    { name: "Reports", href: "/reports", icon: FileText },
    { name: "Settings", href: "/settings", icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[#0d1627] border-r border-[#24324D] flex flex-col shrink-0 select-none min-h-screen">
      {/* Brand Header */}
      <div className="h-16 flex items-center px-5 border-b border-[#24324D] gap-3">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-blue-600 to-cyan-400 flex items-center justify-center shadow-lg shadow-blue-500/20">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center gap-1.5">
            <span className="font-bold text-base tracking-tight text-white font-sans">
              CloudShield
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.2 bg-blue-900/60 text-cyan-300 rounded border border-blue-700/50">
              v1.0
            </span>
          </div>
          <p className="text-[11px] text-slate-400 font-medium truncate max-w-[140px]">
            Posture & Risk Engine
          </p>
        </div>
      </div>

      {/* Live Poller Status Banner */}
      <div className="mx-3 mt-3 px-3 py-2 rounded-lg bg-[#111B2E] border border-[#24324D] flex items-center justify-between text-xs">
        <div className="flex items-center gap-2">
          <span className={`w-2.5 h-2.5 rounded-full ${isLive ? "bg-emerald-500 animate-pulse-live" : "bg-red-500"}`} />
          <span className="text-slate-300 font-medium">
            {isLive ? "Live Stream Active" : "Connecting..."}
          </span>
        </div>
        <Radio className={`w-3.5 h-3.5 ${isLive ? "text-cyan-400" : "text-slate-500"}`} />
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                isActive
                  ? "bg-blue-600/15 text-blue-400 border border-blue-500/30 shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-[#162238] border border-transparent"
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isActive ? "text-blue-400" : "text-slate-400"}`} />
                <span>{item.name}</span>
              </div>

              {item.badge && (
                <span className="px-1.5 py-0.5 text-[11px] font-bold bg-red-600 text-white rounded-full min-w-[18px] text-center">
                  {item.badge}
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* User & Role footer */}
      <div className="p-3 border-t border-[#24324D] bg-[#090f1b]">
        <div className="flex items-center justify-between p-2 rounded-lg bg-[#111B2E] border border-[#24324D]">
          <div className="min-w-0 pr-2">
            <p className="text-xs font-semibold text-slate-200 truncate">
              {user?.email || "Security Analyst"}
            </p>
            <div className="flex items-center gap-1.5 mt-0.5">
              <span className={`text-[10px] font-bold px-1.5 py-0.2 uppercase rounded ${
                isAdmin ? "bg-amber-500/20 text-amber-400 border border-amber-600/30" : "bg-blue-500/20 text-blue-400"
              }`}>
                {user?.role || "Admin"}
              </span>
            </div>
          </div>
          <button
            onClick={logout}
            title="Sign out"
            className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-950/30 rounded transition"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </aside>
  );
}
