"use client";

import React from "react";
import { AlertTriangle, AlertCircle, Info, ShieldCheck, Flame } from "lucide-react";

interface SeverityPillProps {
  severity: number | string;
  size?: "sm" | "md" | "lg";
  showIcon?: boolean;
}

export function SeverityPill({ severity, size = "md", showIcon = true }: SeverityPillProps) {
  let label = "Low";
  let bg = "bg-blue-900/30 text-blue-400 border-blue-800/50";
  let icon = <Info className="w-3.5 h-3.5 mr-1" />;

  const sevStr = String(severity).toLowerCase();

  if (sevStr === "5" || sevStr === "critical") {
    label = "Critical";
    bg = "bg-red-950/50 text-red-400 border-red-800/60";
    icon = <Flame className="w-3.5 h-3.5 mr-1 text-red-400" />;
  } else if (sevStr === "4" || sevStr === "high") {
    label = "High";
    bg = "bg-orange-950/50 text-orange-400 border-orange-800/60";
    icon = <AlertTriangle className="w-3.5 h-3.5 mr-1 text-orange-400" />;
  } else if (sevStr === "3" || sevStr === "medium") {
    label = "Medium";
    bg = "bg-amber-950/50 text-amber-400 border-amber-800/60";
    icon = <AlertCircle className="w-3.5 h-3.5 mr-1 text-amber-400" />;
  } else if (sevStr === "0" || sevStr === "ok" || sevStr === "passed") {
    label = "Passed";
    bg = "bg-emerald-950/50 text-emerald-400 border-emerald-800/60";
    icon = <ShieldCheck className="w-3.5 h-3.5 mr-1 text-emerald-400" />;
  }

  const sizeClasses = {
    sm: "px-1.5 py-0.5 text-xs font-medium",
    md: "px-2.5 py-1 text-xs font-semibold",
    lg: "px-3 py-1.5 text-sm font-bold",
  }[size];

  return (
    <span
      className={`inline-flex items-center rounded-full border ${bg} ${sizeClasses} whitespace-nowrap`}
    >
      {showIcon && icon}
      {label}
    </span>
  );
}
