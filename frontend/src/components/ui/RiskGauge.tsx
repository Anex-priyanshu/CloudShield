"use client";

import React from "react";

interface RiskGaugeProps {
  score: number; // 0 - 100
  size?: number;
}

export function RiskGauge({ score, size = 180 }: RiskGaugeProps) {
  const clampedScore = Math.max(0, Math.min(100, Math.round(score)));

  let strokeColor = "#16A34A"; // low risk / green
  let statusText = "Low Risk";
  let statusBg = "text-emerald-400";

  if (clampedScore >= 70) {
    strokeColor = "#DC2626";
    statusText = "Critical Risk";
    statusBg = "text-red-400";
  } else if (clampedScore >= 50) {
    strokeColor = "#EA580C";
    statusText = "High Risk";
    statusBg = "text-orange-400";
  } else if (clampedScore >= 20) {
    strokeColor = "#CA8A04";
    statusText = "Medium Risk";
    statusBg = "text-amber-400";
  }

  const strokeWidth = 14;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  // Semi-circle or 270 degree arc
  const arcLength = circumference * 0.75;
  const strokeDashoffset = arcLength - (clampedScore / 100) * arcLength;

  return (
    <div className="relative flex flex-col items-center justify-center p-3">
      <svg
        width={size}
        height={size}
        className="transform -rotate-[135deg]"
        style={{ overflow: "visible" }}
      >
        {/* Background track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="#1A2740"
          strokeWidth={strokeWidth}
          fill="none"
          strokeDasharray={arcLength}
          strokeDashoffset={0}
          strokeLinecap="round"
        />
        {/* Colored progress arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
          fill="none"
          strokeDasharray={arcLength}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.8s ease-out" }}
        />
      </svg>

      {/* Center Score */}
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className="text-4xl font-extrabold tracking-tight text-white font-mono">
          {clampedScore}
        </span>
        <span className="text-xs uppercase tracking-wider text-slate-400 font-medium mt-0.5">
          Score / 100
        </span>
        <span className={`text-xs font-semibold mt-1 px-2 py-0.5 rounded-full ${statusBg} bg-slate-900/60 border border-slate-800`}>
          {statusText}
        </span>
      </div>
    </div>
  );
}
