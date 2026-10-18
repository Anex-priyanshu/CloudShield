"use client";

import React, { useEffect, useState } from "react";
import { useRouter, usePathname } from "next/navigation";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { useAuth } from "@/lib/auth";

export function AppShell({
  children,
  onAccountChange,
  selectedAccountId,
}: {
  children: React.ReactNode;
  onAccountChange?: (account: any) => void;
  selectedAccountId?: number;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const { user, loading } = useAuth();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    if (!loading && !user && pathname !== "/login") {
      router.push("/login");
    }
  }, [user, loading, pathname, router]);

  if (!mounted || loading) {
    return (
      <div className="min-h-screen bg-[#0B1220] flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin" />
          <span className="text-sm font-medium text-slate-400">Loading CloudShield...</span>
        </div>
      </div>
    );
  }

  if (!user && pathname !== "/login") {
    return null;
  }

  return (
    <div className="flex min-h-screen bg-[#0B1220] text-[#E5EAF3]">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <TopBar onAccountChange={onAccountChange} selectedAccountId={selectedAccountId} />
        <main className="flex-1 p-6 max-w-[1440px] w-full mx-auto overflow-y-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
