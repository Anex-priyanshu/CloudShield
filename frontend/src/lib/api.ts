/**
 * CloudShield API Client
 */

export function getApiBase(): string {
  if (typeof window !== "undefined") {
    return `${window.location.protocol}//${window.location.hostname}:8000/api/v1`;
  }
  return process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("cloudshield_token");
}

export function setToken(token: string) {
  if (typeof window !== "undefined") {
    localStorage.setItem("cloudshield_token", token);
  }
}

export function clearToken() {
  if (typeof window !== "undefined") {
    localStorage.removeItem("cloudshield_token");
    localStorage.removeItem("cloudshield_user");
  }
}

export function getUser(): any | null {
  if (typeof window === "undefined") return null;
  const user = localStorage.getItem("cloudshield_user");
  try {
    return user ? JSON.parse(user) : null;
  } catch {
    return null;
  }
}

export function setUser(user: any) {
  if (typeof window !== "undefined") {
    localStorage.setItem("cloudshield_user", JSON.stringify(user));
  }
}

async function request<T = any>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string> || {}),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  if (!(options.body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  const res = await fetch(`${getApiBase()}${endpoint}`, {
    ...options,
    headers,
  });

  if (res.status === 401) {
    clearToken();
    if (typeof window !== "undefined" && !window.location.pathname.includes("/login")) {
      window.location.href = "/login";
    }
    throw new Error("Session expired. Please log in again.");
  }

  if (!res.ok) {
    let errorDetail = "An unexpected error occurred.";
    try {
      const errJson = await res.json();
      errorDetail = errJson.detail || errJson.message || JSON.stringify(errJson);
    } catch {
      errorDetail = await res.text();
    }
    throw new Error(errorDetail);
  }

  // Handle binary / text responses
  const contentType = res.headers.get("content-type");
  if (contentType?.includes("application/pdf") || contentType?.includes("text/csv")) {
    return (await res.blob()) as unknown as T;
  }

  return res.json();
}

export const api = {
  // Auth
  login: async (email: string, password: string) => {
    const data = await request("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    setToken(data.access_token);
    const userData = { email: data.email, role: data.role };
    setUser(userData);
    return { ...data, user: userData };
  },
  getMe: () => request("/auth/me"),

  // Accounts
  getAccounts: () => request("/accounts"),
  createAccount: (accountData: any) =>
    request("/accounts", { method: "POST", body: JSON.stringify(accountData) }),
  testAccount: (id: number) =>
    request(`/accounts/${id}/test`, { method: "POST" }),
  deleteAccount: (id: number) =>
    request(`/accounts/${id}`, { method: "DELETE" }),

  // Scans
  startScan: (accountId: number) =>
    request("/scans", { method: "POST", body: JSON.stringify({ account_id: accountId }) }),
  getScans: (accountId?: number) =>
    request(`/scans${accountId ? `?account_id=${accountId}` : ""}`),
  getScan: (id: number) => request(`/scans/${id}`),
  cancelScan: (id: number) =>
    request(`/scans/${id}/cancel`, { method: "POST" }),
  compareScan: (id: number) =>
    request(`/scans/${id}/compare`),

  // Findings
  getFindings: (params: Record<string, any> = {}) => {
    const q = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") q.append(k, String(v));
    });
    return request(`/findings?${q.toString()}`);
  },
  getFinding: (id: number) => request(`/findings/${id}`),
  updateFinding: (id: number, updateData: any) =>
    request(`/findings/${id}`, { method: "PATCH", body: JSON.stringify(updateData) }),
  bulkUpdateFindings: (ids: number[], status: string, note?: string) =>
    request("/findings/bulk", {
      method: "POST",
      body: JSON.stringify({ finding_ids: ids, status, note }),
    }),

  // Dashboard
  getDashboardSummary: (accountId?: number) =>
    request(`/dashboard/summary${accountId ? `?account_id=${accountId}` : ""}`),
  getDashboardTrend: (accountId?: number) =>
    request(`/dashboard/trend${accountId ? `?account_id=${accountId}` : ""}`),

  // Events & Alerts
  getEvents: (accountId?: number, limit: number = 50) =>
    request(`/events?limit=${limit}${accountId ? `&account_id=${accountId}` : ""}`),
  getAlerts: (params: Record<string, any> = {}) => {
    const q = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") q.append(k, String(v));
    });
    return request(`/alerts?${q.toString()}`);
  },
  updateAlert: (id: number, status: string, note?: string) =>
    request(`/alerts/${id}`, { method: "PATCH", body: JSON.stringify({ status, note }) }),

  // IaC Scanner
  scanIacSample: (sampleType: "insecure" | "secure" = "insecure") => {
    const form = new FormData();
    form.append("sample_type", sampleType);
    return request("/iac/sample", { method: "POST", body: form });
  },
  scanIacFiles: (files: File[]) => {
    const form = new FormData();
    files.forEach((f) => form.append("files", f));
    return request("/iac/scan", { method: "POST", body: form });
  },
  getIacScans: () => request("/iac/scans"),

  // Reports
  getReports: () => request("/reports"),
  downloadPdf: (scanId: number) =>
    request<Blob>(`/reports/${scanId}/pdf`),
  downloadCsv: (scanId: number) =>
    request<Blob>(`/reports/${scanId}/csv`),
  downloadJson: (scanId: number) =>
    request(`/reports/${scanId}/json`),

  // Settings
  getSettings: () => request("/settings"),
  updateSettings: (settingsData: any) =>
    request("/settings", { method: "PUT", body: JSON.stringify(settingsData) }),
  recalculateScores: () =>
    request("/settings/recalculate", { method: "POST" }),
  changePassword: (currentPassword: string, newPassword: string) =>
    request("/settings/change-password", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),
};
