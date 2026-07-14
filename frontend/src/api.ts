const BASE = "/api";

async function request<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export interface DashboardMetrics {
  overall_security_score: number;
  total_items: number;
  password_reuse_percentage: number;
  weak_password_percentage: number;
  breached_password_percentage: number;
  mfa_coverage_percentage: number;
  passkey_adoption_percentage: number;
  duplicate_percentage: number;
  last_audit_date: string | null;
  password_age_avg_days: number;
  grade_distribution: {
    a_plus: number;
    a: number;
    b: number;
    c: number;
    d: number;
    f: number;
  };
}

export async function getDashboardMetrics(): Promise<DashboardMetrics> {
  return request("/dashboard/metrics");
}

export async function importVault(format: string, data: string) {
  return request("/vault/import", {
    method: "POST",
    body: JSON.stringify({ format, data }),
  });
}

export async function checkPassword(password: string) {
  return request("/strength/check", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

export async function checkBreach(password: string) {
  return request("/breach/check", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

export async function generatePassword(opts: {
  length?: number;
  style?: string;
  include_lowercase?: boolean;
  include_uppercase?: boolean;
  include_digits?: boolean;
  include_symbols?: boolean;
}) {
  return request("/generator/generate", {
    method: "POST",
    body: JSON.stringify(opts),
  });
}

export async function getAnalysis() {
  return request("/analysis/report");
}

export async function getHealth(): Promise<string> {
  const res = await fetch(`${BASE}/health`);
  return res.text();
}
