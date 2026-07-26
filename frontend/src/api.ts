const BASE = "/api";

async function request<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

// ─── Dashboard ────────────────────────────────────────────────

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

// ─── Vault / Items ────────────────────────────────────────────

export interface VaultItem {
  id: string;
  name: string;
  username: string | null;
  password_encrypted?: string | null;
  uris: string[];
  notes?: string | null;
  folder_id: string | null;
  organization_id?: string | null;
  item_type?: string;
  favorite?: boolean;
  mfa_enabled?: boolean;
  passkey?: boolean;
  reprompt?: string;
  strength: string | null;
  strength_detail?: { entropy: number; length: number; grade: string } | null;
  breached: boolean;
  breach_detail?: { password_breached: boolean; email_breached: boolean; breach_count: number } | null;
  created_at: string;
  updated_at: string;
  last_used?: string | null;
}

export interface Folder {
  id: string;
  vault_id: string;
  name: string;
  parent_id: string | null;
  item_count: number;
  created_at: string;
  updated_at: string;
}

export interface ImportResult {
  vault_id: string;
  item_count: number;
}

export async function listVaultItems(): Promise<VaultItem[]> {
  return request("/vault/items");
}

export async function importVault(format: string, data: string): Promise<ImportResult> {
  return request("/vault/import", {
    method: "POST",
    body: JSON.stringify({ format, data }),
  });
}

export async function exportVault(): Promise<{ format: string; data: string }> {
  return request("/vault/export");
}

export async function listVaults(): Promise<{ id: string; name: string; source: string; item_count: number }[]> {
  return request("/vault/list");
}

export async function deleteVault(id: string): Promise<void> {
  await request(`/vault/${id}`, { method: "DELETE" });
}

// ─── Item CRUD ────────────────────────────────────────────────

export interface UpdateItemRequest {
  id: string;
  name?: string;
  username?: string;
  password_encrypted?: string;
  uris?: string[];
  notes?: string;
  folder_id?: string | null;
  favorite?: boolean;
  mfa_enabled?: boolean;
  passkey?: boolean;
}

export async function updateItem(req: UpdateItemRequest): Promise<void> {
  await request("/vault/items/update", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export async function deleteItems(ids: string[]): Promise<{ deleted: number }> {
  return request("/vault/items/delete", {
    method: "POST",
    body: JSON.stringify({ ids }),
  });
}

export async function moveItems(ids: string[], folder_id?: string | null, vault_id?: string): Promise<void> {
  await request("/vault/items/move", {
    method: "POST",
    body: JSON.stringify({ ids, folder_id: folder_id ?? undefined, vault_id }),
  });
}

// ─── Folders ──────────────────────────────────────────────────

export async function listFolders(vaultId: string): Promise<Folder[]> {
  return request(`/vault/folders/${vaultId}`);
}

export async function createFolder(vaultId: string, name: string, parentId?: string): Promise<Folder> {
  return request("/vault/folders", {
    method: "POST",
    body: JSON.stringify({ vault_id: vaultId, name, parent_id: parentId }),
  });
}

export async function updateFolder(folderId: string, name?: string, parentId?: string | null): Promise<void> {
  await request(`/vault/folders/${folderId}`, {
    method: "PUT",
    body: JSON.stringify({ name, parent_id: parentId }),
  });
}

export async function deleteFolder(folderId: string): Promise<void> {
  await request(`/vault/folders/${folderId}`, { method: "DELETE" });
}

// ─── Strength & Breach ────────────────────────────────────────

export interface PasswordStrengthResult {
  entropy: number;
  length: number;
  charset_size: number;
  grade: string;
  has_lowercase: boolean;
  has_uppercase: boolean;
  has_digits: boolean;
  has_symbols: boolean;
  contains_dictionary_word: boolean;
  contains_keyboard_walk: boolean;
  contains_date: boolean;
}

export interface BreachCheckResult {
  password_breached: boolean;
  email_breached: boolean;
  username_leaked: boolean;
  breach_count: number;
  breach_sources: string[];
}

export async function checkPassword(password: string): Promise<PasswordStrengthResult> {
  return request("/strength/check", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

export async function checkBreach(password: string): Promise<BreachCheckResult> {
  return request("/breach/check", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

// ─── Generator ────────────────────────────────────────────────

export interface GenerateResult {
  password: string;
}

export async function generatePassword(opts: {
  length?: number;
  style?: string;
  include_lowercase?: boolean;
  include_uppercase?: boolean;
  include_digits?: boolean;
  include_symbols?: boolean;
  no_ambiguous?: boolean;
}): Promise<GenerateResult> {
  return request("/generator/generate", {
    method: "POST",
    body: JSON.stringify(opts),
  });
}

// ─── Analysis ─────────────────────────────────────────────────

export interface AnalysisReport {
  total_logins: number;
  passwords_reused: number;
  weak_passwords: number;
  old_passwords: number;
  duplicate_entries: number;
  accounts_without_mfa: number;
  overall_score: number;
}

export async function getAnalysis(): Promise<AnalysisReport> {
  return request("/analysis/report");
}

// ─── Duplicates ───────────────────────────────────────────────

export interface DuplicateGroupResponse {
  canonical_item_id: string;
  duplicate_item_ids: string[];
  match_reason: string;
  can_merge: boolean;
  merge_suggestion?: string;
}

export interface DuplicateResponse {
  groups: DuplicateGroupResponse[];
}

export async function findDuplicates(): Promise<DuplicateResponse> {
  return request("/duplicates");
}

export async function mergeDuplicates(canonicalItemId: string, duplicateItemIds: string[], deleteAfterMerge = true): Promise<void> {
  await request("/duplicates/merge", {
    method: "POST",
    body: JSON.stringify({ canonical_item_id: canonicalItemId, duplicate_item_ids: duplicateItemIds, delete_after_merge: deleteAfterMerge }),
  });
}

// ─── Rotation ─────────────────────────────────────────────────

export interface RotateResponse {
  item_id: string;
  new_password: string;
  status: string;
  domain: string | null;
}

export interface RotateBulkResponse {
  results: RotateResponse[];
  total: number;
  succeeded: number;
}

export async function rotatePassword(itemId: string): Promise<RotateResponse> {
  return request("/rotation/rotate", {
    method: "POST",
    body: JSON.stringify({ item_id: itemId }),
  });
}

export async function rotateBulk(itemIds: string[]): Promise<RotateBulkResponse> {
  return request("/rotation/rotate-bulk", {
    method: "POST",
    body: JSON.stringify({ item_ids: itemIds }),
  });
}

export interface RotationHistoryEntry {
  id: string;
  item_id: string;
  old_password_hash: string | null;
  new_password_hash: string;
  status: string;
  domain: string | null;
  rotated_at: string;
}

export async function getRotationHistory(): Promise<{ entries: RotationHistoryEntry[] }> {
  return request("/rotation/history");
}

// ─── Audit ────────────────────────────────────────────────────

export interface AuditLogEntry {
  id: string;
  action: string;
  item_id: string | null;
  details: string | null;
  created_at: string;
}

export async function listAuditLogs(): Promise<{ entries: AuditLogEntry[] }> {
  return request("/audit/logs");
}

// ─── Health ───────────────────────────────────────────────────

export async function getHealth(): Promise<string> {
  const res = await fetch(`${BASE}/health`);
  return res.text();
}
