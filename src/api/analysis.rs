use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;

use crate::api::AppError;
use crate::AppState;

#[derive(Serialize)]
pub struct AnalysisResponse {
    pub total_logins: u32,
    pub passwords_reused: u32,
    pub weak_passwords: u32,
    pub old_passwords: u32,
    pub duplicate_entries: u32,
    pub accounts_without_mfa: u32,
    pub overall_score: u8,
}

pub async fn get_report(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AnalysisResponse>, AppError> {
    let items = state.db.list_all_items()?;
    let total_logins = items.len() as u32;
    let passwords_reused = count_reused(&items);
    let weak_passwords = count_weak(&items);
    let old_passwords = count_old(&items);
    let duplicate_entries = count_dup(&items);
    let accounts_without_mfa = items.iter().filter(|i| !i.mfa_enabled).count() as u32;
    let overall_score = compute_score(total_logins, passwords_reused, weak_passwords, accounts_without_mfa);

    Ok(Json(AnalysisResponse {
        total_logins,
        passwords_reused,
        weak_passwords,
        old_passwords,
        duplicate_entries,
        accounts_without_mfa,
        overall_score,
    }))
}

fn count_reused(items: &[pspm_core::types::Item]) -> u32 {
    let mut hashes: Vec<&str> = items.iter().filter_map(|i| i.password_hash.as_deref()).filter(|h| !h.is_empty()).collect();
    let total = hashes.len();
    hashes.sort_unstable();
    hashes.dedup();
    (total - hashes.len()) as u32
}

fn count_weak(items: &[pspm_core::types::Item]) -> u32 {
    items.iter().filter(|i| i.password_hash.as_deref().map(|h| h.len() < 20).unwrap_or(false)).count() as u32
}

fn count_old(items: &[pspm_core::types::Item]) -> u32 {
    let cutoff = chrono::Utc::now() - chrono::Duration::days(365);
    items.iter().filter(|i| i.updated_at < cutoff).count() as u32
}

fn count_dup(items: &[pspm_core::types::Item]) -> u32 {
    let mut seen = std::collections::HashSet::new();
    let mut dup = 0;
    for item in items {
        let key = (item.uris.first().map(|s| s.as_str()).unwrap_or(""), item.username.as_deref());
        if !seen.insert(key) {
            dup += 1;
        }
    }
    dup
}

fn compute_score(total: u32, reused: u32, weak: u32, no_mfa: u32) -> u8 {
    if total == 0 { return 100; }
    let reuse_penalty = (reused as f64 / total as f64) * 25.0;
    let weak_penalty = (weak as f64 / total as f64) * 30.0;
    let mfa_penalty = (no_mfa as f64 / total as f64) * 15.0;
    (100.0 - reuse_penalty - weak_penalty - mfa_penalty).clamp(0.0, 100.0) as u8
}
