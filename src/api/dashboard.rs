use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;

use crate::api::AppError;
use crate::AppState;

#[derive(Serialize)]
pub struct DashboardResponse {
    pub overall_security_score: u8,
    pub total_items: u32,
    pub password_reuse_percentage: f64,
    pub weak_password_percentage: f64,
    pub breached_password_percentage: f64,
    pub mfa_coverage_percentage: f64,
    pub passkey_adoption_percentage: f64,
    pub duplicate_percentage: f64,
    pub last_audit_date: Option<String>,
    pub password_age_avg_days: f64,
    pub grade_distribution: GradeDistResponse,
}

#[derive(Serialize)]
pub struct GradeDistResponse {
    pub a_plus: u32,
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub f: u32,
}

pub async fn get_metrics(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DashboardResponse>, AppError> {
    let items = state.db.list_all_items()?;
    let total = items.len();
    let total_f = total as f64;

    let reused = count_reused(&items);
    let weak = count_weak(&items);
    let no_mfa = items.iter().filter(|i| !i.mfa_enabled).count() as u32;
    let passkeys = items.iter().filter(|i| i.passkey).count() as u32;
    let dup = count_dup(&items);

    // Count breached passwords from breach_checks table
    let breached = state.db.list_breach_checks()
        .map(|checks| checks.iter().filter(|c| c.password_breached).count() as u32)
        .unwrap_or(0);

    // Get last audit date
    let last_audit_date = state.db.list_audit_logs(1)
        .ok()
        .and_then(|logs| logs.first().map(|e| e.4.clone()));

    let mut grade_dist = GradeDistResponse { a_plus: 0, a: 0, b: 0, c: 0, d: 0, f: 0 };
    for item in &items {
        if let Some(pw) = &item.password_encrypted {
            let result = pspm_strength::StrengthAnalyzer::analyze(pw);
            match result.grade {
                pspm_core::types::PasswordGrade::APlus => grade_dist.a_plus += 1,
                pspm_core::types::PasswordGrade::A => grade_dist.a += 1,
                pspm_core::types::PasswordGrade::B => grade_dist.b += 1,
                pspm_core::types::PasswordGrade::C => grade_dist.c += 1,
                pspm_core::types::PasswordGrade::D => grade_dist.d += 1,
                pspm_core::types::PasswordGrade::F => grade_dist.f += 1,
            }
        }
    }

    let reuse_penalty = if total > 0 { (reused as f64 / total_f) * 25.0 } else { 0.0 };
    let weak_penalty = if total > 0 { (weak as f64 / total_f) * 30.0 } else { 0.0 };
    let breach_penalty = if total > 0 { (breached as f64 / total_f) * 30.0 } else { 0.0 };
    let mfa_penalty = if total > 0 { (no_mfa as f64 / total_f) * 15.0 } else { 0.0 };
    let score = (100.0 - reuse_penalty - weak_penalty - breach_penalty - mfa_penalty).clamp(0.0, 100.0) as u8;

    let avg_age = if total > 0 {
        let now = chrono::Utc::now();
        items.iter().map(|i| (now - i.updated_at).num_days() as f64).sum::<f64>() / total_f
    } else {
        0.0
    };

    let pct = |n: f64| if total_f > 0.0 { (n / total_f * 100.0 * 100.0).round() / 100.0 } else { 0.0 };

    Ok(Json(DashboardResponse {
        overall_security_score: score,
        total_items: total as u32,
        password_reuse_percentage: pct(reused as f64),
        weak_password_percentage: pct(weak as f64),
        breached_password_percentage: pct(breached as f64),
        mfa_coverage_percentage: pct((total as f64) - no_mfa as f64),
        passkey_adoption_percentage: pct(passkeys as f64),
        duplicate_percentage: pct(dup as f64),
        last_audit_date,
        password_age_avg_days: avg_age,
        grade_distribution: grade_dist,
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

fn count_dup(items: &[pspm_core::types::Item]) -> u32 {
    let mut seen = std::collections::HashSet::new();
    let mut dup = 0;
    for item in items {
        let key = (item.uris.first().map(|s| s.as_str()).unwrap_or(""), item.username.as_deref());
        if !seen.insert(key) { dup += 1; }
    }
    dup
}
