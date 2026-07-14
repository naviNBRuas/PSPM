use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;

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
    State(_state): State<Arc<AppState>>,
) -> Json<AnalysisResponse> {
    Json(AnalysisResponse {
        total_logins: 0,
        passwords_reused: 0,
        weak_passwords: 0,
        old_passwords: 0,
        duplicate_entries: 0,
        accounts_without_mfa: 0,
        overall_score: 100,
    })
}
