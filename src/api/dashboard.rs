use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;

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
    State(_state): State<Arc<AppState>>,
) -> Json<DashboardResponse> {
    Json(DashboardResponse {
        overall_security_score: 0,
        total_items: 0,
        password_reuse_percentage: 0.0,
        weak_password_percentage: 0.0,
        breached_password_percentage: 0.0,
        mfa_coverage_percentage: 0.0,
        passkey_adoption_percentage: 0.0,
        duplicate_percentage: 0.0,
        last_audit_date: None,
        password_age_avg_days: 0.0,
        grade_distribution: GradeDistResponse {
            a_plus: 0,
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            f: 0,
        },
    })
}
