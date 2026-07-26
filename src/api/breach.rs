use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::AppError;
use crate::AppState;

#[derive(Deserialize)]
pub struct BreachRequest {
    pub password: String,
}

#[derive(Serialize)]
pub struct BreachResponse {
    pub breach_count: u32,
    pub compromised: bool,
}

pub async fn check_breach(
    _state: State<Arc<AppState>>,
    Json(req): Json<BreachRequest>,
) -> Json<BreachResponse> {
    let detector = pspm_breach::BreachDetector::new(None);
    match detector.check_password_hibp(&req.password).await {
        Ok(count) => Json(BreachResponse {
            breach_count: count,
            compromised: count > 0,
        }),
        Err(e) => {
            tracing::warn!("Breach check failed: {e}");
            Json(BreachResponse {
                breach_count: 0,
                compromised: false,
            })
        }
    }
}

#[derive(Serialize)]
pub struct BreachCheckEntry {
    pub item_id: String,
    pub password_breached: bool,
    pub email_breached: bool,
    pub username_leaked: bool,
    pub domain_compromised: bool,
    pub breach_count: u32,
    pub breach_sources: Vec<String>,
}

#[derive(Serialize)]
pub struct BreachCheckListResponse {
    pub checks: Vec<BreachCheckEntry>,
}

pub async fn list_breach_checks(
    State(state): State<Arc<AppState>>,
) -> Result<Json<BreachCheckListResponse>, AppError> {
    let checks = state.db.list_breach_checks()?;
    Ok(Json(BreachCheckListResponse {
        checks: checks.into_iter().map(|c| BreachCheckEntry {
            item_id: c.item_id.to_string(),
            password_breached: c.password_breached,
            email_breached: c.email_breached,
            username_leaked: c.username_leaked,
            domain_compromised: c.domain_compromised,
            breach_count: c.breach_count,
            breach_sources: c.breach_sources,
        }).collect(),
    }))
}
