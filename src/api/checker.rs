use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::AppError;
use crate::AppState;

#[derive(Deserialize)]
pub struct PrepareCheckRequest {
    pub item_id: String,
    pub url: String,
    pub username: String,
}

#[derive(Serialize)]
pub struct PrepareCheckResponse {
    pub requires_approval: bool,
    pub request: Option<serde_json::Value>,
}

pub async fn prepare_check(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PrepareCheckRequest>,
) -> Result<Json<PrepareCheckResponse>, AppError> {
    let item = state.db.get_item(&req.item_id)?;

    if let Err(e) = state.db.append_audit_log(
        "login_check_prepared",
        Some(&req.item_id),
        Some(&format!("URL: {}, Username: {}", req.url, req.username)),
    ) {
        tracing::error!("Failed to append audit log: {e}");
    }

    Ok(Json(PrepareCheckResponse {
        requires_approval: true,
        request: Some(serde_json::json!({
            "item_id": req.item_id,
            "url": req.url,
            "username": req.username,
            "item_name": item.as_ref().map(|i| &i.name),
            "password_available": item.as_ref().and_then(|i| i.password_encrypted.as_ref()).is_some(),
        })),
    }))
}
