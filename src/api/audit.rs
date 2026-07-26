use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;

use crate::api::AppError;
use crate::AppState;

#[derive(Serialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub action: String,
    pub item_id: Option<String>,
    pub details: Option<String>,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct AuditLogResponse {
    pub entries: Vec<AuditLogEntry>,
}

pub async fn list_audit_logs(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AuditLogResponse>, AppError> {
    let logs = state.db.list_audit_logs(200)?;
    let entries = logs
        .into_iter()
        .map(|(id, action, item_id, details, created_at)| AuditLogEntry {
            id,
            action,
            item_id,
            details,
            created_at,
        })
        .collect();

    Ok(Json(AuditLogResponse { entries }))
}
