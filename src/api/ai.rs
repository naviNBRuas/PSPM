use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::AppState;

#[derive(Deserialize)]
pub struct AiSuggestRequest {
    pub vault_id: String,
    pub context_only: Option<bool>,
}

#[derive(Serialize)]
pub struct AiSuggestResponse {
    pub suggestions: Vec<serde_json::Value>,
}

pub async fn get_suggestions(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<AiSuggestRequest>,
) -> Json<AiSuggestResponse> {
    let assistant = pspm_ai::AiAssistant::new("http://localhost:11434", "llama3.2");

    // Level 0 — metadata only by default
    let context = assistant.build_sanitized_context(
        &pspm_core::types::Vault {
            id: uuid::Uuid::nil(),
            name: String::new(),
            description: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            source: pspm_core::types::ImportSource::BitwardenJson,
            item_count: 0,
            folder_count: 0,
            organization_count: 0,
        },
        &[],
    );

    tracing::info!("AI context (Level 0 — no secrets): {context}");

    Json(AiSuggestResponse {
        suggestions: vec![],
    })
}
