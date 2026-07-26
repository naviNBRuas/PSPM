use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::AppError;
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
    State(state): State<Arc<AppState>>,
    Json(req): Json<AiSuggestRequest>,
) -> Result<Json<AiSuggestResponse>, AppError> {
    let vault = state.db.get_vault(&req.vault_id)?;
    let items = state.db.list_items(&req.vault_id)?;
    let all_items = if items.is_empty() {
        state.db.list_all_items().unwrap_or_default()
    } else {
        items
    };

    let vault = vault.unwrap_or_else(|| {
        let now = chrono::Utc::now();
        pspm_core::types::Vault {
            id: uuid::Uuid::nil(),
            name: "Imported Vault".to_string(),
            description: None,
            created_at: now,
            updated_at: now,
            source: pspm_core::types::ImportSource::BitwardenJson,
            item_count: all_items.len() as u32,
            folder_count: 0,
            organization_count: 0,
        }
    });

    let config = &state.config;
    let assistant = pspm_ai::AiAssistant::new(&config.ai_endpoint, &config.ai_model);

    let context = assistant.build_sanitized_context(&vault, &all_items);
    tracing::info!("AI context: {}", serde_json::to_string(&context).unwrap_or_default());

    if req.context_only.unwrap_or(false) {
        return Ok(Json(AiSuggestResponse {
            suggestions: vec![serde_json::json!({ "context": context })],
        }));
    }

    match assistant.suggest_organization(context).await {
        Ok(suggestions) => {
            let json_suggestions: Vec<serde_json::Value> = suggestions
                .into_iter()
                .map(|s| {
                    serde_json::json!({
                        "item_id": s.item_id.to_string(),
                        "suggestion_type": format!("{:?}", s.suggestion_type),
                        "description": s.description,
                        "confidence": s.confidence,
                    })
                })
                .collect();

            if !json_suggestions.is_empty() {
                if let Err(e) = state.db.append_audit_log("ai_suggestions", None, Some(&format!("Generated {} suggestions", json_suggestions.len()))) {
                    tracing::error!("Failed to append audit log: {e}");
                }
            }

            Ok(Json(AiSuggestResponse { suggestions: json_suggestions }))
        }
        Err(e) => {
            tracing::warn!("AI suggestion failed: {e}");
            Ok(Json(AiSuggestResponse { suggestions: vec![] }))
        }
    }
}
