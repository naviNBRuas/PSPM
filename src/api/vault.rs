use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::AppState;

#[derive(Deserialize)]
pub struct ImportRequest {
    pub format: String,
    pub data: String,
}

#[derive(Serialize)]
pub struct ImportResponse {
    pub vault_id: String,
    pub item_count: usize,
    pub warnings: Vec<String>,
}

pub async fn import_vault(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<ImportRequest>,
) -> Json<ImportResponse> {
    tracing::info!("Importing vault from format: {}", req.format);

    let engine: Box<dyn pspm_import::ImportEngine> = match req.format.as_str() {
        "bitwarden_json" => Box::new(pspm_import::bitwarden::BitwardenJsonImporter),
        "bitwarden_csv" => Box::new(pspm_import::bitwarden::BitwardenCsvImporter),
        _ => {
            return Json(ImportResponse {
                vault_id: String::new(),
                item_count: 0,
                warnings: vec![format!("Unsupported format: {}", req.format)],
            })
        }
    };

    match engine.parse(&req.data) {
        Ok((vault, items)) => Json(ImportResponse {
            vault_id: vault.id.to_string(),
            item_count: items.len(),
            warnings: vec![],
        }),
        Err(e) => Json(ImportResponse {
            vault_id: String::new(),
            item_count: 0,
            warnings: vec![e.to_string()],
        }),
    }
}

#[derive(Serialize)]
pub struct ExportResponse {
    pub format: String,
    pub data: String,
}

pub async fn export_vault(
    State(_state): State<Arc<AppState>>,
) -> Json<ExportResponse> {
    Json(ExportResponse {
        format: "bitwarden_json".to_string(),
        data: "{}".to_string(),
    })
}

#[derive(Serialize)]
pub struct ItemResponse {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub uris: Vec<String>,
    pub folder_id: Option<String>,
    pub strength: Option<String>,
    pub breached: bool,
}

pub async fn list_items(
    State(_state): State<Arc<AppState>>,
) -> Json<Vec<ItemResponse>> {
    Json(vec![])
}
