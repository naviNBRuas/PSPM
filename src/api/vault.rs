use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::AppError;
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
    State(state): State<Arc<AppState>>,
    Json(req): Json<ImportRequest>,
) -> Result<Json<ImportResponse>, AppError> {
    tracing::info!("Importing vault from format: {}", req.format);

    let engine: Box<dyn pspm_import::ImportEngine> = match req.format.as_str() {
        "bitwarden_json" => Box::new(pspm_import::bitwarden::BitwardenJsonImporter),
        "bitwarden_csv" => Box::new(pspm_import::bitwarden::BitwardenCsvImporter),
        _ => {
            return Err(AppError::BadRequest(format!("Unsupported format: {}", req.format)));
        }
    };

    let (vault, items) = engine.parse(&req.data)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    state.db.insert_vault(&vault)?;

    let vault_id = vault.id.to_string();
    for item in &items {
        if let Err(e) = state.db.insert_item(item) {
            tracing::error!("Failed to insert item {}: {e}", item.name);
        }
    }

    if let Err(e) = state.db.update_vault_counts(&vault_id) {
        tracing::error!("Failed to update vault counts: {e}");
    }
    if let Err(e) = state.db.append_audit_log("vault_import", None, Some(&format!("Imported {} items from {}", items.len(), req.format))) {
        tracing::error!("Failed to append audit log: {e}");
    }

    tracing::info!("Imported {} items into vault {}", items.len(), vault_id);

    Ok(Json(ImportResponse {
        vault_id,
        item_count: items.len(),
        warnings: vec![],
    }))
}

#[derive(Serialize)]
pub struct ExportResponse {
    pub format: String,
    pub data: String,
}

pub async fn export_vault(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ExportResponse>, AppError> {
    let vaults = state.db.list_vaults()?;
    if vaults.is_empty() {
        return Err(AppError::NotFound("No vaults found to export".into()));
    }

    let vault = &vaults[0];
    let items = state.db.list_items(&vault.id.to_string())?;

    let data = pspm_export::ExportEngine::export_to_bitwarden_json(vault, &[], &items, &[])
        .map_err(|e| AppError::Internal(format!("Export failed: {e}")))?;

    Ok(Json(ExportResponse {
        format: "bitwarden_json".to_string(),
        data,
    }))
}

#[derive(Serialize)]
pub struct ItemResponse {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub password_encrypted: Option<String>,
    pub uris: Vec<String>,
    pub notes: Option<String>,
    pub folder_id: Option<String>,
    pub organization_id: Option<String>,
    pub item_type: String,
    pub favorite: bool,
    pub mfa_enabled: bool,
    pub passkey: bool,
    pub reprompt: String,
    pub strength: Option<String>,
    pub strength_detail: Option<StrengthDetail>,
    pub breached: bool,
    pub breach_detail: Option<BreachDetail>,
    pub created_at: String,
    pub updated_at: String,
    pub last_used: Option<String>,
}

#[derive(Serialize)]
pub struct StrengthDetail {
    pub entropy: f64,
    pub length: u32,
    pub grade: String,
}

#[derive(Serialize)]
pub struct BreachDetail {
    pub password_breached: bool,
    pub email_breached: bool,
    pub breach_count: u32,
}

pub async fn list_items(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ItemResponse>>, AppError> {
    let items = state.db.list_all_items()?;
    let items_with_scores: Vec<ItemResponse> = items
        .iter()
        .map(|item| {
            let (grade, entropy, length) = match state.db.get_strength_score(&item.id.to_string()) {
                Ok(Some((e, l, _, g))) => (Some(g), Some(e), Some(l)),
                _ => {
                    let live = item.password_encrypted.as_ref().map(|pw| {
                        let result = pspm_strength::StrengthAnalyzer::analyze(pw);
                        (format!("{:?}", result.grade), result.entropy, result.length)
                    });
                    match live {
                        Some((g, e, l)) => (Some(g), Some(e), Some(l)),
                        None => (None, None, None),
                    }
                }
            };

            let breach_detail = state.db.get_breach_check(&item.id.to_string()).ok().flatten().map(|bc| BreachDetail {
                password_breached: bc.password_breached,
                email_breached: bc.email_breached,
                breach_count: bc.breach_count,
            });

            ItemResponse {
                id: item.id.to_string(),
                name: item.name.clone(),
                username: item.username.clone(),
                password_encrypted: None,
                uris: item.uris.clone(),
                notes: item.notes.clone(),
                folder_id: item.folder_id.map(|f| f.to_string()),
                organization_id: item.organization_id.map(|o| o.to_string()),
                item_type: format!("{:?}", item.item_type),
                favorite: item.favorite,
                mfa_enabled: item.mfa_enabled,
                passkey: item.passkey,
                reprompt: format!("{:?}", item.reprompt),
                strength: grade.clone(),
                strength_detail: grade.zip(entropy).zip(length).map(|((g, e), l)| StrengthDetail { entropy: e, length: l, grade: g }),
                breached: breach_detail.as_ref().map(|b| b.password_breached).unwrap_or(false),
                breach_detail,
                created_at: item.created_at.to_rfc3339(),
                updated_at: item.updated_at.to_rfc3339(),
                last_used: item.last_used.map(|d| d.to_rfc3339()),
            }
        })
        .collect();

    Ok(Json(items_with_scores))
}

#[derive(Deserialize)]
pub struct UpdateItemRequest {
    pub id: String,
    pub name: Option<String>,
    pub username: Option<String>,
    pub password_encrypted: Option<String>,
    pub uris: Option<Vec<String>>,
    pub notes: Option<String>,
    pub folder_id: Option<Option<String>>,
    pub organization_id: Option<Option<String>>,
    pub favorite: Option<bool>,
    pub mfa_enabled: Option<bool>,
    pub passkey: Option<bool>,
}

pub async fn update_item(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateItemRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut item = state.db.get_item(&req.id)?.ok_or_else(|| AppError::NotFound(format!("Item {} not found", req.id)))?;

    if let Some(name) = req.name { item.name = name; }
    if let Some(username) = req.username { item.username = Some(username); }
    if let Some(password) = req.password_encrypted { item.password_encrypted = Some(password); }
    if let Some(uris) = req.uris { item.uris = uris; }
    if let Some(notes) = req.notes { item.notes = Some(notes); }
    if let Some(folder_id) = req.folder_id { item.folder_id = folder_id.and_then(|s| uuid::Uuid::parse_str(&s).ok()); }
    if let Some(org_id) = req.organization_id { item.organization_id = org_id.and_then(|s| uuid::Uuid::parse_str(&s).ok()); }
    if let Some(favorite) = req.favorite { item.favorite = favorite; }
    if let Some(mfa) = req.mfa_enabled { item.mfa_enabled = mfa; }
    if let Some(passkey) = req.passkey { item.passkey = passkey; }
    item.updated_at = chrono::Utc::now();

    state.db.update_item(&item)?;

    if let Err(e) = state.db.append_audit_log("item_updated", Some(&req.id), Some("Updated item fields")) {
        tracing::error!("Failed to append audit log: {e}");
    }

    Ok(Json(serde_json::json!({ "updated": true, "id": req.id })))
}

#[derive(Deserialize)]
pub struct DeleteItemsRequest {
    pub ids: Vec<String>,
}

pub async fn delete_item(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeleteItemsRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if req.ids.is_empty() {
        return Err(AppError::BadRequest("No item IDs provided".into()));
    }
    state.db.delete_items_batch(&req.ids)?;

    if let Err(e) = state.db.append_audit_log("items_deleted", None, Some(&format!("Deleted {} items", req.ids.len()))) {
        tracing::error!("Failed to append audit log: {e}");
    }

    Ok(Json(serde_json::json!({ "deleted": req.ids.len() })))
}

#[derive(Deserialize)]
pub struct MoveItemsRequest {
    pub ids: Vec<String>,
    pub folder_id: Option<String>,
    pub vault_id: Option<String>,
}

pub async fn move_items(
    State(state): State<Arc<AppState>>,
    Json(req): Json<MoveItemsRequest>,
) -> Result<Json<serde_json::value::Value>, AppError> {
    if req.ids.is_empty() {
        return Err(AppError::BadRequest("No item IDs provided".into()));
    }

    if let Some(ref vault_id) = req.vault_id {
        state.db.move_items_to_vault(&req.ids, vault_id)?;
    }

    if let Some(ref folder_id) = req.folder_id {
        state.db.move_items_to_folder(&req.ids, Some(folder_id))?;
    } else if req.vault_id.is_none() {
        // Only clear folder if no vault move requested
        // (vault move might also set folder)
        state.db.move_items_to_folder(&req.ids, None)?;
    }

    if let Err(e) = state.db.append_audit_log("items_moved", None, Some(&format!("Moved {} items", req.ids.len()))) {
        tracing::error!("Failed to append audit log: {e}");
    }

    Ok(Json(serde_json::json!({ "moved": req.ids.len() })))
}

#[derive(Serialize)]
pub struct VaultResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub source: String,
    pub item_count: u32,
    pub folder_count: u32,
    pub created_at: String,
    pub updated_at: String,
}

pub async fn list_vaults(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<VaultResponse>>, AppError> {
    let vaults = state.db.list_vaults()?;
    Ok(Json(vaults.into_iter().map(|v| VaultResponse {
        id: v.id.to_string(),
        name: v.name,
        description: v.description,
        source: v.source.to_string(),
        item_count: v.item_count,
        folder_count: v.folder_count,
        created_at: v.created_at.to_rfc3339(),
        updated_at: v.updated_at.to_rfc3339(),
    }).collect()))
}

pub async fn delete_vault(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.db.delete_vault(&vault_id)?;

    if let Err(e) = state.db.append_audit_log("vault_deleted", None, Some(&format!("Deleted vault {}", vault_id))) {
        tracing::error!("Failed to append audit log: {e}");
    }

    Ok(Json(serde_json::json!({ "deleted": true })))
}

// ─── Folder Routes ─────────────────────────────────────────────

#[derive(Serialize)]
pub struct FolderResponse {
    pub id: String,
    pub vault_id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub item_count: u32,
    pub created_at: String,
    pub updated_at: String,
}

pub async fn list_folders(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
) -> Result<Json<Vec<FolderResponse>>, AppError> {
    let vaults = state.db.list_vaults()?;
    let vid = if vault_id == "_all" {
        vaults.first().map(|v| v.id.to_string()).unwrap_or(vault_id)
    } else {
        vault_id
    };
    let folders = state.db.list_folders(&vid)?;
    let mut resp: Vec<FolderResponse> = Vec::new();
    for f in folders {
        let count = state.db.get_items_by_folder(&f.id.to_string())?.len() as u32;
        resp.push(FolderResponse {
            id: f.id.to_string(),
            vault_id: f.vault_id.to_string(),
            name: f.name,
            parent_id: f.parent_id.map(|p| p.to_string()),
            item_count: count,
            created_at: f.created_at.to_rfc3339(),
            updated_at: f.updated_at.to_rfc3339(),
        });
    }
    Ok(Json(resp))
}

#[derive(Deserialize)]
pub struct CreateFolderRequest {
    pub vault_id: String,
    pub name: String,
    pub parent_id: Option<String>,
}

pub async fn create_folder(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateFolderRequest>,
) -> Result<Json<FolderResponse>, AppError> {
    let now = chrono::Utc::now();
    let folder = pspm_core::types::Folder {
        id: uuid::Uuid::new_v4(),
        vault_id: uuid::Uuid::parse_str(&req.vault_id).map_err(|_| AppError::BadRequest("Invalid vault_id".into()))?,
        name: req.name,
        parent_id: req.parent_id.and_then(|s| uuid::Uuid::parse_str(&s).ok()),
        created_at: now,
        updated_at: now,
    };

    state.db.insert_folder(&folder)?;

    if let Err(e) = state.db.append_audit_log("folder_created", None, Some(&format!("Folder: {}", folder.name))) {
        tracing::error!("Failed to append audit log: {e}");
    }

    Ok(Json(FolderResponse {
        id: folder.id.to_string(),
        vault_id: folder.vault_id.to_string(),
        name: folder.name,
        parent_id: folder.parent_id.map(|p| p.to_string()),
        item_count: 0,
        created_at: folder.created_at.to_rfc3339(),
        updated_at: folder.updated_at.to_rfc3339(),
    }))
}

#[derive(Deserialize)]
pub struct UpdateFolderRequest {
    pub name: Option<String>,
    pub parent_id: Option<Option<String>>,
}

pub async fn update_folder(
    State(state): State<Arc<AppState>>,
    Path(folder_id): Path<String>,
    Json(req): Json<UpdateFolderRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut folder = state.db.get_folder(&folder_id)?.ok_or_else(|| AppError::NotFound(format!("Folder {} not found", folder_id)))?;

    if let Some(name) = req.name { folder.name = name; }
    if let Some(parent_id) = req.parent_id { folder.parent_id = parent_id.and_then(|s| uuid::Uuid::parse_str(&s).ok()); }
    folder.updated_at = chrono::Utc::now();

    state.db.update_folder(&folder)?;
    Ok(Json(serde_json::json!({ "updated": true })))
}

pub async fn delete_folder(
    State(state): State<Arc<AppState>>,
    Path(folder_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.db.delete_folder(&folder_id)?;

    if let Err(e) = state.db.append_audit_log("folder_deleted", None, Some(&format!("Folder {}", folder_id))) {
        tracing::error!("Failed to append audit log: {e}");
    }

    Ok(Json(serde_json::json!({ "deleted": true })))
}
