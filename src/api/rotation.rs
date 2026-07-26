use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::AppError;
use crate::AppState;

#[derive(Serialize)]
pub struct RecipeResponse {
    pub recipes: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct CreateRecipeRequest {
    pub domain: String,
    pub url: String,
    pub login_selector: Option<String>,
    pub password_selector: Option<String>,
}

pub async fn list_recipes(
    State(state): State<Arc<AppState>>,
) -> Result<Json<RecipeResponse>, AppError> {
    let recipes = state.db.list_recipes()?;
    let json_recipes: Vec<serde_json::Value> = recipes
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "domain": r.domain,
                "url": r.url,
                "login_selector": r.login_selector,
                "password_selector": r.password_selector,
                "current_password_selector": r.current_password_selector,
                "new_password_selector": r.new_password_selector,
                "confirm_selector": r.confirm_selector,
                "submit_selector": r.submit_selector,
                "success_indicator": r.success_indicator,
                "known_working": r.known_working,
                "last_success": r.last_success.map(|d| d.to_rfc3339()),
                "recipe_version": r.recipe_version,
            })
        })
        .collect();

    Ok(Json(RecipeResponse { recipes: json_recipes }))
}

pub async fn create_recipe(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateRecipeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let recipe = pspm_core::types::RotationRecipe {
        domain: req.domain.clone(),
        url: req.url.clone(),
        login_selector: req.login_selector,
        password_selector: req.password_selector,
        current_password_selector: None,
        new_password_selector: None,
        confirm_selector: None,
        submit_selector: None,
        success_indicator: None,
        known_working: false,
        last_success: None,
        recipe_version: 1,
    };

    state.db.insert_rotation_recipe(&recipe)?;

    if let Err(e) = state.db.append_audit_log("recipe_created", None, Some(&format!("Domain: {}", req.domain))) {
        tracing::error!("Failed to append audit log: {e}");
    }

    Ok(Json(serde_json::json!({
        "domain": req.domain,
        "url": req.url,
        "created": true,
    })))
}

#[derive(Deserialize)]
pub struct RotateRequest {
    pub item_id: String,
}

#[derive(Serialize)]
pub struct RotateResponse {
    pub item_id: String,
    pub new_password: String,
    pub status: String,
    pub domain: Option<String>,
}

pub async fn rotate_password(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RotateRequest>,
) -> Result<Json<RotateResponse>, AppError> {
    let item = state.db.get_item(&req.item_id)?
        .ok_or_else(|| AppError::NotFound(format!("Item {} not found", req.item_id)))?;

    let result = pspm_rotation::RotationEngine::rotate(&item);

    state.db.update_item_password(
        &result.item_id.to_string(),
        Some(&result.new_password_hash),
        Some(&result.new_password),
    )?;

    state.db.insert_rotation_history(
        &result.item_id.to_string(),
        result.old_password_hash.as_deref(),
        &result.new_password_hash,
        "Success",
        result.domain.as_deref(),
    )?;

    if let Err(e) = state.db.append_audit_log("password_rotated", Some(&req.item_id), None) {
        tracing::error!("Failed to append audit log: {e}");
    }

    Ok(Json(RotateResponse {
        item_id: result.item_id.to_string(),
        new_password: result.new_password,
        status: format!("{:?}", result.status),
        domain: result.domain,
    }))
}

#[derive(Deserialize)]
pub struct RotateBulkRequest {
    pub item_ids: Vec<String>,
}

#[derive(Serialize)]
pub struct RotateBulkResponse {
    pub results: Vec<RotateResponse>,
    pub total: usize,
    pub succeeded: usize,
}

pub async fn rotate_bulk(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RotateBulkRequest>,
) -> Result<Json<RotateBulkResponse>, AppError> {
    if req.item_ids.is_empty() {
        return Err(AppError::BadRequest("No item IDs provided".into()));
    }

    let mut results = Vec::new();
    let mut succeeded = 0;

    for item_id in &req.item_ids {
        match state.db.get_item(item_id) {
            Ok(Some(item)) => {
                let result = pspm_rotation::RotationEngine::rotate(&item);

                if let Err(e) = state.db.update_item_password(
                    &result.item_id.to_string(),
                    Some(&result.new_password_hash),
                    Some(&result.new_password),
                ) {
                    tracing::error!("Failed to update password for item {item_id}: {e}");
                    continue;
                }

                if let Err(e) = state.db.insert_rotation_history(
                    &result.item_id.to_string(),
                    result.old_password_hash.as_deref(),
                    &result.new_password_hash,
                    "Success",
                    result.domain.as_deref(),
                ) {
                    tracing::error!("Failed to log rotation for item {item_id}: {e}");
                }

                succeeded += 1;
                results.push(RotateResponse {
                    item_id: result.item_id.to_string(),
                    new_password: result.new_password,
                    status: format!("{:?}", result.status),
                    domain: result.domain,
                });
            }
            Ok(None) => {
                results.push(RotateResponse {
                    item_id: item_id.clone(),
                    new_password: String::new(),
                    status: "NotFound".into(),
                    domain: None,
                });
            }
            Err(e) => {
                tracing::error!("Error fetching item {item_id}: {e}");
                results.push(RotateResponse {
                    item_id: item_id.clone(),
                    new_password: String::new(),
                    status: "Error".into(),
                    domain: None,
                });
            }
        }
    }

    if let Err(e) = state.db.append_audit_log("bulk_password_rotation", None, Some(&format!("Rotated {} items, {} succeeded", req.item_ids.len(), succeeded))) {
        tracing::error!("Failed to append audit log: {e}");
    }

    Ok(Json(RotateBulkResponse {
        total: req.item_ids.len(),
        succeeded,
        results,
    }))
}

#[derive(Serialize)]
pub struct RotationHistoryResponse {
    pub entries: Vec<serde_json::Value>,
}

pub async fn list_rotation_history(
    State(state): State<Arc<AppState>>,
) -> Result<Json<RotationHistoryResponse>, AppError> {
    let entries = state.db.list_rotation_history(100)?;
    let json_entries: Vec<serde_json::Value> = entries
        .into_iter()
        .map(|(id, item_id, old_hash, new_hash, status, domain, rotated_at)| {
            serde_json::json!({
                "id": id,
                "item_id": item_id,
                "old_password_hash": old_hash,
                "new_password_hash": new_hash,
                "status": status,
                "domain": domain,
                "rotated_at": rotated_at,
            })
        })
        .collect();

    Ok(Json(RotationHistoryResponse { entries: json_entries }))
}
