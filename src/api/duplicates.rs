use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::AppError;
use crate::AppState;

#[derive(Serialize)]
pub struct DuplicateResponse {
    pub groups: Vec<DuplicateGroupResponse>,
}

#[derive(Serialize)]
pub struct DuplicateGroupResponse {
    pub canonical_item_id: String,
    pub duplicate_item_ids: Vec<String>,
    pub match_reason: String,
    pub can_merge: bool,
    pub merge_suggestion: Option<String>,
}

pub async fn find_duplicates(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DuplicateResponse>, AppError> {
    let items = state.db.list_all_items()?;
    let groups = pspm_duplicate::DuplicateDetector::find_duplicates(&items);

    state.db.clear_duplicate_groups()?;
    for g in &groups {
        if let Err(e) = state.db.insert_duplicate_group(g) {
            tracing::error!("Failed to store duplicate group: {e}");
        }
    }

    let groups_resp: Vec<DuplicateGroupResponse> = groups
        .into_iter()
        .map(|g| DuplicateGroupResponse {
            canonical_item_id: g.canonical_item_id.to_string(),
            duplicate_item_ids: g.duplicate_item_ids.iter().map(|id| id.to_string()).collect(),
            match_reason: format!("{:?}", g.match_reason),
            can_merge: g.can_merge,
            merge_suggestion: Some(g.merge_suggestion),
        })
        .collect();

    Ok(Json(DuplicateResponse { groups: groups_resp }))
}

#[derive(Deserialize)]
pub struct MergeRequest {
    pub canonical_item_id: String,
    pub duplicate_item_ids: Vec<String>,
    pub delete_after_merge: Option<bool>,
}

#[derive(Serialize)]
pub struct MergeResponse {
    pub merged: bool,
    pub kept_item_id: String,
    pub removed_count: usize,
}

pub async fn merge_duplicates(
    State(state): State<Arc<AppState>>,
    Json(req): Json<MergeRequest>,
) -> Result<Json<MergeResponse>, AppError> {
    let canonical = state.db.get_item(&req.canonical_item_id)?
        .ok_or_else(|| AppError::NotFound(format!("Canonical item {} not found", req.canonical_item_id)))?;

    let mut merged_notes = String::new();
    if let Some(ref notes) = canonical.notes {
        merged_notes.push_str(notes);
    }

    let mut removed_count = 0;
    for dup_id in &req.duplicate_item_ids {
        if let Ok(Some(dup)) = state.db.get_item(dup_id) {
            if !merged_notes.is_empty() {
                merged_notes.push_str("\n---\n");
            }
            if let Some(ref notes) = dup.notes {
                merged_notes.push_str(&format!("[from {}]: {}", dup.name, notes));
            }

            let delete = req.delete_after_merge.unwrap_or(true);
            if delete {
                if let Err(e) = state.db.delete_item(dup_id) {
                    tracing::error!("Failed to delete duplicate item {dup_id}: {e}");
                } else {
                    removed_count += 1;
                }
            }
        }
    }

    state.db.update_item(&canonical)?;

    if let Err(e) = state.db.append_audit_log("duplicates_merged", Some(&req.canonical_item_id),
        Some(&format!("Merged {} duplicates into {}", req.duplicate_item_ids.len(), canonical.name))) {
        tracing::error!("Failed to append audit log: {e}");
    }

    Ok(Json(MergeResponse {
        merged: true,
        kept_item_id: req.canonical_item_id,
        removed_count,
    }))
}
