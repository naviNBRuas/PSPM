use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;

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
}

pub async fn find_duplicates(
    State(_state): State<Arc<AppState>>,
) -> Json<DuplicateResponse> {
    Json(DuplicateResponse { groups: vec![] })
}
