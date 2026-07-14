use axum::Json;
use serde::{Deserialize, Serialize};

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
    Json(req): Json<PrepareCheckRequest>,
) -> Json<PrepareCheckResponse> {
    Json(PrepareCheckResponse {
        requires_approval: true,
        request: Some(serde_json::json!({
            "item_id": req.item_id,
            "url": req.url,
            "username": req.username,
        })),
    })
}
