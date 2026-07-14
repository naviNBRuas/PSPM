use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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
    State(_state): State<Arc<AppState>>,
) -> Json<RecipeResponse> {
    Json(RecipeResponse { recipes: vec![] })
}

pub async fn create_recipe(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<CreateRecipeRequest>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "domain": req.domain,
        "url": req.url,
        "created": true,
    }))
}
