pub mod vault;
pub mod analysis;
pub mod strength;
pub mod breach;
pub mod duplicates;
pub mod dashboard;
pub mod generator;
pub mod ai;
pub mod checker;
pub mod rotation;
pub mod audit;
pub mod frontend;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Application-level error that renders into an HTTP response.
pub enum AppError {
    Database(String),
    NotFound(String),
    BadRequest(String),
    Internal(String),
}

impl From<pspm_core::error::PspmError> for AppError {
    fn from(e: pspm_core::error::PspmError) -> Self {
        AppError::Database(e.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::Database(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
