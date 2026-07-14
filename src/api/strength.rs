use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct StrengthRequest {
    pub password: String,
}

#[derive(Serialize)]
pub struct StrengthResponse {
    pub entropy: f64,
    pub length: u32,
    pub charset_size: u32,
    pub has_lowercase: bool,
    pub has_uppercase: bool,
    pub has_digits: bool,
    pub has_symbols: bool,
    pub contains_dictionary_word: bool,
    pub contains_keyboard_walk: bool,
    pub grade: String,
}

pub async fn check_password(
    Json(req): Json<StrengthRequest>,
) -> Json<StrengthResponse> {
    let result = pspm_strength::StrengthAnalyzer::analyze(&req.password);
    Json(StrengthResponse {
        entropy: result.entropy,
        length: result.length,
        charset_size: result.charset_size,
        has_lowercase: result.has_lowercase,
        has_uppercase: result.has_uppercase,
        has_digits: result.has_digits,
        has_symbols: result.has_symbols,
        contains_dictionary_word: result.contains_dictionary_word,
        contains_keyboard_walk: result.contains_keyboard_walk,
        grade: format!("{:?}", result.grade),
    })
}
