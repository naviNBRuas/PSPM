use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct GenerateRequest {
    pub length: Option<u32>,
    pub include_lowercase: Option<bool>,
    pub include_uppercase: Option<bool>,
    pub include_digits: Option<bool>,
    pub include_symbols: Option<bool>,
    pub no_ambiguous: Option<bool>,
    pub style: Option<String>,
}

#[derive(Serialize)]
pub struct GenerateResponse {
    pub password: String,
    pub entropy: f64,
}

pub async fn generate_password(
    Json(req): Json<GenerateRequest>,
) -> Json<GenerateResponse> {
    let policy = pspm_core::types::GenerationPolicy {
        length: req.length.unwrap_or(32),
        include_lowercase: req.include_lowercase.unwrap_or(true),
        include_uppercase: req.include_uppercase.unwrap_or(true),
        include_digits: req.include_digits.unwrap_or(true),
        include_symbols: req.include_symbols.unwrap_or(true),
        no_ambiguous: req.no_ambiguous.unwrap_or(false),
        min_numbers: 0,
        min_symbols: 0,
        style: match req.style.as_deref() {
            Some("diceware") => pspm_core::types::PasswordStyle::Diceware,
            Some("pin") => pspm_core::types::PasswordStyle::Pin,
            Some("memorable") => pspm_core::types::PasswordStyle::Memorable,
            _ => pspm_core::types::PasswordStyle::Random,
        },
    };

    let password = pspm_generator::PasswordGenerator::generate(&policy);
    let strength = pspm_strength::StrengthAnalyzer::analyze(&password);

    Json(GenerateResponse {
        password,
        entropy: strength.entropy,
    })
}
