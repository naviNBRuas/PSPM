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
    let mut policy = pspm_core::types::GenerationPolicy::default();
    policy.length = req.length.unwrap_or(32);
    policy.include_lowercase = req.include_lowercase.unwrap_or(true);
    policy.include_uppercase = req.include_uppercase.unwrap_or(true);
    policy.include_digits = req.include_digits.unwrap_or(true);
    policy.include_symbols = req.include_symbols.unwrap_or(true);
    policy.no_ambiguous = req.no_ambiguous.unwrap_or(false);

    policy.style = match req.style.as_deref() {
        Some("diceware") => pspm_core::types::PasswordStyle::Diceware,
        Some("pin") => pspm_core::types::PasswordStyle::Pin,
        Some("memorable") => pspm_core::types::PasswordStyle::Memorable,
        _ => pspm_core::types::PasswordStyle::Random,
    };

    let password = pspm_generator::PasswordGenerator::generate(&policy);
    let strength = pspm_strength::StrengthAnalyzer::analyze(&password);

    Json(GenerateResponse {
        password,
        entropy: strength.entropy,
    })
}
