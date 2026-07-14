use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct BreachRequest {
    pub password: String,
}

#[derive(Serialize)]
pub struct BreachResponse {
    pub breach_count: u32,
    pub compromised: bool,
}

pub async fn check_breach(
    Json(req): Json<BreachRequest>,
) -> Json<BreachResponse> {
    // Password is only hashed — SHA-1 prefix sent to HIBP
    let detector = pspm_breach::BreachDetector::new(None);
    match detector.check_password_hibp(&req.password).await {
        Ok(count) => Json(BreachResponse {
            breach_count: count,
            compromised: count > 0,
        }),
        Err(e) => {
            tracing::warn!("Breach check failed: {e}");
            Json(BreachResponse {
                breach_count: 0,
                compromised: false,
            })
        }
    }
}
