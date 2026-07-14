use pspm_core::crypto::hash_password_for_hibp;
use pspm_core::error::{PspmError, Result};
use pspm_core::types::{BreachCheck, Item};

pub struct BreachDetector {
    client: reqwest::Client,
    hibp_api_key: Option<String>,
}

impl BreachDetector {
    pub fn new(hibp_api_key: Option<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("PSPM/0.1.0")
                .build()
                .expect("HTTP client"),
            hibp_api_key,
        }
    }

    /// Check a password against HIBP's k-Anonymity API.
    /// Never sends the full password — only the first 5 chars of the SHA-1 hash.
    pub async fn check_password_hibp(&self, password: &str) -> Result<u32> {
        let hash = hash_password_for_hibp(password);
        let prefix = &hash[..5];
        let suffix = &hash[5..];

        let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
        let resp = self
            .client
            .get(&url)
            .header("Add-Padding", "true")
            .send()
            .await
            .map_err(|e| PspmError::Network(format!("HIBP request failed: {e}")))?;

        let body = resp
            .text()
            .await
            .map_err(|e| PspmError::Network(format!("HIBP read failed: {e}")))?;

        for line in body.lines() {
            if let Some((hash_suffix, count_str)) = line.split_once(':') {
                if hash_suffix.trim() == suffix {
                    return Ok(count_str.trim().parse().unwrap_or(1));
                }
            }
        }

        Ok(0)
    }

    pub async fn check_item(&self, item: &Item) -> Result<BreachCheck> {
        let password_breached = if let Some(ref pw) = item.password_encrypted {
            self.check_password_hibp(pw).await? > 0
        } else {
            false
        };

        let email_breached = if let Some(ref email) = item.username {
            self.check_email_breach(email).await?
        } else {
            false
        };

        Ok(BreachCheck {
            item_id: item.id,
            password_breached,
            email_breached,
            username_leaked: email_breached,
            domain_compromised: false,
            breach_count: if password_breached { 1 } else { 0 },
            breach_sources: vec![],
        })
    }

    async fn check_email_breach(&self, _email: &str) -> Result<bool> {
        // Placeholder — HIBP email breach API requires paid subscription
        Ok(false)
    }
}
