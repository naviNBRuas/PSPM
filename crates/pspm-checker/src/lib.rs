use pspm_core::types::{Item, LoginCheckResult, LoginStatus};

pub struct LoginChecker;

impl LoginChecker {
    /// Prepares a login check request for user approval.
    /// The actual browser automation is performed by the frontend via Playwright.
    pub fn prepare_check(item: &Item) -> Option<LoginCheckRequest> {
        let url = item.uris.first()?;
        let username = item.username.as_ref()?;

        Some(LoginCheckRequest {
            item_id: item.id,
            url: url.clone(),
            username: username.clone(),
            name: item.name.clone(),
        })
    }

    pub fn analyze_result(
        page_title: &str,
        page_url: &str,
        visible_text: &str,
    ) -> LoginCheckResult {
        let text = visible_text.to_lowercase();

        let status = if text.contains("incorrect password")
            || text.contains("wrong password")
            || text.contains("invalid password")
        {
            LoginStatus::WrongPassword
        } else if text.contains("incorrect username")
            || text.contains("account not found")
            || text.contains("user not found")
        {
            LoginStatus::WrongUsername
        } else if text.contains("two-factor")
            || text.contains("2fa")
            || text.contains("verification code")
            || text.contains("authenticator")
        {
            LoginStatus::MfaRequired
        } else if text.contains("captcha") || text.contains("are you a human") {
            LoginStatus::CaptchaRequired
        } else if text.contains("account locked")
            || text.contains("too many attempts")
        {
            LoginStatus::AccountLocked
        } else if text.contains("password expired")
            || text.contains("change your password")
        {
            LoginStatus::PasswordExpired
        } else {
            // If we got past login form and are on a different page, it likely succeeded
            LoginStatus::Success
        };

        LoginCheckResult {
            item_id: uuid::Uuid::nil(),
            url: page_url.to_string(),
            status,
            message: String::new(),
            requires_mfa: matches!(status, LoginStatus::MfaRequired),
            requires_captcha: matches!(status, LoginStatus::CaptchaRequired),
            account_locked: matches!(status, LoginStatus::AccountLocked),
            password_expired: matches!(status, LoginStatus::PasswordExpired),
            checked_at: chrono::Utc::now(),
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LoginCheckRequest {
    pub item_id: uuid::Uuid,
    pub url: String,
    pub username: String,
    pub name: String,
}
