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
        _page_title: &str,
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

        let requires_mfa = matches!(status, LoginStatus::MfaRequired);
        let requires_captcha = matches!(status, LoginStatus::CaptchaRequired);
        let account_locked = matches!(status, LoginStatus::AccountLocked);
        let password_expired = matches!(status, LoginStatus::PasswordExpired);

        LoginCheckResult {
            item_id: uuid::Uuid::nil(),
            url: page_url.to_string(),
            status,
            message: String::new(),
            requires_mfa,
            requires_captcha,
            account_locked,
            password_expired,
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

#[cfg(test)]
mod tests {
    use super::*;
    use pspm_core::types::{Item, ItemType, RepromptType};

    fn test_item() -> Item {
        Item {
            id: uuid::Uuid::new_v4(), vault_id: uuid::Uuid::nil(),
            folder_id: None, organization_id: None,
            name: "Test".into(), username: Some("user".into()),
            password_hash: Some("hash".into()), password_encrypted: Some("pass".into()),
            uris: vec!["https://example.com".into()],
            notes: None, fields: vec![],
            totp_secret_encrypted: None, totp_uri: None,
            passkey: false, mfa_enabled: false,
            item_type: ItemType::Login, favorite: false, reprompt: RepromptType::None,
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(), last_used: None,
        }
    }

    #[test]
    fn test_prepare_check() {
        let item = test_item();
        let req = LoginChecker::prepare_check(&item);
        assert!(req.is_some());
        let req = req.unwrap();
        assert_eq!(req.url, "https://example.com");
        assert_eq!(req.username, "user");
    }

    #[test]
    fn test_prepare_check_no_uris() {
        let mut item = test_item();
        item.uris = vec![];
        let req = LoginChecker::prepare_check(&item);
        assert!(req.is_none());
    }

    #[test]
    fn test_analyze_success() {
        let result = LoginChecker::analyze_result("Dashboard", "https://example.com/dashboard", "Welcome back! You have 3 new messages.");
        assert_eq!(result.status, LoginStatus::Success);
    }

    #[test]
    fn test_analyze_wrong_password() {
        let result = LoginChecker::analyze_result("Login", "https://example.com/login", "Incorrect password. Please try again.");
        assert_eq!(result.status, LoginStatus::WrongPassword);
    }

    #[test]
    fn test_analyze_wrong_username() {
        let result = LoginChecker::analyze_result("Login", "https://example.com/login", "Account not found. Check your username.");
        assert_eq!(result.status, LoginStatus::WrongUsername);
    }

    #[test]
    fn test_analyze_mfa_required() {
        let result = LoginChecker::analyze_result("Login", "https://example.com/login", "Enter your two-factor authentication code.");
        assert_eq!(result.status, LoginStatus::MfaRequired);
        assert!(result.requires_mfa);
    }

    #[test]
    fn test_analyze_captcha() {
        let result = LoginChecker::analyze_result("Login", "https://example.com/login", "Please complete the captcha to continue.");
        assert_eq!(result.status, LoginStatus::CaptchaRequired);
        assert!(result.requires_captcha);
    }

    #[test]
    fn test_analyze_account_locked() {
        let result = LoginChecker::analyze_result("Login", "https://example.com/login", "Your account has been locked due to too many attempts.");
        assert_eq!(result.status, LoginStatus::AccountLocked);
        assert!(result.account_locked);
    }

    #[test]
    fn test_analyze_password_expired() {
        let result = LoginChecker::analyze_result("Login", "https://example.com/login", "Your password has expired. Please change your password.");
        assert_eq!(result.status, LoginStatus::PasswordExpired);
        assert!(result.password_expired);
    }
}
