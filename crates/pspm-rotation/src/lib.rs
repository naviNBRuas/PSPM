use pspm_core::types::{GenerationPolicy, Item, PasswordStyle, RotationRecipe, RotationStatus};
use sha2::{Digest, Sha256};

pub struct RotationEngine;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RotateResult {
    pub item_id: uuid::Uuid,
    pub old_password_hash: Option<String>,
    pub new_password: String,
    pub new_password_hash: String,
    pub domain: Option<String>,
    pub status: RotationStatus,
}

impl RotationEngine {
    pub fn find_recipe<'a>(item: &Item, recipes: &'a [RotationRecipe]) -> Option<&'a RotationRecipe> {
        let domain = item.uris.first().and_then(|u| extract_domain(u))?;
        recipes.iter().find(|r| r.domain == domain)
    }

    pub fn suggest_recipe(item: &Item) -> Option<RotationRecipe> {
        let url = item.uris.first()?;
        let domain = extract_domain(url)?;

        Some(RotationRecipe {
            domain: domain.clone(),
            url: url.clone(),
            login_selector: None,
            password_selector: None,
            current_password_selector: None,
            new_password_selector: None,
            confirm_selector: None,
            submit_selector: None,
            success_indicator: None,
            known_working: false,
            last_success: None,
            recipe_version: 1,
        })
    }

    pub fn rotate(item: &Item) -> RotateResult {
        let policy = GenerationPolicy {
            length: 24,
            include_lowercase: true,
            include_uppercase: true,
            include_digits: true,
            include_symbols: true,
            no_ambiguous: false,
            min_numbers: 2,
            min_symbols: 2,
            style: PasswordStyle::Random,
        };

        let new_password = pspm_generator::PasswordGenerator::generate(&policy);
        let new_hash = hex::encode(Sha256::digest(new_password.as_bytes()));

        let domain = item.uris.first().and_then(|u| extract_domain(u));

        RotateResult {
            item_id: item.id,
            old_password_hash: item.password_hash.clone(),
            new_password,
            new_password_hash: new_hash,
            domain,
            status: RotationStatus::Success,
        }
    }

    pub fn rotate_batch(items: &[Item]) -> Vec<RotateResult> {
        items.iter().map(Self::rotate).collect()
    }
}

fn extract_domain(url: &str) -> Option<String> {
    let url = url.trim();
    let without_protocol = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    without_protocol.split('/').next().map(|s| s.to_lowercase())
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RotationRequest {
    pub item_id: uuid::Uuid,
    pub recipe: RotationRecipe,
    pub new_password: String,
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
            password_hash: Some("old_hash".into()), password_encrypted: Some("old_pw".into()),
            uris: vec!["https://example.com/login".into()],
            notes: None, fields: vec![],
            totp_secret_encrypted: None, totp_uri: None,
            passkey: false, mfa_enabled: false,
            item_type: ItemType::Login, favorite: false, reprompt: RepromptType::None,
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(), last_used: None,
        }
    }

    #[test]
    fn test_rotate_generates_new_password() {
        let item = test_item();
        let result = RotationEngine::rotate(&item);
        assert_eq!(result.item_id, item.id);
        assert_eq!(result.old_password_hash, Some("old_hash".into()));
        assert!(!result.new_password.is_empty());
        assert!(result.new_password.len() >= 24);
        assert_eq!(result.domain, Some("example.com".into()));
        assert!(matches!(result.status, RotationStatus::Success));
    }

    #[test]
    fn test_rotate_batch() {
        let items = vec![test_item(), test_item()];
        let results = RotationEngine::rotate_batch(&items);
        assert_eq!(results.len(), 2);
        for r in &results {
            assert!(!r.new_password.is_empty());
        }
        // Each gets a unique password
        assert_ne!(results[0].new_password, results[1].new_password);
    }

    #[test]
    fn test_extract_domain() {
        let item = test_item();
        let recipe = RotationEngine::suggest_recipe(&item);
        assert!(recipe.is_some());
        assert_eq!(recipe.unwrap().domain, "example.com");
    }

    #[test]
    fn test_find_recipe() {
        let item = test_item();
        let recipes = vec![RotationRecipe {
            domain: "example.com".into(),
            url: "https://example.com/login".into(),
            login_selector: Some("#username".into()),
            password_selector: Some("#password".into()),
            current_password_selector: None,
            new_password_selector: None,
            confirm_selector: None,
            submit_selector: Some("#submit".into()),
            success_indicator: Some("/dashboard".into()),
            known_working: true,
            last_success: None,
            recipe_version: 1,
        }];
        let found = RotationEngine::find_recipe(&item, &recipes);
        assert!(found.is_some());
        assert_eq!(found.unwrap().domain, "example.com");
    }

    #[test]
    fn test_find_recipe_no_match() {
        let item = test_item();
        let recipes = vec![RotationRecipe {
            domain: "other.com".into(),
            url: "https://other.com".into(),
            login_selector: None, password_selector: None,
            current_password_selector: None, new_password_selector: None,
            confirm_selector: None, submit_selector: None,
            success_indicator: None, known_working: false,
            last_success: None, recipe_version: 1,
        }];
        let found = RotationEngine::find_recipe(&item, &recipes);
        assert!(found.is_none());
    }

    #[test]
    fn test_suggest_recipe_no_uri() {
        let mut item = test_item();
        item.uris = vec![];
        let recipe = RotationEngine::suggest_recipe(&item);
        assert!(recipe.is_none());
    }

    #[test]
    fn test_extract_domain_no_protocol() {
        let domain = super::extract_domain("example.com/path");
        assert_eq!(domain, Some("example.com".into()));
    }

    #[test]
    fn test_extract_domain_www() {
        let domain = super::extract_domain("https://www.example.com/login");
        assert_eq!(domain, Some("www.example.com".into()));
    }
}
