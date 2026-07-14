use pspm_core::types::{Item, RotationRecipe, RotationStatus};

pub struct RotationEngine;

impl RotationEngine {
    /// Find a recipe for the given item's domain.
    pub fn find_recipe(item: &Item, recipes: &[RotationRecipe]) -> Option<&RotationRecipe> {
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
