use pspm_core::error::{PspmError, Result};
use pspm_core::types::{
    AiPermissionLevel, AiSuggestion, AiSuggestionType, Item, Vault,
};

const SYSTEM_PROMPT: &str = r#"You are a password vault organization assistant.
You ONLY receive metadata: titles, folder names, website URLs, usernames, creation dates, password length, and entropy.
You NEVER see plaintext passwords, TOTP secrets, recovery codes, or private keys.
Your job is to suggest improvements to vault organization."#;

pub struct AiAssistant {
    endpoint: String,
    model: String,
    client: reqwest::Client,
    permission: AiPermissionLevel,
}

impl AiAssistant {
    pub fn new(endpoint: &str, model: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            model: model.to_string(),
            client: reqwest::Client::new(),
            permission: AiPermissionLevel::Level0,
        }
    }

    pub fn set_permission(&mut self, level: AiPermissionLevel) {
        self.permission = level;
    }

    pub fn build_sanitized_context(
        &self,
        vault: &Vault,
        items: &[Item],
    ) -> serde_json::Value {
        let sanitized: Vec<serde_json::Value> = items
            .iter()
            .map(|item| {
                let mut entry = serde_json::json!({
                    "id": item.id,
                    "name": item.name,
                    "folder_id": item.folder_id,
                    "uris": item.uris,
                    "username": item.username,
                    "created_at": item.created_at,
                    "updated_at": item.updated_at,
                    "favorite": item.favorite,
                    "item_type": item.item_type,
                });

                if matches!(self.permission, AiPermissionLevel::Level1 | AiPermissionLevel::Level2) {
                    entry["password_length"] = serde_json::json!(
                        item.password_hash.as_ref().map(|h| h.len())
                    );
                }

                if matches!(self.permission, AiPermissionLevel::Level2) {
                    if let Some(ref notes) = item.notes {
                        entry["notes"] = serde_json::json!(notes);
                    }
                }

                entry
            })
            .collect();

        serde_json::json!({
            "vault_name": vault.name,
            "item_count": vault.item_count,
            "items": sanitized,
        })
    }

    pub async fn suggest_organization(
        &self,
        context: serde_json::Value,
    ) -> Result<Vec<AiSuggestion>> {
        let body = serde_json::json!({
            "model": self.model,
            "system": SYSTEM_PROMPT,
            "messages": [{
                "role": "user",
                "content": format!(
                    "Analyze this vault and suggest organization improvements: {}",
                    serde_json::to_string(&context)?
                )
            }],
            "stream": false,
        });

        let resp = self
            .client
            .post(format!("{}/api/chat", self.endpoint))
            .json(&body)
            .send()
            .await
            .map_err(|e| PspmError::Ai(format!("AI request failed: {e}")))?;

        let result: OllamaResponse = resp
            .json()
            .await
            .map_err(|e| PspmError::Ai(format!("AI parse failed: {e}")))?;

        Self::parse_suggestions(&result.message.content)
    }

    fn parse_suggestions(_content: &str) -> Result<Vec<AiSuggestion>> {
        // TODO: Parse structured suggestions from LLM response
        Ok(vec![])
    }
}

#[derive(serde::Deserialize)]
struct OllamaResponse {
    message: OllamaMessage,
}

#[derive(serde::Deserialize)]
struct OllamaMessage {
    content: String,
}
