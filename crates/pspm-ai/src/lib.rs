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

    fn parse_suggestions(content: &str) -> Result<Vec<AiSuggestion>> {
        let mut suggestions = Vec::new();
        let content = content.trim();

        let json_blocks: Vec<&str> = if content.starts_with('[') || content.starts_with('{') {
            vec![content]
        } else {
            content.lines()
                .filter(|l| l.trim().starts_with('[') || l.trim().starts_with('{'))
                .collect()
        };

        for block in json_blocks {
            let v: serde_json::Value = match serde_json::from_str(block.trim()) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let entries = if let Some(arr) = v.as_array() {
                arr.clone()
            } else {
                vec![v.clone()]
            };

            for entry in entries {
                let item_id_str = entry.get("item_id")
                    .or_else(|| entry.get("id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let item_id = uuid::Uuid::parse_str(item_id_str).unwrap_or_else(|_| uuid::Uuid::nil());

                let suggestion_type_str = entry.get("suggestion_type")
                    .or_else(|| entry.get("type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("SecurityImprovement");

                let suggestion_type = match suggestion_type_str {
                    "MoveToFolder" => AiSuggestionType::MoveToFolder,
                    "RenameTitle" => AiSuggestionType::RenameTitle,
                    "DeleteDuplicate" => AiSuggestionType::DeleteDuplicate,
                    "Archive" => AiSuggestionType::Archive,
                    "Merge" => AiSuggestionType::Merge,
                    "Tag" => AiSuggestionType::Tag,
                    "CreateFolderStructure" => AiSuggestionType::CreateFolderStructure,
                    "IdentifyObsolete" => AiSuggestionType::IdentifyObsolete,
                    _ => AiSuggestionType::SecurityImprovement,
                };

                let description = entry.get("description")
                    .or_else(|| entry.get("suggestion"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let confidence = entry.get("confidence")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.5) as f32;

                suggestions.push(AiSuggestion {
                    item_id,
                    suggestion_type,
                    description,
                    confidence,
                    applies: false,
                });
            }
        }

        if suggestions.is_empty() {
            let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
            for line in lines {
                let line = line.trim().trim_start_matches("- ").trim_start_matches("* ");
                if line.len() > 15 {
                    suggestions.push(AiSuggestion {
                        item_id: uuid::Uuid::nil(),
                        suggestion_type: AiSuggestionType::SecurityImprovement,
                        description: line.to_string(),
                        confidence: 0.5,
                        applies: false,
                    });
                }
            }
        }

        if suggestions.len() > 20 {
            suggestions.truncate(20);
        }

        Ok(suggestions)
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

#[cfg(test)]
mod tests {
    use super::*;
    use pspm_core::types::{Item, ItemType, RepromptType};

    fn test_vault() -> Vault {
        Vault {
            id: uuid::Uuid::nil(), name: "Test Vault".into(), description: None,
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            source: pspm_core::types::ImportSource::BitwardenJson,
            item_count: 1, folder_count: 0, organization_count: 0,
        }
    }

    fn test_item() -> Item {
        Item {
            id: uuid::Uuid::new_v4(), vault_id: uuid::Uuid::nil(),
            folder_id: None, organization_id: None,
            name: "Example".into(), username: Some("user".into()),
            password_hash: Some("hash".into()), password_encrypted: Some("pass".into()),
            uris: vec!["https://example.com".into()],
            notes: Some("some notes".into()), fields: vec![],
            totp_secret_encrypted: None, totp_uri: None,
            passkey: false, mfa_enabled: false,
            item_type: ItemType::Login, favorite: false, reprompt: RepromptType::None,
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(), last_used: None,
        }
    }

    #[test]
    fn test_build_sanitized_context_level0() {
        let assistant = AiAssistant::new("http://localhost:11434", "llama3.2");
        let vault = test_vault();
        let items = vec![test_item()];
        let context = assistant.build_sanitized_context(&vault, &items);

        assert_eq!(context["vault_name"], "Test Vault");
        assert!(context["items"].is_array());
        assert_eq!(context["items"][0]["name"], "Example");

        // Level 0 should NOT include password_length or notes
        assert!(context["items"][0].get("password_length").is_none());
        assert!(context["items"][0].get("notes").is_none());
    }

    #[test]
    fn test_build_sanitized_context_level1() {
        let mut assistant = AiAssistant::new("http://localhost:11434", "llama3.2");
        assistant.set_permission(AiPermissionLevel::Level1);
        let vault = test_vault();
        let items = vec![test_item()];
        let context = assistant.build_sanitized_context(&vault, &items);

        // Level 1 should include password_length but NOT notes
        assert!(context["items"][0].get("password_length").is_some());
        assert!(context["items"][0].get("notes").is_none());
    }

    #[test]
    fn test_build_sanitized_context_level2() {
        let mut assistant = AiAssistant::new("http://localhost:11434", "llama3.2");
        assistant.set_permission(AiPermissionLevel::Level2);
        let vault = test_vault();
        let items = vec![test_item()];
        let context = assistant.build_sanitized_context(&vault, &items);

        // Level 2 should include both password_length and notes
        assert!(context["items"][0].get("password_length").is_some());
        assert!(context["items"][0].get("notes").is_some());
    }

    #[test]
    fn test_parse_suggestions_empty() {
        let suggestions = AiAssistant::parse_suggestions("No suggestions").unwrap();
        assert!(suggestions.is_empty());
    }

    #[test]
    fn test_parse_suggestions_json_array() {
        let content = r#"[
            {"item_id": "550e8400-e29b-41d4-a716-446655440000", "suggestion_type": "MoveToFolder", "description": "Move to Social folder", "confidence": 0.85},
            {"item_id": "550e8400-e29b-41d4-a716-446655440001", "suggestion_type": "RenameTitle", "description": "Rename to Netflix", "confidence": 0.7}
        ]"#;
        let suggestions = AiAssistant::parse_suggestions(content).unwrap();
        assert_eq!(suggestions.len(), 2);
        assert_eq!(suggestions[0].suggestion_type, AiSuggestionType::MoveToFolder);
        assert!((suggestions[0].confidence - 0.85).abs() < 0.001);
    }

    #[test]
    fn test_parse_suggestions_uses_alternative_field_names() {
        let content = r#"[
            {"id": "550e8400-e29b-41d4-a716-446655440000", "type": "Archive", "suggestion": "This account is unused", "confidence": 0.9}
        ]"#;
        let suggestions = AiAssistant::parse_suggestions(content).unwrap();
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].suggestion_type, AiSuggestionType::Archive);
        assert_eq!(suggestions[0].description, "This account is unused");
    }

    #[test]
    fn test_parse_suggestions_markdown_list() {
        let content = "Here are my suggestions:\n- Move old accounts to archive\n- Merge duplicate entries\n- Enable MFA on all accounts";
        let suggestions = AiAssistant::parse_suggestions(content).unwrap();
        assert!(!suggestions.is_empty());
    }

    #[test]
    fn test_parse_suggestions_max_limit() {
        let mut entries = Vec::new();
        for i in 0..30 {
            entries.push(serde_json::json!({
                "item_id": format!("550e8400-e29b-41d4-a716-44665544{i:04}"),
                "suggestion_type": "SecurityImprovement",
                "description": format!("Suggestion {i}"),
                "confidence": 0.5,
            }));
        }
        let content = serde_json::to_string(&entries).unwrap();
        let suggestions = AiAssistant::parse_suggestions(&content).unwrap();
        assert!(suggestions.len() <= 20);
    }
}
