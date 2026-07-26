use pspm_core::error::{PspmError, Result};
use pspm_core::types::{Folder, Item, Organization, Vault};

pub struct ExportEngine;

impl ExportEngine {
    pub fn export_to_bitwarden_json(
        _vault: &Vault,
        folders: &[Folder],
        items: &[Item],
        _organizations: &[Organization],
    ) -> Result<String> {
        let export = serde_json::json!({
            "encrypted": false,
            "folders": folders.iter().map(|f| serde_json::json!({
                "id": f.id,
                "name": f.name,
            })).collect::<Vec<_>>(),
            "items": items.iter().map(|i| {
                serde_json::json!({
                    "id": i.id,
                    "organizationId": i.organization_id,
                    "folderId": i.folder_id,
                    "type": item_type_to_u32(&i.item_type),
                    "name": i.name,
                    "notes": i.notes,
                    "favorite": i.favorite,
                    "login": {
                        "uris": i.uris.iter().map(|u| serde_json::json!({
                            "uri": u,
                            "match": null,
                        })).collect::<Vec<_>>(),
                        "username": i.username,
                        "password": i.password_encrypted,
                        "totp": i.totp_secret_encrypted,
                    },
                    "fields": i.fields.iter().map(|f| serde_json::json!({
                        "name": f.name,
                        "value": f.value_encrypted,
                        "type": 0,
                    })).collect::<Vec<_>>(),
                })
            }).collect::<Vec<_>>(),
            "collections": [],
        });

        Ok(serde_json::to_string_pretty(&export)?)
    }

    pub fn export_to_bitwarden_csv(
        _vault: &Vault,
        items: &[Item],
    ) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());

        wtr.write_record([
            "folder", "favorite", "type", "name", "notes", "fields",
            "login_uri", "login_username", "login_password", "login_totp",
        ]).map_err(|e| PspmError::Export(e.to_string()))?;

        for item in items {
            wtr.write_record([
                "",
                if item.favorite { "1" } else { "0" },
                "login",
                &item.name,
                item.notes.as_deref().unwrap_or(""),
                "",
                item.uris.first().map(|s| s.as_str()).unwrap_or(""),
                item.username.as_deref().unwrap_or(""),
                item.password_encrypted.as_deref().unwrap_or(""),
                item.totp_secret_encrypted.as_deref().unwrap_or(""),
            ]).map_err(|e| PspmError::Export(e.to_string()))?;
        }

        wtr.flush().map_err(|e| PspmError::Export(e.to_string()))?;
        let data = String::from_utf8(wtr.into_inner().map_err(|e| PspmError::Export(e.to_string()))?)
            .map_err(|e| PspmError::Export(e.to_string()))?;
        Ok(data)
    }
}

fn item_type_to_u32(item_type: &pspm_core::types::ItemType) -> u32 {
    match item_type {
        pspm_core::types::ItemType::Login => 1,
        pspm_core::types::ItemType::Note => 2,
        pspm_core::types::ItemType::Card => 3,
        pspm_core::types::ItemType::Identity => 4,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pspm_core::types::{Item, ItemType, RepromptType, Vault};

    fn test_vault() -> Vault {
        Vault {
            id: uuid::Uuid::nil(), name: "Test".into(), description: None,
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            source: pspm_core::types::ImportSource::BitwardenJson,
            item_count: 1, folder_count: 0, organization_count: 0,
        }
    }

    fn test_item(name: &str, username: &str, password: &str, uri: &str) -> Item {
        Item {
            id: uuid::Uuid::new_v4(), vault_id: uuid::Uuid::nil(),
            folder_id: None, organization_id: None,
            name: name.into(), username: Some(username.into()),
            password_hash: Some(pspm_core::crypto::sha1_hex(password.as_bytes())),
            password_encrypted: Some(password.into()),
            uris: vec![uri.into()], notes: None, fields: vec![],
            totp_secret_encrypted: None, totp_uri: None,
            passkey: false, mfa_enabled: false, item_type: ItemType::Login,
            favorite: false, reprompt: RepromptType::None,
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(), last_used: None,
        }
    }

    #[test]
    fn test_export_json() {
        let vault = test_vault();
        let items = vec![test_item("Test", "user", "pass", "https://example.com")];
        let folders = vec![];
        let orgs = vec![];
        let result = ExportEngine::export_to_bitwarden_json(&vault, &folders, &items, &orgs).unwrap();
        assert!(result.contains("Test"));
        assert!(result.contains("user"));
        assert!(result.contains("pass"));
        assert!(result.contains("example.com"));
    }

    #[test]
    fn test_export_csv() {
        let vault = test_vault();
        let items = vec![test_item("Test", "user", "pass", "https://example.com")];
        let result = ExportEngine::export_to_bitwarden_csv(&vault, &items).unwrap();
        assert!(result.contains("Test"));
        assert!(result.contains("user"));
        assert!(result.contains("pass"));
        assert!(result.contains("example.com"));
    }

    #[test]
    fn test_export_empty_json() {
        let vault = test_vault();
        let result = ExportEngine::export_to_bitwarden_json(&vault, &[], &[], &[]).unwrap();
        assert!(result.contains("\"items\": []"));
    }
}
