use pspm_core::error::{PspmError, Result};

use crate::ImportEngine;

pub struct BitwardenJsonImporter;

impl ImportEngine for BitwardenJsonImporter {
    fn name(&self) -> &'static str {
        "Bitwarden JSON"
    }

    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["json"]
    }

    fn parse(&self, data: &str) -> Result<(pspm_core::types::Vault, Vec<pspm_core::types::Item>)> {
        let export: BitwardenExport = serde_json::from_str(data)
            .map_err(|e| PspmError::Import(format!("Invalid Bitwarden JSON: {e}")))?;

        let vault = export.into_vault()?;
        let items = export.into_items()?;

        Ok((vault, items))
    }
}

pub struct BitwardenCsvImporter;

impl ImportEngine for BitwardenCsvImporter {
    fn name(&self) -> &'static str {
        "Bitwarden CSV"
    }

    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["csv"]
    }

    fn parse(&self, data: &str) -> Result<(pspm_core::types::Vault, Vec<pspm_core::types::Item>)> {
        let mut reader = csv::Reader::from_reader(data.as_bytes());
        let headers = reader.headers()
            .map_err(|e| PspmError::Import(format!("Invalid CSV headers: {e}")))?
            .clone();

        let mut items = Vec::new();
        for result in reader.records() {
            let record = result.map_err(|e| PspmError::Import(format!("CSV parse error: {e}")))?;
            // TODO: Map CSV fields to Item struct
        }

        let vault = pspm_core::types::Vault {
            id: uuid::Uuid::new_v4(),
            name: "Bitwarden CSV Import".to_string(),
            description: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            source: pspm_core::types::ImportSource::BitwardenCsv,
            item_count: items.len() as u32,
            folder_count: 0,
            organization_count: 0,
        };

        Ok((vault, items))
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenExport {
    encrypted: Option<bool>,
    folders: Option<Vec<BitwardenFolder>>,
    items: Vec<BitwardenItem>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenFolder {
    id: Option<String>,
    name: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenItem {
    id: Option<String>,
    organization_id: Option<String>,
    folder_id: Option<String>,
    #[serde(rename = "type")]
    item_type: Option<u32>,
    name: String,
    notes: Option<String>,
    favorite: Option<bool>,
    reprompt: Option<u32>,
    login: Option<BitwardenLogin>,
    fields: Option<Vec<BitwardenField>>,
    collection_ids: Option<Vec<String>>,
    secure_note: Option<serde_json::Value>,
    card: Option<serde_json::Value>,
    identity: Option<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenLogin {
    uris: Option<Vec<BitwardenUri>>,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct BitwardenUri {
    uri: Option<String>,
    match_detected: Option<u32>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenField {
    name: String,
    value: Option<String>,
    #[serde(rename = "type")]
    field_type: Option<u32>,
    linked_id: Option<String>,
}

impl BitwardenExport {
    fn into_vault(self) -> Result<pspm_core::types::Vault> {
        let folder_count = self.folders.as_ref().map(|f| f.len() as u32).unwrap_or(0);
        let item_count = self.items.len() as u32;

        Ok(pspm_core::types::Vault {
            id: uuid::Uuid::new_v4(),
            name: "Bitwarden Export".to_string(),
            description: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            source: pspm_core::types::ImportSource::BitwardenJson,
            item_count,
            folder_count,
            organization_count: 0,
        })
    }

    fn into_items(self) -> Result<Vec<pspm_core::types::Item>> {
        let items = self
            .items
            .into_iter()
            .map(|bi| {
                let uris = bi
                    .login
                    .as_ref()
                    .and_then(|l| l.uris.as_ref())
                    .map(|u| u.iter().filter_map(|u| u.uri.clone()).collect())
                    .unwrap_or_default();

                let username = bi.login.as_ref().and_then(|l| l.username.clone());
                let password = bi.login.as_ref().and_then(|l| l.password.clone());

                let fields = bi
                    .fields
                    .unwrap_or_default()
                    .into_iter()
                    .map(|f| pspm_core::types::CustomField {
                        name: f.name,
                        value_encrypted: f.value,
                        field_type: pspm_core::types::FieldType::Text,
                        linked_item_id: None,
                    })
                    .collect();

                let item_type = match bi.item_type {
                    Some(1) => pspm_core::types::ItemType::Login,
                    Some(2) => pspm_core::types::ItemType::Note,
                    Some(3) => pspm_core::types::ItemType::Card,
                    Some(4) => pspm_core::types::ItemType::Identity,
                    _ => pspm_core::types::ItemType::Login,
                };

                let folder_id = bi.folder_id.and_then(|s| {
                    if s.is_empty() {
                        None
                    } else {
                        uuid::Uuid::parse_str(&s).ok()
                    }
                });

                let now = chrono::Utc::now();

                pspm_core::types::Item {
                    id: bi
                        .id
                        .and_then(|s| uuid::Uuid::parse_str(&s).ok())
                        .unwrap_or_else(uuid::Uuid::new_v4),
                    vault_id: uuid::Uuid::nil(),
                    folder_id,
                    organization_id: None,
                    name: bi.name,
                    username,
                    password_hash: password.as_ref().map(|p| pspm_core::crypto::sha1_hex(p.as_bytes())),
                    password_encrypted: password,
                    uris,
                    notes: bi.notes,
                    fields,
                    totp_secret_encrypted: bi.login.as_ref().and_then(|l| l.totp.clone()),
                    totp_uri: None,
                    passkey: false,
                    mfa_enabled: bi.login.as_ref().and_then(|l| l.totp.as_ref()).is_some(),
                    item_type,
                    favorite: bi.favorite.unwrap_or(false),
                    reprompt: match bi.reprompt {
                        Some(1) => pspm_core::types::RepromptType::Password,
                        Some(2) => pspm_core::types::RepromptType::Pin,
                        _ => pspm_core::types::RepromptType::None,
                    },
                    created_at: now,
                    updated_at: now,
                    last_used: None,
                }
            })
            .collect();

        Ok(items)
    }
}
