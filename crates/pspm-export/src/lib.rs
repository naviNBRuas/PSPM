use pspm_core::error::Result;
use pspm_core::types::{ExportFormat, Folder, Item, Organization, Vault};

pub struct ExportEngine;

impl ExportEngine {
    pub fn export_to_bitwarden_json(
        vault: &Vault,
        folders: &[Folder],
        items: &[Item],
        organizations: &[Organization],
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
        vault: &Vault,
        items: &[Item],
    ) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());

        wtr.write_record([
            "folder", "favorite", "type", "name", "notes", "fields",
            "login_uri", "login_username", "login_password", "login_totp",
        ])?;

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
            ])?;
        }

        wtr.flush()?;
        let data = String::from_utf8(wtr.into_inner()?)?;
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
