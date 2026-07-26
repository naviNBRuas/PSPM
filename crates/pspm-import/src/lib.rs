pub mod bitwarden;
pub mod csv_import;
pub mod normalize;

use pspm_core::error::Result;
use pspm_core::types::{Item, Vault};

pub trait ImportEngine {
    fn name(&self) -> &'static str;
    fn supported_extensions(&self) -> Vec<&'static str>;
    fn parse(&self, data: &str) -> Result<(Vault, Vec<Item>)>;
}

pub struct ImportResult {
    pub vault: Vault,
    pub items: Vec<Item>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitwarden_json_importer_empty() {
        let data = r#"{"encrypted": false, "items": []}"#;
        let importer = crate::bitwarden::BitwardenJsonImporter;
        let (_vault, items) = importer.parse(data).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn test_bitwarden_json_importer_with_items() {
        let data = r#"{
            "encrypted": false,
            "items": [{
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "Example Site",
                "type": 1,
                "login": {
                    "uris": [{"uri": "https://example.com"}],
                    "username": "user@example.com",
                    "password": "s3cret!"
                }
            }]
        }"#;
        let importer = crate::bitwarden::BitwardenJsonImporter;
        let (vault, items) = importer.parse(data).unwrap();
        assert_eq!(vault.item_count, 1);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "Example Site");
        assert_eq!(items[0].username.as_deref(), Some("user@example.com"));
        assert_eq!(items[0].password_encrypted.as_deref(), Some("s3cret!"));
        assert_eq!(items[0].uris, vec!["https://example.com"]);
        assert!(items[0].password_hash.is_some());
    }

    #[test]
    fn test_bitwarden_json_importer_invalid_json() {
        let data = r#"not valid json"#;
        let importer = crate::bitwarden::BitwardenJsonImporter;
        let result = importer.parse(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_bitwarden_csv_importer() {
        let data = "folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp\n\
                     ,0,login,Test Site,,,https://test.com,testuser,testpass,";
        let importer = crate::bitwarden::BitwardenCsvImporter;
        let (_, items) = importer.parse(data).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "Test Site");
        assert_eq!(items[0].username.as_deref(), Some("testuser"));
        assert_eq!(items[0].password_encrypted.as_deref(), Some("testpass"));
    }

    #[test]
    fn test_bitwarden_csv_importer_invalid_header() {
        let data = "bad,col,umns\n1,2,3";
        let importer = crate::bitwarden::BitwardenCsvImporter;
        let result = importer.parse(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_url() {
        let mut items = vec![
            pspm_core::types::Item {
                id: uuid::Uuid::new_v4(), vault_id: uuid::Uuid::nil(),
                folder_id: None, organization_id: None,
                name: "".into(), username: None,
                password_hash: None, password_encrypted: None,
                uris: vec!["HTTPS://Example.COM/Path/".into()],
                notes: None, fields: vec![],
                totp_secret_encrypted: None, totp_uri: None,
                passkey: false, mfa_enabled: false,
                item_type: pspm_core::types::ItemType::Login,
                favorite: false, reprompt: pspm_core::types::RepromptType::None,
                created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(), last_used: None,
            }
        ];
        crate::normalize::normalize_items(&mut items);
        assert_eq!(items[0].uris[0], "https://example.com/path");
        assert_eq!(items[0].name, "example.com");
    }

    #[test]
    fn test_import_engine_name() {
        let json_importer = crate::bitwarden::BitwardenJsonImporter;
        let csv_importer = crate::bitwarden::BitwardenCsvImporter;
        assert_eq!(json_importer.name(), "Bitwarden JSON");
        assert_eq!(csv_importer.name(), "Bitwarden CSV");
    }

    #[test]
    fn test_import_engine_extensions() {
        let json_importer = crate::bitwarden::BitwardenJsonImporter;
        let csv_importer = crate::bitwarden::BitwardenCsvImporter;
        assert_eq!(json_importer.supported_extensions(), vec!["json"]);
        assert_eq!(csv_importer.supported_extensions(), vec!["csv"]);
    }
}
