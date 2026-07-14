use pspm_core::types::Item;
use pspm_core::error::{PspmError, Result};

pub fn parse_bitwarden_csv(data: &str) -> Result<Vec<Item>> {
    let mut reader = csv::Reader::from_reader(data.as_bytes());

    let valid_headers = [
        "folder", "favorite", "type", "name", "notes", "fields",
        "login_uri", "login_username", "login_password", "login_totp",
    ];

    let headers = reader.headers()
        .map_err(|e| PspmError::Import(format!("CSV header error: {e}")))?;

    let header_names: Vec<String> = headers.iter().map(|h| h.to_lowercase()).collect();

    for h in &header_names {
        if !valid_headers.contains(&h.as_str()) {
            return Err(PspmError::Import(format!("Unknown CSV column: {h}")));
        }
    }

    let mut items = Vec::new();
    for result in reader.records() {
        let record = result.map_err(|e| PspmError::Import(format!("CSV row error: {e}")))?;

        let name = record
            .get(header_names.iter().position(|h| h == "name"))
            .unwrap_or("")
            .to_string();

        let username = record
            .get(header_names.iter().position(|h| h == "login_username"));

        let password = record
            .get(header_names.iter().position(|h| h == "login_password"));

        let uri = record
            .get(header_names.iter().position(|h| h == "login_uri"))
            .unwrap_or("")
            .to_string();

        let now = chrono::Utc::now();

        items.push(Item {
            id: uuid::Uuid::new_v4(),
            vault_id: uuid::Uuid::nil(),
            folder_id: None,
            organization_id: None,
            name,
            username: username.map(|s| s.to_string()).filter(|s| !s.is_empty()),
            password_hash: password
                .filter(|s| !s.is_empty())
                .map(|p| pspm_core::crypto::sha1_hex(p.as_bytes())),
            password_encrypted: password.map(|s| s.to_string()).filter(|s| !s.is_empty()),
            uris: if uri.is_empty() { vec![] } else { vec![uri] },
            notes: None,
            fields: vec![],
            totp_secret_encrypted: None,
            totp_uri: None,
            passkey: false,
            mfa_enabled: false,
            item_type: pspm_core::types::ItemType::Login,
            favorite: false,
            reprompt: pspm_core::types::RepromptType::None,
            created_at: now,
            updated_at: now,
            last_used: None,
        });
    }

    Ok(items)
}
