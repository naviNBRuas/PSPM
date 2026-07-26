use pspm_core::error::{PspmError, Result};
use pspm_core::types::Item;

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

    let idx = |name: &str| header_names.iter().position(|h| h == name);

    let mut items = Vec::new();
    for result in reader.records() {
        let record = result.map_err(|e| PspmError::Import(format!("CSV row error: {e}")))?;

        let name = idx("name").and_then(|i| record.get(i)).unwrap_or("").to_string();
        let username = idx("login_username").and_then(|i| record.get(i));
        let password = idx("login_password").and_then(|i| record.get(i));
        let uri = idx("login_uri").and_then(|i| record.get(i)).unwrap_or("");
        let _folder = idx("folder").and_then(|i| record.get(i)).unwrap_or("");
        let favorite = idx("favorite").and_then(|i| record.get(i)).unwrap_or("0");
        let notes = idx("notes").and_then(|i| record.get(i));
        let _fields = idx("fields").and_then(|i| record.get(i)).unwrap_or("");
        let totp = idx("login_totp").and_then(|i| record.get(i));

        let now = chrono::Utc::now();

        items.push(Item {
            id: uuid::Uuid::new_v4(),
            vault_id: uuid::Uuid::nil(),
            folder_id: None,
            organization_id: None,
            name: if name.is_empty() { uri.to_string() } else { name },
            username: username.filter(|s| !s.is_empty()).map(|s| s.to_string()),
            password_hash: password
                .filter(|s| !s.is_empty())
                .map(|p| pspm_core::crypto::sha1_hex(p.as_bytes())),
            password_encrypted: password.filter(|s| !s.is_empty()).map(|s| s.to_string()),
            uris: if uri.is_empty() { vec![] } else { vec![uri.to_string()] },
            notes: notes.filter(|s| !s.is_empty()).map(|s| s.to_string()),
            fields: vec![],
            totp_secret_encrypted: totp.filter(|s| !s.is_empty()).map(|s| s.to_string()),
            totp_uri: None,
            passkey: false,
            mfa_enabled: totp.filter(|s| !s.is_empty()).is_some(),
            item_type: pspm_core::types::ItemType::Login,
            favorite: favorite == "1",
            reprompt: pspm_core::types::RepromptType::None,
            created_at: now,
            updated_at: now,
            last_used: None,
        });
    }

    Ok(items)
}
