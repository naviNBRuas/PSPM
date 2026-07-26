use pspm_core::types::*;

pub struct Analyzer;

impl Analyzer {
    pub fn analyze(vault: &Vault, items: &[Item]) -> VaultReport {
        let now = chrono::Utc::now();

        let total_logins = items.len() as u32;
        let passwords_reused = count_reused_passwords(items);
        let weak_passwords = count_weak_passwords(items);
        let old_passwords = count_old_passwords(items, &now);
        let compromised_passwords = 0; // Requires breach module
        let duplicate_entries = count_duplicates(items);
        let unused_accounts = count_unused(items, &now);
        let accounts_without_mfa = items.iter().filter(|i| !i.mfa_enabled).count() as u32;
        let accounts_with_passkeys = items.iter().filter(|i| i.passkey).count() as u32;
        let accounts_with_totp = items
            .iter()
            .filter(|i| i.totp_secret_encrypted.is_some())
            .count() as u32;

        let overall_score = compute_overall_score(
            total_logins,
            passwords_reused,
            weak_passwords,
            accounts_without_mfa,
        );

        VaultReport {
            vault_id: vault.id,
            generated_at: now,
            total_logins,
            passwords_reused,
            weak_passwords,
            old_passwords,
            compromised_passwords,
            duplicate_entries,
            unused_accounts,
            accounts_without_mfa,
            accounts_with_passkeys,
            accounts_with_totp,
            overall_score,
            password_age_distribution: compute_age_distribution(items, &now),
            items: items.iter().map(|i| item_to_report(i, &now)).collect(),
        }
    }
}

fn count_reused_passwords(items: &[Item]) -> u32 {
    let mut hashes: Vec<&str> = items
        .iter()
        .filter_map(|i| i.password_hash.as_deref())
        .filter(|h| !h.is_empty())
        .collect();
    hashes.sort_unstable();
    hashes.dedup();
    (items.len() - hashes.len()) as u32
}

fn count_weak_passwords(items: &[Item]) -> u32 {
    items
        .iter()
        .filter(|i| {
            i.password_encrypted
                .as_ref()
                .map(|pw| {
                    let result = pspm_strength::StrengthAnalyzer::analyze(pw);
                    matches!(result.grade, PasswordGrade::F | PasswordGrade::D)
                })
                .unwrap_or(false)
        })
        .count() as u32
}

fn count_old_passwords(items: &[Item], now: &chrono::DateTime<chrono::Utc>) -> u32 {
    let cutoff = *now - chrono::Duration::days(365);
    items
        .iter()
        .filter(|i| i.updated_at < cutoff)
        .count() as u32
}

fn count_duplicates(items: &[Item]) -> u32 {
    let mut seen: std::collections::HashSet<(&str, Option<&str>)> = std::collections::HashSet::new();
    let mut duplicates = 0;
    for item in items {
        let key = (
            item.uris.first().map(|s| s.as_str()).unwrap_or(""),
            item.username.as_deref(),
        );
        if !seen.insert(key) {
            duplicates += 1;
        }
    }
    duplicates
}

fn count_unused(items: &[Item], now: &chrono::DateTime<chrono::Utc>) -> u32 {
    let cutoff = *now - chrono::Duration::days(180);
    items
        .iter()
        .filter(|i| i.last_used.map(|lu| lu < cutoff).unwrap_or(true))
        .count() as u32
}

fn compute_overall_score(
    total: u32,
    reused: u32,
    weak: u32,
    no_mfa: u32,
) -> u8 {
    if total == 0 {
        return 100;
    }
    let reuse_penalty = (reused as f64 / total as f64) * 25.0;
    let weak_penalty = (weak as f64 / total as f64) * 30.0;
    let mfa_penalty = (no_mfa as f64 / total as f64) * 15.0;
    let score = 100.0 - reuse_penalty - weak_penalty - mfa_penalty;
    score.clamp(0.0, 100.0) as u8
}

fn compute_age_distribution(
    items: &[Item],
    now: &chrono::DateTime<chrono::Utc>,
) -> PasswordAgeDistribution {
    let mut dist = PasswordAgeDistribution {
        less_than_30_days: 0,
        one_to_three_months: 0,
        three_to_six_months: 0,
        six_months_to_year: 0,
        more_than_year: 0,
    };

    for item in items {
        let days = now.signed_duration_since(item.updated_at).num_days();
        match days {
            0..=30 => dist.less_than_30_days += 1,
            31..=90 => dist.one_to_three_months += 1,
            91..=180 => dist.three_to_six_months += 1,
            181..=365 => dist.six_months_to_year += 1,
            _ => dist.more_than_year += 1,
        }
    }

    dist
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_item(id: u32, password: Option<&str>, updated_days_ago: i64, mfa: bool) -> Item {
        let now = chrono::Utc::now();
        let password_hash = password.map(|p| {
            let hash = pspm_core::crypto::sha1_hex(p.as_bytes());
            hash
        });
        Item {
            id: uuid::Uuid::from_u128(id as u128),
            vault_id: uuid::Uuid::nil(),
            folder_id: None, organization_id: None,
            name: format!("Site {id}"),
            username: Some(format!("user{id}")),
            password_hash,
            password_encrypted: password.map(|s| s.to_string()),
            uris: vec![format!("https://site{id}.com")],
            notes: None, fields: vec![],
            totp_secret_encrypted: None, totp_uri: None,
            passkey: false, mfa_enabled: mfa,
            item_type: ItemType::Login, favorite: false, reprompt: RepromptType::None,
            created_at: now, updated_at: now - chrono::Duration::days(updated_days_ago),
            last_used: Some(now - chrono::Duration::days(updated_days_ago + 10)),
        }
    }

    #[test]
    fn test_analyze_empty_vault() {
        let vault = Vault {
            id: uuid::Uuid::nil(), name: "Empty".into(), description: None,
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            source: ImportSource::BitwardenJson, item_count: 0, folder_count: 0, organization_count: 0,
        };
        let report = Analyzer::analyze(&vault, &[]);
        assert_eq!(report.total_logins, 0);
        assert_eq!(report.overall_score, 100);
    }

    #[test]
    fn test_analyze_reused_passwords() {
        let vault = Vault { id: uuid::Uuid::nil(), name: "Test".into(), description: None,
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            source: ImportSource::BitwardenJson, item_count: 2, folder_count: 0, organization_count: 0,
        };
        let items = vec![
            test_item(1, Some("samepass"), 30, false),
            test_item(2, Some("samepass"), 30, false),
        ];
        let report = Analyzer::analyze(&vault, &items);
        assert_eq!(report.passwords_reused, 1);
        assert_eq!(report.total_logins, 2);
    }

    #[test]
    fn test_analyze_weak_passwords() {
        let vault = Vault { id: uuid::Uuid::nil(), name: "Test".into(), description: None,
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            source: ImportSource::BitwardenJson, item_count: 1, folder_count: 0, organization_count: 0,
        };
        let items = vec![test_item(1, Some("weak"), 30, false)];
        let report = Analyzer::analyze(&vault, &items);
        assert_eq!(report.weak_passwords, 1);
    }

    #[test]
    fn test_analyze_old_passwords() {
        let vault = Vault { id: uuid::Uuid::nil(), name: "Test".into(), description: None,
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            source: ImportSource::BitwardenJson, item_count: 1, folder_count: 0, organization_count: 0,
        };
        let items = vec![test_item(1, Some("StrongPass123!"), 400, false)];
        let report = Analyzer::analyze(&vault, &items);
        assert_eq!(report.old_passwords, 1);
    }

    #[test]
    fn test_analyze_mfa_stats() {
        let vault = Vault { id: uuid::Uuid::nil(), name: "Test".into(), description: None,
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            source: ImportSource::BitwardenJson, item_count: 2, folder_count: 0, organization_count: 0,
        };
        let items = vec![
            test_item(1, Some("pass1"), 30, true),
            test_item(2, Some("pass2"), 30, false),
        ];
        let report = Analyzer::analyze(&vault, &items);
        assert_eq!(report.accounts_without_mfa, 1);
        assert_eq!(report.accounts_with_mfa(), 1);
    }

    #[test]
    fn test_item_report_strength_analysis() {
        let now = chrono::Utc::now();
        let item = test_item(1, Some("VeryStrongP@ssw0rd!2024"), 30, false);
        let report = item_to_report(&item, &now);
        assert!(report.entropy > 0.0);
        assert_ne!(report.strength_score, PasswordGrade::F);
        assert!(report.has_uppercase);
        assert!(report.has_lowercase);
        assert!(report.has_digits);
        assert!(report.has_symbols);
        assert_eq!(report.length, 23);
    }

    #[test]
    fn test_count_unused_accounts() {
        let now = chrono::Utc::now();
        let recently_used = Item {
            id: uuid::Uuid::new_v4(), vault_id: uuid::Uuid::nil(),
            folder_id: None, organization_id: None, name: "Recent".into(),
            username: Some("u".into()), password_hash: None, password_encrypted: None,
            uris: vec![], notes: None, fields: vec![],
            totp_secret_encrypted: None, totp_uri: None,
            passkey: false, mfa_enabled: false,
            item_type: ItemType::Login, favorite: false, reprompt: RepromptType::None,
            created_at: now, updated_at: now, last_used: Some(now),
        };
        let old_item = Item {
            last_used: Some(now - chrono::Duration::days(365)),
            ..recently_used.clone()
        };
        let items = vec![recently_used, old_item];
        let unused = count_unused(&items, &now);
        assert_eq!(unused, 1);
    }

    #[test]
    fn test_age_distribution() {
        let now = chrono::Utc::now();
        let items = vec![
            test_item(1, Some("p1"), 15, false),
            test_item(2, Some("p2"), 60, false),
            test_item(3, Some("p3"), 150, false),
            test_item(4, Some("p4"), 300, false),
            test_item(5, Some("p5"), 500, false),
        ];
        let dist = compute_age_distribution(&items, &now);
        assert_eq!(dist.less_than_30_days, 1);
        assert_eq!(dist.one_to_three_months, 1);
        assert_eq!(dist.three_to_six_months, 1);
        assert_eq!(dist.six_months_to_year, 1);
        assert_eq!(dist.more_than_year, 1);
    }

    #[test]
    fn test_overall_score_perfect() {
        let score = compute_overall_score(10, 0, 0, 0);
        assert_eq!(score, 100);
    }

    #[test]
    fn test_overall_score_penalties() {
        let score = compute_overall_score(10, 5, 3, 2);
        assert!(score > 0 && score < 100);
    }

    #[test]
    fn test_overall_score_zero_total() {
        let score = compute_overall_score(0, 0, 0, 0);
        assert_eq!(score, 100);
    }
}

fn item_to_report(item: &Item, now: &chrono::DateTime<chrono::Utc>) -> ItemReport {
    let days_since_modified = now.signed_duration_since(item.updated_at).num_days();
    let strength = item
        .password_encrypted
        .as_ref()
        .map(|pw| pspm_strength::StrengthAnalyzer::analyze(pw));

    ItemReport {
        item_id: item.id,
        name: item.name.clone(),
        username: item.username.clone(),
        website: item.uris.first().cloned(),
        folder: None,
        strength_score: strength.as_ref().map(|s| s.grade.clone()).unwrap_or(PasswordGrade::F),
        entropy: strength.as_ref().map(|s| s.entropy).unwrap_or(0.0),
        length: item.password_encrypted.as_ref().map(|pw| pw.len() as u32).unwrap_or(0),
        has_lowercase: strength.as_ref().map(|s| s.has_lowercase).unwrap_or(false),
        has_uppercase: strength.as_ref().map(|s| s.has_uppercase).unwrap_or(false),
        has_digits: strength.as_ref().map(|s| s.has_digits).unwrap_or(false),
        has_symbols: strength.as_ref().map(|s| s.has_symbols).unwrap_or(false),
        breached: false,
        reused: false,
        duplicate: false,
        old_password: days_since_modified > 365,
        mfa_enabled: item.mfa_enabled,
        passkey_enabled: item.passkey,
        days_since_modified,
        last_used: item.last_used,
    }
}
