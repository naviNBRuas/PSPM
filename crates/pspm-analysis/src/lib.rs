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
            i.password_hash
                .as_ref()
                .map(|h| h.len() < 20)
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
    score.max(0.0).min(100.0) as u8
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
        let days = (now - item.updated_at).num_days();
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

fn item_to_report(item: &Item, now: &chrono::DateTime<chrono::Utc>) -> ItemReport {
    ItemReport {
        item_id: item.id,
        name: item.name.clone(),
        username: item.username.clone(),
        website: item.uris.first().cloned(),
        folder: None,
        strength_score: PasswordGrade::F,
        entropy: 0.0,
        length: item.password_hash.as_ref().map(|h| h.len() as u32).unwrap_or(0),
        has_lowercase: false,
        has_uppercase: false,
        has_digits: false,
        has_symbols: false,
        breached: false,
        reused: false,
        duplicate: false,
        old_password: (chrono::Duration::days(365) < *now - item.updated_at),
        mfa_enabled: item.mfa_enabled,
        passkey_enabled: item.passkey,
        days_since_modified: (chrono::Duration::days(365) < *now - item.updated_at) as i64,
        last_used: item.last_used,
    }
}
