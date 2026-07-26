use pspm_core::types::{
    DashboardMetrics, GradeDistribution, Item, PasswordGrade, VaultReport,
};

pub struct Dashboard;

impl Dashboard {
    pub fn compute_metrics(
        _vault: &pspm_core::types::Vault,
        items: &[Item],
        report: &VaultReport,
    ) -> DashboardMetrics {
        let total = items.len() as f64;
        if total == 0.0 {
            return DashboardMetrics {
                overall_security_score: report.overall_score,
                ..DashboardMetrics::default()
            };
        }

        let mut grade_dist = GradeDistribution {
            a_plus: 0, a: 0, b: 0, c: 0, d: 0, f: 0,
        };

        for item in items {
            if let Some(ref pw) = item.password_encrypted {
                let result = pspm_strength::StrengthAnalyzer::analyze(pw);
                match result.grade {
                    PasswordGrade::APlus => grade_dist.a_plus += 1,
                    PasswordGrade::A => grade_dist.a += 1,
                    PasswordGrade::B => grade_dist.b += 1,
                    PasswordGrade::C => grade_dist.c += 1,
                    PasswordGrade::D => grade_dist.d += 1,
                    PasswordGrade::F => grade_dist.f += 1,
                }
            }
        }

        DashboardMetrics {
            overall_security_score: report.overall_score,
            total_items: items.len() as u32,
            password_reuse_percentage: percentage(report.passwords_reused as f64, total),
            weak_password_percentage: percentage(report.weak_passwords as f64, total),
            breached_password_percentage: percentage(report.compromised_passwords as f64, total),
            mfa_coverage_percentage: percentage(
                total - report.accounts_without_mfa as f64,
                total,
            ),
            passkey_adoption_percentage: percentage(report.accounts_with_passkeys as f64, total),
            duplicate_percentage: percentage(report.duplicate_entries as f64, total),
            last_audit_date: Some(report.generated_at),
            password_age_avg_days: compute_avg_age_days(items),
            grade_distribution: grade_dist,
        }
    }
}

fn percentage(part: f64, total: f64) -> f64 {
    if total == 0.0 {
        0.0
    } else {
        (part / total * 100.0 * 100.0).round() / 100.0
    }
}

fn compute_avg_age_days(items: &[Item]) -> f64 {
    if items.is_empty() {
        return 0.0;
    }
    let now = chrono::Utc::now();
    let total_days: i64 = items
        .iter()
        .map(|i| (now - i.updated_at).num_days())
        .sum();
    total_days as f64 / items.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use pspm_core::types::{Item, ItemType, RepromptType, Vault};

    fn test_item(updated_days_ago: i64, password: Option<&str>) -> Item {
        let now = chrono::Utc::now();
        Item {
            id: uuid::Uuid::new_v4(), vault_id: uuid::Uuid::nil(),
            folder_id: None, organization_id: None,
            name: "Test".into(), username: Some("user".into()),
            password_hash: password.map(|p| pspm_core::crypto::sha1_hex(p.as_bytes())),
            password_encrypted: password.map(|s| s.to_string()),
            uris: vec![], notes: None, fields: vec![],
            totp_secret_encrypted: None, totp_uri: None,
            passkey: false, mfa_enabled: false,
            item_type: ItemType::Login, favorite: false, reprompt: RepromptType::None,
            created_at: now, updated_at: now - chrono::Duration::days(updated_days_ago),
            last_used: None,
        }
    }

    #[test]
    fn test_empty_dashboard() {
        let vault = Vault {
            id: uuid::Uuid::nil(), name: "Empty".into(), description: None,
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            source: pspm_core::types::ImportSource::BitwardenJson,
            item_count: 0, folder_count: 0, organization_count: 0,
        };
        let report = pspm_core::types::VaultReport {
            vault_id: uuid::Uuid::nil(), generated_at: chrono::Utc::now(),
            total_logins: 0, passwords_reused: 0, weak_passwords: 0,
            old_passwords: 0, compromised_passwords: 0, duplicate_entries: 0,
            unused_accounts: 0, accounts_without_mfa: 0, accounts_with_passkeys: 0,
            accounts_with_totp: 0, overall_score: 100,
            password_age_distribution: pspm_core::types::PasswordAgeDistribution {
                less_than_30_days: 0, one_to_three_months: 0,
                three_to_six_months: 0, six_months_to_year: 0, more_than_year: 0,
            },
            items: vec![],
        };
        let metrics = Dashboard::compute_metrics(&vault, &[], &report);
        assert_eq!(metrics.total_items, 0);
        assert_eq!(metrics.overall_security_score, 100);
    }

    #[test]
    fn test_dashboard_with_items() {
        let vault = Vault {
            id: uuid::Uuid::nil(), name: "Test".into(), description: None,
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            source: pspm_core::types::ImportSource::BitwardenJson,
            item_count: 2, folder_count: 0, organization_count: 0,
        };
        let items = vec![
            test_item(10, Some("StrongP@ss1")),  // grade A
            test_item(200, Some("weak")),         // grade F
        ];
        let report = pspm_core::types::VaultReport {
            vault_id: uuid::Uuid::nil(), generated_at: chrono::Utc::now(),
            total_logins: 2, passwords_reused: 0, weak_passwords: 0,
            old_passwords: 0, compromised_passwords: 0, duplicate_entries: 0,
            unused_accounts: 0, accounts_without_mfa: 2, accounts_with_passkeys: 0,
            accounts_with_totp: 0, overall_score: 85,
            password_age_distribution: pspm_core::types::PasswordAgeDistribution {
                less_than_30_days: 1, one_to_three_months: 0,
                three_to_six_months: 0, six_months_to_year: 0, more_than_year: 1,
            },
            items: vec![],
        };
        let metrics = Dashboard::compute_metrics(&vault, &items, &report);
        assert_eq!(metrics.total_items, 2);
        assert!(!metrics.password_age_avg_days.is_nan());
    }

    #[test]
    fn test_grade_distribution() {
        let vault = Vault {
            id: uuid::Uuid::nil(), name: "Test".into(), description: None,
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            source: pspm_core::types::ImportSource::BitwardenJson,
            item_count: 3, folder_count: 0, organization_count: 0,
        };
        let items = vec![
            test_item(10, Some("VeryStr0ngP@ssw0rd!2024X")),  // A+
            test_item(10, Some("Str0ngP@ssword!X")),            // A (16+ chars)
            test_item(10, Some("weakpass")),                    // D
        ];
        let report = pspm_core::types::VaultReport {
            vault_id: uuid::Uuid::nil(), generated_at: chrono::Utc::now(),
            total_logins: 3, passwords_reused: 0, weak_passwords: 0,
            old_passwords: 0, compromised_passwords: 0, duplicate_entries: 0,
            unused_accounts: 0, accounts_without_mfa: 3, accounts_with_passkeys: 0,
            accounts_with_totp: 0, overall_score: 70,
            password_age_distribution: pspm_core::types::PasswordAgeDistribution {
                less_than_30_days: 3, one_to_three_months: 0,
                three_to_six_months: 0, six_months_to_year: 0, more_than_year: 0,
            },
            items: vec![],
        };
        let metrics = Dashboard::compute_metrics(&vault, &items, &report);
        let gd = metrics.grade_distribution;

        assert_eq!(gd.a_plus, 1);
        assert_eq!(gd.a, 1);
        assert_eq!(gd.d, 1);
    }

    #[test]
    fn test_percentage() {
        assert!((super::percentage(25.0, 100.0) - 25.0).abs() < 0.01);
        assert!((super::percentage(0.0, 100.0) - 0.0).abs() < 0.01);
        assert!((super::percentage(0.0, 0.0) - 0.0).abs() < 0.01);
        assert!((super::percentage(1.0, 3.0) - 33.33).abs() < 0.01);
    }

    #[test]
    fn test_avg_age_empty() {
        assert_eq!(super::compute_avg_age_days(&[]), 0.0);
    }
}


