use pspm_core::types::{
    DashboardMetrics, GradeDistribution, Item, Vault, VaultReport,
};

pub struct Dashboard;

impl Dashboard {
    pub fn compute_metrics(
        vault: &Vault,
        items: &[Item],
        report: &VaultReport,
    ) -> DashboardMetrics {
        let total = items.len() as f64;
        if total == 0.0 {
            return DashboardMetrics::default();
        }

        DashboardMetrics {
            overall_security_score: report.overall_score,
            total_items: items.len() as u32,
            password_reuse_percentage: percentage(report.passwords_reused as f64, total),
            weak_password_percentage: percentage(report.weak_passwords as f64, total),
            breached_password_percentage: percentage(report.compromised_passwords as f64, total),
            mfa_coverage_percentage: percentage(
                (total - report.accounts_without_mfa as f64),
                total,
            ),
            passkey_adoption_percentage: percentage(report.accounts_with_passkeys as f64, total),
            duplicate_percentage: percentage(report.duplicate_entries as f64, total),
            last_audit_date: Some(report.generated_at),
            password_age_avg_days: compute_avg_age_days(items),
            grade_distribution: GradeDistribution {
                a_plus: 0,
                a: 0,
                b: 0,
                c: 0,
                d: 0,
                f: 0,
            },
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

impl Default for DashboardMetrics {
    fn default() -> Self {
        Self {
            overall_security_score: 0,
            total_items: 0,
            password_reuse_percentage: 0.0,
            weak_password_percentage: 0.0,
            breached_password_percentage: 0.0,
            mfa_coverage_percentage: 0.0,
            passkey_adoption_percentage: 0.0,
            duplicate_percentage: 0.0,
            last_audit_date: None,
            password_age_avg_days: 0.0,
            grade_distribution: GradeDistribution {
                a_plus: 0,
                a: 0,
                b: 0,
                c: 0,
                d: 0,
                f: 0,
            },
        }
    }
}
