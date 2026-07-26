use pspm_core::types::{PasswordGrade, PasswordStrength, PasswordPolicy};

pub struct StrengthAnalyzer;

impl StrengthAnalyzer {
    pub fn analyze(password: &str) -> PasswordStrength {
        let length = password.len() as u32;
        let charset_size = compute_charset_size(password);
        let entropy = compute_entropy(length, charset_size);
        let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
        let has_digits = password.chars().any(|c| c.is_ascii_digit());
        let has_symbols = password.chars().any(|c| !c.is_ascii_alphanumeric());

        let contains_dictionary_word = check_dictionary(password);
        let contains_keyboard_walk = check_keyboard_walk(password);
        let contains_date = check_date_pattern(password);
        let contains_name = false;

        let grade = compute_grade(
            entropy,
            length,
            has_lowercase && has_uppercase,
            has_digits,
            has_symbols,
            contains_dictionary_word || contains_keyboard_walk,
        );

        PasswordStrength {
            entropy,
            length,
            charset_size,
            has_lowercase,
            has_uppercase,
            has_digits,
            has_symbols,
            contains_dictionary_word,
            contains_leaked_pattern: false,
            contains_keyboard_walk,
            contains_date,
            contains_name,
            grade,
        }
    }

    pub fn check_policy(password: &str, policy: &PasswordPolicy) -> Vec<String> {
        let mut violations = Vec::new();

        if password.len() < policy.min_length as usize {
            violations.push(format!("Minimum length: {}", policy.min_length));
        }
        if password.len() > policy.max_length as usize {
            violations.push(format!("Maximum length: {}", policy.max_length));
        }
        if policy.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
            violations.push("Requires lowercase letter".into());
        }
        if policy.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
            violations.push("Requires uppercase letter".into());
        }
        if policy.require_digits && !password.chars().any(|c| c.is_ascii_digit()) {
            violations.push("Requires digit".into());
        }
        if policy.require_symbols && !password.chars().any(|c| !c.is_ascii_alphanumeric()) {
            violations.push("Requires symbol".into());
        }

        violations
    }
}

fn compute_charset_size(s: &str) -> u32 {
    let mut size = 0u32;
    if s.chars().any(|c| c.is_ascii_lowercase()) {
        size += 26;
    }
    if s.chars().any(|c| c.is_ascii_uppercase()) {
        size += 26;
    }
    if s.chars().any(|c| c.is_ascii_digit()) {
        size += 10;
    }
    if s.chars().any(|c| !c.is_ascii_alphanumeric()) {
        size += 33;
    }
    if size == 0 {
        size = 1;
    }
    size
}

fn compute_entropy(length: u32, charset: u32) -> f64 {
    if charset <= 1 {
        return 0.0;
    }
    length as f64 * (charset as f64).log2()
}

fn check_dictionary(password: &str) -> bool {
    let common: &[&str] = &[
        "password", "123456", "qwerty", "letmein", "admin", "welcome",
        "monkey", "dragon", "master", "sunshine", "princess", "football",
        "iloveyou", "trustno1", "shadow", "superman", "batman", "passw0rd",
    ];
    let lower = password.to_lowercase();
    common.iter().any(|w| lower.contains(w))
}

fn check_keyboard_walk(password: &str) -> bool {
    let rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];
    let lower = password.to_lowercase();

    for row in rows {
        for w in row.chars().collect::<Vec<_>>().windows(3) {
            let pattern: String = w.iter().collect();
            if lower.contains(&pattern) {
                return true;
            }
            let rev: String = w.iter().rev().collect();
            if lower.contains(&rev) {
                return true;
            }
        }
    }
    false
}

fn check_date_pattern(password: &str) -> bool {
    let patterns = [
        r"\d{4}-\d{2}-\d{2}",
        r"\d{2}/\d{2}/\d{4}",
        r"\d{8}",
    ];
    patterns.iter().any(|p| {
        regex_lite::Regex::new(p)
            .map(|r| r.is_match(password))
            .unwrap_or(false)
    })
}

fn compute_grade(
    entropy: f64,
    length: u32,
    has_mixed_case: bool,
    has_digits: bool,
    has_symbols: bool,
    has_weak_pattern: bool,
) -> PasswordGrade {
    if has_weak_pattern && length < 12 {
        return PasswordGrade::F;
    }
    if entropy >= 120.0 && length >= 20 && has_mixed_case && has_digits && has_symbols {
        return PasswordGrade::APlus;
    }
    if entropy >= 80.0 && length >= 16 && has_mixed_case && has_digits {
        return PasswordGrade::A;
    }
    if entropy >= 60.0 && length >= 12 && has_mixed_case {
        return PasswordGrade::B;
    }
    if entropy >= 40.0 && length >= 8 {
        return PasswordGrade::C;
    }
    if entropy >= 28.0 && length >= 6 {
        return PasswordGrade::D;
    }
    PasswordGrade::F
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_empty() {
        let result = StrengthAnalyzer::analyze("");
        assert_eq!(result.length, 0);
        assert_eq!(result.entropy, 0.0);
        assert_eq!(result.grade, PasswordGrade::F);
    }

    #[test]
    fn test_password_very_strong() {
        let result = StrengthAnalyzer::analyze("CorrectHorseBatteryStaple!2024");
        assert_eq!(result.grade, PasswordGrade::APlus);
        assert!(result.entropy > 100.0);
    }

    #[test]
    fn test_password_strong() {
        let result = StrengthAnalyzer::analyze("Str0ngP@ssword!X");
        assert_eq!(result.grade, PasswordGrade::A);
        assert!(result.entropy > 80.0);
    }

    #[test]
    fn test_password_medium() {
        let result = StrengthAnalyzer::analyze("MediumP@ssw0rd");
        assert_eq!(result.grade, PasswordGrade::B);
        assert!(result.entropy >= 60.0);
    }

    #[test]
    fn test_password_weak() {
        let result = StrengthAnalyzer::analyze("pass1");
        assert_eq!(result.grade, PasswordGrade::F);
        assert!(result.entropy < 28.0);
    }

    #[test]
    fn test_dictionary_word_detected() {
        let result = StrengthAnalyzer::analyze("mypassword123");
        assert!(result.contains_dictionary_word);
    }

    #[test]
    fn test_keyboard_walk_detected() {
        let result = StrengthAnalyzer::analyze("qwertyasdf");
        assert!(result.contains_keyboard_walk);
    }

    #[test]
    fn test_date_pattern_detected() {
        let result = StrengthAnalyzer::analyze("pass2024-01-15");
        assert!(result.contains_date);
    }

    #[test]
    fn test_date_pattern_compact_detected() {
        let result = StrengthAnalyzer::analyze("pass20240115");
        assert!(result.contains_date);
    }

    #[test]
    fn test_charset_all() {
        let result = StrengthAnalyzer::analyze("Ab1!xxxx");
        assert!(result.has_lowercase);
        assert!(result.has_uppercase);
        assert!(result.has_digits);
        assert!(result.has_symbols);
        assert_eq!(result.charset_size, 95);
    }

    #[test]
    fn test_charset_digits_only() {
        let result = StrengthAnalyzer::analyze("12345678");
        assert!(!result.has_lowercase);
        assert!(!result.has_uppercase);
        assert!(result.has_digits);
        assert!(!result.has_symbols);
        assert_eq!(result.charset_size, 10);
    }

    #[test]
    fn test_policy_no_violations() {
        let policy = PasswordPolicy {
            min_length: 8, max_length: 64, require_lowercase: true,
            require_uppercase: true, require_digits: true, require_symbols: true,
            no_ambiguous: false, min_entropy: 0.0, avoid_common: false,
        };
        let violations = StrengthAnalyzer::check_policy("Abcd1234!", &policy);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_policy_violations() {
        let policy = PasswordPolicy {
            min_length: 10, max_length: 64, require_lowercase: true,
            require_uppercase: true, require_digits: true, require_symbols: true,
            no_ambiguous: false, min_entropy: 0.0, avoid_common: false,
        };
        let violations = StrengthAnalyzer::check_policy("short", &policy);
        assert!(!violations.is_empty());
        assert!(violations.iter().any(|v| v.contains("Minimum length")));
    }

    #[test]
    fn test_keyboard_reverse_walk_detected() {
        let result = StrengthAnalyzer::analyze("poiuytrewq");
        assert!(result.contains_keyboard_walk);
    }

    #[test]
    fn test_dictionary_word_case_insensitive() {
        let result = StrengthAnalyzer::analyze("MyPaSsWoRd!");
        assert!(result.contains_dictionary_word);
    }

    #[test]
    fn test_password_edge_d_minimal() {
        let result = StrengthAnalyzer::analyze("Ab1def");
        assert_eq!(result.grade, PasswordGrade::D);
    }

    #[test]
    fn test_password_entropy_computation() {
        // 8 chars, all lowercase: 8 * log2(26) = 8 * 4.7 = 37.6
        let result = StrengthAnalyzer::analyze("abcdefgh");
        assert!((result.entropy - 37.6).abs() < 0.1);
    }
}
