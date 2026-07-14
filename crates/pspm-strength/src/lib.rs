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
