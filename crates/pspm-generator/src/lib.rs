use pspm_core::types::{GenerationPolicy, PasswordStyle};
use rand::Rng;

pub struct PasswordGenerator;

impl PasswordGenerator {
    pub fn generate(policy: &GenerationPolicy) -> String {
        match policy.style {
            PasswordStyle::Random => Self::generate_random(policy),
            PasswordStyle::Diceware => Self::generate_diceware(),
            PasswordStyle::Pin => Self::generate_pin(policy),
            PasswordStyle::Memorable => Self::generate_memorable(),
        }
    }

    fn generate_random(policy: &GenerationPolicy) -> String {
        let mut rng = rand::thread_rng();
        let mut chars = Vec::new();

        let lower: Vec<char> = "abcdefghijklmnopqrstuvwxyz".chars().collect();
        let upper: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
        let digits: Vec<char> = "0123456789".chars().collect();
        let symbols: Vec<char> = "!@#$%^&*()_+-=[]{}|;:,.<>?".chars().collect();
        let ambiguous: &[char] = &['1', 'l', 'I', '0', 'O', 'o'];

        let mut pool: Vec<char> = Vec::new();
        let mut guaranteed = Vec::new();

        if policy.include_lowercase {
            pool.extend(&lower);
            guaranteed.push(lower[rng.gen_range(0..lower.len())]);
        }
        if policy.include_uppercase {
            pool.extend(&upper);
            guaranteed.push(upper[rng.gen_range(0..upper.len())]);
        }
        if policy.include_digits {
            pool.extend(&digits);
            guaranteed.push(digits[rng.gen_range(0..digits.len())]);
        }
        if policy.include_symbols {
            pool.extend(&symbols);
            guaranteed.push(symbols[rng.gen_range(0..symbols.len())]);
        }

        if policy.no_ambiguous {
            pool.retain(|c| !ambiguous.contains(c));
        }

        if pool.is_empty() {
            pool.extend(&lower);
            pool.extend(&digits);
        }

        let remaining = policy.length as usize - guaranteed.len();
        for _ in 0..remaining {
            let idx = rng.gen_range(0..pool.len());
            chars.push(pool[idx]);
        }
        chars.extend(guaranteed);

        // Shuffle
        for i in (1..chars.len()).rev() {
            let j = rng.gen_range(0..=i);
            chars.swap(i, j);
        }

        chars.into_iter().collect()
    }

    fn generate_diceware() -> String {
        // Placeholder — real Diceware uses a word list
        let words = [
            "correct", "horse", "battery", "staple", "quantum",
            "galaxy", "purple", "dragon", "eagle", "forest",
        ];
        let mut rng = rand::thread_rng();
        let selected: Vec<&str> = (0..6).map(|_| words[rng.gen_range(0..words.len())]).collect();
        selected.join("-")
    }

    fn generate_pin(policy: &GenerationPolicy) -> String {
        let mut rng = rand::thread_rng();
        let len = policy.length.max(4).min(12) as usize;
        (0..len)
            .map(|_| rng.gen_range(0..10).to_string())
            .collect()
    }

    fn generate_memorable() -> String {
        let adjectives = [
            "happy", "bright", "swift", "calm", "bold",
            "cool", "dark", "fast", "gold", "keen",
        ];
        let nouns = [
            "tiger", "eagle", "panda", "lion", "wolf",
            "hawk", "bear", "deer", "frog", "swan",
        ];
        let mut rng = rand::thread_rng();
        let adj = adjectives[rng.gen_range(0..adjectives.len())];
        let noun = nouns[rng.gen_range(0..nouns.len())];
        let num: u32 = rng.gen_range(10..999);
        format!("{adj}{noun}{num}")
    }
}
