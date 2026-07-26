use sha1::{Digest, Sha1};
use sha2::Sha256;

pub fn sha1_hex(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn hash_password_for_hibp(password: &str) -> String {
    sha1_hex(password.as_bytes()).to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_hex() {
        let result = sha1_hex(b"hello");
        assert_eq!(result.len(), 40);
        assert_eq!(result, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
    }

    #[test]
    fn test_sha256_hex() {
        let result = sha256_hex(b"hello");
        assert_eq!(result.len(), 64);
        assert_eq!(result, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_hash_password_for_hibp() {
        let result = hash_password_for_hibp("password123");
        assert_eq!(result.len(), 40);
        // Should be uppercase
        assert_eq!(result, result.to_uppercase());
    }

    #[test]
    fn test_sha1_empty() {
        let result = sha1_hex(b"");
        assert_eq!(result, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }
}
