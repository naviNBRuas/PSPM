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
