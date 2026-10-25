//! Content digests and the canonical spelling used by stored evidence receipts

use sha2::{Digest, Sha256};

/// Hash exact byte contents without assigning meaning or source authenticity
#[must_use]
pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Stored identities use the lowercase spelling produced by the digest writer
pub fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
