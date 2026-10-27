//! Content digests and the canonical spelling used by stored evidence receipts

use sha2::{Digest, Sha256};

/// Hash exact byte contents without assigning meaning or source authenticity
#[must_use]
pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn sha256_matches(bytes: &[u8], digest: &str) -> bool {
    if !is_sha256_digest(digest) {
        return false;
    }
    let expected = digest.as_bytes();
    Sha256::digest(bytes)
        .iter()
        .zip(expected.chunks_exact(2))
        .all(|(byte, pair)| {
            pair.first().copied() == Some(hex_digit(byte >> 4))
                && pair.get(1).copied() == Some(hex_digit(byte & 0x0f))
        })
}

const fn hex_digit(nibble: u8) -> u8 {
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + nibble - 10
    }
}

/// Stored identities use the lowercase spelling produced by the digest writer
pub fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Parse the canonical lowercase hexadecimal form of a SHA-256 digest
#[must_use]
pub fn parse_sha256_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0; 32];
    for (slot, pair) in digest.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let [high, low] = pair else { return None };
        let nibble = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        *slot = (nibble(*high)? << 4) | nibble(*low)?;
    }
    Some(digest)
}
