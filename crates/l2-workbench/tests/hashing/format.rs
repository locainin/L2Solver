use crate::hashing::{is_sha256_digest, sha256_matches};

#[test]
fn lowercase_digest_hex_format() {
    for value in ["0".repeat(64), "abcdef0123456789".repeat(4)] {
        assert!(is_sha256_digest(&value));
    }
    for value in [
        String::new(),
        "0".repeat(63),
        "0".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
        "é".repeat(32),
        format!("{}\n", "0".repeat(63)),
    ] {
        assert!(
            !is_sha256_digest(&value),
            "accepted invalid digest: {value:?}"
        );
    }
}

#[test]
fn digest_matching_checks_exact_bytes_and_canonical_lowercase() {
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert!(sha256_matches(b"abc", digest));
    assert!(!sha256_matches(b"abd", digest));
    assert!(!sha256_matches(b"abc", &digest.to_ascii_uppercase()));
    assert!(!sha256_matches(
        b"abc",
        digest.get(..63).unwrap_or_default()
    ));
}
