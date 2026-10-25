use crate::hashing::is_sha256_digest;

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
