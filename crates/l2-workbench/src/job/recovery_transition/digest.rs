//! Compact, strictly bounded hexadecimal encoding for SHA-256 values

use serde::{Deserializer, Serializer, de, ser::Error as _};
use std::fmt::Write as _;

pub(super) fn serialize<S: Serializer>(
    digest: &[u8; 32],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut text = String::with_capacity(64);
    for byte in digest {
        write!(&mut text, "{byte:02x}").map_err(S::Error::custom)?;
    }
    serializer.serialize_str(&text)
}

pub(super) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<[u8; 32], D::Error> {
    struct DigestVisitor;
    impl serde::de::Visitor<'_> for DigestVisitor {
        type Value = [u8; 32];
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("64 lowercase hexadecimal SHA-256 digits")
        }
        fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
            crate::parse_sha256_digest(value)
                .ok_or_else(|| E::custom("invalid lowercase SHA-256 digest"))
        }
    }
    deserializer.deserialize_str(DigestVisitor)
}

pub(super) mod optional {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    struct Digest(#[serde(with = "super")] [u8; 32]);

    #[expect(
        clippy::ref_option,
        reason = "Serde passes optional fields by reference"
    )]
    pub(in crate::job::recovery_transition) fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.map(Digest).serialize(serializer)
    }

    pub(in crate::job::recovery_transition) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        Option::<Digest>::deserialize(deserializer).map(|value| value.map(|digest| digest.0))
    }
}
