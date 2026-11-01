//! Canonical padded Base64 for admitted evidence and checkpoint byte strings

use ::base64::{Engine as _, display::Base64Display, engine::general_purpose::STANDARD};
use serde::{Deserializer, Serializer, de::Visitor};
use std::{fmt, fmt::Write as _};

/// Encode bytes as a canonical padded Base64 string
///
/// # Errors
/// Returns an error if the serializer cannot write the encoded string
pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.collect_str(&Base64Display::new(bytes, &STANDARD))
}

/// Decode a canonical padded Base64 string after caller-side memory admission
///
/// # Errors
/// Returns an error for invalid encoding, noncanonical padding, or allocation failure
pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Base64Visitor;

    impl Visitor<'_> for Base64Visitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("canonical padded base64 within the aggregate byte budget")
        }

        fn visit_str<E>(self, encoded: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let decoded_length =
                decoded_length(encoded).ok_or_else(|| E::custom("invalid base64 padding"))?;
            let mut bytes = Vec::new();
            // The decoder first resizes to its estimate, including any padding
            bytes
                .try_reserve_exact(::base64::decoded_len_estimate(encoded.len()))
                .map_err(E::custom)?;
            STANDARD
                .decode_vec(encoded, &mut bytes)
                .map_err(E::custom)?;
            if bytes.len() != decoded_length || !is_canonical(&bytes, encoded) {
                return Err(E::custom("base64 bytes are not canonical"));
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_str(Base64Visitor)
}

/// Return the decoded length after checking padding placement
pub fn decoded_length(encoded: &str) -> Option<usize> {
    let bytes = encoded.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let padding = bytes.iter().rev().take_while(|&&byte| byte == b'=').count();
    if padding > 2
        || bytes
            .get(..bytes.len().checked_sub(padding)?)?
            .contains(&b'=')
    {
        return None;
    }
    bytes
        .len()
        .checked_div(4)?
        .checked_mul(3)?
        .checked_sub(padding)
}

fn is_canonical(bytes: &[u8], encoded: &str) -> bool {
    struct ExactText<'a> {
        expected: &'a [u8],
        offset: usize,
    }

    impl fmt::Write for ExactText<'_> {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            let Some(end) = self.offset.checked_add(value.len()) else {
                return Err(fmt::Error);
            };
            if self.expected.get(self.offset..end) != Some(value.as_bytes()) {
                return Err(fmt::Error);
            }
            self.offset = end;
            Ok(())
        }
    }

    let mut output = ExactText {
        expected: encoded.as_bytes(),
        offset: 0,
    };
    write!(&mut output, "{}", Base64Display::new(bytes, &STANDARD)).is_ok()
        && output.offset == encoded.len()
}
