use base64::{Engine as _, display::Base64Display, engine::general_purpose::STANDARD};
use serde::{
    Deserialize, Deserializer, Serializer,
    de::{Error as _, IgnoredAny, SeqAccess, Visitor},
};
use std::{fmt, fmt::Write as _, marker::PhantomData};

pub(super) fn serialize_blob_bytes<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.collect_str(&Base64Display::new(bytes, &STANDARD))
}

pub(super) fn deserialize_blob_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Base64BlobVisitor;

    impl Visitor<'_> for Base64BlobVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("canonical padded base64 within the aggregate byte budget")
        }

        fn visit_str<E>(self, encoded: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let decoded_length = decoded_base64_length(encoded)
                .ok_or_else(|| E::custom("invalid base64 padding"))?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(decoded_length).map_err(E::custom)?;
            STANDARD
                .decode_vec(encoded, &mut bytes)
                .map_err(E::custom)?;
            if bytes.len() != decoded_length || !is_canonical_base64(&bytes, encoded) {
                return Err(E::custom("base64 blob is not canonical"));
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_str(Base64BlobVisitor)
}

pub(super) fn decoded_base64_length(encoded: &str) -> Option<usize> {
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

fn is_canonical_base64(bytes: &[u8], encoded: &str) -> bool {
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

pub(super) fn deserialize_vec<'de, D, T, const MAXIMUM: usize>(
    deserializer: D,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct LimitedVecVisitor<T, const MAXIMUM: usize> {
        marker: PhantomData<T>,
    }

    impl<'de, T, const MAXIMUM: usize> Visitor<'de> for LimitedVecVisitor<T, MAXIMUM>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a sequence with at most {MAXIMUM} entries")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence.size_hint().unwrap_or_default().min(MAXIMUM);
            let mut values = Vec::new();
            values.try_reserve(capacity).map_err(A::Error::custom)?;
            while values.len() < MAXIMUM {
                let Some(value) = sequence.next_element()? else {
                    return Ok(values);
                };
                values.push(value);
            }
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("sequence exceeds its limit"));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(LimitedVecVisitor::<T, MAXIMUM> {
        marker: PhantomData,
    })
}
