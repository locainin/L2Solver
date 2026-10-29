//! Canonical receipt JSON without materializing complete arrays or nested values

use super::scratch::{Charge, Scratch};
use serde::{
    Deserializer, Serialize, Serializer,
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
};
use serde_json::value::RawValue;
use std::{fmt, io, marker::PhantomData};

// Match the default serde_json recursion boundary for previously accepted receipts
pub(super) const MAX_DEPTH: usize = 128;

pub(super) struct CanonicalJson<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) scratch: &'a Scratch,
}

impl Serialize for CanonicalJson<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let _workspace =
            parser_workspace(self.bytes, self.scratch).map_err(serde::ser::Error::custom)?;
        let raw: &RawValue =
            serde_json::from_slice(self.bytes).map_err(serde::ser::Error::custom)?;
        CanonicalValue {
            raw,
            depth: 0,
            scratch: self.scratch,
        }
        .serialize(serializer)
    }
}

struct CanonicalValue<'a> {
    raw: &'a RawValue,
    depth: usize,
    scratch: &'a Scratch,
}

impl Serialize for CanonicalValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.depth > MAX_DEPTH {
            return Err(serde::ser::Error::custom(
                "receipt nesting exceeds its limit",
            ));
        }
        match self.raw.get().as_bytes().first() {
            Some(b'{') => {
                let fields =
                    RawObject::parse(self.raw, self.scratch).map_err(serde::ser::Error::custom)?;
                let mut map = serializer.serialize_map(None)?;
                for (key, raw) in fields.unique() {
                    map.serialize_entry(
                        key,
                        &CanonicalValue {
                            raw,
                            depth: self.depth + 1,
                            scratch: self.scratch,
                        },
                    )?;
                }
                map.end()
            }
            Some(b'[') => {
                let seq = serializer.serialize_seq(None)?;
                let mut deserializer = serde_json::Deserializer::from_str(self.raw.get());
                let result = deserializer
                    .deserialize_seq(ArrayWriter {
                        output: seq,
                        depth: self.depth,
                        scratch: self.scratch,
                    })
                    .map_err(serde::ser::Error::custom)?;
                deserializer.end().map_err(serde::ser::Error::custom)?;
                Ok(result)
            }
            Some(_) => serialize_scalar(self.raw, self.scratch, serializer),
            None => Err(serde::ser::Error::custom("empty receipt JSON")),
        }
    }
}

// Scan nesting before allocating validation stacks or choosing receipt encoding
pub(super) fn nesting_depth(bytes: &[u8], limit: usize) -> Option<usize> {
    let mut depth = 0_usize;
    let mut maximum = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for &byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'[' | b'{' => {
                    depth += 1;
                    if depth > limit {
                        return None;
                    }
                    maximum = maximum.max(depth);
                }
                b']' | b'}' => depth = depth.checked_sub(1)?,
                _ => {}
            }
        }
    }
    (!quoted && depth == 0).then_some(maximum)
}

// Bound the nested Serde validation stacks before parsing a borrowed receipt
pub(super) fn parser_workspace<'a>(bytes: &[u8], scratch: &'a Scratch) -> io::Result<Charge<'a>> {
    let maximum = nesting_depth(bytes, MAX_DEPTH + 1)
        .ok_or_else(|| io::Error::other("receipt nesting is invalid or exceeds its limit"))?;
    let maximum = u64::try_from(maximum).map_err(io::Error::other)?;
    // Several borrowed-array visitors can keep validation stacks alive at once
    let cost = maximum * maximum * 4 + (maximum + 1) * 256;
    scratch.claim(cost)
}

pub(super) fn serialize_scalar<S: Serializer>(
    raw: &RawValue,
    scratch: &Scratch,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let bytes = raw.get().as_bytes();
    if bytes.first() == Some(&b'"') && !bytes.contains(&b'\\') {
        // Borrow ordinary strings instead of copying every receipt value
        let value: &str = serde_json::from_str(raw.get()).map_err(serde::ser::Error::custom)?;
        return value.serialize(serializer);
    }
    if bytes
        .first()
        .is_some_and(|byte| *byte == b'-' || byte.is_ascii_digit())
    {
        // Number preserves Serde's configured numeric representation
        let value: serde_json::Number =
            serde_json::from_str(raw.get()).map_err(serde::ser::Error::custom)?;
        return value.serialize(serializer);
    }
    // Reserve for the parser buffer before decoding escaped strings
    let _charge = if bytes.first() == Some(&b'"') {
        let length = u64::try_from(bytes.len()).map_err(serde::ser::Error::custom)?;
        let cost = length
            .checked_mul(2)
            .and_then(|value| value.checked_add(256))
            .ok_or_else(|| serde::ser::Error::custom("receipt string size overflow"))?;
        Some(scratch.claim(cost).map_err(serde::ser::Error::custom)?)
    } else {
        None
    };
    let mut input = serde_json::Deserializer::from_str(raw.get());
    let output = input
        .deserialize_any(ScalarWriter { serializer })
        .map_err(serde::ser::Error::custom)?;
    input.end().map_err(serde::ser::Error::custom)?;
    Ok(output)
}

struct ScalarWriter<S> {
    serializer: S,
}

impl<S: Serializer> Visitor<'_> for ScalarWriter<S> {
    type Value = S::Ok;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON scalar")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        self.serializer.serialize_bool(value).map_err(E::custom)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.serializer.serialize_str(value).map_err(E::custom)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        self.serializer.serialize_unit().map_err(E::custom)
    }
}

pub(super) struct RawObject<'a> {
    fields: Vec<(String, &'a RawValue)>,
    // Fields are dropped before their accounting lease
    _charge: Charge<'a>,
}

impl<'a> RawObject<'a> {
    pub(super) fn parse(raw: &'a RawValue, scratch: &'a Scratch) -> io::Result<Self> {
        let (count, key_bytes) = object_keys(raw.get())?;
        let cost = u64::try_from(count)
            .ok()
            .and_then(|n| n.checked_mul(128))
            .and_then(|n| {
                u64::try_from(key_bytes)
                    .ok()
                    .and_then(|keys| keys.checked_mul(3))
                    .and_then(|keys| n.checked_add(keys))
            })
            .and_then(|n| n.checked_add(256))
            .ok_or_else(|| io::Error::other("receipt object size overflow"))?;
        let charge = scratch.claim(cost)?;
        let mut fields = Vec::new();
        fields.try_reserve_exact(count).map_err(io::Error::other)?;
        let mut deserializer = serde_json::Deserializer::from_str(raw.get());
        let mut fields = deserializer
            .deserialize_map(ObjectVisitor {
                fields,
                marker: PhantomData,
            })
            .map_err(|error| scratch.error(error))?;
        deserializer.end().map_err(io::Error::other)?;
        // Stable ordering retains the last occurrence of each duplicate key
        fields.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(Self {
            fields,
            _charge: charge,
        })
    }

    pub(super) fn unique(&self) -> impl Iterator<Item = (&str, &'a RawValue)> {
        self.fields
            .iter()
            .enumerate()
            .filter_map(|(index, (key, value))| {
                self.fields
                    .get(index + 1)
                    .is_none_or(|next| next.0 != *key)
                    .then_some((key.as_str(), *value))
            })
    }
}

// Count direct object keys before allocating their strings and sorting workspace
fn object_keys(text: &str) -> io::Result<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut depth = 0_usize;
    let mut count = 0_usize;
    let mut length = 0_usize;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'{' | b'[' => {
                depth += 1;
                index += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                index += 1;
            }
            b'"' => {
                let start = index;
                index += 1;
                while let Some(&byte) = bytes.get(index) {
                    match byte {
                        b'\\' => index = index.saturating_add(2),
                        b'"' => {
                            index += 1;
                            break;
                        }
                        _ => index += 1,
                    }
                }
                if depth == 1 {
                    let mut next = index;
                    while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                        next += 1;
                    }
                    if bytes.get(next) == Some(&b':') {
                        count = count
                            .checked_add(1)
                            .ok_or_else(|| io::Error::other("receipt key count overflow"))?;
                        length = length
                            .checked_add(index - start)
                            .ok_or_else(|| io::Error::other("receipt key size overflow"))?;
                    }
                }
            }
            _ => index += 1,
        }
    }
    Ok((count, length))
}

struct ObjectVisitor<'a> {
    fields: Vec<(String, &'a RawValue)>,
    marker: PhantomData<&'a RawValue>,
}
impl<'de: 'a, 'a> Visitor<'de> for ObjectVisitor<'a> {
    type Value = Vec<(String, &'a RawValue)>;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a receipt object")
    }
    fn visit_map<M: MapAccess<'de>>(mut self, mut map: M) -> Result<Self::Value, M::Error> {
        while let Some((key, value)) = map.next_entry::<String, &'de RawValue>()? {
            self.fields.push((key, value));
        }
        Ok(self.fields)
    }
}

struct ArrayWriter<'a, S> {
    output: S,
    depth: usize,
    scratch: &'a Scratch,
}
impl<'de, S: SerializeSeq> Visitor<'de> for ArrayWriter<'_, S> {
    type Value = S::Ok;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a receipt array")
    }
    fn visit_seq<A: SeqAccess<'de>>(mut self, mut array: A) -> Result<Self::Value, A::Error> {
        while let Some(raw) = array.next_element::<&'de RawValue>()? {
            self.output
                .serialize_element(&CanonicalValue {
                    raw,
                    depth: self.depth + 1,
                    scratch: self.scratch,
                })
                .map_err(de::Error::custom)?;
        }
        self.output.end().map_err(de::Error::custom)
    }
}
