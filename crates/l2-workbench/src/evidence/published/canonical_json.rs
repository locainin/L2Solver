//! Canonical receipt JSON without materializing complete arrays or nested values

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
};
use serde_json::{Value, value::RawValue};
use std::{fmt, marker::PhantomData};

// Match the default serde_json recursion boundary for previously accepted receipts
pub(super) const MAX_DEPTH: usize = 128;

pub(super) struct CanonicalJson<'a>(pub(super) &'a [u8]);

impl Serialize for CanonicalJson<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let raw: &RawValue = serde_json::from_slice(self.0).map_err(serde::ser::Error::custom)?;
        CanonicalValue { raw, depth: 0 }.serialize(serializer)
    }
}

struct CanonicalValue<'a> {
    raw: &'a RawValue,
    depth: usize,
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
                let fields = RawObject::parse(self.raw).map_err(serde::ser::Error::custom)?;
                let mut map = serializer.serialize_map(None)?;
                for (key, raw) in fields.unique() {
                    map.serialize_entry(
                        key,
                        &CanonicalValue {
                            raw,
                            depth: self.depth + 1,
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
                    })
                    .map_err(serde::ser::Error::custom)?;
                deserializer.end().map_err(serde::ser::Error::custom)?;
                Ok(result)
            }
            Some(_) => {
                // Scalar parsing preserves serde_json's number and string rules
                let value: Value =
                    serde_json::from_str(self.raw.get()).map_err(serde::ser::Error::custom)?;
                value.serialize(serializer)
            }
            None => Err(serde::ser::Error::custom("empty receipt JSON")),
        }
    }
}

pub(super) struct RawObject<'a>(Vec<(String, &'a RawValue)>);

impl<'a> RawObject<'a> {
    pub(super) fn parse(raw: &'a RawValue) -> serde_json::Result<Self> {
        let mut fields: Self = serde_json::from_str(raw.get())?;
        // Stable ordering retains the last occurrence of each duplicate key
        fields.0.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(fields)
    }

    pub(super) fn unique(&self) -> impl Iterator<Item = (&str, &'a RawValue)> {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(index, (key, value))| {
                self.0
                    .get(index + 1)
                    .is_none_or(|next| next.0 != *key)
                    .then_some((key.as_str(), *value))
            })
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for RawObject<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<'a>(PhantomData<&'a RawValue>);
        impl<'de: 'a, 'a> Visitor<'de> for ObjectVisitor<'a> {
            type Value = RawObject<'a>;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a receipt object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut fields = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, &'de RawValue>()? {
                    fields.try_reserve(1).map_err(de::Error::custom)?;
                    fields.push((key, value));
                }
                Ok(RawObject(fields))
            }
        }
        deserializer.deserialize_map(ObjectVisitor(PhantomData))
    }
}

struct ArrayWriter<S> {
    output: S,
    depth: usize,
}

impl<'de, S: SerializeSeq> Visitor<'de> for ArrayWriter<S> {
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
                })
                .map_err(de::Error::custom)?;
        }
        self.output.end().map_err(de::Error::custom)
    }
}
