//! Reconstruct schema-encoded receipt JSON while validating all references

use super::super::canonical_json::MAX_DEPTH;
use super::{MAX_SCHEMA_BYTES, MAX_SCHEMA_FIELDS, MAX_SCHEMAS};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
};
use serde_json::{Value, value::RawValue};
use std::fmt;

pub(in crate::evidence::published) struct DecodedSchemaJson<'a>(
    pub(in crate::evidence::published) &'a RawValue,
);

impl Serialize for DecodedSchemaJson<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let payload: Payload<'_> =
            serde_json::from_str(self.0.get()).map_err(serde::ser::Error::custom)?;
        DecodedValue {
            raw: payload.root,
            schemas: &payload.schemas.0,
            depth: 0,
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload<'a> {
    schemas: SchemaTable,
    #[serde(borrow)]
    root: &'a RawValue,
}

struct SchemaTable(Vec<Vec<String>>);
struct Schema(Vec<String>);

impl<'de> Deserialize<'de> for Schema {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        super::super::super::bounded::deserialize_vec::<D, String, MAX_SCHEMA_FIELDS>(deserializer)
            .map(Self)
    }
}

impl<'de> Deserialize<'de> for SchemaTable {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TableVisitor;
        impl<'de> Visitor<'de> for TableVisitor {
            type Value = SchemaTable;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded receipt schema table")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut schemas = Vec::new();
                let mut bytes = 0_usize;
                while let Some(Schema(keys)) = sequence.next_element()? {
                    if schemas.len() == MAX_SCHEMAS {
                        return Err(de::Error::custom("too many receipt schemas"));
                    }
                    for key in &keys {
                        bytes = bytes
                            .checked_add(key.len())
                            .ok_or_else(|| de::Error::custom("receipt schema size overflow"))?;
                    }
                    if bytes > MAX_SCHEMA_BYTES
                        || keys
                            .windows(2)
                            .any(|pair| matches!(pair, [left, right] if left >= right))
                    {
                        return Err(de::Error::custom("invalid receipt schema"));
                    }
                    schemas.push(keys);
                }
                Ok(SchemaTable(schemas))
            }
        }
        deserializer.deserialize_seq(TableVisitor)
    }
}

struct RawItems<'a>(Vec<&'a RawValue>);
impl<'de: 'a, 'a> Deserialize<'de> for RawItems<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        super::super::super::bounded::deserialize_vec::<D, &'de RawValue, 3>(deserializer).map(Self)
    }
}

struct DecodedValue<'a> {
    raw: &'a RawValue,
    schemas: &'a [Vec<String>],
    depth: usize,
}

impl Serialize for DecodedValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.depth > MAX_DEPTH {
            return Err(serde::ser::Error::custom(
                "receipt nesting exceeds its limit",
            ));
        }
        match self.raw.get().as_bytes().first() {
            Some(b'[') => {
                let parts: RawItems<'_> =
                    serde_json::from_str(self.raw.get()).map_err(serde::ser::Error::custom)?;
                let tag: u8 = serde_json::from_str(
                    parts
                        .0
                        .first()
                        .ok_or_else(|| serde::ser::Error::custom("missing receipt value tag"))?
                        .get(),
                )
                .map_err(serde::ser::Error::custom)?;
                // Tags distinguish arrays, shared object shapes, and inline object fields
                match (tag, parts.0.as_slice()) {
                    (0, [_, values]) => decode_array(serializer, values, self.schemas, self.depth),
                    (1, [_, index, values]) => {
                        let index: usize =
                            serde_json::from_str(index.get()).map_err(serde::ser::Error::custom)?;
                        let keys = self
                            .schemas
                            .get(index)
                            .ok_or_else(|| serde::ser::Error::custom("missing receipt schema"))?;
                        decode_object(serializer, values, self.schemas, keys, self.depth)
                    }
                    (2, [_, fields]) => {
                        decode_inline_object(serializer, fields, self.schemas, self.depth)
                    }
                    _ => Err(serde::ser::Error::custom("invalid receipt value tag")),
                }
            }
            Some(b'{') | None => Err(serde::ser::Error::custom("invalid encoded receipt value")),
            Some(_) => {
                let value: Value =
                    serde_json::from_str(self.raw.get()).map_err(serde::ser::Error::custom)?;
                value.serialize(serializer)
            }
        }
    }
}

fn decode_array<S: Serializer>(
    serializer: S,
    values: &RawValue,
    schemas: &[Vec<String>],
    depth: usize,
) -> Result<S::Ok, S::Error> {
    let output = serializer.serialize_seq(None)?;
    let mut deserializer = serde_json::Deserializer::from_str(values.get());
    let result = deserializer
        .deserialize_seq(ArrayVisitor {
            output,
            schemas,
            depth,
        })
        .map_err(serde::ser::Error::custom)?;
    deserializer.end().map_err(serde::ser::Error::custom)?;
    Ok(result)
}

struct ArrayVisitor<'a, S> {
    output: S,
    schemas: &'a [Vec<String>],
    depth: usize,
}
impl<'de, S: SerializeSeq> Visitor<'de> for ArrayVisitor<'_, S> {
    type Value = S::Ok;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a receipt value array")
    }
    fn visit_seq<A: SeqAccess<'de>>(mut self, mut sequence: A) -> Result<Self::Value, A::Error> {
        while let Some(raw) = sequence.next_element::<&'de RawValue>()? {
            self.output
                .serialize_element(&DecodedValue {
                    raw,
                    schemas: self.schemas,
                    depth: self.depth + 1,
                })
                .map_err(de::Error::custom)?;
        }
        self.output.end().map_err(de::Error::custom)
    }
}

fn decode_object<S: Serializer>(
    serializer: S,
    values: &RawValue,
    schemas: &[Vec<String>],
    keys: &[String],
    depth: usize,
) -> Result<S::Ok, S::Error> {
    let output = serializer.serialize_map(None)?;
    let mut deserializer = serde_json::Deserializer::from_str(values.get());
    let result = deserializer
        .deserialize_seq(ObjectVisitor {
            output,
            schemas,
            keys,
            depth,
        })
        .map_err(serde::ser::Error::custom)?;
    deserializer.end().map_err(serde::ser::Error::custom)?;
    Ok(result)
}

struct ObjectVisitor<'a, S> {
    output: S,
    schemas: &'a [Vec<String>],
    keys: &'a [String],
    depth: usize,
}
impl<'de, S: SerializeMap> Visitor<'de> for ObjectVisitor<'_, S> {
    type Value = S::Ok;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("receipt object values")
    }
    fn visit_seq<A: SeqAccess<'de>>(mut self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut count = 0_usize;
        while let Some(raw) = sequence.next_element::<&'de RawValue>()? {
            let key = self
                .keys
                .get(count)
                .ok_or_else(|| de::Error::custom("too many receipt object values"))?;
            self.output
                .serialize_entry(
                    key,
                    &DecodedValue {
                        raw,
                        schemas: self.schemas,
                        depth: self.depth + 1,
                    },
                )
                .map_err(de::Error::custom)?;
            count += 1;
        }
        if count != self.keys.len() {
            return Err(de::Error::custom("missing receipt object value"));
        }
        self.output.end().map_err(de::Error::custom)
    }
}

fn decode_inline_object<S: Serializer>(
    serializer: S,
    fields: &RawValue,
    schemas: &[Vec<String>],
    depth: usize,
) -> Result<S::Ok, S::Error> {
    let output = serializer.serialize_map(None)?;
    let mut deserializer = serde_json::Deserializer::from_str(fields.get());
    let result = deserializer
        .deserialize_seq(InlineVisitor {
            output,
            schemas,
            depth,
        })
        .map_err(serde::ser::Error::custom)?;
    deserializer.end().map_err(serde::ser::Error::custom)?;
    Ok(result)
}

struct InlineVisitor<'a, S> {
    output: S,
    schemas: &'a [Vec<String>],
    depth: usize,
}
impl<'de, S: SerializeMap> Visitor<'de> for InlineVisitor<'_, S> {
    type Value = S::Ok;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("inline receipt object fields")
    }
    fn visit_seq<A: SeqAccess<'de>>(mut self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut previous: Option<String> = None;
        while let Some((key, raw)) = sequence.next_element::<(String, &'de RawValue)>()? {
            if previous.as_ref().is_some_and(|last| last >= &key) {
                return Err(de::Error::custom("invalid inline receipt keys"));
            }
            self.output
                .serialize_entry(
                    &key,
                    &DecodedValue {
                        raw,
                        schemas: self.schemas,
                        depth: self.depth + 1,
                    },
                )
                .map_err(de::Error::custom)?;
            previous = Some(key);
        }
        self.output.end().map_err(de::Error::custom)
    }
}
