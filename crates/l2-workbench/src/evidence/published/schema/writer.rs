//! Encode repeated receipt object shapes without retaining decoded arrays

use super::super::canonical_json::{MAX_DEPTH, RawObject, parser_workspace, serialize_scalar};
use super::super::scratch::{Charge, Scratch};
use super::{MAX_SCHEMA_BYTES, MAX_SCHEMA_FIELDS, MAX_SCHEMAS};
use serde::{
    Deserializer, Serialize, Serializer,
    de::{self, SeqAccess, Visitor},
    ser::{SerializeSeq, SerializeStruct, SerializeTuple},
};
use serde_json::value::RawValue;
use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    fmt,
    hash::{Hash, Hasher},
    io,
};

pub(in crate::evidence::published) struct SchemaJson<'a> {
    pub(in crate::evidence::published) bytes: &'a [u8],
    pub(in crate::evidence::published) scratch: &'a Scratch,
}

impl Serialize for SchemaJson<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let _workspace =
            parser_workspace(self.bytes, self.scratch).map_err(serde::ser::Error::custom)?;
        let root: &RawValue =
            serde_json::from_slice(self.bytes).map_err(serde::ser::Error::custom)?;
        let mut schemas = Schemas::new(self.scratch).map_err(serde::ser::Error::custom)?;
        schemas
            .collect(root, 0)
            .map_err(serde::ser::Error::custom)?;
        let mut output = serializer.serialize_struct("SchemaPayload", 2)?;
        output.serialize_field("schemas", &schemas.shapes)?;
        output.serialize_field(
            "root",
            &EncodedValue {
                raw: root,
                schemas: &schemas,
                depth: 0,
            },
        )?;
        output.end()
    }
}

struct Schemas<'a> {
    shapes: Vec<Vec<String>>,
    lookup: HashMap<u64, Vec<usize>>,
    bytes: usize,
    full: bool,
    scratch: &'a Scratch,
    // Shapes and lookup storage must be released before the lease
    charge: Charge<'a>,
}

impl<'a> Schemas<'a> {
    fn new(scratch: &'a Scratch) -> io::Result<Self> {
        Ok(Self {
            shapes: Vec::new(),
            lookup: HashMap::new(),
            bytes: 0,
            full: false,
            scratch,
            charge: scratch.claim(0)?,
        })
    }

    fn collect(&mut self, raw: &RawValue, depth: usize) -> io::Result<()> {
        if depth > MAX_DEPTH {
            return Err(io::Error::other("receipt nesting exceeds its limit"));
        }
        match raw.get().as_bytes().first() {
            Some(b'{') => {
                let fields = RawObject::parse(raw, self.scratch)?;
                self.add(&fields)?;
                for (_, value) in fields.unique() {
                    self.collect(value, depth + 1)?;
                }
            }
            Some(b'[') => {
                let mut deserializer = serde_json::Deserializer::from_str(raw.get());
                deserializer
                    .deserialize_seq(CollectArray {
                        schemas: self,
                        depth,
                    })
                    .map_err(io::Error::other)?;
                deserializer.end().map_err(io::Error::other)?;
            }
            Some(_) => {}
            None => return Err(io::Error::other("empty receipt JSON")),
        }
        Ok(())
    }

    fn find(&self, fields: &RawObject<'_>) -> Option<usize> {
        // Schema IDs follow encounter order, never hash-table iteration order
        self.lookup
            .get(&shape_hash(fields))?
            .iter()
            .copied()
            .find(|index| {
                self.shapes.get(*index).is_some_and(|shape| {
                    shape.len() == fields.unique().count()
                        && shape
                            .iter()
                            .map(String::as_str)
                            .eq(fields.unique().map(|(key, _)| key))
                })
            })
    }

    fn add(&mut self, fields: &RawObject<'_>) -> io::Result<()> {
        if self.full || self.find(fields).is_some() || self.shapes.len() == MAX_SCHEMAS {
            return Ok(());
        }
        let count = fields.unique().count();
        if count > MAX_SCHEMA_FIELDS {
            return Ok(());
        }
        let bytes = fields
            .unique()
            .try_fold(0_usize, |total, (key, _)| total.checked_add(key.len()))
            .ok_or_else(|| io::Error::other("receipt schema size overflow"))?;
        let next = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| io::Error::other("receipt schema size overflow"))?;
        if next > MAX_SCHEMA_BYTES {
            return Ok(());
        }
        let cost = u64::try_from(count)
            .ok()
            .and_then(|n| n.checked_mul(128))
            .and_then(|n| {
                u64::try_from(bytes)
                    .ok()
                    .and_then(|bytes| n.checked_add(bytes))
            })
            .and_then(|n| n.checked_add(512))
            .ok_or_else(|| io::Error::other("receipt schema size overflow"))?;
        // Unindexed shapes remain inline when the shared budget is exhausted
        if !self.charge.grow(cost, true)? {
            self.full = true;
            return Ok(());
        }
        let mut shape = Vec::new();
        shape.try_reserve_exact(count).map_err(io::Error::other)?;
        for (key, _) in fields.unique() {
            let mut text = String::new();
            text.try_reserve_exact(key.len())
                .map_err(io::Error::other)?;
            text.push_str(key);
            shape.push(text);
        }
        self.shapes.try_reserve(1).map_err(io::Error::other)?;
        self.lookup.try_reserve(1).map_err(io::Error::other)?;
        let hash = shape_hash(fields);
        let bucket = self.lookup.entry(hash).or_default();
        bucket.try_reserve(1).map_err(io::Error::other)?;
        bucket.push(self.shapes.len());
        self.shapes.push(shape);
        self.bytes = next;
        Ok(())
    }
}

fn shape_hash(fields: &RawObject<'_>) -> u64 {
    let mut hasher = DefaultHasher::new();
    for (key, _) in fields.unique() {
        key.hash(&mut hasher);
    }
    hasher.finish()
}

struct CollectArray<'a, 's> {
    schemas: &'a mut Schemas<'s>,
    depth: usize,
}
impl<'de> Visitor<'de> for CollectArray<'_, '_> {
    type Value = ();
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a receipt array")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut array: A) -> Result<(), A::Error> {
        while let Some(raw) = array.next_element::<&'de RawValue>()? {
            self.schemas
                .collect(raw, self.depth + 1)
                .map_err(de::Error::custom)?;
        }
        Ok(())
    }
}

struct EncodedValue<'a> {
    raw: &'a RawValue,
    schemas: &'a Schemas<'a>,
    depth: usize,
}

impl Serialize for EncodedValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.depth > MAX_DEPTH {
            return Err(serde::ser::Error::custom(
                "receipt nesting exceeds its limit",
            ));
        }
        match self.raw.get().as_bytes().first() {
            Some(b'{') => {
                let fields = RawObject::parse(self.raw, self.schemas.scratch)
                    .map_err(serde::ser::Error::custom)?;
                if let Some(index) = self.schemas.find(&fields) {
                    let mut tuple = serializer.serialize_tuple(3)?;
                    tuple.serialize_element(&1_u8)?;
                    tuple.serialize_element(&index)?;
                    tuple.serialize_element(&FieldValues {
                        fields: &fields,
                        schemas: self.schemas,
                        depth: self.depth,
                    })?;
                    tuple.end()
                } else {
                    // Shapes beyond the metadata cap remain losslessly inline
                    let mut tuple = serializer.serialize_tuple(2)?;
                    tuple.serialize_element(&2_u8)?;
                    tuple.serialize_element(&FieldEntries {
                        fields: &fields,
                        schemas: self.schemas,
                        depth: self.depth,
                    })?;
                    tuple.end()
                }
            }
            Some(b'[') => {
                let mut tuple = serializer.serialize_tuple(2)?;
                tuple.serialize_element(&0_u8)?;
                tuple.serialize_element(&ArrayValues {
                    raw: self.raw,
                    schemas: self.schemas,
                    depth: self.depth,
                })?;
                tuple.end()
            }
            Some(_) => serialize_scalar(self.raw, self.schemas.scratch, serializer),
            None => Err(serde::ser::Error::custom("empty receipt JSON")),
        }
    }
}

struct FieldValues<'a> {
    fields: &'a RawObject<'a>,
    schemas: &'a Schemas<'a>,
    depth: usize,
}
impl Serialize for FieldValues<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(None)?;
        for (_, raw) in self.fields.unique() {
            sequence.serialize_element(&EncodedValue {
                raw,
                schemas: self.schemas,
                depth: self.depth + 1,
            })?;
        }
        sequence.end()
    }
}

struct FieldEntries<'a> {
    fields: &'a RawObject<'a>,
    schemas: &'a Schemas<'a>,
    depth: usize,
}
impl Serialize for FieldEntries<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(None)?;
        for (key, raw) in self.fields.unique() {
            sequence.serialize_element(&(
                key,
                EncodedValue {
                    raw,
                    schemas: self.schemas,
                    depth: self.depth + 1,
                },
            ))?;
        }
        sequence.end()
    }
}

struct ArrayValues<'a> {
    raw: &'a RawValue,
    schemas: &'a Schemas<'a>,
    depth: usize,
}
impl Serialize for ArrayValues<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let output = serializer.serialize_seq(None)?;
        let mut deserializer = serde_json::Deserializer::from_str(self.raw.get());
        let result = deserializer
            .deserialize_seq(EncodeArray {
                output,
                schemas: self.schemas,
                depth: self.depth,
            })
            .map_err(serde::ser::Error::custom)?;
        deserializer.end().map_err(serde::ser::Error::custom)?;
        Ok(result)
    }
}
struct EncodeArray<'a, S> {
    output: S,
    schemas: &'a Schemas<'a>,
    depth: usize,
}
impl<'de, S: SerializeSeq> Visitor<'de> for EncodeArray<'_, S> {
    type Value = S::Ok;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a receipt array")
    }
    fn visit_seq<A: SeqAccess<'de>>(mut self, mut array: A) -> Result<Self::Value, A::Error> {
        while let Some(raw) = array.next_element::<&'de RawValue>()? {
            self.output
                .serialize_element(&EncodedValue {
                    raw,
                    schemas: self.schemas,
                    depth: self.depth + 1,
                })
                .map_err(de::Error::custom)?;
        }
        self.output.end().map_err(de::Error::custom)
    }
}
