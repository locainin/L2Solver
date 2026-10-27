//! Versioned records and bounded dictionary references

use super::super::{EvidenceStatus, Source};
use serde::{
    Deserialize, Serialize,
    de::{self, SeqAccess, Visitor},
};
use serde_json::{Value, value::RawValue};
use std::{fmt, io};

pub(super) const LEGACY_VERSION: u32 = 3;
pub(super) const VERSION: u32 = 4;
pub(super) const MAX_STRINGS: usize = 4096;
pub(super) const MAX_DICTIONARY_BYTES: usize = 512 * 1024;

#[derive(Serialize)]
pub(super) struct HeaderRef<'a> {
    pub(super) version: u32,
    pub(super) case_id: &'a str,
    pub(super) ordinal: u64,
    pub(super) scope: &'a Value,
    pub(super) metadata: &'a super::canonical::Metadata,
    pub(super) strings: &'a [&'a str],
    pub(super) counts: Counts,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Counts {
    pub(super) sources: usize,
    pub(super) blobs: usize,
    pub(super) nodes: usize,
    pub(super) edges: usize,
    pub(super) limitations: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Header {
    pub(super) version: u32,
    pub(super) case_id: String,
    pub(super) ordinal: u64,
    pub(super) scope: Box<RawValue>,
    pub(super) metadata: Metadata,
    pub(super) strings: Dictionary,
    pub(super) counts: Counts,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Metadata {
    pub(super) schema_version: u32,
    pub(super) collection_complete: bool,
    pub(super) blob_byte_limit: Option<usize>,
}

pub(super) struct Dictionary(pub(super) Vec<String>);

impl<'de> Deserialize<'de> for Dictionary {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DictionaryVisitor;
        impl<'de> Visitor<'de> for DictionaryVisitor {
            type Value = Dictionary;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded string dictionary")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut strings = Vec::new();
                let mut bytes = 0_usize;
                while let Some(string) = seq.next_element::<String>()? {
                    bytes = bytes
                        .checked_add(string.len())
                        .ok_or_else(|| de::Error::custom("dictionary size overflow"))?;
                    if strings.len() == MAX_STRINGS || bytes > MAX_DICTIONARY_BYTES {
                        return Err(de::Error::custom("dictionary exceeds its limit"));
                    }
                    strings.push(string);
                }
                Ok(Dictionary(strings))
            }
        }
        deserializer.deserialize_seq(DictionaryVisitor)
    }
}

#[derive(Deserialize)]
#[serde(
    tag = "record",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum Record {
    Header(Header),
    Source(Source),
    Blob(Blob),
    Node(Node),
    Edge(Edge),
    Limitation(String),
    End,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Blob {
    pub(super) id: String,
    pub(super) byte_length: usize,
    #[serde(default, deserialize_with = "present_raw")]
    pub(super) inline_payload: Option<Box<RawValue>>,
    #[serde(default, deserialize_with = "present_raw")]
    pub(super) schema_payload: Option<Box<RawValue>>,
}

impl Serialize for Blob {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut output = serializer.serialize_struct(
            "BlobRecord",
            if self.inline_payload.is_some() || self.schema_payload.is_some() {
                3
            } else {
                2
            },
        )?;
        output.serialize_field("id", &self.id)?;
        output.serialize_field("byte_length", &self.byte_length)?;
        match (&self.inline_payload, &self.schema_payload) {
            (Some(_), Some(_)) => {
                return Err(serde::ser::Error::custom("multiple receipt payloads"));
            }
            (Some(raw), None) => output.serialize_field("inline_payload", raw)?,
            (None, Some(raw)) => {
                output.serialize_field("inline_payload", &super::schema::DecodedSchemaJson(raw))?;
            }
            (None, None) => {}
        }
        output.end()
    }
}

fn present_raw<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Box<RawValue>>, D::Error> {
    Box::<RawValue>::deserialize(deserializer).map(Some)
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum Text {
    Index(usize),
    Inline(String),
}

type Range = (usize, Option<u64>, u64, u64);

impl Text {
    pub(super) fn resolve(self, dictionary: &[String]) -> io::Result<String> {
        match self {
            Self::Index(index) => dictionary
                .get(index)
                .cloned()
                .ok_or_else(|| io::Error::other("missing evidence dictionary reference")),
            Self::Inline(value) => Ok(value),
        }
    }
}

#[derive(Deserialize)]
pub(super) struct Node(
    pub(super) u64,
    pub(super) Text,
    pub(super) Option<String>,
    #[serde(deserialize_with = "deserialize_ranges")] pub(super) Vec<Range>,
    pub(super) Box<RawValue>,
);

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum Details {
    Object(#[serde(deserialize_with = "deserialize_details")] Vec<(Text, DetailValue)>),
    Value(Box<RawValue>),
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum DetailValue {
    Text(Text),
    Value(Box<RawValue>),
}

#[derive(Deserialize)]
struct CompactField(Text, u8, Box<RawValue>);

struct CompactFields(Vec<CompactField>);

impl<'de> Deserialize<'de> for CompactFields {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        super::super::bounded::deserialize_vec::<
            D,
            CompactField,
            { super::super::MAX_NODE_DETAILS_BYTES },
        >(deserializer)
        .map(Self)
    }
}

pub(super) fn expand_compact_details(raw: &RawValue, dictionary: &[String]) -> io::Result<Value> {
    let (kind, contents): (u8, Box<RawValue>) =
        serde_json::from_str(raw.get()).map_err(io::Error::other)?;
    match kind {
        0 => {
            let fields: CompactFields =
                serde_json::from_str(contents.get()).map_err(io::Error::other)?;
            let mut output = serde_json::Map::new();
            for CompactField(key, kind, value) in fields.0 {
                let key = key.resolve(dictionary)?;
                let value = match kind {
                    0 => Value::String(
                        serde_json::from_str::<Text>(value.get())
                            .map_err(io::Error::other)?
                            .resolve(dictionary)?,
                    ),
                    1 => serde_json::from_str(value.get()).map_err(io::Error::other)?,
                    _ => return Err(io::Error::other("invalid evidence detail field kind")),
                };
                if output.insert(key, value).is_some() {
                    return Err(io::Error::other("duplicate evidence detail field"));
                }
            }
            Ok(Value::Object(output))
        }
        1 => serde_json::from_str(contents.get()).map_err(io::Error::other),
        _ => Err(io::Error::other("invalid evidence details kind")),
    }
}

fn deserialize_details<'de, D>(deserializer: D) -> Result<Vec<(Text, DetailValue)>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    super::super::bounded::deserialize_vec::<D, _, { super::super::MAX_NODE_DETAILS_BYTES }>(
        deserializer,
    )
}

impl Details {
    pub(super) fn expand(self, dictionary: &[String]) -> io::Result<Value> {
        match self {
            Self::Value(raw) => serde_json::from_str(raw.get()).map_err(io::Error::other),
            Self::Object(fields) => {
                let mut output = serde_json::Map::new();
                for (key, value) in fields {
                    let key = key.resolve(dictionary)?;
                    let value = match value {
                        DetailValue::Text(text) => Value::String(text.resolve(dictionary)?),
                        DetailValue::Value(raw) => {
                            serde_json::from_str(raw.get()).map_err(io::Error::other)?
                        }
                    };
                    if output.insert(key, value).is_some() {
                        return Err(io::Error::other("duplicate evidence detail field"));
                    }
                }
                Ok(Value::Object(output))
            }
        }
    }
}

fn deserialize_ranges<'de, D>(deserializer: D) -> Result<Vec<Range>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    super::super::bounded::deserialize_vec::<D, _, { super::super::MAX_NODE_RANGES }>(deserializer)
}

#[derive(Deserialize)]
pub(super) struct Edge(
    pub(super) u64,
    pub(super) u64,
    pub(super) Text,
    pub(super) EvidenceStatus,
    pub(super) Text,
);
