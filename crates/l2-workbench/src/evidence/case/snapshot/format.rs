//! Versioned snapshot records and bounded JSON text decoding

use super::super::super::bounded;
use super::super::super::model::EvidenceStatus;
use super::super::{CaseResourceLimits, MAX_NODE_RANGES, MAX_SOURCE_ALIASES};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{IgnoredAny, Visitor},
};
use serde_json::value::RawValue;
use std::{borrow::Cow, fmt, marker::PhantomData};

pub(super) const SNAPSHOT_FORMAT_VERSION: u32 = 1;
pub(super) const MAX_SNAPSHOT_RECORD_BYTES: usize = 256 * 1024;
pub(super) const SNAPSHOT_BUFFER_CAPACITY: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SnapshotHeader {
    pub(super) format_version: u32,
    pub(super) schema_version: u32,
    pub(super) collection_complete: bool,
    pub(super) resource_limits: CaseResourceLimits,
    pub(super) source_count: u64,
    pub(super) blob_count: u64,
    pub(super) node_count: u64,
    pub(super) edge_count: u64,
    pub(super) limitation_count: u64,
    pub(super) blob_pack_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SnapshotBlob {
    pub(super) id: String,
    pub(super) offset: u64,
    pub(super) length: u64,
}

#[derive(Serialize)]
pub(super) struct SnapshotBlobRef<'a> {
    pub(super) id: &'a str,
    pub(super) offset: u64,
    pub(super) length: u64,
}

#[derive(Deserialize)]
#[serde(
    tag = "record",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum RawSnapshotRecord<'a> {
    #[serde(borrow)]
    Header(&'a RawValue),
    #[serde(borrow)]
    Source(&'a RawValue),
    #[serde(borrow)]
    Blob(&'a RawValue),
    #[serde(borrow)]
    Node(&'a RawValue),
    #[serde(borrow)]
    Edge(&'a RawValue),
    #[serde(borrow)]
    Limitation(&'a RawValue),
}

#[derive(Deserialize)]
#[serde(transparent)]
pub(super) struct RawLimitation<'a>(#[serde(borrow)] pub(super) SnapshotText<'a>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawSource<'a> {
    #[serde(borrow)]
    pub(super) id: SnapshotText<'a>,
    #[serde(borrow)]
    pub(super) label: SnapshotText<'a>,
    #[serde(borrow, deserialize_with = "deserialize_aliases")]
    pub(super) aliases: Vec<SnapshotText<'a>>,
    #[serde(borrow)]
    pub(super) kind: SnapshotText<'a>,
    #[serde(rename = "length")]
    _length: u64,
    #[serde(borrow)]
    pub(super) blob: Option<SnapshotText<'a>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawNode<'a> {
    pub(super) id: u64,
    #[serde(borrow)]
    pub(super) kind: SnapshotText<'a>,
    #[serde(borrow)]
    pub(super) blob: Option<SnapshotText<'a>>,
    #[serde(borrow)]
    pub(super) ranges: &'a RawValue,
    #[serde(borrow)]
    pub(super) details: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawEdge<'a> {
    #[serde(rename = "from")]
    _from: u64,
    #[serde(rename = "to")]
    _to: u64,
    #[serde(borrow)]
    pub(super) relation: SnapshotText<'a>,
    #[serde(rename = "status")]
    _status: EvidenceStatus,
    #[serde(borrow)]
    pub(super) reason: SnapshotText<'a>,
}

pub(super) struct SnapshotText<'a>(Cow<'a, str>);

impl SnapshotText<'_> {
    pub(super) fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    pub(super) fn into_string(self) -> String {
        self.0.into_owned()
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for SnapshotText<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SnapshotTextVisitor<'a>(PhantomData<&'a str>);

        impl<'de: 'a, 'a> Visitor<'de> for SnapshotTextVisitor<'a> {
            type Value = SnapshotText<'a>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bounded snapshot text")
            }

            fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() > MAX_SNAPSHOT_RECORD_BYTES {
                    return Err(E::custom("snapshot text exceeds its record bound"));
                }
                Ok(SnapshotText(Cow::Borrowed(value)))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut owned = String::new();
                if value.len() > MAX_SNAPSHOT_RECORD_BYTES {
                    return Err(E::custom("snapshot text exceeds its record bound"));
                }
                owned.try_reserve_exact(value.len()).map_err(E::custom)?;
                owned.push_str(value);
                Ok(SnapshotText(Cow::Owned(owned)))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() > MAX_SNAPSHOT_RECORD_BYTES {
                    return Err(E::custom("snapshot text exceeds its record bound"));
                }
                Ok(SnapshotText(Cow::Owned(value)))
            }
        }

        deserializer.deserialize_str(SnapshotTextVisitor(PhantomData))
    }
}

pub(super) struct RangeCount(pub(super) usize);

impl<'de> Deserialize<'de> for RangeCount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RangeCountVisitor;

        impl<'de> serde::de::Visitor<'de> for RangeCountVisitor {
            type Value = RangeCount;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded source-range array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut count = 0_usize;
                while sequence.next_element::<IgnoredAny>()?.is_some() {
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| serde::de::Error::custom("source-range count overflow"))?;
                    if count > MAX_NODE_RANGES {
                        return Err(serde::de::Error::custom("too many source ranges"));
                    }
                }
                Ok(RangeCount(count))
            }
        }

        deserializer.deserialize_seq(RangeCountVisitor)
    }
}

fn deserialize_aliases<'de, D>(deserializer: D) -> Result<Vec<SnapshotText<'de>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded::deserialize_vec::<D, SnapshotText<'de>, MAX_SOURCE_ALIASES>(deserializer)
}
