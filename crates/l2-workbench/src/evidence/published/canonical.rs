//! Canonical version-two records shared by identity and publication

use super::super::{Blob, Case, Edge, Node, Source};
use serde::{
    Serialize,
    ser::{SerializeSeq, SerializeStruct},
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::{self, Write},
};

pub(super) const HASH_DOMAIN: &[u8] = b"l2solver-export-case-v2\0";
pub(super) const PLACEHOLDER: &str = concat!(
    "case-", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000",
    "00000000"
);

#[derive(Serialize)]
pub(super) struct Metadata {
    pub(super) schema_version: u32,
    pub(super) collection_complete: bool,
    pub(super) blob_byte_limit: Option<usize>,
}

impl Metadata {
    pub(super) const fn of(case: &Case) -> Self {
        Self {
            schema_version: case.schema_version(),
            collection_complete: case.collection_complete(),
            blob_byte_limit: case.blob_byte_limit(),
        }
    }
}

/// Field order defines the existing content-derived Case ID
#[derive(Serialize)]
pub(super) struct CanonicalRecord<'a> {
    pub(super) case_id: &'a str,
    pub(super) scope: &'a Value,
    pub(super) metadata: Metadata,
    pub(super) sources: &'a [Source],
    pub(super) blobs: BlobRecords<'a>,
    pub(super) nodes: &'a [Node],
    pub(super) edges: &'a [Edge],
    pub(super) limitations: &'a [String],
}

pub(super) struct BlobRecords<'a> {
    blobs: &'a [Blob],
    inline_ids: BTreeMap<&'a str, bool>,
}

impl<'a> BlobRecords<'a> {
    pub(super) fn new(case: &'a Case) -> Self {
        let mut inline_ids = BTreeMap::new();
        for node in case.nodes() {
            if node.details.get("representation").and_then(Value::as_str) == Some("json_blob")
                && let Some(id) = node.blob.as_deref()
            {
                *inline_ids.entry(id).or_insert(false) |= node.kind == "record_parse_receipt";
            }
        }
        Self {
            blobs: case.blobs(),
            inline_ids,
        }
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = BlobRecord<'_>> {
        self.blobs.iter().map(|blob| {
            let schema = self.inline_ids.get(blob.id.as_str());
            BlobRecord {
                blob,
                inline: schema.is_some(),
                schema: schema.copied().unwrap_or(false),
            }
        })
    }
}

impl Serialize for BlobRecords<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.blobs.len()))?;
        for blob in self.iter() {
            seq.serialize_element(&blob)?;
        }
        seq.end()
    }
}

pub(super) struct BlobRecord<'a> {
    blob: &'a Blob,
    inline: bool,
    schema: bool,
}

impl BlobRecord<'_> {
    pub(super) const fn normalized(&self) -> NormalizedBlob<'_> {
        NormalizedBlob(self)
    }

    fn serialize_with<S: serde::Serializer>(
        &self,
        serializer: S,
        normalized: bool,
    ) -> Result<S::Ok, S::Error> {
        let mut record =
            serializer.serialize_struct("BlobRecord", if self.inline { 3 } else { 2 })?;
        record.serialize_field("id", &self.blob.id)?;
        record.serialize_field("byte_length", &self.blob.bytes.len())?;
        if self.inline && self.schema && normalized && super::schema::within_depth(&self.blob.bytes)
        {
            record.serialize_field(
                "schema_payload",
                &super::schema::SchemaJson(&self.blob.bytes),
            )?;
        } else if self.inline {
            record.serialize_field(
                "inline_payload",
                &super::canonical_json::CanonicalJson(&self.blob.bytes),
            )?;
        }
        record.end()
    }
}

impl Serialize for BlobRecord<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.serialize_with(serializer, false)
    }
}

pub(super) struct NormalizedBlob<'a>(&'a BlobRecord<'a>);

impl Serialize for NormalizedBlob<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize_with(serializer, true)
    }
}

pub(super) struct CountWriter<W> {
    pub(super) inner: W,
    pub(super) written: u64,
    maximum: u64,
}

impl<W> CountWriter<W> {
    pub(super) const fn new(inner: W, maximum: u64) -> Self {
        Self {
            inner,
            written: 0,
            maximum,
        }
    }
}

impl<W: Write> Write for CountWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let len = u64::try_from(bytes.len()).map_err(io::Error::other)?;
        let next = self
            .written
            .checked_add(len)
            .ok_or_else(|| io::Error::other("evidence byte count overflow"))?;
        if next > self.maximum {
            return Err(io::Error::other("evidence stream exceeds its byte limit"));
        }
        let written = self.inner.write(bytes)?;
        self.written += u64::try_from(written).map_err(io::Error::other)?;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
