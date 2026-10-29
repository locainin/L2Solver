//! Write one Case using bounded shared strings and compact graph references

use super::super::{Case, Source, SourceRange, record::RecordRef};
use super::{
    PublishedCaseUsage,
    canonical::{BlobRecords, CanonicalRecord, CountWriter, HASH_DOMAIN, Metadata, PLACEHOLDER},
    format::{Counts, HeaderRef, MAX_DICTIONARY_BYTES, MAX_STRINGS, VERSION},
    scratch::Scratch,
};
use crate::job::MemoryBudget;
use serde::{
    Serialize,
    ser::{SerializeSeq, SerializeTuple},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::{self, Write},
};

/// Write one normalized, independently complete Case and return its canonical identity
///
/// The selected ordinal is one-based and includes Cases omitted by the storage budget
/// The caller must keep or discard the entire stream as one unit
/// A supplied budget must be shared with the enclosing recovery job
/// A memory rejection remains available through `io::Error::get_ref`
///
/// # Errors
/// Returns an error for an invalid ordinal, invalid receipt JSON, or a failed write
pub fn write_published_case<W: Write>(
    case: &Case,
    scope: &Value,
    ordinal: u64,
    writer: W,
    budget: Option<&MemoryBudget>,
) -> io::Result<PublishedCaseUsage> {
    if ordinal == 0 {
        return Err(io::Error::other("evidence ordinal must be one-based"));
    }
    let scratch = Scratch::new(budget)?;
    let blobs = BlobRecords::new(case, &scratch)?;
    let canonical = CanonicalRecord {
        case_id: PLACEHOLDER,
        scope,
        metadata: Metadata::of(case),
        sources: case.sources(),
        blobs,
        nodes: case.nodes(),
        edges: case.edges(),
        limitations: case.limitations(),
    };
    let mut hash = HashWriter::new(ordinal);
    serde_json::to_writer(&mut hash, &canonical).map_err(|error| scratch.error(error))?;
    hash.write_all(b"\n")?;
    let case_id = format!("case-{:x}", hash.digest.finalize());

    let dictionary = build_dictionary(case, &scratch)?;
    let mut output = CountWriter::new(writer, u64::MAX);
    write_graph(
        &mut output,
        case,
        &canonical,
        ordinal,
        &case_id,
        &dictionary,
    )
    .map_err(|error| scratch.error(error))?;
    scratch.check()?;
    Ok(PublishedCaseUsage {
        case_id,
        encoded_bytes: output.written,
    })
}

fn build_dictionary<'a>(case: &'a Case, scratch: &Scratch) -> io::Result<Dictionary<'a>> {
    // Borrow existing strings so the dictionary does not duplicate graph contents
    let mut dictionary = Dictionary::default();
    // Keep graph kinds and relationship text ahead of less frequently repeated details
    for node in case.nodes() {
        dictionary.add(&node.kind, scratch)?;
    }
    for edge in case.edges() {
        dictionary.add(&edge.relation, scratch)?;
        dictionary.add(&edge.reason, scratch)?;
    }
    for node in case.nodes() {
        if let Value::Object(fields) = &node.details {
            for (key, value) in fields {
                dictionary.add(key, scratch)?;
                if let Value::String(text) = value {
                    // Digests are usually unique and would crowd useful shared descriptions out
                    if !(text.starts_with("sha256:")
                        || text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()))
                    {
                        dictionary.add(text, scratch)?;
                    }
                }
            }
        }
    }
    Ok(dictionary)
}

fn write_graph<W: Write>(
    output: &mut CountWriter<W>,
    case: &Case,
    canonical: &CanonicalRecord<'_>,
    ordinal: u64,
    case_id: &str,
    dictionary: &Dictionary<'_>,
) -> io::Result<()> {
    let counts = Counts {
        sources: case.sources().len(),
        blobs: case.blobs().len(),
        nodes: case.nodes().len(),
        edges: case.edges().len(),
        limitations: case.limitations().len(),
    };
    let header = HeaderRef {
        version: VERSION,
        case_id,
        ordinal,
        scope: canonical.scope,
        metadata: &canonical.metadata,
        strings: &dictionary.values,
        counts,
    };
    write_record(output, "header", &header)?;
    for source in case.sources() {
        write_record(output, "source", source)?;
    }
    for blob in canonical.blobs.iter() {
        write_record(output, "blob", &blob.normalized())?;
    }
    for node in case.nodes() {
        let ranges = Ranges {
            values: &node.ranges,
            sources: case.sources(),
        };
        // Case already indexes blob IDs in their stable serialization order
        let blob = node
            .blob
            .as_deref()
            .map(|id| {
                case.blob_position(id)
                    .ok_or_else(|| io::Error::other("missing node blob"))
            })
            .transpose()?;
        let record = (
            node.id,
            dictionary.reference(&node.kind),
            blob,
            ranges,
            DetailsRef::new(&node.details, dictionary, node.blob.as_deref()),
        );
        write_record(output, "node", &record)?;
    }
    for edge in case.edges() {
        let record = (
            edge.from,
            edge.to,
            dictionary.reference(&edge.relation),
            edge.status,
            dictionary.reference(&edge.reason),
        );
        write_record(output, "edge", &record)?;
    }
    for limitation in case.limitations() {
        write_record(output, "limitation", limitation)?;
    }
    output.write_all(b"{\"record\":\"end\"}\n")?;
    Ok(())
}

fn write_record<W: Write, T: Serialize + ?Sized>(
    output: &mut W,
    record: &'static str,
    value: &T,
) -> io::Result<()> {
    serde_json::to_writer(&mut *output, &RecordRef { record, value }).map_err(io::Error::other)?;
    output.write_all(b"\n")
}

#[derive(Default)]
struct Dictionary<'a> {
    indexes: HashMap<&'a str, usize>,
    values: Vec<&'a str>,
    bytes: usize,
}

impl<'a> Dictionary<'a> {
    fn add(&mut self, value: &'a str, scratch: &Scratch) -> io::Result<()> {
        if self.indexes.contains_key(value) || self.values.len() == MAX_STRINGS {
            return Ok(());
        }
        let Some(next) = self.bytes.checked_add(value.len()) else {
            return Ok(());
        };
        if next > MAX_DICTIONARY_BYTES {
            return Ok(());
        }
        // Budget pressure fails the Case so retention cannot depend on worker timing
        scratch.grow(256)?;
        self.indexes.try_reserve(1).map_err(io::Error::other)?;
        self.values.try_reserve(1).map_err(io::Error::other)?;
        self.indexes.insert(value, self.values.len());
        self.values.push(value);
        self.bytes = next;
        Ok(())
    }

    fn reference(&self, value: &'a str) -> TextRef<'a> {
        self.indexes
            .get(value)
            .copied()
            .map_or(TextRef::Inline(value), TextRef::Index)
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum TextRef<'a> {
    Index(usize),
    Inline(&'a str),
}

enum DetailsRef<'a> {
    Object(DetailEntries<'a>),
    Value(&'a Value),
}

impl Serialize for DetailsRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_tuple(2)?;
        match self {
            Self::Object(fields) => {
                sequence.serialize_element(&0_u8)?;
                sequence.serialize_element(fields)?;
            }
            Self::Value(value) => {
                sequence.serialize_element(&1_u8)?;
                sequence.serialize_element(value)?;
            }
        }
        sequence.end()
    }
}

impl<'a> DetailsRef<'a> {
    fn new(value: &'a Value, dictionary: &'a Dictionary<'a>, blob: Option<&'a str>) -> Self {
        match value {
            Value::Object(fields) => Self::Object(DetailEntries {
                fields,
                dictionary,
                digest: blob.and_then(|id| id.strip_prefix("sha256:")),
            }),
            _ => Self::Value(value),
        }
    }
}

struct DetailEntries<'a> {
    fields: &'a serde_json::Map<String, Value>,
    dictionary: &'a Dictionary<'a>,
    digest: Option<&'a str>,
}

impl Serialize for DetailEntries<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.fields.len()))?;
        for (key, value) in self.fields {
            let key = self.dictionary.reference(key);
            match value {
                Value::String(text) if self.digest == Some(text.as_str()) => {
                    sequence.serialize_element(&(key, 2_u8, Option::<u8>::None))?;
                }
                Value::String(text) => {
                    sequence.serialize_element(&(key, 0_u8, self.dictionary.reference(text)))?;
                }
                _ => sequence.serialize_element(&(key, 1_u8, value))?,
            }
        }
        sequence.end()
    }
}

struct Ranges<'a> {
    values: &'a [SourceRange],
    sources: &'a [Source],
}

impl Serialize for Ranges<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.values.len()))?;
        for range in self.values {
            let index = self
                .sources
                .iter()
                .position(|source| source.id == range.source)
                .ok_or_else(|| serde::ser::Error::custom("missing evidence source"))?;
            sequence.serialize_element(&(index, range.packet, range.offset, range.length))?;
        }
        sequence.end()
    }
}

struct HashWriter {
    digest: Sha256,
}
impl HashWriter {
    fn new(ordinal: u64) -> Self {
        let mut digest = Sha256::new();
        // The ordinal preserves identity when equal Cases are selected more than once
        digest.update(HASH_DOMAIN);
        digest.update(ordinal.to_be_bytes());
        Self { digest }
    }
}
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.digest.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
