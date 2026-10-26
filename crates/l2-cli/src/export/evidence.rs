//! Bounded, disk-backed recovery evidence sidecar for capture exports

use flate2::{Compression, write::GzEncoder};
use l2_workbench::evidence::{Blob, Case, Edge, Node, Source};
use serde::{
    Serialize,
    ser::{SerializeSeq, SerializeStruct},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    error::Error,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub(super) const SIDECAR_FILE_NAME: &str = "evidence.jsonl.gz";
pub(super) const ENCODING_VERSION: u32 = 2;
const TEMP_FILE_PREFIX: &str = ".l2solver-evidence-case-";
const RECORD_BUFFER_CAPACITY: usize = 64 * 1024;
// The serialized first field prefix `{"case_id":"` occupies twelve bytes
const CASE_ID_VALUE_OFFSET: u64 = 12;
// Equal width lets the final digest replace this field without serializing the record again
const CASE_ID_PLACEHOLDER: &str = concat!(
    "case-", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000",
    "00000000",
);
const CASE_ID_HASH_DOMAIN: &[u8] = b"l2solver-export-case-v2\0";

/// Exact aggregate selection, retention, omission, and byte totals for Case evidence
#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct EvidenceCoverage {
    pub(super) encoding_version: u32,
    pub(super) selected_cases: u64,
    pub(super) retained_cases: u64,
    pub(super) omitted_cases: u64,
    /// Physical gzip bytes retained within the aggregate budget
    pub(super) retained_bytes: u64,
    /// Physical gzip bytes omitted because the aggregate budget was exceeded
    pub(super) omitted_bytes: u64,
    /// Logical JSONL bytes represented by retained gzip members
    pub(super) raw_retained_bytes: u64,
    /// Logical JSONL bytes represented by omitted gzip members
    pub(super) raw_omitted_bytes: u64,
    /// Maximum physical gzip bytes retained
    pub(super) budget_bytes: u64,
}

impl Default for EvidenceCoverage {
    fn default() -> Self {
        Self {
            encoding_version: ENCODING_VERSION,
            selected_cases: 0,
            retained_cases: 0,
            omitted_cases: 0,
            retained_bytes: 0,
            omitted_bytes: 0,
            raw_retained_bytes: 0,
            raw_omitted_bytes: 0,
            budget_bytes: 0,
        }
    }
}

/// Stable sidecar identity and whole-Case retention outcome
pub(super) struct EvidenceRecordResult {
    pub(super) case_id: String,
    pub(super) retained: bool,
    /// Logical uncompressed JSONL bytes
    pub(super) encoded_bytes: u64,
    /// Physical bytes in this Case's standalone gzip member
    pub(super) compressed_bytes: u64,
}

/// Append complete Case records only after their entire encoding fits the aggregate budget
pub(super) struct EvidenceSidecar {
    staging: PathBuf,
    file: File,
    coverage: EvidenceCoverage,
}

impl EvidenceSidecar {
    pub(super) fn new(staging: &Path, budget_bytes: u64) -> io::Result<Self> {
        let path = staging.join(SIDECAR_FILE_NAME);
        let mut file = File::options().write(true).create_new(true).open(&path)?;
        let empty_member = GzEncoder::new(Vec::new(), Compression::fast()).finish()?;
        let empty_member_bytes = u64::try_from(empty_member.len())
            .map_err(|_| io::Error::other("empty gzip member length exceeds u64"))?;
        let mut coverage = EvidenceCoverage {
            budget_bytes,
            ..EvidenceCoverage::default()
        };
        if empty_member_bytes <= budget_bytes {
            file.write_all(&empty_member)?;
            coverage.retained_bytes = empty_member_bytes;
        }
        Ok(Self {
            staging: staging.to_owned(),
            file,
            coverage,
        })
    }

    pub(super) fn record_case(
        &mut self,
        case: &Case,
        scope: &Value,
    ) -> Result<EvidenceRecordResult, Box<dyn Error>> {
        self.coverage.selected_cases = evidence_add(self.coverage.selected_cases, 1)?;
        let spool_path = self.staging.join(format!(
            "{TEMP_FILE_PREFIX}{}.jsonl",
            self.coverage.selected_cases
        ));
        let spool_file = File::options()
            .write(true)
            .create_new(true)
            .open(&spool_path)?;
        let mut spool = BufWriter::with_capacity(
            RECORD_BUFFER_CAPACITY,
            HashingWriter::new(spool_file, self.coverage.selected_cases),
        );
        let record = CaseRecord::new(CASE_ID_PLACEHOLDER, scope, case);
        let write_result = serde_json::to_writer(&mut spool, &record)
            .and_then(|()| spool.write_all(b"\n").map_err(serde_json::Error::io))
            .and_then(|()| spool.flush().map_err(serde_json::Error::io));
        if let Err(error) = write_result {
            drop(spool);
            fs::remove_file(&spool_path)?;
            return Err(error.into());
        }

        // V2 hashes the JSONL record with a zero ID and the one-based ordinal prefix
        // Persisted blob IDs already carry SHA-256 payload digests
        let case_id = spool.get_mut().finish_case_id()?;
        spool.seek(SeekFrom::Start(CASE_ID_VALUE_OFFSET))?;
        spool.write_all(case_id.as_bytes())?;
        spool.flush()?;
        let encoded_bytes = spool.get_ref().inner.metadata()?.len();
        let compressed_spool_path = self.staging.join(format!(
            "{TEMP_FILE_PREFIX}{}.member.gz",
            self.coverage.selected_cases
        ));
        let available_bytes = self
            .coverage
            .budget_bytes
            .saturating_sub(self.coverage.retained_bytes);
        let compressed = compress_spool(&spool_path, &compressed_spool_path, available_bytes)?;
        let retained_end = self
            .coverage
            .retained_bytes
            .checked_add(compressed.total_bytes)
            .ok_or("evidence retained byte count overflow")?;
        let retained = retained_end <= self.coverage.budget_bytes;
        if retained {
            if compressed.stored_bytes != compressed.total_bytes {
                return Err(io::Error::other(
                    "gzip spool is incomplete despite fitting the budget",
                )
                .into());
            }
            let mut input = File::open(&compressed_spool_path)?;
            io::copy(&mut input, &mut self.file)?;
            self.coverage.retained_cases = evidence_add(self.coverage.retained_cases, 1)?;
            self.coverage.retained_bytes = retained_end;
            self.coverage.raw_retained_bytes = self
                .coverage
                .raw_retained_bytes
                .checked_add(encoded_bytes)
                .ok_or("raw evidence retained byte count overflow")?;
        } else {
            self.coverage.omitted_cases = evidence_add(self.coverage.omitted_cases, 1)?;
            self.coverage.omitted_bytes = self
                .coverage
                .omitted_bytes
                .checked_add(compressed.total_bytes)
                .ok_or("evidence omitted byte count overflow")?;
            self.coverage.raw_omitted_bytes = self
                .coverage
                .raw_omitted_bytes
                .checked_add(encoded_bytes)
                .ok_or("raw evidence omitted byte count overflow")?;
        }
        drop(spool);
        fs::remove_file(spool_path)?;
        fs::remove_file(compressed_spool_path)?;
        Ok(EvidenceRecordResult {
            case_id,
            retained,
            encoded_bytes,
            compressed_bytes: compressed.total_bytes,
        })
    }

    pub(super) const fn coverage(&self) -> EvidenceCoverage {
        self.coverage
    }

    pub(super) fn finish(&mut self) -> io::Result<()> {
        self.file.flush()?;
        self.file.sync_all()
    }
}

fn evidence_add(value: u64, increment: u64) -> Result<u64, Box<dyn Error>> {
    value
        .checked_add(increment)
        .ok_or_else(|| "evidence coverage count overflow".into())
}

struct CompressedSpool {
    total_bytes: u64,
    stored_bytes: u64,
}

fn compress_spool(
    raw_path: &Path,
    compressed_path: &Path,
    maximum_stored_bytes: u64,
) -> io::Result<CompressedSpool> {
    let raw_file = File::open(raw_path)?;
    let mut raw = BufReader::with_capacity(RECORD_BUFFER_CAPACITY, raw_file);
    let compressed_file = File::options()
        .write(true)
        .create_new(true)
        .open(compressed_path)?;
    let bounded_spool = BoundedSpoolWriter::new(compressed_file, maximum_stored_bytes);
    let mut encoder = GzEncoder::new(bounded_spool, Compression::fast());
    io::copy(&mut raw, &mut encoder)?;
    let mut bounded_spool = encoder.finish()?;
    bounded_spool.flush()?;
    Ok(CompressedSpool {
        total_bytes: bounded_spool.total_bytes,
        stored_bytes: bounded_spool.stored_bytes,
    })
}

struct BoundedSpoolWriter {
    writer: BufWriter<File>,
    maximum_stored_bytes: u64,
    total_bytes: u64,
    stored_bytes: u64,
    truncated: bool,
}

impl BoundedSpoolWriter {
    fn new(file: File, maximum_stored_bytes: u64) -> Self {
        Self {
            writer: BufWriter::with_capacity(RECORD_BUFFER_CAPACITY, file),
            maximum_stored_bytes,
            total_bytes: 0,
            stored_bytes: 0,
            truncated: false,
        }
    }
}

impl Write for BoundedSpoolWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = u64::try_from(bytes.len())
            .map_err(|_| io::Error::other("compressed chunk length exceeds u64"))?;
        let next_total = self
            .total_bytes
            .checked_add(length)
            .ok_or_else(|| io::Error::other("compressed member length overflow"))?;

        if !self.truncated {
            let available = self.maximum_stored_bytes.saturating_sub(self.stored_bytes);
            if length <= available {
                self.writer.write_all(bytes)?;
                self.stored_bytes = self
                    .stored_bytes
                    .checked_add(length)
                    .ok_or_else(|| io::Error::other("compressed spool length overflow"))?;
            } else {
                // Discard this and later chunks once the physical budget cannot hold the member
                self.truncated = true;
            }
        }

        self.total_bytes = next_total;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

struct HashingWriter<W> {
    inner: W,
    digest: Option<Sha256>,
}

impl<W> HashingWriter<W> {
    fn new(inner: W, ordinal: u64) -> Self {
        let mut digest = Sha256::new();
        // The fixed-size ordinal prefix keeps otherwise identical source Cases distinct
        digest.update(CASE_ID_HASH_DOMAIN);
        digest.update(ordinal.to_be_bytes());
        Self {
            inner,
            digest: Some(digest),
        }
    }

    fn finish_case_id(&mut self) -> io::Result<String> {
        let digest = self
            .digest
            .take()
            .ok_or_else(|| io::Error::other("case digest was already finalized"))?;
        Ok(format!("case-{:x}", digest.finalize()))
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write_all(bytes)?;
        if let Some(digest) = &mut self.digest {
            digest.update(bytes);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Seek> Seek for HashingWriter<W> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}

/// Field order is part of the v2 case identity encoding
#[derive(Serialize)]
struct CaseRecord<'a> {
    case_id: &'a str,
    scope: &'a Value,
    metadata: CaseMetadata,
    sources: &'a [Source],
    blobs: BlobRecords<'a>,
    nodes: &'a [Node],
    edges: &'a [Edge],
    limitations: &'a [String],
}

impl<'a> CaseRecord<'a> {
    fn new(case_id: &'a str, scope: &'a Value, case: &'a Case) -> Self {
        let inline_blob_ids = case
            .nodes()
            .iter()
            .filter(|node| {
                node.details.get("representation").and_then(Value::as_str) == Some("json_blob")
            })
            .filter_map(|node| node.blob.as_deref())
            .collect();
        Self {
            case_id,
            scope,
            metadata: CaseMetadata {
                schema_version: case.schema_version(),
                collection_complete: case.collection_complete(),
                blob_byte_limit: case.blob_byte_limit(),
            },
            sources: case.sources(),
            blobs: BlobRecords {
                blobs: case.blobs(),
                inline_blob_ids,
            },
            nodes: case.nodes(),
            edges: case.edges(),
            limitations: case.limitations(),
        }
    }
}

#[derive(Serialize)]
struct CaseMetadata {
    schema_version: u32,
    collection_complete: bool,
    blob_byte_limit: Option<usize>,
}

struct BlobRecords<'a> {
    blobs: &'a [Blob],
    inline_blob_ids: BTreeSet<&'a str>,
}

impl Serialize for BlobRecords<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.blobs.len()))?;
        for blob in self.blobs {
            sequence.serialize_element(&BlobRecord {
                blob,
                inline: self.inline_blob_ids.contains(blob.id.as_str()),
            })?;
        }
        sequence.end()
    }
}

struct BlobRecord<'a> {
    blob: &'a Blob,
    inline: bool,
}

impl Serialize for BlobRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut record = serializer.serialize_struct("BlobRecord", 3)?;
        record.serialize_field("id", &self.blob.id)?;
        record.serialize_field("byte_length", &self.blob.bytes.len())?;
        if self.inline {
            record.serialize_field("inline_payload", &InlineJson(&self.blob.bytes))?;
        }
        record.end()
    }
}

struct InlineJson<'a>(&'a [u8]);

impl Serialize for InlineJson<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value: Value = serde_json::from_slice(self.0).map_err(serde::ser::Error::custom)?;
        value.serialize(serializer)
    }
}
