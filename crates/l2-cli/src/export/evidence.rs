//! Bounded, disk-backed recovery evidence sidecar for capture exports

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
    io::{self, Write},
    path::{Path, PathBuf},
};

pub(super) const SIDECAR_FILE_NAME: &str = "evidence.jsonl";
const TEMP_FILE_PREFIX: &str = ".l2solver-evidence-case-";

/// Exact aggregate selection, retention, omission, and byte totals for Case evidence
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(super) struct EvidenceCoverage {
    pub(super) selected_cases: u64,
    pub(super) retained_cases: u64,
    pub(super) omitted_cases: u64,
    pub(super) retained_bytes: u64,
    pub(super) omitted_bytes: u64,
    pub(super) budget_bytes: u64,
}

/// Stable sidecar identity and whole-Case retention outcome
pub(super) struct EvidenceRecordResult {
    pub(super) case_id: String,
    pub(super) retained: bool,
    pub(super) encoded_bytes: u64,
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
        let file = File::options().write(true).create_new(true).open(&path)?;
        Ok(Self {
            staging: staging.to_owned(),
            file,
            coverage: EvidenceCoverage {
                budget_bytes,
                ..EvidenceCoverage::default()
            },
        })
    }

    pub(super) fn record_case(
        &mut self,
        case: &Case,
        scope: &Value,
    ) -> Result<EvidenceRecordResult, Box<dyn Error>> {
        self.coverage.selected_cases = evidence_add(self.coverage.selected_cases, 1)?;
        let case_id = stable_case_id(scope, case, self.coverage.selected_cases)?;
        let spool_path = self.staging.join(format!(
            "{TEMP_FILE_PREFIX}{}.jsonl",
            self.coverage.selected_cases
        ));
        let mut spool = File::options()
            .write(true)
            .create_new(true)
            .open(&spool_path)?;
        let record = CaseRecord::new(&case_id, scope, case);
        let write_result = serde_json::to_writer(&mut spool, &record)
            .and_then(|()| spool.write_all(b"\n").map_err(serde_json::Error::io));
        if let Err(error) = write_result {
            drop(spool);
            fs::remove_file(&spool_path)?;
            return Err(error.into());
        }
        spool.flush()?;
        let encoded_bytes = spool.metadata()?.len();
        let retained_end = self
            .coverage
            .retained_bytes
            .checked_add(encoded_bytes)
            .ok_or("evidence retained byte count overflow")?;
        let retained = retained_end <= self.coverage.budget_bytes;
        if retained {
            let mut input = File::open(&spool_path)?;
            io::copy(&mut input, &mut self.file)?;
            self.coverage.retained_cases = evidence_add(self.coverage.retained_cases, 1)?;
            self.coverage.retained_bytes = retained_end;
        } else {
            self.coverage.omitted_cases = evidence_add(self.coverage.omitted_cases, 1)?;
            self.coverage.omitted_bytes = self
                .coverage
                .omitted_bytes
                .checked_add(encoded_bytes)
                .ok_or("evidence omitted byte count overflow")?;
        }
        drop(spool);
        fs::remove_file(spool_path)?;
        Ok(EvidenceRecordResult {
            case_id,
            retained,
            encoded_bytes,
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

fn stable_case_id(scope: &Value, case: &Case, ordinal: u64) -> Result<String, Box<dyn Error>> {
    let mut writer = HashingWriter(Sha256::new());
    writer.write_all(b"l2solver-export-case-v1\0")?;
    serde_json::to_writer(&mut writer, scope)?;
    writer.write_all(b"\0case\0")?;
    serde_json::to_writer(&mut writer, case)?;
    writer.write_all(&ordinal.to_be_bytes())?;
    Ok(format!("case-{:x}", writer.0.finalize()))
}

struct HashingWriter(Sha256);

impl Write for HashingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

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
