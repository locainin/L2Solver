//! Bounded, disk-backed recovery evidence sidecar for capture exports

use flate2::{Compression, write::GzEncoder};
use l2_workbench::evidence::{Case, write_published_case};
use serde::Serialize;
use serde_json::Value;
use std::{
    error::Error,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

pub(super) const SIDECAR_FILE_NAME: &str = "evidence.jsonl.gz";
pub(super) const ENCODING_VERSION: u32 = 3;
// Compression can change which whole Cases fit without changing the record format
pub(super) const COMPRESSION_POLICY_VERSION: u32 = 1;
// Level 3 reduces repeated evidence while retaining a fast streaming encoder
const CASE_COMPRESSION_LEVEL: u32 = 3;
const TEMP_FILE_PREFIX: &str = ".l2solver-evidence-case-";
const RECORD_BUFFER_CAPACITY: usize = 64 * 1024;
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
        let usage = write_case_spool(&spool_path, case, scope, self.coverage.selected_cases)?;
        let case_id = usage.case_id;
        let encoded_bytes = usage.encoded_bytes;
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

fn write_case_spool(
    path: &Path,
    case: &Case,
    scope: &Value,
    ordinal: u64,
) -> io::Result<l2_workbench::evidence::PublishedCaseUsage> {
    let file = File::options().write(true).create_new(true).open(path)?;
    let mut spool = BufWriter::with_capacity(RECORD_BUFFER_CAPACITY, file);
    let result = write_published_case(case, scope, ordinal, &mut spool).and_then(|usage| {
        spool.flush()?;
        if spool.get_ref().metadata()?.len() != usage.encoded_bytes {
            return Err(io::Error::other(
                "evidence spool length differs from its record count",
            ));
        }
        Ok(usage)
    });
    if result.is_err() {
        drop(spool);
        fs::remove_file(path)?;
    }
    result
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
    let mut encoder = GzEncoder::new(bounded_spool, Compression::new(CASE_COMPRESSION_LEVEL));
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
