//! Disk-backed artifact files, exact-byte indexes, and streamed provenance

use l2_workbench::{
    evidence::{Node, SourceRange},
    job::{MemoryBudget, MemoryClass, MemoryLease, RecoveryArtifactSample},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const INDEX_DIRECTORY: &str = ".l2solver-artifact-index";
// One normal export keeps these aggregate bounds; callers pass the resolved policy explicitly
const MAXIMUM_ARTIFACTS: u64 = 16_384;
const MAXIMUM_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAXIMUM_PROVENANCE_ENTRIES: u64 = 65_536;
const MAXIMUM_PROVENANCE_BYTES: u64 = 128 * 1024 * 1024;
const MAXIMUM_EVIDENCE_BYTES: u64 = 512 * 1024 * 1024;

/// Explicit aggregate limits for one published export
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(super) struct ArtifactLimits {
    pub(super) artifacts: u64,
    pub(super) artifact_bytes: u64,
    pub(super) provenance_entries: u64,
    pub(super) provenance_bytes: u64,
    pub(super) evidence_bytes: u64,
}

impl Default for ArtifactLimits {
    fn default() -> Self {
        Self {
            artifacts: MAXIMUM_ARTIFACTS,
            artifact_bytes: MAXIMUM_ARTIFACT_BYTES,
            provenance_entries: MAXIMUM_PROVENANCE_ENTRIES,
            provenance_bytes: MAXIMUM_PROVENANCE_BYTES,
            evidence_bytes: MAXIMUM_EVIDENCE_BYTES,
        }
    }
}

/// Aggregate counts for selected, retained, and explicitly omitted artifact references
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(super) struct ArtifactCoverage {
    pub(super) references_selected: u64,
    pub(super) references_retained: u64,
    pub(super) references_omitted: u64,
    pub(super) omission_details_retained: u64,
    pub(super) omission_details_not_retained: u64,
    pub(super) omission_detail_bytes_retained: u64,
    pub(super) unidentified_omissions: u64,
    pub(super) unique_artifacts_retained: u64,
    pub(super) artifact_bytes_retained: u64,
    pub(super) provenance_bytes_retained: u64,
    pub(super) duplicate_byte_references_grouped: u64,
    pub(super) candidate_bytes_omitted: u64,
    pub(super) count_limit_omissions: u64,
    pub(super) artifact_byte_limit_omissions: u64,
    pub(super) provenance_count_limit_omissions: u64,
    pub(super) provenance_byte_limit_omissions: u64,
    pub(super) unreadable_object_omissions: u64,
    pub(super) same_origin_references_suppressed: u64,
    pub(super) native_http_body_references_retained: u64,
    pub(super) native_ftp_candidate_references_retained: u64,
    pub(super) recovered_artifact_references_retained: u64,
    pub(super) tshark_object_references_retained: u64,
}

/// Source context retained for one artifact reference
#[derive(Deserialize, Serialize)]
pub(super) struct ArtifactProvenance {
    pub(super) category: String,
    pub(super) case_id: Option<String>,
    pub(super) selected_node_id: Option<u64>,
    pub(super) validation_node_id: Option<u64>,
    pub(super) extension_node_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) flow: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) supporting_flows: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) cohort_scope: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) node: Option<Node>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) selection: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) signature_candidates: Vec<Node>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) source_ranges: Vec<SourceRange>,
    #[serde(skip)]
    pub(super) canonical_origin: serde_json::Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AddOutcome {
    Stored,
    Duplicate,
    SameOrigin,
    Omitted(OmissionReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OmissionReason {
    ArtifactCount,
    ArtifactBytes,
    ProvenanceCount,
    ProvenanceBytes,
    UnreadableObject,
}

impl OmissionReason {
    const fn manifest_name(self) -> &'static str {
        match self {
            Self::ArtifactCount => "artifact_count_limit",
            Self::ArtifactBytes => "artifact_byte_limit",
            Self::ProvenanceCount => "provenance_count_limit",
            Self::ProvenanceBytes => "provenance_byte_limit",
            Self::UnreadableObject => "unreadable_object",
        }
    }
}

#[derive(Deserialize, Serialize)]
struct IndexedArtifact {
    entry_id: u64,
    file_name: String,
    bucket_name: String,
    byte_length: u64,
}

#[derive(Deserialize, Serialize)]
struct StoredProvenanceRecord {
    canonical_origin: Vec<u8>,
    provenance: ArtifactProvenance,
}

#[derive(Serialize)]
struct StoredProvenanceRecordRef<'a> {
    canonical_origin: &'a [u8],
    provenance: &'a ArtifactProvenance,
}

#[derive(Serialize)]
struct OmittedArtifactDetailRef<'a> {
    reason: &'static str,
    bytes: u64,
    category: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    case_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_node_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validation_node_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extension_node_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    archive_parent_node_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    archive_path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_file_name: Option<&'a str>,
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    maximum: usize,
    failure: Option<Box<dyn Error>>,
    // The encoded bytes drop before their shared charge
    memory: Option<MemoryLease>,
}

impl BoundedBuffer {
    fn new(maximum: usize, budget: Option<&MemoryBudget>) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            bytes: Vec::new(),
            maximum,
            failure: None,
            memory: budget
                .map(|budget| budget.try_reserve(MemoryClass::Publication, 0))
                .transpose()?,
        })
    }

    fn encode<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Box<dyn Error>> {
        if let Err(error) = serde_json::to_writer(&mut *self, value) {
            return Err(self.failure.take().unwrap_or_else(|| Box::new(error)));
        }
        Ok(())
    }
}

impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(new_length) = self.bytes.len().checked_add(bytes.len()) else {
            return Err(io::Error::other("omission detail size overflow"));
        };
        if new_length > self.maximum {
            return Err(io::Error::other("omission detail exceeds its byte limit"));
        }
        if let Err(error) = crate::retained_memory::grow_vec_optional(
            &mut self.bytes,
            &mut self.memory,
            bytes.len(),
        ) {
            self.failure = Some(error);
            return Err(io::Error::other("publication buffer admission failed"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Stage exact bytes immediately and keep only a disk index and bounded counters in memory
pub(super) struct ArtifactCollection {
    staging: PathBuf,
    index: PathBuf,
    ordered_records_path: PathBuf,
    ordered_records: Option<File>,
    omitted_records_path: PathBuf,
    omitted_records: Option<File>,
    limits: ArtifactLimits,
    coverage: ArtifactCoverage,
}

impl ArtifactCollection {
    pub(super) fn new(staging: &Path, limits: ArtifactLimits) -> Result<Self, Box<dyn Error>> {
        if limits.artifacts == 0
            || limits.artifact_bytes == 0
            || limits.provenance_entries == 0
            || limits.provenance_bytes == 0
        {
            return Err(invalid("artifact export limits must be positive").into());
        }
        let index = staging.join(INDEX_DIRECTORY);
        fs::create_dir(&index)?;
        let ordered_records_path = index.join("ordered-artifacts.jsonl");
        let ordered_records = File::options()
            .write(true)
            .create_new(true)
            .open(&ordered_records_path)?;
        let omitted_records_path = index.join("omitted-artifacts.jsonl");
        let omitted_records = File::options()
            .write(true)
            .create_new(true)
            .open(&omitted_records_path)?;
        Ok(Self {
            staging: staging.to_owned(),
            index,
            ordered_records_path,
            ordered_records: Some(ordered_records),
            omitted_records_path,
            omitted_records: Some(omitted_records),
            limits,
            coverage: ArtifactCoverage::default(),
        })
    }

    pub(super) fn add_bytes(
        &mut self,
        bytes: &[u8],
        suggested_name: &str,
        provenance: &ArtifactProvenance,
        memory: Option<&MemoryBudget>,
    ) -> Result<AddOutcome, Box<dyn Error>> {
        let digest = format!("{:x}", Sha256::digest(bytes));
        self.add_bytes_with_digest(bytes, &digest, suggested_name, provenance, memory)
    }

    pub(super) fn add_bytes_with_digest(
        &mut self,
        bytes: &[u8],
        digest: &str,
        suggested_name: &str,
        provenance: &ArtifactProvenance,
        memory: Option<&MemoryBudget>,
    ) -> Result<AddOutcome, Box<dyn Error>> {
        if !valid_sha256(digest) {
            return Err(invalid("artifact digest is malformed").into());
        }
        self.coverage.references_selected = add_counter(self.coverage.references_selected, 1)?;
        let length = u64::try_from(bytes.len())?;
        let bucket = self.bucket_path(length, digest);
        if let Some(record) = self.find_bytes_duplicate(&bucket, bytes)? {
            return self.record_duplicate(&bucket, &record, provenance, memory);
        }
        self.store_bytes(bytes, length, suggested_name, provenance, &bucket, memory)
    }

    /// Hash and stage one open `TShark` object without buffering it in memory
    pub(super) fn add_open_file(
        &mut self,
        source: &mut File,
        suggested_name: &str,
        provenance: &ArtifactProvenance,
        memory: Option<&MemoryBudget>,
    ) -> Result<AddOutcome, Box<dyn Error>> {
        self.coverage.references_selected = add_counter(self.coverage.references_selected, 1)?;
        let metadata = source.metadata()?;
        if !metadata.file_type().is_file() {
            self.omit_reference_with_provenance(
                OmissionReason::UnreadableObject,
                metadata.len(),
                provenance,
                memory,
            )?;
            return Ok(AddOutcome::Omitted(OmissionReason::UnreadableObject));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                self.omit_reference_with_provenance(
                    OmissionReason::UnreadableObject,
                    metadata.len(),
                    provenance,
                    memory,
                )?;
                return Ok(AddOutcome::Omitted(OmissionReason::UnreadableObject));
            }
        }
        let Ok((byte_length, digest)) = digest_open_file(source) else {
            self.omit_reference_with_provenance(
                OmissionReason::UnreadableObject,
                metadata.len(),
                provenance,
                memory,
            )?;
            return Ok(AddOutcome::Omitted(OmissionReason::UnreadableObject));
        };
        if byte_length != metadata.len() {
            self.omit_reference_with_provenance(
                OmissionReason::UnreadableObject,
                metadata.len(),
                provenance,
                memory,
            )?;
            return Ok(AddOutcome::Omitted(OmissionReason::UnreadableObject));
        }
        let bucket = self.bucket_path(byte_length, &digest);
        if let Some(record) = self.find_open_file_duplicate(&bucket, source)? {
            return self.record_duplicate(&bucket, &record, provenance, memory);
        }
        self.store_open_file(
            source,
            (byte_length, &digest),
            suggested_name,
            provenance,
            &bucket,
            memory,
        )
    }

    pub(super) fn record_omission(
        &mut self,
        reason: OmissionReason,
        candidate_bytes: u64,
    ) -> Result<(), Box<dyn Error>> {
        self.record_omissions(reason, 1, candidate_bytes)
    }

    pub(super) fn record_omissions(
        &mut self,
        reason: OmissionReason,
        count: u64,
        candidate_bytes: u64,
    ) -> Result<(), Box<dyn Error>> {
        self.coverage.references_selected = add_counter(self.coverage.references_selected, count)?;
        self.omit_references(reason, count, candidate_bytes)?;
        self.coverage.unidentified_omissions =
            add_counter(self.coverage.unidentified_omissions, count)?;
        Ok(())
    }

    fn omit_references(
        &mut self,
        reason: OmissionReason,
        count: u64,
        candidate_bytes: u64,
    ) -> Result<(), Box<dyn Error>> {
        self.coverage.references_omitted = add_counter(self.coverage.references_omitted, count)?;
        self.coverage.candidate_bytes_omitted =
            add_counter(self.coverage.candidate_bytes_omitted, candidate_bytes)?;
        let counter = match reason {
            OmissionReason::ArtifactCount => &mut self.coverage.count_limit_omissions,
            OmissionReason::ArtifactBytes => &mut self.coverage.artifact_byte_limit_omissions,
            OmissionReason::ProvenanceCount => &mut self.coverage.provenance_count_limit_omissions,
            OmissionReason::ProvenanceBytes => &mut self.coverage.provenance_byte_limit_omissions,
            OmissionReason::UnreadableObject => &mut self.coverage.unreadable_object_omissions,
        };
        *counter = add_counter(*counter, count)?;
        Ok(())
    }

    pub(super) const fn coverage(&self) -> ArtifactCoverage {
        self.coverage
    }

    pub(super) fn first_artifact_sample(
        &self,
    ) -> Result<Option<RecoveryArtifactSample>, Box<dyn Error>> {
        // Read one bounded index row rather than loading the artifact inventory
        const MAX_INDEX_ROW_BYTES: u64 = 4_096;
        let file = File::open(&self.ordered_records_path)?;
        let mut reader = BufReader::new(file).take(MAX_INDEX_ROW_BYTES + 1);
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        if u64::try_from(line.len())? > MAX_INDEX_ROW_BYTES || !line.ends_with('\n') {
            return Err(invalid("artifact index row is incomplete or too large").into());
        }
        let record: IndexedArtifact = serde_json::from_str(line.trim_end())?;
        let sha256 = record
            .bucket_name
            .split_once('-')
            .and_then(|(_, digest)| l2_workbench::parse_sha256_digest(digest))
            .ok_or_else(|| invalid("artifact index has no valid content digest"))?;
        Ok(Some(RecoveryArtifactSample {
            sha256,
            byte_length: record.byte_length,
        }))
    }

    pub(super) fn file_names(
        &self,
    ) -> Result<std::collections::HashSet<std::ffi::OsString>, Box<dyn Error>> {
        let mut names = std::collections::HashSet::new();
        for record in self.ordered_records()? {
            names.insert(record.file_name.into());
        }
        Ok(names)
    }

    pub(super) fn visit_artifact_origins(
        &mut self,
        mut visitor: impl FnMut(&str, u64, &ArtifactProvenance) -> Result<(), Box<dyn Error>>,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(records) = self.ordered_records.as_mut() {
            records.flush()?;
        }
        for record in self.ordered_records()? {
            let path = self.provenance_path(&record);
            let mut lines = BufReader::new(File::open(path)?);
            let mut line = String::new();
            loop {
                line.clear();
                if lines.read_line(&mut line)? == 0 {
                    break;
                }
                let stored: StoredProvenanceRecord = serde_json::from_str(line.trim_end())?;
                visitor(&record.file_name, record.byte_length, &stored.provenance)?;
            }
        }
        Ok(())
    }

    pub(super) fn next_file_number(&self) -> Result<u64, Box<dyn Error>> {
        self.coverage
            .references_selected
            .checked_add(1)
            .ok_or_else(|| invalid("artifact file number overflow").into())
    }

    pub(super) const fn remaining_provenance_entries(&self) -> u64 {
        self.limits.provenance_entries - self.coverage.references_retained
    }

    pub(super) fn write_manifest_artifacts(
        &mut self,
        output: &mut impl Write,
    ) -> Result<(), Box<dyn Error>> {
        self.sync_index()?;
        let ordered = File::open(&self.ordered_records_path)?;
        let mut ordered = BufReader::new(ordered);
        let mut line = String::new();
        let mut first = true;
        loop {
            line.clear();
            if ordered.read_line(&mut line)? == 0 {
                break;
            }
            let indexed: IndexedArtifact = serde_json::from_str(line.trim_end())?;
            if !first {
                output.write_all(b",")?;
            }
            first = false;
            output.write_all(b"{\"file\":")?;
            serde_json::to_writer(&mut *output, &indexed.file_name)?;
            // The byte index already stores the digest used when this artifact was staged
            let digest = indexed
                .bucket_name
                .split_once('-')
                .map(|(_, digest)| digest)
                .filter(|digest| valid_sha256(digest))
                .ok_or_else(|| invalid("artifact index has no valid content digest"))?;
            output.write_all(b",\"sha256\":")?;
            serde_json::to_writer(&mut *output, digest)?;
            write!(
                output,
                ",\"byte_length\":{},\"provenance\":[",
                indexed.byte_length
            )?;
            let provenance_path = self.provenance_path(&indexed);
            write_provenance_json_lines(output, &provenance_path)?;
            output.write_all(b"]}")?;
        }
        Ok(())
    }

    pub(super) fn write_manifest_omissions(
        &mut self,
        output: &mut impl Write,
    ) -> Result<(), Box<dyn Error>> {
        let omitted_records = self
            .omitted_records
            .as_mut()
            .ok_or_else(|| invalid("artifact omission index is already closed"))?;
        omitted_records.flush()?;
        let mut records = BufReader::new(File::open(&self.omitted_records_path)?);
        let mut line = String::new();
        let mut first = true;
        output.write_all(b"{\"details\":[")?;
        loop {
            line.clear();
            if records.read_line(&mut line)? == 0 {
                break;
            }
            if !first {
                output.write_all(b",")?;
            }
            first = false;
            output.write_all(line.trim_end().as_bytes())?;
        }
        write!(
            output,
            "],\"details_retained\":{},\"details_not_retained\":{},\
             \"detail_bytes_retained\":{},\"unidentified\":{}}}",
            self.coverage.omission_details_retained,
            self.coverage.omission_details_not_retained,
            self.coverage.omission_detail_bytes_retained,
            self.coverage.unidentified_omissions
        )?;
        Ok(())
    }

    pub(super) fn cleanup_index(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(mut records) = self.ordered_records.take() {
            records.flush()?;
            records.sync_all()?;
        }
        drop(self.omitted_records.take());
        fs::remove_dir_all(&self.index)?;
        Ok(())
    }

    fn store_bytes(
        &mut self,
        bytes: &[u8],
        byte_length: u64,
        suggested_name: &str,
        provenance: &ArtifactProvenance,
        bucket: &Path,
        memory: Option<&MemoryBudget>,
    ) -> Result<AddOutcome, Box<dyn Error>> {
        let (canonical_origin, encoded) = encode_provenance_record(provenance, memory)?;
        if let Some(reason) = self.unique_omission_reason(byte_length, encoded.bytes.len()) {
            drop(canonical_origin);
            drop(encoded);
            self.omit_reference_with_provenance(reason, byte_length, provenance, memory)?;
            return Ok(AddOutcome::Omitted(reason));
        }

        let file_name = self.unique_file_name(suggested_name)?;
        let path = self.staging.join(&file_name);
        let mut file = File::options().write(true).create_new(true).open(&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.record_new_file(
            bucket,
            file_name,
            byte_length,
            &provenance.category,
            &canonical_origin.bytes,
            &encoded.bytes,
        )?;
        Ok(AddOutcome::Stored)
    }

    fn store_open_file(
        &mut self,
        source: &mut File,
        identity: (u64, &str),
        suggested_name: &str,
        provenance: &ArtifactProvenance,
        bucket: &Path,
        memory: Option<&MemoryBudget>,
    ) -> Result<AddOutcome, Box<dyn Error>> {
        let (byte_length, digest) = identity;
        let (canonical_origin, encoded) = encode_provenance_record(provenance, memory)?;
        if let Some(reason) = self.unique_omission_reason(byte_length, encoded.bytes.len()) {
            drop(canonical_origin);
            drop(encoded);
            self.omit_reference_with_provenance(reason, byte_length, provenance, memory)?;
            return Ok(AddOutcome::Omitted(reason));
        }

        let file_name = self.unique_file_name(suggested_name)?;
        let path = self.staging.join(&file_name);
        let mut destination = File::options().write(true).create_new(true).open(&path)?;
        let copied = match copy_open_file(source, &mut destination) {
            Ok(copied) => copied,
            Err(OpenFileCopyError::Source) => {
                drop(destination);
                fs::remove_file(path)?;
                drop(canonical_origin);
                drop(encoded);
                self.omit_reference_with_provenance(
                    OmissionReason::UnreadableObject,
                    byte_length,
                    provenance,
                    memory,
                )?;
                return Ok(AddOutcome::Omitted(OmissionReason::UnreadableObject));
            }
            Err(OpenFileCopyError::Destination(error)) => {
                drop(destination);
                let _ = fs::remove_file(path);
                return Err(error.into());
            }
        };
        if copied.0 != byte_length || copied.1 != digest {
            drop(destination);
            fs::remove_file(path)?;
            drop(canonical_origin);
            drop(encoded);
            self.omit_reference_with_provenance(
                OmissionReason::UnreadableObject,
                byte_length,
                provenance,
                memory,
            )?;
            return Ok(AddOutcome::Omitted(OmissionReason::UnreadableObject));
        }
        destination.sync_all()?;
        self.record_new_file(
            bucket,
            file_name,
            byte_length,
            &provenance.category,
            &canonical_origin.bytes,
            &encoded.bytes,
        )?;
        Ok(AddOutcome::Stored)
    }

    fn record_new_file(
        &mut self,
        bucket: &Path,
        file_name: String,
        byte_length: u64,
        category: &str,
        canonical_origin: &[u8],
        provenance_record: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        fs::create_dir_all(bucket)?;
        let entry_id = next_entry_id(bucket)?;
        let record = IndexedArtifact {
            entry_id,
            file_name,
            bucket_name: bucket
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("artifact index bucket name is unavailable")?
                .to_owned(),
            byte_length,
        };
        let record_path = Self::record_path(bucket, entry_id);
        write_json_line(&record_path, &record)?;
        let provenance_path = self.provenance_path(&record);
        let origin_directory = Self::origin_directory(bucket, entry_id);
        fs::create_dir(&origin_directory)?;
        append_provenance_record(
            &provenance_path,
            &origin_directory,
            canonical_origin,
            provenance_record,
            true,
        )?;
        let ordered = self
            .ordered_records
            .as_mut()
            .ok_or_else(|| invalid("artifact index is already closed"))?;
        serde_json::to_writer(&mut *ordered, &record)?;
        ordered.write_all(b"\n")?;
        self.coverage.unique_artifacts_retained =
            add_counter(self.coverage.unique_artifacts_retained, 1)?;
        self.coverage.artifact_bytes_retained =
            add_counter(self.coverage.artifact_bytes_retained, byte_length)?;
        self.retain_provenance(provenance_record.len(), category)?;
        Ok(())
    }

    fn record_duplicate(
        &mut self,
        bucket: &Path,
        record: &IndexedArtifact,
        provenance: &ArtifactProvenance,
        memory: Option<&MemoryBudget>,
    ) -> Result<AddOutcome, Box<dyn Error>> {
        let (canonical_origin, encoded) = encode_provenance_record(provenance, memory)?;
        let path = bucket.join(provenance_file_name(record.entry_id));
        let origin_directory = Self::origin_directory(bucket, record.entry_id);
        let origin_index = Self::origin_index_path(&origin_directory, &canonical_origin.bytes);
        if origin_index_contains(&path, &origin_index, &canonical_origin.bytes)? {
            self.coverage.same_origin_references_suppressed =
                add_counter(self.coverage.same_origin_references_suppressed, 1)?;
            return Ok(AddOutcome::SameOrigin);
        }
        if let Some(reason) = self.provenance_omission_reason(encoded.bytes.len()) {
            drop(canonical_origin);
            drop(encoded);
            self.omit_reference_with_provenance(reason, record.byte_length, provenance, memory)?;
            return Ok(AddOutcome::Omitted(reason));
        }
        append_provenance_record(
            &path,
            &origin_directory,
            &canonical_origin.bytes,
            &encoded.bytes,
            false,
        )?;
        self.retain_provenance(encoded.bytes.len(), &provenance.category)?;
        self.coverage.duplicate_byte_references_grouped =
            add_counter(self.coverage.duplicate_byte_references_grouped, 1)?;
        Ok(AddOutcome::Duplicate)
    }

    fn retain_provenance(
        &mut self,
        json_bytes: usize,
        category: &str,
    ) -> Result<(), Box<dyn Error>> {
        let byte_count = u64::try_from(json_bytes)?
            .checked_add(1)
            .ok_or("artifact provenance byte count overflow")?;
        self.coverage.references_retained = add_counter(self.coverage.references_retained, 1)?;
        self.coverage.provenance_bytes_retained =
            add_counter(self.coverage.provenance_bytes_retained, byte_count)?;
        let category_counter = match category {
            "native_http_body" => &mut self.coverage.native_http_body_references_retained,
            "native_ftp_candidate" => &mut self.coverage.native_ftp_candidate_references_retained,
            "recovered_artifact" => &mut self.coverage.recovered_artifact_references_retained,
            "tshark_object" => &mut self.coverage.tshark_object_references_retained,
            _ => return Ok(()),
        };
        *category_counter = add_counter(*category_counter, 1)?;
        Ok(())
    }

    fn unique_omission_reason(
        &self,
        artifact_length: u64,
        provenance_length: usize,
    ) -> Option<OmissionReason> {
        if let Some(reason) = self.provenance_omission_reason(provenance_length) {
            return Some(reason);
        }
        if self.coverage.unique_artifacts_retained >= self.limits.artifacts {
            return Some(OmissionReason::ArtifactCount);
        }
        if artifact_length > self.limits.artifact_bytes - self.coverage.artifact_bytes_retained {
            return Some(OmissionReason::ArtifactBytes);
        }
        None
    }

    fn provenance_omission_reason(&self, json_length: usize) -> Option<OmissionReason> {
        if self.coverage.references_retained >= self.limits.provenance_entries {
            return Some(OmissionReason::ProvenanceCount);
        }
        let line_length = u64::try_from(json_length).ok()?.checked_add(1)?;
        (line_length > self.limits.provenance_bytes - self.coverage.provenance_bytes_retained)
            .then_some(OmissionReason::ProvenanceBytes)
    }

    fn omit_reference_with_provenance(
        &mut self,
        reason: OmissionReason,
        candidate_bytes: u64,
        provenance: &ArtifactProvenance,
        memory: Option<&MemoryBudget>,
    ) -> Result<(), Box<dyn Error>> {
        self.omit_references(reason, 1, candidate_bytes)?;
        self.append_omission_detail(reason, candidate_bytes, provenance, memory)
    }

    fn append_omission_detail(
        &mut self,
        reason: OmissionReason,
        candidate_bytes: u64,
        provenance: &ArtifactProvenance,
        memory: Option<&MemoryBudget>,
    ) -> Result<(), Box<dyn Error>> {
        if self.coverage.omission_details_retained >= self.limits.provenance_entries {
            self.coverage.omission_details_not_retained =
                add_counter(self.coverage.omission_details_not_retained, 1)?;
            return Ok(());
        }
        let remaining = self
            .limits
            .provenance_bytes
            .checked_sub(self.coverage.omission_detail_bytes_retained)
            .ok_or_else(|| invalid("omission detail byte count exceeds its limit"))?;
        let maximum = usize::try_from(remaining.saturating_sub(1)).unwrap_or(usize::MAX);
        let archive_path = selection_string(provenance, "archive_path");
        let selected_file_name = selection_string(provenance, "selected_file_name");
        let archive_parent_node_id = provenance
            .selection
            .as_ref()
            .and_then(|selection| selection.get("archive_parent"))
            .and_then(|parent| parent.get("node_id"))
            .and_then(serde_json::Value::as_u64);
        let detail = OmittedArtifactDetailRef {
            reason: reason.manifest_name(),
            bytes: candidate_bytes,
            category: &provenance.category,
            case_id: provenance.case_id.as_deref(),
            selected_node_id: provenance.selected_node_id,
            validation_node_id: provenance.validation_node_id,
            extension_node_id: provenance.extension_node_id,
            archive_parent_node_id,
            archive_path,
            selected_file_name,
        };
        let mut encoded = BoundedBuffer::new(maximum, memory)?;
        if serde_json::to_writer(&mut encoded, &detail).is_err() {
            if let Some(error) = encoded.failure.take() {
                return Err(error);
            }
            self.coverage.omission_details_not_retained =
                add_counter(self.coverage.omission_details_not_retained, 1)?;
            return Ok(());
        }
        let encoded_length = u64::try_from(encoded.bytes.len())?;
        let line_length = encoded_length
            .checked_add(1)
            .ok_or("omission detail byte count overflow")?;
        let records = self
            .omitted_records
            .as_mut()
            .ok_or_else(|| invalid("artifact omission index is already closed"))?;
        records.write_all(&encoded.bytes)?;
        records.write_all(b"\n")?;
        self.coverage.omission_details_retained =
            add_counter(self.coverage.omission_details_retained, 1)?;
        self.coverage.omission_detail_bytes_retained =
            add_counter(self.coverage.omission_detail_bytes_retained, line_length)?;
        Ok(())
    }

    fn find_bytes_duplicate(
        &self,
        bucket: &Path,
        bytes: &[u8],
    ) -> io::Result<Option<IndexedArtifact>> {
        let entries = match fs::read_dir(bucket) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            if !entry
                .file_name()
                .to_string_lossy()
                .ends_with(".record.json")
            {
                continue;
            }
            let record = serde_json::from_slice::<IndexedArtifact>(&fs::read(entry.path())?)?;
            if file_matches_bytes(&self.staging.join(&record.file_name), bytes)? {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    fn find_open_file_duplicate(
        &self,
        bucket: &Path,
        source: &mut File,
    ) -> io::Result<Option<IndexedArtifact>> {
        let entries = match fs::read_dir(bucket) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            if !entry
                .file_name()
                .to_string_lossy()
                .ends_with(".record.json")
            {
                continue;
            }
            let record = serde_json::from_slice::<IndexedArtifact>(&fs::read(entry.path())?)?;
            if file_matches_open(source, &self.staging.join(&record.file_name))? {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    fn bucket_path(&self, byte_length: u64, digest: &str) -> PathBuf {
        self.index.join(format!("{byte_length:020}-{digest}"))
    }

    fn record_path(bucket: &Path, entry_id: u64) -> PathBuf {
        bucket.join(record_file_name(entry_id))
    }

    fn provenance_path(&self, record: &IndexedArtifact) -> PathBuf {
        self.index
            .join(&record.bucket_name)
            .join(provenance_file_name(record.entry_id))
    }

    fn origin_directory(bucket: &Path, entry_id: u64) -> PathBuf {
        bucket.join(format!("entry-{entry_id:020}.origins"))
    }

    fn origin_index_path(origin_directory: &Path, canonical_origin: &[u8]) -> PathBuf {
        let digest = Sha256::digest(canonical_origin);
        origin_directory.join(format!("{digest:x}"))
    }

    fn unique_file_name(&self, suggested: &str) -> io::Result<String> {
        validate_flat_file_name(suggested)?;
        if !self.staging.join(suggested).exists() {
            return Ok(suggested.to_owned());
        }
        let (stem, extension) = suggested
            .rsplit_once('.')
            .filter(|(stem, _)| !stem.is_empty())
            .unwrap_or((suggested, ""));
        let mut suffix = 2_u64;
        loop {
            let candidate = if extension.is_empty() {
                format!("{stem}-{suffix}")
            } else {
                format!("{stem}-{suffix}.{extension}")
            };
            if !self.staging.join(&candidate).exists() {
                return Ok(candidate);
            }
            suffix = suffix.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "artifact name count overflow")
            })?;
        }
    }

    fn sync_index(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(mut records) = self.ordered_records.take() {
            records.flush()?;
            records.sync_all()?;
        }
        let ordered = BufReader::new(File::open(&self.ordered_records_path)?);
        for line in ordered.lines() {
            let record: IndexedArtifact = serde_json::from_str(&line?)?;
            let provenance_path = self.provenance_path(&record);
            OpenOptions::new()
                .append(true)
                .open(provenance_path)?
                .sync_all()?;
            let origin_directory =
                Self::origin_directory(&self.index.join(&record.bucket_name), record.entry_id);
            for entry in fs::read_dir(origin_directory)? {
                OpenOptions::new()
                    .append(true)
                    .open(entry?.path())?
                    .sync_all()?;
            }
            File::open(Self::record_path(
                &self.index.join(&record.bucket_name),
                record.entry_id,
            ))?
            .sync_all()?;
        }
        Ok(())
    }

    fn ordered_records(&self) -> Result<Vec<IndexedArtifact>, Box<dyn Error>> {
        let file = File::open(&self.ordered_records_path)?;
        BufReader::new(file)
            .lines()
            .map(|line| serde_json::from_str::<IndexedArtifact>(&line?).map_err(Into::into))
            .collect()
    }
}

fn record_file_name(entry_id: u64) -> String {
    format!("entry-{entry_id:020}.record.json")
}

fn provenance_file_name(entry_id: u64) -> String {
    format!("entry-{entry_id:020}.provenance.jsonl")
}

fn next_entry_id(bucket: &Path) -> io::Result<u64> {
    let mut next = 0_u64;
    for entry in fs::read_dir(bucket)? {
        let file_name = entry?.file_name();
        let Some(stem) = file_name
            .to_str()
            .and_then(|name| name.strip_prefix("entry-"))
        else {
            continue;
        };
        let Some(digits) = stem.strip_suffix(".record.json") else {
            continue;
        };
        let Ok(id) = digits.parse::<u64>() else {
            continue;
        };
        next = next.max(id.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "artifact index entry count overflow",
            )
        })?);
    }
    Ok(next)
}

fn write_json_line(path: &Path, value: &impl Serialize) -> Result<(), Box<dyn Error>> {
    let mut file = File::options().write(true).create_new(true).open(path)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn encode_provenance_record(
    provenance: &ArtifactProvenance,
    memory: Option<&MemoryBudget>,
) -> Result<(BoundedBuffer, BoundedBuffer), Box<dyn Error>> {
    let mut canonical_origin = BoundedBuffer::new(usize::MAX, memory)?;
    canonical_origin.encode(&provenance.canonical_origin)?;
    let mut record = BoundedBuffer::new(usize::MAX, memory)?;
    record.encode(&StoredProvenanceRecordRef {
        canonical_origin: &canonical_origin.bytes,
        provenance,
    })?;
    Ok((canonical_origin, record))
}

fn selection_string<'a>(provenance: &'a ArtifactProvenance, key: &str) -> Option<&'a str> {
    provenance
        .selection
        .as_ref()
        .and_then(|selection| selection.get(key))
        .and_then(serde_json::Value::as_str)
}

fn append_provenance_record(
    provenance_path: &Path,
    origin_directory: &Path,
    canonical_origin: &[u8],
    provenance_record: &[u8],
    create_new: bool,
) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .append(!create_new)
        .create_new(create_new);
    let mut provenance_file = options.open(provenance_path)?;
    let offset = provenance_file.seek(SeekFrom::End(0))?;
    provenance_file.write_all(provenance_record)?;
    provenance_file.write_all(b"\n")?;

    let origin_index = ArtifactCollection::origin_index_path(origin_directory, canonical_origin);
    let mut index_file = OpenOptions::new()
        .append(true)
        .create(!create_new)
        .create_new(create_new)
        .open(origin_index)?;
    writeln!(index_file, "{offset}")?;
    Ok(())
}

fn origin_index_contains(
    provenance_path: &Path,
    origin_index_path: &Path,
    expected: &[u8],
) -> io::Result<bool> {
    let index = match File::open(origin_index_path) {
        Ok(index) => index,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let mut indexes = BufReader::new(index);
    let mut offset_text = String::new();
    let mut record = Vec::new();
    let mut provenance = File::open(provenance_path)?;
    loop {
        offset_text.clear();
        if indexes.read_line(&mut offset_text)? == 0 {
            return Ok(false);
        }
        let offset = offset_text
            .trim_end()
            .parse::<u64>()
            .map_err(|_| invalid("artifact origin index offset is malformed"))?;
        provenance.seek(SeekFrom::Start(offset))?;
        record.clear();
        if BufReader::new(&mut provenance).read_until(b'\n', &mut record)? == 0 {
            return Err(invalid(
                "artifact origin index points beyond provenance rows",
            ));
        }
        if record.last() == Some(&b'\n') {
            record.pop();
        }
        let stored: StoredProvenanceRecord = serde_json::from_slice(&record)?;
        if stored.canonical_origin == expected {
            return Ok(true);
        }
    }
}

fn write_provenance_json_lines(output: &mut impl Write, path: &Path) -> Result<(), Box<dyn Error>> {
    let file = File::open(path)?;
    let mut lines = BufReader::new(file);
    let mut line = String::new();
    let mut first = true;
    loop {
        line.clear();
        if lines.read_line(&mut line)? == 0 {
            break;
        }
        let stored: StoredProvenanceRecord = serde_json::from_str(line.trim_end())?;
        if !first {
            output.write_all(b",")?;
        }
        first = false;
        serde_json::to_writer(&mut *output, &stored.provenance)?;
    }
    Ok(())
}

fn file_matches_bytes(path: &Path, expected: &[u8]) -> io::Result<bool> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() != u64::try_from(expected.len()).map_err(io::Error::other)? {
        return Ok(false);
    }
    let mut buffer = [0_u8; 16 * 1024];
    let mut offset = 0_usize;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            return Ok(offset == expected.len());
        }
        let Some(actual) = buffer.get(..count) else {
            return Ok(false);
        };
        let Some(end) = offset.checked_add(count) else {
            return Ok(false);
        };
        if expected.get(offset..end) != Some(actual) {
            return Ok(false);
        }
        offset = end;
    }
}

fn file_matches_open(source: &mut File, stored_path: &Path) -> io::Result<bool> {
    let mut stored = File::open(stored_path)?;
    if source.metadata()?.len() != stored.metadata()?.len() {
        return Ok(false);
    }
    source.seek(SeekFrom::Start(0))?;
    let comparison = (|| {
        let mut source_buffer = [0_u8; 16 * 1024];
        let mut stored_buffer = [0_u8; 16 * 1024];
        loop {
            let source_count = source.read(&mut source_buffer)?;
            let stored_count = stored.read(&mut stored_buffer)?;
            if source_count != stored_count {
                return Ok(false);
            }
            if source_count == 0 {
                return Ok(true);
            }
            if source_buffer.get(..source_count) != stored_buffer.get(..stored_count) {
                return Ok(false);
            }
        }
    })();
    source.seek(SeekFrom::Start(0))?;
    comparison
}

fn digest_open_file(source: &mut File) -> io::Result<(u64, String)> {
    source.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut length = 0_u64;
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(u64::try_from(count).map_err(io::Error::other)?)
            .ok_or_else(|| invalid("artifact byte count overflow"))?;
        let bytes = buffer
            .get(..count)
            .ok_or_else(|| invalid("artifact read exceeded its buffer"))?;
        hasher.update(bytes);
    }
    source.seek(SeekFrom::Start(0))?;
    Ok((length, format!("{:x}", hasher.finalize())))
}

enum OpenFileCopyError {
    Source,
    Destination(io::Error),
}

fn copy_open_file(
    source: &mut File,
    destination: &mut File,
) -> Result<(u64, String), OpenFileCopyError> {
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| OpenFileCopyError::Source)?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|_| OpenFileCopyError::Source)?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(u64::try_from(count).map_err(|_| OpenFileCopyError::Source)?)
            .ok_or(OpenFileCopyError::Source)?;
        let bytes = buffer.get(..count).ok_or(OpenFileCopyError::Source)?;
        hasher.update(bytes);
        destination
            .write_all(bytes)
            .map_err(OpenFileCopyError::Destination)?;
    }
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| OpenFileCopyError::Source)?;
    Ok((length, format!("{:x}", hasher.finalize())))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_flat_file_name(file_name: &str) -> io::Result<()> {
    if !crate::safe_filename::is_safe_flat_file_name(file_name) {
        return Err(invalid("artifact file name must be a safe flat name"));
    }
    Ok(())
}

fn add_counter(value: u64, increment: u64) -> io::Result<u64> {
    value
        .checked_add(increment)
        .ok_or_else(|| invalid("artifact export counter overflow"))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
