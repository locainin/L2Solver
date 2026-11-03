use super::{ResultIdentity, ResultKind, bounded};
use crate::{publish, safe_filename::is_safe_flat_file_name};
use l2_workbench::{job::JobSnapshot, job::cache::SourceIdentity};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    io::{self, Read},
    path::Path,
};

use super::stamp::OutputFileStamp;

const MANIFEST_FILE: &str = "manifest.json";
const SUMMARY_FILE: &str = "summary.txt";
const EVIDENCE_FILE: &str = "evidence.jsonl";
const GZIP_EVIDENCE_FILE: &str = "evidence.jsonl.gz";
const LIMITATIONS_FILE: &str = "limitations.txt";
const MAX_DIRECTORY_ENTRIES: usize = 100_000;
const MAX_MANIFEST_BYTES: u64 = 512 * 1024 * 1024;
/// Matches the default extraction artifact-count ceiling
pub(super) const MAX_RESULT_ARTIFACTS: usize = 16_384;
/// Matches the maximum refinement source-record count
pub(super) const MAX_RESULT_SOURCES: usize = 4_096;
/// Allows one stamp for each artifact and each declared metadata output
pub(super) const MAX_RESULT_OUTPUT_STAMPS: usize = MAX_RESULT_ARTIFACTS + 3;

/// State retained after the destination has been inspected
pub(super) enum DirectoryState {
    /// The destination name was absent
    Missing,
    /// An older extraction is safe but has no reusable receipt
    Legacy {
        /// Held directory and its verified manifest
        prepared: publish::PreparedDirectoryReplacement,
    },
    /// A result published with the current receipt format
    Owned {
        /// Held directory and its verified manifest
        prepared: publish::PreparedDirectoryReplacement,
        /// Parsed manifest data used for the whitelist
        manifest: OwnedManifest,
        /// Job and output receipts stored in the manifest
        receipt: Box<ResultReceipt>,
    },
}

/// Manifest facts needed to validate ownership and the directory's exact file set
pub(super) struct OwnedManifest {
    /// Overall completion recorded by the generating workflow
    pub complete: bool,
    /// Safe flat output artifacts declared by the manifest
    pub artifacts: Vec<ManifestArtifact>,
    /// Sidecar selected by the extract manifest, or absent for refinement results
    pub evidence_file: Option<String>,
    /// Strong source SHA-256 values recorded by the generating workflow
    pub source_sha256s: Vec<Option<String>>,
    /// Strong identity for the complete ordered source set
    pub source_identity_sha256: Option<String>,
    /// Ordered refinement labels bind reused output provenance to the input names
    pub source_labels: Vec<Option<String>>,
}

/// One declared artifact from an extract or refine manifest
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(super) struct ManifestArtifact {
    /// Safe flat artifact name
    #[serde(deserialize_with = "bounded::deserialize_file_name")]
    pub file: String,
    /// Byte length recorded by the generating workflow
    pub byte_length: u64,
    /// Strong digest when the workflow's manifest already contains one
    #[serde(default)]
    #[serde(deserialize_with = "bounded::deserialize_optional_sha256")]
    pub sha256: Option<String>,
}

/// Receipt embedded in the existing manifest's `l2solver_result` field
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct ResultReceipt {
    /// Receipt format version
    pub schema_version: u32,
    /// Stable algorithm and source identity
    pub identity: ResultIdentity,
    /// Whether the published result completed every requested component
    pub complete: bool,
    /// Strong source identities copied from the generating manifest
    #[serde(deserialize_with = "bounded::deserialize_source_digests")]
    pub source_sha256s: Vec<Option<String>>,
    /// Strong identity for the complete ordered source set
    #[serde(deserialize_with = "bounded::deserialize_optional_sha256")]
    pub source_identity_sha256: Option<String>,
    /// Job state at the start of atomic publication
    #[serde(deserialize_with = "bounded::deserialize_job_snapshot")]
    pub job: JobSnapshot,
    /// File stamps for every output except the manifest containing this receipt
    #[serde(deserialize_with = "bounded::deserialize_output_stamps")]
    pub output_files: Vec<OutputFileStamp>,
}

#[derive(Deserialize)]
struct RawManifest {
    schema_version: u32,
    #[serde(default)]
    #[serde(deserialize_with = "bounded::deserialize_status")]
    export_status: Option<String>,
    #[serde(default)]
    complete: Option<bool>,
    #[serde(default)]
    evidence: Option<RawEvidence>,
    #[serde(default)]
    full_source_coverage: Option<RawFullSourceCoverage>,
    #[serde(default)]
    #[serde(deserialize_with = "bounded::deserialize_optional_sources")]
    sources: Option<Vec<RawSource>>,
    #[serde(default)]
    #[serde(deserialize_with = "bounded::deserialize_artifacts")]
    artifacts: Vec<ManifestArtifact>,
    #[serde(default)]
    l2solver_result: Option<ResultReceipt>,
}

#[derive(Deserialize)]
struct RawEvidence {
    #[serde(deserialize_with = "bounded::deserialize_file_name")]
    file: String,
}

#[derive(Deserialize)]
struct RawFullSourceCoverage {
    source: RawSourceIdentity,
}

#[derive(Deserialize)]
struct RawSourceIdentity {
    #[serde(deserialize_with = "bounded::deserialize_source_id")]
    source_id: String,
}

#[derive(Deserialize)]
struct RawSource {
    #[serde(
        default,
        deserialize_with = "bounded::deserialize_optional_source_label"
    )]
    label: Option<String>,
    byte_length: u64,
    #[serde(default, deserialize_with = "bounded::deserialize_optional_sha256")]
    sha256: Option<String>,
}

pub(super) fn inspect(
    path: &Path,
    kind: ResultKind,
) -> Result<super::ResultDirectory, Box<dyn Error>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => inspect_existing(path, kind),
        Ok(_) => {
            Err(actionable_conflict("result destination exists and is not a real directory").into())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            publish::check_new_directory_destination(path)?;
            Ok(super::ResultDirectory {
                path: path.to_owned(),
                kind,
                state: DirectoryState::Missing,
            })
        }
        Err(error) => Err(error.into()),
    }
}

fn inspect_existing(
    path: &Path,
    kind: ResultKind,
) -> Result<super::ResultDirectory, Box<dyn Error>> {
    let prepared = publish::prepare_directory_replacement(path).map_err(|error| {
        actionable_conflict(&format!("existing result destination is unsafe: {error}"))
    })?;
    let manifest_file = prepared.open_file(MANIFEST_FILE).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            return unrelated_output_directory();
        }
        actionable_conflict(&format!(
            "could not safely open the existing result manifest: {error}"
        ))
    })?;
    let (raw, manifest_identity) = read_manifest(manifest_file).map_err(|error| {
        actionable_conflict(&format!("existing result manifest is invalid: {error}"))
    })?;
    verify_named_manifest(&prepared, manifest_identity)?;
    inspect_prepared(path, kind, prepared, raw).map_err(|error| {
        actionable_conflict(&format!(
            "existing result directory cannot be reused: {error}"
        ))
        .into()
    })
}

fn inspect_prepared(
    path: &Path,
    kind: ResultKind,
    prepared: publish::PreparedDirectoryReplacement,
    raw: RawManifest,
) -> Result<super::ResultDirectory, Box<dyn Error>> {
    prepared.check_location()?;
    let SourceFacts {
        complete,
        source_sha256s,
        source_identity_sha256,
    } = manifest_identity_facts(&raw, kind)?;
    let manifest = OwnedManifest {
        complete,
        evidence_file: evidence_file(&raw, kind)?,
        source_labels: source_labels(&raw),
        artifacts: validate_artifacts(raw.artifacts)?,
        source_sha256s,
        source_identity_sha256,
    };
    let state = if let Some(receipt) = raw.l2solver_result {
        validate_receipt(&receipt, &manifest, kind)?;
        validate_directory_entries(&prepared, kind, &manifest, Some(&receipt))?;
        DirectoryState::Owned {
            prepared,
            manifest,
            receipt: Box::new(receipt),
        }
    } else if kind == ResultKind::Extract {
        validate_directory_entries(&prepared, kind, &manifest, None)?;
        DirectoryState::Legacy { prepared }
    } else {
        return Err(actionable_conflict(
            "existing directory is not a result owned by this workflow",
        )
        .into());
    };
    if let DirectoryState::Owned { prepared, .. } | DirectoryState::Legacy { prepared } = &state {
        prepared.check_location()?;
    }

    Ok(super::ResultDirectory {
        path: path.to_owned(),
        kind,
        state,
    })
}

pub(super) fn parse_staged_manifest(
    path: &Path,
    kind: ResultKind,
) -> Result<OwnedManifest, Box<dyn Error>> {
    let raw = read_manifest_path::<RawManifest>(path)?;
    if raw.l2solver_result.is_some() {
        return Err(invalid_result("writer supplied a reserved l2solver_result field").into());
    }
    let SourceFacts {
        complete,
        source_sha256s,
        source_identity_sha256,
    } = manifest_identity_facts(&raw, kind)?;
    let manifest = OwnedManifest {
        complete,
        evidence_file: evidence_file(&raw, kind)?,
        source_labels: source_labels(&raw),
        artifacts: validate_artifacts(raw.artifacts)?,
        source_sha256s,
        source_identity_sha256,
    };
    Ok(manifest)
}

pub(super) fn validate_staged_receipt(path: &Path, kind: ResultKind) -> Result<(), Box<dyn Error>> {
    let raw = read_manifest_path::<RawManifest>(path)?;
    let SourceFacts {
        complete,
        source_sha256s,
        source_identity_sha256,
    } = manifest_identity_facts(&raw, kind)?;
    let manifest = OwnedManifest {
        complete,
        evidence_file: evidence_file(&raw, kind)?,
        source_labels: source_labels(&raw),
        artifacts: validate_artifacts(raw.artifacts)?,
        source_sha256s,
        source_identity_sha256,
    };
    let receipt = raw
        .l2solver_result
        .as_ref()
        .ok_or_else(|| invalid_result("generated result receipt is missing"))?;
    validate_receipt(receipt, &manifest, kind)?;
    validate_staged_entries(path, kind, &manifest, Some(receipt))?;
    Ok(())
}

fn source_labels(raw: &RawManifest) -> Vec<Option<String>> {
    raw.sources.as_ref().map_or_else(Vec::new, |sources| {
        sources.iter().map(|source| source.label.clone()).collect()
    })
}

pub(super) fn staged_output_files(
    path: &Path,
    kind: ResultKind,
    manifest: &OwnedManifest,
) -> Result<Vec<String>, Box<dyn Error>> {
    validate_staged_entries(path, kind, manifest, None)
}

fn read_manifest<T: DeserializeOwned>(
    file: fs::File,
) -> Result<(T, ManifestFileIdentity), Box<dyn Error>> {
    deserialize_limited_manifest(file, MAX_MANIFEST_BYTES)
}

fn read_manifest_path<T: DeserializeOwned>(path: &Path) -> Result<T, Box<dyn Error>> {
    let manifest_path = path.join(MANIFEST_FILE);
    let file = super::stamp::open_regular_path(&manifest_path)?;
    let (value, identity) = deserialize_limited_manifest(file, MAX_MANIFEST_BYTES)?;
    let current = super::stamp::open_regular_path(&manifest_path)?;
    ensure_same_manifest_identity(
        identity,
        ManifestFileIdentity::from_metadata(&current.metadata()?)?,
    )?;
    Ok(value)
}

fn deserialize_limited_manifest<T: DeserializeOwned>(
    mut file: fs::File,
    maximum_bytes: u64,
) -> Result<(T, ManifestFileIdentity), Box<dyn Error>> {
    let before = ManifestFileIdentity::from_metadata(&file.metadata()?)?;
    if before.length > maximum_bytes {
        return Err(invalid_result("result manifest exceeds the safe size limit").into());
    }
    let value = deserialize_manifest_value(&mut file, maximum_bytes)?;
    let after = ManifestFileIdentity::from_metadata(&file.metadata()?)?;
    ensure_same_manifest_identity(before, after)?;
    Ok((value, after))
}

pub(super) fn deserialize_manifest_value<T: DeserializeOwned>(
    file: &mut fs::File,
    maximum_bytes: u64,
) -> Result<T, Box<dyn Error>> {
    let read_limit = maximum_bytes
        .checked_add(1)
        .ok_or_else(|| invalid_result("result manifest size limit overflow"))?;
    let mut limited = (&mut *file).take(read_limit);
    let value = {
        let mut deserializer = serde_json::Deserializer::from_reader(&mut limited);
        let value = T::deserialize(&mut deserializer)?;
        deserializer.end()?;
        value
    };
    if limited.limit() == 0 {
        return Err(invalid_result("result manifest exceeds the safe size limit").into());
    }
    Ok(value)
}

fn verify_named_manifest(
    prepared: &publish::PreparedDirectoryReplacement,
    expected: ManifestFileIdentity,
) -> Result<(), Box<dyn Error>> {
    let file = prepared.open_file(MANIFEST_FILE)?;
    ensure_same_manifest_identity(
        expected,
        ManifestFileIdentity::from_metadata(&file.metadata()?)?,
    )?;
    prepared.check_location()?;
    Ok(())
}

pub(super) fn ensure_same_manifest_identity(
    expected: ManifestFileIdentity,
    actual: ManifestFileIdentity,
) -> io::Result<()> {
    if expected != actual {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "result manifest changed while it was parsed",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ManifestFileIdentity {
    length: u64,
    #[cfg(unix)]
    device_id: u64,
    #[cfg(unix)]
    file_id: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(unix)]
    link_count: u64,
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
}

impl ManifestFileIdentity {
    pub(super) fn from_metadata(metadata: &fs::Metadata) -> io::Result<Self> {
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "result manifest is not a regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "result manifest has multiple hard links",
                ));
            }
            Ok(Self {
                length: metadata.len(),
                device_id: metadata.dev(),
                file_id: metadata.ino(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
                link_count: metadata.nlink(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                length: metadata.len(),
                modified: metadata.modified().ok(),
            })
        }
    }
}

struct SourceFacts {
    complete: bool,
    source_sha256s: Vec<Option<String>>,
    source_identity_sha256: Option<String>,
}

fn manifest_identity_facts(
    raw: &RawManifest,
    kind: ResultKind,
) -> Result<SourceFacts, Box<dyn Error>> {
    if !matches!(
        (kind, raw.schema_version),
        (ResultKind::Extract, 1) | (ResultKind::Refine, 1 | 2)
    ) {
        return Err(invalid_result("result manifest schema is unsupported").into());
    }
    match kind {
        ResultKind::Extract => {
            let complete = match raw.export_status.as_deref() {
                Some("complete") => true,
                Some("partial") => false,
                _ => {
                    return Err(
                        invalid_result("extract manifest has no valid export status").into(),
                    );
                }
            };
            let source_id = raw
                .full_source_coverage
                .as_ref()
                .map(|coverage| coverage.source.source_id.as_str())
                .ok_or_else(|| invalid_result("extract manifest has no full-source identity"))?;
            let digest = source_id
                .strip_prefix("sha256:")
                .filter(|digest| is_sha256(digest))
                .ok_or_else(|| invalid_result("extract manifest has no strong source SHA-256"))?;
            Ok(SourceFacts {
                complete,
                source_sha256s: vec![Some(digest.to_owned())],
                source_identity_sha256: Some(digest.to_owned()),
            })
        }
        ResultKind::Refine => {
            let complete = raw
                .complete
                .ok_or_else(|| invalid_result("refine manifest has no completion status"))?;
            let sources = raw
                .sources
                .as_ref()
                .ok_or_else(|| invalid_result("refine manifest has no source identities"))?;
            if sources.is_empty() {
                return Err(invalid_result("refine manifest has no source identities").into());
            }
            let digests = sources
                .iter()
                .map(|source| source.sha256.clone())
                .collect::<Vec<_>>();
            let identity_sources = sources
                .iter()
                .map(|source| {
                    source
                        .sha256
                        .as_deref()
                        .map(|digest| (source.byte_length, digest))
                })
                .collect::<Option<Vec<_>>>();
            let source_identity_sha256 = if let Some(identity_sources) = identity_sources {
                if raw.schema_version != 1 {
                    return Err(invalid_result(
                        "refine manifest schema does not match its source identities",
                    )
                    .into());
                }
                Some(crate::refine::refine_source_identity_sha256(
                    identity_sources,
                )?)
            } else {
                if complete || raw.schema_version != 2 {
                    return Err(invalid_result("complete refinement has an unread source").into());
                }
                None
            };
            Ok(SourceFacts {
                complete,
                source_sha256s: digests,
                source_identity_sha256,
            })
        }
    }
}

fn validate_artifacts(
    artifacts: Vec<ManifestArtifact>,
) -> Result<Vec<ManifestArtifact>, Box<dyn Error>> {
    let mut names = BTreeSet::new();
    for artifact in &artifacts {
        if !is_safe_flat_file_name(&artifact.file)
            || matches!(
                artifact.file.as_str(),
                MANIFEST_FILE
                    | SUMMARY_FILE
                    | EVIDENCE_FILE
                    | GZIP_EVIDENCE_FILE
                    | LIMITATIONS_FILE
            )
            || !names.insert(artifact.file.clone())
        {
            return Err(
                invalid_result("result manifest has an unsafe or duplicate artifact name").into(),
            );
        }
        if artifact
            .sha256
            .as_deref()
            .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(
                invalid_result("result manifest contains an invalid artifact SHA-256").into(),
            );
        }
    }
    Ok(artifacts)
}

fn evidence_file(raw: &RawManifest, kind: ResultKind) -> Result<Option<String>, Box<dyn Error>> {
    if kind == ResultKind::Refine {
        if raw.evidence.is_some() {
            return Err(
                invalid_result("refine manifest declares an extraction evidence sidecar").into(),
            );
        }
        return Ok(None);
    }

    let file = raw
        .evidence
        .as_ref()
        .map_or(EVIDENCE_FILE, |evidence| evidence.file.as_str());
    if !matches!(file, EVIDENCE_FILE | GZIP_EVIDENCE_FILE) {
        return Err(
            invalid_result("extract manifest declares an unsupported evidence sidecar").into(),
        );
    }
    Ok(Some(file.to_owned()))
}

fn validate_receipt(
    receipt: &ResultReceipt,
    manifest: &OwnedManifest,
    kind: ResultKind,
) -> Result<(), Box<dyn Error>> {
    let schema_version = if manifest.source_identity_sha256.is_some() {
        1
    } else {
        2
    };
    if receipt.schema_version != schema_version || receipt.identity.kind != kind {
        return Err(
            actionable_conflict("result receipt is incompatible with this workflow").into(),
        );
    }
    if receipt.complete != manifest.complete
        || receipt.source_sha256s != manifest.source_sha256s
        || receipt.source_identity_sha256 != manifest.source_identity_sha256
    {
        return Err(invalid_result("result receipt does not match its generating manifest").into());
    }
    validate_source_receipt(
        &receipt.identity.source,
        receipt.source_identity_sha256.as_deref(),
    )?;

    let mut names = BTreeSet::new();
    for stamp in &receipt.output_files {
        if !is_safe_flat_file_name(&stamp.file)
            || stamp.file == MANIFEST_FILE
            || !names.insert(stamp.file.clone())
            || stamp
                .sha256
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(invalid_result("result receipt contains an unsafe output stamp").into());
        }
    }
    let allowed_output_names = expected_names(kind, manifest)
        .into_iter()
        .filter(|name| *name != MANIFEST_FILE)
        .collect::<BTreeSet<_>>();
    let required_output_names = required_names(kind, manifest)
        .into_iter()
        .filter(|name| *name != MANIFEST_FILE)
        .collect::<BTreeSet<_>>();
    if !names
        .iter()
        .all(|name| allowed_output_names.contains(name.as_str()))
        || !required_output_names
            .iter()
            .all(|name| names.contains(*name))
    {
        return Err(invalid_result("result receipt contains an undeclared output file").into());
    }
    let output_stamps = receipt
        .output_files
        .iter()
        .map(|stamp| (stamp.file.as_str(), stamp))
        .collect::<BTreeMap<_, _>>();
    for artifact in &manifest.artifacts {
        let stamp = output_stamps
            .get(artifact.file.as_str())
            .ok_or_else(|| invalid_result("result receipt is missing a declared artifact"))?;
        if stamp.sha256.is_none() {
            return Err(invalid_result("result receipt has no artifact SHA-256").into());
        }
        if stamp.byte_length != artifact.byte_length
            || artifact
                .sha256
                .as_ref()
                .is_some_and(|digest| Some(digest) != stamp.sha256.as_ref())
        {
            return Err(invalid_result(
                "result receipt disagrees with an artifact manifest record",
            )
            .into());
        }
    }
    Ok(())
}

fn validate_source_receipt(
    source: &SourceIdentity,
    source_identity_sha256: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    match (source, source_identity_sha256) {
        (SourceIdentity::Unavailable, None) | (SourceIdentity::Fast(_), Some(_)) => Ok(()),
        (SourceIdentity::Sha256(digest), Some(expected)) if digest == expected => Ok(()),
        _ => {
            Err(invalid_result("result identity disagrees with its manifest source SHA-256").into())
        }
    }
}

fn validate_directory_entries(
    prepared: &publish::PreparedDirectoryReplacement,
    kind: ResultKind,
    manifest: &OwnedManifest,
    receipt: Option<&ResultReceipt>,
) -> Result<(), Box<dyn Error>> {
    use publish::DirectoryEntryKind;

    let mut expected = expected_names(kind, manifest);
    if let Some(receipt) = receipt {
        expected.extend(receipt.output_files.iter().map(|stamp| stamp.file.as_str()));
    }
    let mut observed = BTreeSet::new();
    let artifacts = manifest
        .artifacts
        .iter()
        .map(|artifact| (artifact.file.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let stamps = receipt.map(|receipt| {
        receipt
            .output_files
            .iter()
            .map(|stamp| (stamp.file.as_str(), stamp))
            .collect::<BTreeMap<_, _>>()
    });
    for entry in prepared.entries(MAX_DIRECTORY_ENTRIES)? {
        let Some(name) = entry.relative_path.to_str() else {
            return Err(invalid_result("result directory contains a non-UTF-8 file name").into());
        };
        if entry.relative_path.components().count() != 1
            || !is_safe_flat_file_name(name)
            || entry.kind != DirectoryEntryKind::File
            || entry.link_count != 1
            || !expected.contains(name)
            || !observed.insert(name.to_owned())
        {
            return Err(actionable_conflict(
                "result directory contains an unexpected, unsafe, linked, or nested entry",
            )
            .into());
        }
        if let Some(artifact) = artifacts.get(name)
            && artifact.byte_length != entry.length
        {
            return Err(
                invalid_result("artifact length does not match its manifest record").into(),
            );
        }
        if let Some(stamp) = stamps.as_ref().and_then(|stamps| stamps.get(name))
            && stamp.byte_length != entry.length
        {
            return Err(invalid_result("output length does not match its stored receipt").into());
        }
    }
    if !required_names(kind, manifest)
        .iter()
        .all(|name| observed.contains(*name))
    {
        return Err(invalid_result("result directory is missing a declared output file").into());
    }
    if let Some(receipt) = receipt {
        let stamped = receipt
            .output_files
            .iter()
            .map(|stamp| stamp.file.as_str())
            .collect::<BTreeSet<_>>();
        let expected_non_manifest = observed
            .iter()
            .filter(|name| name.as_str() != MANIFEST_FILE)
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if stamped != expected_non_manifest {
            return Err(
                invalid_result("result receipt does not cover the exact output file set").into(),
            );
        }
    }
    prepared.check_location()?;
    Ok(())
}

/// Atomically add the result receipt to a generated manifest without loading it all into memory
pub(super) fn append_receipt(
    manifest_path: &Path,
    receipt: &ResultReceipt,
) -> Result<(), Box<dyn Error>> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut source = super::stamp::open_regular_path(manifest_path)?;
    let source_len = source.metadata()?.len();
    if source_len == 0 || source_len > MAX_MANIFEST_BYTES {
        return Err(invalid_result("generated result manifest has an unsafe size").into());
    }
    let brace_offset = last_non_whitespace_offset(&mut source, source_len)?;
    source.seek(SeekFrom::Start(brace_offset))?;
    let mut closing = [0_u8; 1];
    source.read_exact(&mut closing)?;
    if closing[0] != b'}' {
        return Err(invalid_result("generated result manifest does not end with an object").into());
    }

    let temporary_path = manifest_path.with_extension("l2solver-tmp");
    let mut destination = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)?;
    source.seek(SeekFrom::Start(0))?;
    let copied = std::io::copy(&mut source.take(brace_offset), &mut destination)?;
    if copied != brace_offset {
        return Err(invalid_result("generated result manifest changed while it was copied").into());
    }
    destination.write_all(b",\"l2solver_result\":")?;
    serde_json::to_writer(&mut destination, receipt)?;
    destination.write_all(b"}\n")?;
    destination.sync_all()?;
    drop(destination);
    fs::rename(&temporary_path, manifest_path)?;
    Ok(())
}

fn last_non_whitespace_offset(file: &mut fs::File, mut length: u64) -> io::Result<u64> {
    use std::io::{Read, Seek, SeekFrom};

    let mut byte = [0_u8; 1];
    while length != 0 {
        length -= 1;
        file.seek(SeekFrom::Start(length))?;
        file.read_exact(&mut byte)?;
        if !byte[0].is_ascii_whitespace() {
            return Ok(length);
        }
    }
    Err(invalid_result("generated result manifest is empty"))
}

fn validate_staged_entries(
    path: &Path,
    kind: ResultKind,
    manifest: &OwnedManifest,
    receipt: Option<&ResultReceipt>,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut expected = expected_names(kind, manifest);
    if let Some(receipt) = receipt {
        expected.extend(receipt.output_files.iter().map(|stamp| stamp.file.as_str()));
    }
    let mut observed = BTreeSet::new();
    let mut output_files = Vec::new();
    let artifacts = manifest
        .artifacts
        .iter()
        .map(|artifact| (artifact.file.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let stamps = receipt.map(|receipt| {
        receipt
            .output_files
            .iter()
            .map(|stamp| (stamp.file.as_str(), stamp))
            .collect::<BTreeMap<_, _>>()
    });
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid_result("result directory contains a non-UTF-8 file name"))?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !is_safe_flat_file_name(&name)
            || !metadata.file_type().is_file()
            || !staged_single_link(&metadata)
            || !expected.contains(name.as_str())
            || !observed.insert(name.clone())
        {
            return Err(actionable_conflict(
                "result directory contains an unexpected, unsafe, linked, or nested entry",
            )
            .into());
        }
        if let Some(artifact) = artifacts.get(name.as_str())
            && artifact.byte_length != metadata.len()
        {
            return Err(
                invalid_result("artifact length does not match its manifest record").into(),
            );
        }
        if let Some(stamp) = stamps.as_ref().and_then(|stamps| stamps.get(name.as_str()))
            && stamp.byte_length != metadata.len()
        {
            return Err(invalid_result("output length does not match its stored receipt").into());
        }
        if name != MANIFEST_FILE {
            output_files.push(name);
        }
    }
    if !required_names(kind, manifest)
        .iter()
        .all(|name| observed.contains(*name))
    {
        return Err(invalid_result("result directory is missing a declared output file").into());
    }
    if let Some(receipt) = receipt {
        let stamped = receipt
            .output_files
            .iter()
            .map(|stamp| stamp.file.as_str())
            .collect::<BTreeSet<_>>();
        let expected_stamps = output_files
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if stamped != expected_stamps {
            return Err(
                invalid_result("result receipt does not cover the exact output file set").into(),
            );
        }
    }
    output_files.sort();
    Ok(output_files)
}

fn expected_names(kind: ResultKind, manifest: &OwnedManifest) -> BTreeSet<&str> {
    let mut expected = BTreeSet::from([MANIFEST_FILE, SUMMARY_FILE]);
    if kind == ResultKind::Extract
        && let Some(file) = manifest.evidence_file.as_deref()
    {
        expected.insert(file);
    }
    expected.insert(LIMITATIONS_FILE);
    expected.extend(
        manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.file.as_str()),
    );
    expected
}

fn required_names(kind: ResultKind, manifest: &OwnedManifest) -> BTreeSet<&str> {
    expected_names(kind, manifest)
        .into_iter()
        .filter(|name| *name != LIMITATIONS_FILE)
        .collect()
}

fn staged_single_link(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink() == 1
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

pub(super) fn actionable_conflict(message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{message}; use --refresh to replace it or -o PATH to choose another directory"),
    )
}

fn unrelated_output_directory() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "existing output directory is not owned by l2solver; choose an unused -o PATH",
    )
}

fn invalid_result(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[path = "../../tests/result_directory/manifest_validation.rs"]
mod tests;
