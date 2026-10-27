//! Secure bounded source admission for standalone files and artifact manifests

use super::invalid_input;
use crate::safe_filename::is_safe_flat_file_name;
use l2_workbench::{
    job::{
        Job,
        cache::{SourceFingerprint, SourceIdentity},
    },
    sha256,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    error::Error,
    fs::{self, File, Metadata},
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_MANIFEST_ARTIFACTS: usize = 4_096;

#[cfg(target_os = "linux")]
struct DirectoryAnchor {
    descriptor: rustix::fd::OwnedFd,
    path: PathBuf,
    device: u64,
    inode: u64,
}

pub(super) struct InputSet {
    sources: Vec<InputSpec>,
    manifest_sha256: Option<String>,
    #[cfg(target_os = "linux")]
    directory: Option<DirectoryAnchor>,
    #[cfg(not(target_os = "linux"))]
    directory: Option<PathBuf>,
}

struct InputSpec {
    label: String,
    path: InputPath,
    expected_length: Option<usize>,
    expected_sha256: Option<String>,
}

enum InputPath {
    Direct(PathBuf),
    ManifestMember(String),
}

pub(super) struct LoadedSource {
    pub(super) label: String,
    pub(super) data: SourceData,
    pub(super) sha256: String,
}

pub(super) enum SourceData {
    Memory(Vec<u8>),
    File(RangeSource),
}

pub(super) struct RangeSource {
    length: usize,
    metadata: MetadataFingerprint,
}

impl LoadedSource {
    pub(super) const fn length(&self) -> usize {
        match &self.data {
            SourceData::Memory(bytes) => bytes.len(),
            SourceData::File(source) => source.length,
        }
    }

    pub(super) fn bytes(&self) -> Option<&[u8]> {
        match &self.data {
            SourceData::Memory(bytes) => Some(bytes),
            SourceData::File(_) => None,
        }
    }

    pub(super) fn analyze_ranges(
        &self,
        input_set: &InputSet,
        source_index: usize,
        options: l2_workbench::artifact::ArtifactAnalysisOptions,
        job: &Job,
    ) -> Result<l2_workbench::artifact::ArtifactAnalysis, Box<dyn Error>> {
        let SourceData::File(source) = &self.data else {
            return Err(invalid_input("source is not range-backed"));
        };
        let spec = input_set
            .sources
            .get(source_index)
            .ok_or_else(|| invalid_input("range source index is missing"))?;
        let mut file = open_identity_source(input_set, spec)?;
        if metadata_fingerprint(&file.metadata()?) != source.metadata {
            return Err(invalid_input(
                "input artifact changed before range analysis",
            ));
        }
        file.seek(SeekFrom::Start(0))?;
        let mut reader = CancellableReader::new(file, job);
        let report = l2_workbench::artifact::analyze_artifacts_from_reader(
            &mut reader,
            source.length,
            options,
        )?;
        let file = reader.into_inner();
        if metadata_fingerprint(&file.metadata()?) != source.metadata
            || report.source_sha256 != self.sha256
        {
            return Err(invalid_input(
                "input artifact changed during range analysis",
            ));
        }
        Ok(report)
    }
}

pub(super) struct CancellableReader<'a, R> {
    inner: R,
    job: &'a Job,
}

impl<'a, R> CancellableReader<'a, R> {
    pub(super) const fn new(inner: R, job: &'a Job) -> Self {
        Self { inner, job }
    }

    fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for CancellableReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        const MAX_READ_BYTES: usize = 64 * 1024;
        self.job.check_cancelled().map_err(io::Error::other)?;
        let length = buffer.len().min(MAX_READ_BYTES);
        let part = buffer
            .get_mut(..length)
            .ok_or_else(|| io::Error::other("input read buffer is invalid"))?;
        self.inner.read(part)
    }
}

impl<R: MetadataReader> MetadataReader for CancellableReader<'_, R> {
    fn file_metadata(&self) -> io::Result<Metadata> {
        self.inner.file_metadata()
    }
}

/// A bounded local hint; only the ordered full digest proves source content identity
pub(super) struct FingerprintedSources {
    pub(super) identity: SourceIdentity,
    pub(super) labels: Vec<String>,
    pub(super) total_bytes: u64,
}

#[derive(Serialize)]
struct SampledSource<'a> {
    label: &'a str,
    expected_length: Option<usize>,
    expected_sha256: Option<&'a str>,
    fingerprint: SourceFingerprint,
}

#[derive(Deserialize)]
struct InputManifest {
    schema_version: u32,
    artifacts: Vec<InputManifestArtifact>,
}

#[derive(Deserialize)]
struct InputManifestArtifact {
    file: String,
    byte_length: usize,
    #[serde(default)]
    sha256: Option<String>,
}

pub(super) fn prepare_input_set(path: &Path) -> Result<InputSet, Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(invalid_input("input path must not be a symbolic link"));
    }
    if metadata.is_dir() {
        return prepare_export_directory(path);
    }
    if !metadata.is_file() {
        return Err(invalid_input(
            "input must be a regular file or artifact directory",
        ));
    }

    let label = path.file_name().map_or_else(
        || String::from("input.bin"),
        |name| name.to_string_lossy().into_owned(),
    );
    Ok(InputSet {
        sources: vec![InputSpec {
            label,
            path: InputPath::Direct(path.to_owned()),
            expected_length: None,
            expected_sha256: None,
        }],
        manifest_sha256: None,
        #[cfg(target_os = "linux")]
        directory: None,
        #[cfg(not(target_os = "linux"))]
        directory: None,
    })
}

fn prepare_export_directory(path: &Path) -> Result<InputSet, Box<dyn Error>> {
    #[cfg(target_os = "linux")]
    let directory = DirectoryAnchor::open(path)?;
    #[cfg(not(target_os = "linux"))]
    let directory = path.to_owned();

    let (manifest_bytes, manifest_sha256) =
        read_directory_member(&directory, "manifest.json", MAX_MANIFEST_BYTES)?;
    let manifest: InputManifest = serde_json::from_slice(&manifest_bytes)?;
    if manifest.schema_version != 1 {
        return Err(invalid_input(
            "artifact manifest schema version is unsupported",
        ));
    }
    if manifest.artifacts.is_empty() || manifest.artifacts.len() > MAX_MANIFEST_ARTIFACTS {
        return Err(invalid_input(
            "artifact manifest entry count is outside its supported range",
        ));
    }

    let mut seen_files = HashSet::new();
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(manifest.artifacts.len())
        .map_err(|_| io::Error::other("manifest source allocation failed"))?;
    for artifact in manifest.artifacts {
        if !is_safe_flat_file_name(&artifact.file) {
            return Err(invalid_input(
                "artifact manifest contains an unsafe file name",
            ));
        }
        if !seen_files.insert(artifact.file.clone()) {
            return Err(invalid_input("artifact manifest repeats a file name"));
        }
        sources.push(InputSpec {
            label: artifact.file.clone(),
            path: InputPath::ManifestMember(artifact.file),
            expected_length: Some(artifact.byte_length),
            expected_sha256: artifact.sha256,
        });
    }
    Ok(InputSet {
        sources,
        manifest_sha256: Some(manifest_sha256),
        #[cfg(target_os = "linux")]
        directory: Some(directory),
        #[cfg(not(target_os = "linux"))]
        directory: Some(directory),
    })
}

pub(super) fn ensure_manifest_unchanged(
    input_set: &InputSet,
    job: &Job,
) -> Result<(), Box<dyn Error>> {
    let Some(expected) = &input_set.manifest_sha256 else {
        return Ok(());
    };
    #[cfg(target_os = "linux")]
    if let Some(directory) = &input_set.directory {
        directory.check_location()?;
    }
    let file = read_directory_file(input_set, "manifest.json")?;
    let opened = metadata_fingerprint(&file.file_metadata()?);
    let (_, digest) = read_snapshot(
        CancellableReader::new(file, job),
        MAX_MANIFEST_BYTES,
        None,
        None,
    )?;
    let named = read_directory_file(input_set, "manifest.json")?;
    if &digest != expected || opened != metadata_fingerprint(&named.file_metadata()?) {
        return Err(invalid_input(
            "input artifact manifest changed during refinement",
        ));
    }
    #[cfg(target_os = "linux")]
    if let Some(directory) = &input_set.directory {
        directory.check_location()?;
    }
    Ok(())
}

pub(super) fn read_sources(
    input_set: &InputSet,
    total_limit: usize,
    per_file_limit: usize,
    job: &Job,
) -> Result<Vec<LoadedSource>, Box<dyn Error>> {
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(input_set.sources.len())
        .map_err(|_| io::Error::other("input source allocation failed"))?;
    let mut total_bytes = 0_usize;
    for spec in &input_set.sources {
        job.check_cancelled()?;
        let mut file = open_identity_source(input_set, spec)?;
        let metadata = file.metadata()?;
        let length = checked_length(&metadata, spec.expected_length, usize::MAX)?;
        if length > per_file_limit {
            // Record the digest and file identity, then close the source until analysis
            let SourceIdentity::Sha256(digest) =
                SourceIdentity::sha256_open_file_with_check(&mut file, || {
                    job.check_cancelled().map_err(io::Error::other)
                })?
            else {
                return Err(invalid_input("source digest is unavailable"));
            };
            if spec
                .expected_sha256
                .as_ref()
                .is_some_and(|expected| expected != &digest)
            {
                return Err(invalid_input("artifact hash does not match its manifest"));
            }
            let fingerprint = metadata_fingerprint(&metadata);
            if fingerprint != metadata_fingerprint(&file.metadata()?) {
                return Err(invalid_input("input artifact changed while it was hashed"));
            }
            sources.push(LoadedSource {
                label: spec.label.clone(),
                sha256: digest,
                data: SourceData::File(RangeSource {
                    length,
                    metadata: fingerprint,
                }),
            });
        } else {
            total_bytes = checked_total(total_bytes, length, total_limit)?;
            let (bytes, digest) = read_snapshot(
                CancellableReader::new(file, job),
                per_file_limit,
                spec.expected_length,
                spec.expected_sha256.as_deref(),
            )?;
            sources.push(LoadedSource {
                label: spec.label.clone(),
                sha256: digest,
                data: SourceData::Memory(bytes),
            });
        }
    }
    Ok(sources)
}

pub(super) fn fingerprint_sources(
    input_set: &InputSet,
    total_limit: usize,
    per_file_limit: usize,
    job: &Job,
) -> Result<FingerprintedSources, Box<dyn Error>> {
    let mut sampled = Vec::new();
    let mut labels = Vec::new();
    sampled.try_reserve_exact(input_set.sources.len())?;
    labels.try_reserve_exact(input_set.sources.len())?;
    let mut total = 0_u64;
    let mut memory_bytes = 0_usize;
    for spec in &input_set.sources {
        job.check_cancelled()?;
        let mut file = open_identity_source(input_set, spec)?;
        let length = checked_source_length(&file, spec, usize::MAX)?;
        if length <= per_file_limit {
            memory_bytes = checked_total(memory_bytes, length, total_limit)?;
        }
        total = total
            .checked_add(u64::try_from(length)?)
            .ok_or_else(|| invalid_input("input source byte total overflows"))?;
        let fingerprint = SourceFingerprint::fast_open_file(&mut file)?;
        if fingerprint.size_bytes != u64::try_from(length)? {
            return Err(invalid_input(
                "input artifact changed while it was fingerprinted",
            ));
        }
        sampled.push(SampledSource {
            label: &spec.label,
            expected_length: spec.expected_length,
            expected_sha256: spec.expected_sha256.as_deref(),
            fingerprint,
        });
        labels.push(spec.label.clone());
    }

    let mut fingerprint = sampled
        .first()
        .ok_or_else(|| invalid_input("input has no sources"))?
        .fingerprint
        .sample_hint();
    fingerprint.size_bytes = total;
    // The set hint binds ordering, labels, declarations, metadata, and bounded samples
    fingerprint.sample_sha256 = sha256(&serde_json::to_vec(&(
        "l2solver-refine-sample-set-v1",
        &sampled,
    ))?);
    Ok(FingerprintedSources {
        identity: SourceIdentity::Fast(fingerprint),
        labels,
        total_bytes: total,
    })
}

pub(super) fn strong_source_identity(
    input_set: &InputSet,
    total_limit: usize,
    per_file_limit: usize,
    job: &Job,
) -> Result<SourceIdentity, Box<dyn Error>> {
    let mut digests = Vec::new();
    digests.try_reserve_exact(input_set.sources.len())?;
    let mut total = 0_usize;
    for spec in &input_set.sources {
        job.check_cancelled()?;
        let mut file = open_identity_source(input_set, spec)?;
        let length = checked_source_length(&file, spec, usize::MAX)?;
        if length <= per_file_limit {
            total = checked_total(total, length, total_limit)?;
        }
        let SourceIdentity::Sha256(digest) =
            SourceIdentity::sha256_open_file_with_check(&mut file, || {
                job.check_cancelled().map_err(io::Error::other)
            })?
        else {
            return Err(invalid_input("source digest is unavailable"));
        };
        if spec
            .expected_sha256
            .as_ref()
            .is_some_and(|expected| expected != &digest)
        {
            return Err(invalid_input("artifact hash does not match its manifest"));
        }
        if checked_source_length(&file, spec, usize::MAX)? != length {
            return Err(invalid_input("input artifact changed while it was hashed"));
        }
        digests.push((u64::try_from(length)?, digest));
    }
    let digest = super::output::refine_source_identity_sha256(
        digests
            .iter()
            .map(|(length, digest)| (*length, digest.as_str())),
    )?;
    Ok(SourceIdentity::from_sha256(digest)?)
}

fn checked_source_length(
    file: &File,
    spec: &InputSpec,
    maximum: usize,
) -> Result<usize, Box<dyn Error>> {
    checked_length(&file.metadata()?, spec.expected_length, maximum)
}

fn checked_length(
    metadata: &Metadata,
    expected_length: Option<usize>,
    maximum: usize,
) -> Result<usize, Box<dyn Error>> {
    if !metadata.is_file() {
        return Err(invalid_input("input artifact is not a regular file"));
    }
    let length = usize::try_from(metadata.len())?;
    if length > maximum {
        return Err(invalid_input(
            "input artifact exceeds the configured analysis file limit",
        ));
    }
    if expected_length.is_some_and(|expected| expected != length) {
        return Err(invalid_input("artifact length does not match its manifest"));
    }
    Ok(length)
}

fn checked_total(total: usize, length: usize, maximum: usize) -> Result<usize, Box<dyn Error>> {
    let total = total
        .checked_add(length)
        .ok_or_else(|| invalid_input("input source byte total overflows"))?;
    if total > maximum {
        return Err(invalid_input(
            "manifest input bytes exceed the configured recovery memory limit",
        ));
    }
    Ok(total)
}

fn open_identity_source(input_set: &InputSet, spec: &InputSpec) -> Result<File, Box<dyn Error>> {
    match &spec.path {
        InputPath::Direct(path) => Ok(crate::input::regular_no_follow(path)?.into_inner()),
        InputPath::ManifestMember(name) => {
            #[cfg(target_os = "linux")]
            {
                read_directory_file(input_set, name)
            }
            #[cfg(not(target_os = "linux"))]
            {
                Ok(read_directory_file(input_set, name)?.into_inner())
            }
        }
    }
}

pub(super) fn read_snapshot(
    mut file: impl Read + MetadataReader,
    maximum: usize,
    expected_length: Option<usize>,
    expected_sha256: Option<&str>,
) -> Result<(Vec<u8>, String), Box<dyn Error>> {
    let before = file.file_metadata()?;
    let length = checked_length(&before, expected_length, maximum)?;

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| io::Error::other("input artifact allocation failed"))?;
    let sentinel = u64::try_from(length)?
        .checked_add(1)
        .ok_or_else(|| invalid_input("input artifact length exceeds the supported range"))?;
    (&mut file).take(sentinel).read_to_end(&mut bytes)?;
    if bytes.len() != length {
        return Err(invalid_input(
            "input artifact length changed while it was read",
        ));
    }
    let after = file.file_metadata()?;
    if metadata_fingerprint(&before) != metadata_fingerprint(&after) {
        return Err(invalid_input("input artifact changed while it was read"));
    }
    let digest = sha256(&bytes);
    if expected_sha256.is_some_and(|expected| expected != digest) {
        return Err(invalid_input("artifact hash does not match its manifest"));
    }
    Ok((bytes, digest))
}

pub(super) trait MetadataReader {
    fn file_metadata(&self) -> io::Result<Metadata>;
}

impl MetadataReader for crate::input::InputFile {
    fn file_metadata(&self) -> io::Result<Metadata> {
        self.metadata()
    }
}

impl MetadataReader for File {
    fn file_metadata(&self) -> io::Result<Metadata> {
        self.metadata()
    }
}

#[derive(PartialEq, Eq)]
struct MetadataFingerprint {
    length: u64,
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

fn metadata_fingerprint(metadata: &Metadata) -> MetadataFingerprint {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    MetadataFingerprint {
        length: metadata.len(),
        #[cfg(not(unix))]
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        modified_seconds: metadata.mtime(),
        #[cfg(unix)]
        modified_nanoseconds: metadata.mtime_nsec(),
        #[cfg(unix)]
        changed_seconds: metadata.ctime(),
        #[cfg(unix)]
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[cfg(target_os = "linux")]
impl DirectoryAnchor {
    fn open(path: &Path) -> Result<Self, Box<dyn Error>> {
        use rustix::fs::{Mode, OFlags, open};
        use std::os::unix::fs::MetadataExt;

        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        let opened = File::from(descriptor.try_clone()?).metadata()?;
        let named = fs::symlink_metadata(path)?;
        if !named.is_dir() || opened.dev() != named.dev() || opened.ino() != named.ino() {
            return Err(invalid_input("input directory changed while it was opened"));
        }
        Ok(Self {
            descriptor,
            path: path.to_owned(),
            device: opened.dev(),
            inode: opened.ino(),
        })
    }

    fn check_location(&self) -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::MetadataExt;
        let named = fs::symlink_metadata(&self.path)?;
        if !named.is_dir() || named.dev() != self.device || named.ino() != self.inode {
            return Err(invalid_input("input directory changed during refinement"));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn read_directory_member(
    directory: &DirectoryAnchor,
    name: &str,
    maximum: usize,
) -> Result<(Vec<u8>, String), Box<dyn Error>> {
    read_snapshot(open_directory_member(directory, name)?, maximum, None, None)
}

#[cfg(not(target_os = "linux"))]
fn read_directory_member(
    directory: &PathBuf,
    name: &str,
    maximum: usize,
) -> Result<(Vec<u8>, String), Box<dyn Error>> {
    let path = directory.join(name);
    read_snapshot(crate::input::regular_no_follow(&path)?, maximum, None, None)
}

#[cfg(target_os = "linux")]
fn read_directory_file(input_set: &InputSet, name: &str) -> Result<File, Box<dyn Error>> {
    let directory = input_set
        .directory
        .as_ref()
        .ok_or_else(|| invalid_input("manifest member has no anchored input directory"))?;
    open_directory_member(directory, name).map_err(Into::into)
}

#[cfg(not(target_os = "linux"))]
fn read_directory_file(
    input_set: &InputSet,
    name: &str,
) -> Result<crate::input::InputFile, Box<dyn Error>> {
    let directory = input_set
        .directory
        .as_ref()
        .ok_or_else(|| invalid_input("manifest member has no input directory"))?;
    let path = directory.join(name);
    Ok(crate::input::regular_no_follow(&path)?)
}

#[cfg(target_os = "linux")]
fn open_directory_member(directory: &DirectoryAnchor, name: &str) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags, openat};
    use std::ffi::OsStr;

    let descriptor = openat(
        &directory.descriptor,
        OsStr::new(name),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    Ok(File::from(descriptor))
}
