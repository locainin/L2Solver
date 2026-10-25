//! Secure bounded source admission for standalone files and artifact manifests

use super::invalid_input;
use crate::safe_filename::is_safe_flat_file_name;
use l2_workbench::{job::Job, sha256};
use serde::Deserialize;
use std::{
    collections::HashSet,
    error::Error,
    fs::{self, File, Metadata},
    io::{self, Read},
    path::{Path, PathBuf},
};

const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_MANIFEST_ARTIFACTS: usize = 4_096;

#[cfg(target_os = "linux")]
struct DirectoryAnchor {
    descriptor: rustix::fd::OwnedFd,
}

pub(super) struct InputSet {
    sources: Vec<InputSpec>,
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
    pub(super) bytes: Vec<u8>,
    pub(super) sha256: String,
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

    let manifest_bytes = read_directory_member(&directory, "manifest.json", MAX_MANIFEST_BYTES)?;
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
        #[cfg(target_os = "linux")]
        directory: Some(directory),
        #[cfg(not(target_os = "linux"))]
        directory: Some(directory),
    })
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
        let (bytes, digest) = read_source(input_set, spec, per_file_limit)?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| invalid_input("input source byte total overflows"))?;
        if total_bytes > total_limit {
            return Err(invalid_input(
                "manifest input bytes exceed the configured recovery memory limit",
            ));
        }
        sources.push(LoadedSource {
            label: spec.label.clone(),
            bytes,
            sha256: digest,
        });
    }
    Ok(sources)
}

fn read_source(
    input_set: &InputSet,
    spec: &InputSpec,
    maximum: usize,
) -> Result<(Vec<u8>, String), Box<dyn Error>> {
    let file = match &spec.path {
        InputPath::Direct(path) => crate::input::regular_no_follow(path)?,
        InputPath::ManifestMember(name) => {
            let file = read_directory_file(input_set, name)?;
            return read_snapshot(
                file,
                maximum,
                spec.expected_length,
                spec.expected_sha256.as_deref(),
            );
        }
    };
    read_snapshot(
        file,
        maximum,
        spec.expected_length,
        spec.expected_sha256.as_deref(),
    )
}

pub(super) fn read_snapshot(
    mut file: impl Read + MetadataReader,
    maximum: usize,
    expected_length: Option<usize>,
    expected_sha256: Option<&str>,
) -> Result<(Vec<u8>, String), Box<dyn Error>> {
    let before = file.file_metadata()?;
    if !before.is_file() {
        return Err(invalid_input("input artifact is not a regular file"));
    }
    let length = usize::try_from(before.len())?;
    if length > maximum {
        return Err(invalid_input(
            "input artifact exceeds the configured analysis file limit",
        ));
    }
    if expected_length.is_some_and(|expected| expected != length) {
        return Err(invalid_input("artifact length does not match its manifest"));
    }

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

        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        Ok(Self { descriptor })
    }
}

#[cfg(target_os = "linux")]
fn read_directory_member(
    directory: &DirectoryAnchor,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    read_snapshot(open_directory_member(directory, name)?, maximum, None, None)
        .map(|(bytes, _)| bytes)
}

#[cfg(not(target_os = "linux"))]
fn read_directory_member(
    directory: &PathBuf,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let path = directory.join(name);
    read_snapshot(crate::input::regular_no_follow(&path)?, maximum, None, None)
        .map(|(bytes, _)| bytes)
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
