//! Deterministic, source-only review package creation

#[cfg(unix)]
mod archive;
#[cfg(target_os = "linux")]
mod publish;
mod select;

#[cfg(unix)]
use archive::{build_zip, digest_hex, render_manifest};
#[cfg(target_os = "linux")]
use rustix::fd::OwnedFd;
use std::path::{Path, PathBuf};

pub use select::is_excluded_path;

/// Maximum number of files in one review archive
///
/// Classic ZIP reserves `0xffff` as the ZIP64 entry-count sentinel
pub const MAX_FILES: usize = 65_534;

/// Maximum raw directory entries visited before exclusions and file filtering
pub const MAX_TRAVERSAL_ENTRIES: usize = 262_144;

/// Maximum size of one packaged file
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum aggregate source bytes read for one review archive
pub const MAX_SOURCE_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum final ZIP size
pub const MAX_ARCHIVE_BYTES: usize = 512 * 1024 * 1024;

/// One source file selected for a review archive
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    path: String,
    bytes: Vec<u8>,
    sha256: String,
}

impl Entry {
    /// Return the normalized archive path
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Return the source bytes
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the source-byte count
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    /// Return the lowercase SHA-256 digest of the source bytes
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Package output paths and archive digest
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageResult {
    pub archive: PathBuf,
    pub checksum: PathBuf,
    pub manifest: PathBuf,
    pub archive_sha256: String,
    pub file_count: usize,
}

/// Failure while selecting or publishing a review package
#[derive(Debug)]
pub enum PackageError {
    UnsupportedPlatform,
    InvalidRoot(PathBuf),
    ExistingOutput(PathBuf),
    UnsupportedFilesystem {
        path: PathBuf,
        feature: &'static str,
    },
    SecurePublicationUnavailable,
    PartialPublication {
        published: Vec<PathBuf>,
        failure: String,
    },
    Io(PathBuf, std::io::Error),
    Symlink(PathBuf),
    SpecialFile(PathBuf),
    NonUnicodePath(PathBuf),
    FileTooLarge {
        path: PathBuf,
        size: u64,
        maximum: u64,
    },
    TooManyFiles {
        count: usize,
        maximum: usize,
    },
    TooManyEntries {
        count: usize,
        maximum: usize,
    },
    SourceTooLarge {
        size: u64,
        maximum: u64,
    },
    ArchiveTooLarge {
        size: usize,
        maximum: usize,
    },
    ArchiveFieldOverflow,
}

impl std::fmt::Display for PackageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPlatform => formatter
                .write_str("package collection requires a Unix descriptor-relative filesystem"),
            Self::InvalidRoot(path) => write!(
                formatter,
                "workspace root is not a directory: {}",
                path.display()
            ),
            Self::ExistingOutput(path) => write!(
                formatter,
                "refusing to overwrite existing output: {}",
                path.display()
            ),
            Self::UnsupportedFilesystem { path, feature } => write!(
                formatter,
                "filesystem does not support secure {feature}: {}",
                path.display()
            ),
            Self::SecurePublicationUnavailable => formatter
                .write_str("secure publication requires a verified /proc/self/fd exact-inode link"),
            Self::PartialPublication { published, failure } => write!(
                formatter,
                "review publication stopped after {} complete output(s); published outputs were retained to avoid unsafe pathname rollback: {failure}",
                published.len()
            ),
            Self::Io(path, source) => write!(formatter, "{}: {source}", path.display()),
            Self::Symlink(path) => {
                write!(formatter, "refusing to package symlink: {}", path.display())
            }
            Self::SpecialFile(path) => write!(
                formatter,
                "refusing to package non-regular file: {}",
                path.display()
            ),
            Self::NonUnicodePath(path) => write!(
                formatter,
                "archive path is not valid Unicode: {}",
                path.display()
            ),
            Self::FileTooLarge {
                path,
                size,
                maximum,
            } => write!(
                formatter,
                "file {} is {size} bytes, above package limit {maximum}",
                path.display()
            ),
            Self::TooManyFiles { count, maximum } => write!(
                formatter,
                "package contains {count} files, above limit {maximum}"
            ),
            Self::TooManyEntries { count, maximum } => write!(
                formatter,
                "package traversal encountered {count} entries, above limit {maximum}"
            ),
            Self::SourceTooLarge { size, maximum } => write!(
                formatter,
                "source bytes {size} exceed package limit {maximum}"
            ),
            Self::ArchiveTooLarge { size, maximum } => write!(
                formatter,
                "archive size {size} exceeds package limit {maximum}"
            ),
            Self::ArchiveFieldOverflow => {
                formatter.write_str("ZIP metadata exceeds its bounded field width")
            }
        }
    }
}

impl std::error::Error for PackageError {}

/// Collect a sorted, bounded set of source entries without following symlinks
///
/// Unix platforms use descriptor-relative traversal for the root, every parent
/// directory, and every file handle. Other platforms fail closed because a
/// path-based fallback cannot uphold the no-symlink contract.
///
/// # Errors
///
/// Returns an error for an invalid root, symlink or special file, a path that
/// cannot be represented safely in the archive, an unsupported platform, or a
/// package over a size/count limit
pub fn collect_entries(root: &Path) -> Result<Vec<Entry>, PackageError> {
    select::collect_entries(root)
}

/// Create `review-N.zip`, its SHA-256 file, and its deterministic manifest
///
/// # Errors
///
/// Returns an error when package selection fails, the archive exceeds its
/// bounds, or any output already exists
pub fn create_review(root: &Path, number: u32) -> Result<PackageResult, PackageError> {
    #[cfg(target_os = "linux")]
    {
        create_review_unix(root, number)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, number);
        Err(PackageError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
fn create_review_unix(root: &Path, number: u32) -> Result<PackageResult, PackageError> {
    let collected = select::collect_entries_pinned(root)?;
    let archive_bytes = build_zip(&collected.entries)?;
    let archive_sha256 = digest_hex(&archive_bytes);
    publish_review(
        root,
        number,
        &collected.root_fd,
        &collected.entries,
        &archive_bytes,
        &archive_sha256,
    )
}

#[cfg(target_os = "linux")]
fn publish_review(
    root: &Path,
    number: u32,
    root_fd: &OwnedFd,
    entries: &[Entry],
    archive_bytes: &[u8],
    archive_sha256: &str,
) -> Result<PackageResult, PackageError> {
    let archive_name = PathBuf::from(format!("review-{number}.zip"));
    let checksum_name = PathBuf::from(format!("review-{number}.zip.sha256"));
    let manifest_name = PathBuf::from(format!("review-{number}.manifest"));
    let archive = root.join(&archive_name);
    let checksum = root.join(&checksum_name);
    let manifest = root.join(&manifest_name);
    let manifest_text = render_manifest(number, entries, archive_sha256);
    let checksum_text = format!("{archive_sha256}  review-{number}.zip\n");
    let outputs = [
        (&archive_name, &archive, archive_bytes),
        (&checksum_name, &checksum, checksum_text.as_bytes()),
        (&manifest_name, &manifest, manifest_text.as_bytes()),
    ];
    let destinations = outputs
        .iter()
        .map(|(name, display_path, _)| (name.as_path(), display_path.as_path()))
        .collect::<Vec<_>>();
    publish::preflight_outputs(root_fd, &destinations)?;

    // Stage every complete inode before making the first directory entry visible
    let mut staged = Vec::with_capacity(outputs.len());
    for (name, display_path, bytes) in outputs {
        staged.push(publish::stage_output(root_fd, name, display_path, bytes)?);
    }
    let mut published = Vec::new();
    for (output, (_, display_path)) in staged.iter().zip(&destinations) {
        if let Err(error) = publish::publish_output(root_fd, output) {
            if published.is_empty() {
                return Err(error);
            }
            return Err(PackageError::PartialPublication {
                published,
                failure: error.to_string(),
            });
        }
        published.push((*display_path).to_owned());
    }
    if let Err(error) = publish::sync_parent(root_fd, root) {
        return Err(PackageError::PartialPublication {
            published,
            failure: error.to_string(),
        });
    }
    Ok(PackageResult {
        archive,
        checksum,
        manifest,
        archive_sha256: archive_sha256.to_owned(),
        file_count: entries.len(),
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    include!("../../tests/package/publication.rs");
}
