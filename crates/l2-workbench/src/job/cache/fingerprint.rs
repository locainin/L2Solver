#[cfg(not(unix))]
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};
use std::{
    fs::{File, Metadata},
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hashing::is_sha256_digest;

use super::error::{CacheError, Result};

const SAMPLE_BYTES: u64 = 64 * 1024;
const WHOLE_FILE_SAMPLE_LIMIT: u64 = SAMPLE_BYTES * 3;
const READ_BUFFER_BYTES: usize = 64 * 1024;

/// A timestamp with second and nanosecond parts
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct FileTimestamp {
    /// Whole seconds from the Unix epoch
    pub seconds: i64,
    /// Additional nanoseconds within the second
    pub nanoseconds: u32,
}

/// Fast source identity from file metadata and deterministic content samples
///
/// This fingerprint is a cache hint. Its bounded samples do not prove that every source byte
/// is unchanged; use [`SourceIdentity::sha256_file`] when a strong content identity is needed
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct SourceFingerprint {
    /// Source length in bytes
    pub size_bytes: u64,
    /// Unix device number when the platform provides one
    pub device_id: Option<u64>,
    /// Filesystem object number when the platform provides one
    pub file_id: Option<u64>,
    /// Modification time when the platform provides one
    pub modified: Option<FileTimestamp>,
    /// Metadata change time when the platform provides one
    pub changed: Option<FileTimestamp>,
    /// SHA-256 of the bounded sample bytes and their offsets
    pub sample_sha256: String,
}

/// Source identity used as an input to a stage key
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SourceIdentity {
    /// Metadata and bounded content samples, suitable for quick local invalidation
    Fast(SourceFingerprint),
    /// Full-file SHA-256, suitable for content identity across moves and renames
    Sha256(String),
    /// No complete content identity was computed for this source set
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MetadataIdentity {
    size_bytes: u64,
    device_id: Option<u64>,
    file_id: Option<u64>,
    modified: Option<FileTimestamp>,
    changed: Option<FileTimestamp>,
}

impl SourceFingerprint {
    /// Return the exact maximum content bytes read by one fast source sample
    #[must_use]
    pub const fn sample_read_bytes(length: u64) -> u64 {
        if length <= WHOLE_FILE_SAMPLE_LIMIT {
            length
        } else {
            WHOLE_FILE_SAMPLE_LIMIT
        }
    }

    /// Calculates a bounded metadata and sample fingerprint for a regular file
    ///
    /// Small files are sampled in full. Larger files are sampled at the beginning, middle,
    /// and end. The total content read is bounded to 192 KiB
    ///
    /// # Errors
    /// Returns an error for non-regular, symlinked, unreadable, or changing files
    pub fn fast(path: impl AsRef<Path>) -> Result<Self> {
        Self::fast_with_observer(path, |_| Ok(()))
    }

    /// Fingerprint a protected source path and observe each completed content read
    ///
    /// The observer runs after a read returns and cannot interrupt a blocked read
    ///
    /// # Errors
    /// Returns an error for an unsafe, unreadable, changing, or cancelled source
    pub fn fast_with_observer(
        path: impl AsRef<Path>,
        observe: impl FnMut(usize) -> std::io::Result<()>,
    ) -> Result<Self> {
        let mut file = open_source(path.as_ref())?;
        Self::fast_open_file_inner(&mut file, None, observe)
    }

    /// Fingerprint an already opened regular file using bounded content samples
    ///
    /// The caller must open the file with the required path and symlink protections.
    /// This operation changes its cursor and requires exclusive use of that cursor.
    ///
    /// # Errors
    /// Returns an error for non-regular, unreadable, or changing files
    pub fn fast_open_file(file: &mut File) -> Result<Self> {
        Self::fast_open_file_inner(file, None, |_| Ok(()))
    }

    /// Fingerprint an open file only if its length matches an admitted read reservation
    ///
    /// The observer receives each number of bytes actually returned by a source read
    ///
    /// # Errors
    /// Returns an error for a non-regular, unreadable, changing, or differently sized source
    pub fn fast_open_file_with_expected_length_and_observer(
        file: &mut File,
        length: u64,
        observe: impl FnMut(usize) -> std::io::Result<()>,
    ) -> Result<Self> {
        Self::fast_open_file_inner(file, Some(length), observe)
    }

    fn fast_open_file_inner(
        file: &mut File,
        expected_length: Option<u64>,
        mut observe: impl FnMut(usize) -> std::io::Result<()>,
    ) -> Result<Self> {
        let before = file.metadata()?;
        if !before.is_file() {
            return Err(CacheError::UnsafePath("source is not a regular file"));
        }
        let identity = metadata_identity(&before);
        if expected_length.is_some_and(|length| length != identity.size_bytes) {
            return Err(CacheError::SourceChanged);
        }
        let sample_sha256 = sample_digest(
            &mut ObservedReader {
                inner: &mut *file,
                observe: &mut observe,
            },
            identity.size_bytes,
        )?;
        let after = file.metadata()?;
        if identity != metadata_identity(&after) {
            return Err(CacheError::SourceChanged);
        }

        Ok(Self {
            size_bytes: identity.size_bytes,
            device_id: identity.device_id,
            file_id: identity.file_id,
            modified: identity.modified,
            changed: identity.changed,
            sample_sha256,
        })
    }

    /// Returns the bounded size and sample hint without file metadata
    ///
    /// The result remains a fast fingerprint and does not provide content identity. It can
    /// locate a likely moved copy before a caller opts into a full SHA-256 digest
    #[must_use]
    pub fn sample_hint(&self) -> Self {
        Self {
            size_bytes: self.size_bytes,
            device_id: None,
            file_id: None,
            modified: None,
            changed: None,
            sample_sha256: self.sample_sha256.clone(),
        }
    }
}

impl SourceIdentity {
    /// Validates and stores an existing lowercase SHA-256 digest
    ///
    /// # Errors
    /// Returns an error when the digest is not 64 lowercase hexadecimal characters
    pub fn from_sha256(digest: impl Into<String>) -> Result<Self> {
        let digest = digest.into();
        if !is_sha256_digest(&digest) {
            return Err(CacheError::InvalidInput(
                "source SHA-256 must be lowercase hexadecimal",
            ));
        }
        Ok(Self::Sha256(digest))
    }

    /// Reads a source file once and calculates its full SHA-256 identity
    ///
    /// # Errors
    /// Returns an error for non-regular, symlinked, unreadable, or changing files
    pub fn sha256_file(path: impl AsRef<Path>) -> Result<Self> {
        Self::sha256_file_with_check_and_observer(path, || Ok(()), |_| Ok(()))
    }

    /// Hash a protected source path while checking cancellation and observing reads
    ///
    /// The check runs before every bounded read and the observer receives the bytes read
    /// Neither callback can interrupt a read that is already blocked in the filesystem
    ///
    /// # Errors
    /// Returns an error for an unsafe, unreadable, changing, or cancelled source
    pub fn sha256_file_with_check_and_observer(
        path: impl AsRef<Path>,
        check: impl FnMut() -> std::io::Result<()>,
        observe: impl FnMut(usize) -> std::io::Result<()>,
    ) -> Result<Self> {
        let mut file = open_source(path.as_ref())?;
        Self::sha256_open_file_inner(&mut file, None, check, observe)
    }

    /// Calculate the full digest of an already opened regular file
    ///
    /// The caller must open the file with the required path and symlink protections.
    /// This operation changes its cursor and requires exclusive use of that cursor.
    ///
    /// # Errors
    /// Returns an error for non-regular, unreadable, or changing files
    pub fn sha256_open_file(file: &mut File) -> Result<Self> {
        Self::sha256_open_file_with_check(file, || Ok(()))
    }

    /// Calculate an opened file's digest while checking for cancellation between reads
    ///
    /// The caller must enforce path protections and ensure exclusive use of the file cursor.
    /// The check runs before each bounded read and may stop the operation with an I/O error.
    ///
    /// # Errors
    /// Returns an error for non-regular, unreadable, changing, or cancelled files
    pub fn sha256_open_file_with_check(
        file: &mut File,
        check: impl FnMut() -> std::io::Result<()>,
    ) -> Result<Self> {
        Self::sha256_open_file_inner(file, None, check, |_| Ok(()))
    }

    /// Hash an open file only if its length matches an admitted read reservation
    ///
    /// The observer receives each number of bytes actually returned by a source read
    ///
    /// # Errors
    /// Returns an error for a non-regular, unreadable, changing, cancelled, or differently sized source
    pub fn sha256_open_file_with_expected_length_and_check(
        file: &mut File,
        length: u64,
        check: impl FnMut() -> std::io::Result<()>,
        observe: impl FnMut(usize) -> std::io::Result<()>,
    ) -> Result<Self> {
        Self::sha256_open_file_inner(file, Some(length), check, observe)
    }

    fn sha256_open_file_inner(
        file: &mut File,
        expected_length: Option<u64>,
        mut check: impl FnMut() -> std::io::Result<()>,
        mut observe: impl FnMut(usize) -> std::io::Result<()>,
    ) -> Result<Self> {
        let before = file.metadata()?;
        if !before.is_file() {
            return Err(CacheError::UnsafePath("source is not a regular file"));
        }
        let identity = metadata_identity(&before);
        if expected_length.is_some_and(|length| length != identity.size_bytes) {
            return Err(CacheError::SourceChanged);
        }
        file.seek(SeekFrom::Start(0))?;
        let digest = full_digest(
            &mut ObservedReader {
                inner: &mut *file,
                observe: &mut observe,
            },
            identity.size_bytes,
            &mut check,
        )?;
        let after = file.metadata()?;
        if identity != metadata_identity(&after) {
            return Err(CacheError::SourceChanged);
        }
        Ok(Self::Sha256(digest))
    }

    pub(super) fn validate(&self) -> Result<()> {
        let digest = match self {
            Self::Fast(fingerprint) => &fingerprint.sample_sha256,
            Self::Sha256(digest) => digest,
            Self::Unavailable => {
                return Err(CacheError::InvalidInput("source identity is unavailable"));
            }
        };
        if !is_sha256_digest(digest) {
            return Err(CacheError::InvalidInput(
                "source identity must contain lowercase SHA-256 hexadecimal",
            ));
        }
        Ok(())
    }
}

fn open_source(path: &Path) -> Result<File> {
    #[cfg(unix)]
    let file = File::from(
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?,
    );
    #[cfg(not(unix))]
    let file = {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(CacheError::UnsafePath("source file is a symlink"));
        }
        File::open(path)?
    };

    if !file.metadata()?.is_file() {
        return Err(CacheError::UnsafePath("source is not a regular file"));
    }
    Ok(file)
}

struct ObservedReader<'a, R, O> {
    inner: &'a mut R,
    observe: &'a mut O,
}

impl<R: Read, O: FnMut(usize) -> std::io::Result<()>> Read for ObservedReader<'_, R, O> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buffer)?;
        (self.observe)(count)?;
        Ok(count)
    }
}

impl<R: Seek, O> Seek for ObservedReader<'_, R, O> {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(position)
    }
}

fn sample_digest(file: &mut (impl Read + Seek), size_bytes: u64) -> Result<String> {
    // Fixed ranges keep large source reads bounded and repeatable
    let ranges = sample_ranges(size_bytes);
    let mut hasher = Sha256::new();
    let mut buffer =
        vec![0_u8; usize::try_from(SAMPLE_BYTES).map_err(|_| CacheError::SizeOverflow)?];
    for (offset, length) in ranges {
        file.seek(SeekFrom::Start(offset))?;
        hasher.update(offset.to_be_bytes());
        hasher.update(length.to_be_bytes());

        // Whole-file samples can span three read buffers without changing their identity
        let mut remaining = length;
        while remaining > 0 {
            let read_length = remaining.min(SAMPLE_BYTES);
            let count = usize::try_from(read_length).map_err(|_| CacheError::SizeOverflow)?;
            let sample = buffer.get_mut(..count).ok_or(CacheError::SizeOverflow)?;
            if let Err(error) = file.read_exact(sample) {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    return Err(CacheError::SourceChanged);
                }
                return Err(error.into());
            }
            hasher.update(sample);
            remaining -= read_length;
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sample_ranges(size_bytes: u64) -> Vec<(u64, u64)> {
    if size_bytes <= WHOLE_FILE_SAMPLE_LIMIT {
        return vec![(0, size_bytes)];
    }

    let middle = (size_bytes / 2).saturating_sub(SAMPLE_BYTES / 2);
    vec![
        (0, SAMPLE_BYTES),
        (middle, SAMPLE_BYTES),
        (size_bytes - SAMPLE_BYTES, SAMPLE_BYTES),
    ]
}

fn full_digest(
    file: &mut impl Read,
    length: u64,
    check: &mut impl FnMut() -> std::io::Result<()>,
) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; READ_BUFFER_BYTES].into_boxed_slice();
    let buffer_capacity = u64::try_from(READ_BUFFER_BYTES).map_err(|_| CacheError::SizeOverflow)?;
    let mut remaining = length;
    while remaining > 0 {
        check()?;
        let maximum = usize::try_from(remaining.min(buffer_capacity))
            .map_err(|_| CacheError::SizeOverflow)?;
        let part = buffer.get_mut(..maximum).ok_or(CacheError::SizeOverflow)?;
        let count = file.read(part)?;
        if count == 0 {
            return Err(CacheError::SourceChanged);
        }
        hasher.update(buffer.get(..count).ok_or(CacheError::SizeOverflow)?);
        remaining -= u64::try_from(count).map_err(|_| CacheError::SizeOverflow)?;
    }
    check()?;
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(CacheError::SourceChanged);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn metadata_identity(metadata: &Metadata) -> MetadataIdentity {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        MetadataIdentity {
            size_bytes: metadata.len(),
            device_id: Some(metadata.dev()),
            file_id: Some(metadata.ino()),
            modified: Some(FileTimestamp {
                seconds: metadata.mtime(),
                nanoseconds: u32::try_from(metadata.mtime_nsec()).unwrap_or_default(),
            }),
            changed: Some(FileTimestamp {
                seconds: metadata.ctime(),
                nanoseconds: u32::try_from(metadata.ctime_nsec()).unwrap_or_default(),
            }),
        }
    }
    #[cfg(not(unix))]
    {
        MetadataIdentity {
            size_bytes: metadata.len(),
            device_id: None,
            file_id: None,
            modified: metadata.modified().ok().and_then(system_timestamp),
            changed: None,
        }
    }
}

#[cfg(not(unix))]
fn system_timestamp(time: SystemTime) -> Option<FileTimestamp> {
    let (seconds, nanoseconds, negative) = match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => (
            i64::try_from(duration.as_secs()).ok()?,
            duration.subsec_nanos(),
            false,
        ),
        Err(error) => (
            i64::try_from(error.duration().as_secs()).ok()?,
            error.duration().subsec_nanos(),
            true,
        ),
    };
    Some(FileTimestamp {
        seconds: if negative { -seconds } else { seconds },
        nanoseconds,
    })
}
