use crate::publish::PreparedDirectoryReplacement;
use l2_workbench::job::{Counter, Job, MemoryClass, MemoryLease, Phase};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::Metadata,
    io::{self, Read, Seek, SeekFrom},
};

const HASH_BUFFER_BYTES: usize = 64 * 1024;

/// Optional content digest and quick metadata receipt for one published output file
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutputFileStamp {
    /// Safe flat output file name
    #[serde(deserialize_with = "super::bounded::deserialize_file_name")]
    pub file: String,
    /// File size in bytes
    pub byte_length: u64,
    /// SHA-256 from the manifest or publication; absent only for legacy receipts
    #[serde(
        default,
        deserialize_with = "super::bounded::deserialize_optional_sha256"
    )]
    pub sha256: Option<String>,
    /// Device number when the platform exposes one
    pub device_id: Option<u64>,
    /// File identifier when the platform exposes one
    pub file_id: Option<u64>,
    /// Modification time in seconds since the Unix epoch when available
    pub modified_seconds: Option<i64>,
    /// Modification time nanoseconds within its second when available
    pub modified_nanoseconds: Option<u32>,
    /// Metadata change time in seconds since the Unix epoch when available
    pub changed_seconds: Option<i64>,
    /// Metadata change time nanoseconds within its second when available
    pub changed_nanoseconds: Option<u32>,
}

impl OutputFileStamp {
    /// Hash a flat file in a private staging directory before publication
    pub(super) fn capture_path(
        directory: &std::path::Path,
        file_name: &str,
        manifest_sha256: Option<&str>,
        hasher: &mut OutputHasher<'_>,
    ) -> io::Result<Self> {
        hasher.job.check_cancelled().map_err(io::Error::other)?;
        let path = directory.join(file_name);
        let mut file = open_regular_path(&path)?;
        let before = file.metadata()?;
        let before_stamp = metadata_stamp(file_name.to_owned(), None, &before);
        // Reuse the artifact's existing identity when the manifest provides one
        let sha256 = match manifest_sha256 {
            Some(digest) => digest.to_owned(),
            None => hasher.hash_file(&mut file, before.len())?,
        };
        let after = file.metadata()?;
        let after_stamp = metadata_stamp(file_name.to_owned(), Some(sha256), &after);
        let named_after = std::fs::symlink_metadata(&path)?;
        if !same_fast_metadata(&before_stamp, &after_stamp)
            || !single_link(&after)
            || !same_file_identity(&after, &named_after)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "result output changed while its receipt was being written",
            ));
        }
        Ok(after_stamp)
    }

    /// Verify one currently held file using fast metadata or its stored strong digest
    pub(super) fn verify(
        &self,
        prepared: &PreparedDirectoryReplacement,
        strict: bool,
        hasher: &mut OutputHasher<'_>,
    ) -> io::Result<()> {
        hasher.job.check_cancelled().map_err(io::Error::other)?;
        let mut file = prepared.open_file(&self.file)?;
        let before = file.metadata()?;
        let current = metadata_stamp(self.file.clone(), self.sha256.clone(), &before);
        if current.byte_length != self.byte_length {
            return Err(changed_output(&self.file));
        }
        if !strict && !same_fast_metadata(self, &current) {
            return Err(changed_output(&self.file));
        }
        if strict {
            let expected_sha256 = self.sha256.as_ref().ok_or_else(|| {
                super::manifest::actionable_conflict(&format!(
                    "result output has no stored digest: {}",
                    self.file
                ))
            })?;
            let digest = hasher.hash_file(&mut file, before.len())?;
            let after = file.metadata()?;
            let after_stamp = metadata_stamp(self.file.clone(), None, &after);
            if &digest != expected_sha256
                || !single_link(&after)
                || !same_fast_metadata(&current, &after_stamp)
            {
                return Err(changed_output(&self.file));
            }
            // The name must still refer to the file that was just verified
            verify_named_file(prepared, &self.file, &after)?;
        }
        prepared.check_location()?;
        Ok(())
    }
}

pub(super) fn open_regular_path(path: &std::path::Path) -> io::Result<std::fs::File> {
    let before = std::fs::symlink_metadata(path)?;
    if !before.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "result entry is not a regular file",
        ));
    }
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?
    };
    #[cfg(not(unix))]
    let file = std::fs::OpenOptions::new().read(true).open(path)?;

    let opened = file.metadata()?;
    if !opened.is_file() || !single_link(&opened) || !same_file_identity(&opened, &before) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "result entry changed or has multiple links",
        ));
    }
    Ok(file)
}

pub(super) struct OutputHasher<'a> {
    job: &'a Job,
    // Drop the allocation before releasing its shared memory charge
    buffer: Vec<u8>,
    memory: Option<MemoryLease>,
}

impl<'a> OutputHasher<'a> {
    pub(super) const fn new(job: &'a Job) -> Self {
        Self {
            job,
            buffer: Vec::new(),
            memory: None,
        }
    }

    fn hash_file(&mut self, file: &mut std::fs::File, length: u64) -> io::Result<String> {
        self.job.check_cancelled().map_err(io::Error::other)?;
        file.seek(SeekFrom::Start(0))?;
        let mut hasher = Sha256::new();
        if length > 0 {
            self.prepare_buffer()?;
            // Bound the read even if the named file grows while it is being checked
            let mut limited = file.take(length);
            while limited.limit() > 0 {
                self.job.check_cancelled().map_err(io::Error::other)?;
                let read = limited.read(&mut self.buffer)?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "result output became shorter while hashing",
                    ));
                }
                let bytes = u64::try_from(read).map_err(io::Error::other)?;
                self.job
                    .record_work(Phase::Publication, Counter::Bytes, bytes)
                    .map_err(io::Error::other)?;
                let chunk = self
                    .buffer
                    .get(..read)
                    .ok_or_else(|| io::Error::other("file reader returned an oversized chunk"))?;
                hasher.update(chunk);
            }
        }
        self.job.check_cancelled().map_err(io::Error::other)?;
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn prepare_buffer(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            return Ok(());
        }
        // Admit the allocation before reading any output bytes
        let requested = u64::try_from(HASH_BUFFER_BYTES).map_err(io::Error::other)?;
        let mut memory = self
            .job
            .memory_budget()
            .map(|budget| budget.try_reserve(MemoryClass::Publication, requested))
            .transpose()
            .map_err(io::Error::other)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(HASH_BUFFER_BYTES)
            .map_err(io::Error::other)?;
        if let Some(lease) = &mut memory {
            lease
                .try_resize(u64::try_from(buffer.capacity()).map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
        }
        buffer.resize(HASH_BUFFER_BYTES, 0);
        self.buffer = buffer;
        self.memory = memory;
        Ok(())
    }
}

pub(super) fn verify_named_file(
    prepared: &PreparedDirectoryReplacement,
    name: &str,
    held: &Metadata,
) -> io::Result<()> {
    let named = prepared.open_file(name)?.metadata()?;
    let held_stamp = metadata_stamp(name.to_owned(), None, held);
    let named_stamp = metadata_stamp(name.to_owned(), None, &named);
    if !single_link(held)
        || !single_link(&named)
        || !same_file_identity(held, &named)
        || !same_fast_metadata(&held_stamp, &named_stamp)
    {
        return Err(changed_output(name));
    }
    Ok(())
}

fn metadata_stamp(file: String, sha256: Option<String>, metadata: &Metadata) -> OutputFileStamp {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    #[cfg(unix)]
    let (
        device_id,
        file_id,
        modified_seconds,
        modified_nanoseconds,
        changed_seconds,
        changed_nanoseconds,
    ) = (
        Some(metadata.dev()),
        Some(metadata.ino()),
        Some(metadata.mtime()),
        u32::try_from(metadata.mtime_nsec()).ok(),
        Some(metadata.ctime()),
        u32::try_from(metadata.ctime_nsec()).ok(),
    );
    #[cfg(not(unix))]
    let (
        device_id,
        file_id,
        modified_seconds,
        modified_nanoseconds,
        changed_seconds,
        changed_nanoseconds,
    ) = (
        None,
        None,
        modified_time(metadata.modified().ok()).map(|time| time.0),
        modified_time(metadata.modified().ok()).map(|time| time.1),
        None,
        None,
    );

    OutputFileStamp {
        file,
        byte_length: metadata.len(),
        sha256,
        device_id,
        file_id,
        modified_seconds,
        modified_nanoseconds,
        changed_seconds,
        changed_nanoseconds,
    }
}

#[cfg(not(unix))]
fn modified_time(time: Option<std::time::SystemTime>) -> Option<(i64, u32)> {
    let duration = time?.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some((
        i64::try_from(duration.as_secs()).ok()?,
        duration.subsec_nanos(),
    ))
}

fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        left.is_file() && right.is_file() && left.len() == right.len()
    }
}

fn single_link(metadata: &Metadata) -> bool {
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

fn same_fast_metadata(left: &OutputFileStamp, right: &OutputFileStamp) -> bool {
    left.byte_length == right.byte_length
        && left.device_id == right.device_id
        && left.file_id == right.file_id
        && left.modified_seconds == right.modified_seconds
        && left.modified_nanoseconds == right.modified_nanoseconds
        && left.changed_seconds == right.changed_seconds
        && left.changed_nanoseconds == right.changed_nanoseconds
}

fn changed_output(file: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("result output changed after publication: {file}"),
    )
}

#[cfg(test)]
#[path = "../../tests/result_directory/stamp.rs"]
mod tests;
