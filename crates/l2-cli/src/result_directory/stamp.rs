use crate::publish::directory::PreparedDirectoryReplacement;
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
    pub file: String,
    /// File size in bytes
    pub byte_length: u64,
    /// SHA-256 available from the manifest or calculated once for strict verification
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
        artifact: bool,
    ) -> io::Result<Self> {
        let path = directory.join(file_name);
        let mut file = open_regular_path(&path)?;
        let before = file.metadata()?;
        let before_stamp = metadata_stamp(file_name.to_owned(), None, &before);
        let sha256 = match (manifest_sha256, artifact) {
            (Some(digest), _) => Some(digest.to_owned()),
            (None, true) => Some(hash_file(&mut file)?),
            (None, false) => None,
        };
        let after = file.metadata()?;
        let after_stamp = metadata_stamp(file_name.to_owned(), sha256.clone(), &after);
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
    ) -> io::Result<()> {
        let mut file = prepared.open_file(&self.file)?;
        let before = file.metadata()?;
        let current = metadata_stamp(self.file.clone(), self.sha256.clone(), &before);
        if current.byte_length != self.byte_length {
            return Err(changed_output(&self.file));
        }
        if !strict && !same_fast_metadata(self, &current) {
            return Err(changed_output(&self.file));
        }
        if strict && let Some(expected_sha256) = &self.sha256 {
            let digest = hash_file(&mut file)?;
            let after = file.metadata()?;
            let after_stamp = metadata_stamp(self.file.clone(), Some(digest.clone()), &after);
            if &digest != expected_sha256
                || !single_link(&after)
                || !same_fast_metadata(&current, &after_stamp)
            {
                return Err(changed_output(&self.file));
            }
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

fn hash_file(file: &mut std::fs::File) -> io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
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
