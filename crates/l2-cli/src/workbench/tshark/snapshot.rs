use super::{model::SourceIdentity, process, secure_files::Workspace};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Instant,
};

pub(super) struct Snapshot {
    pub(super) source_path: PathBuf,
    pub(super) source_file: crate::input::InputFile,
    pub(super) file: File,
    pub(super) path: PathBuf,
    pub(super) identity: SourceIdentity,
}

pub(super) fn snapshot(
    source_path: &Path,
    directory: &Workspace,
    snapshot_name: &str,
    maximum: u64,
    fallback_label: &str,
    deadline: Instant,
) -> Result<Snapshot, Box<dyn Error>> {
    snapshot_with_clock(
        source_path,
        directory,
        snapshot_name,
        maximum,
        fallback_label,
        deadline,
        Instant::now,
    )
}

pub(super) fn snapshot_with_clock(
    source_path: &Path,
    directory: &Workspace,
    snapshot_name: &str,
    maximum: u64,
    fallback_label: &str,
    deadline: Instant,
    mut now: impl FnMut() -> Instant,
) -> Result<Snapshot, Box<dyn Error>> {
    ensure_before_deadline_at(deadline, now())?;
    // Following a path link is safe after the opened target is verified regular
    let mut source_file = crate::input::regular(source_path)?;
    ensure_before_deadline_at(deadline, now())?;
    if source_file.metadata()?.len() > maximum {
        return Err(format!("source exceeds the configured {maximum}-byte input budget").into());
    }
    let snapshot_path = directory.path().join(snapshot_name);
    let mut snapshot_file = directory.create_file(std::ffi::OsStr::new(snapshot_name))?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = crate::input::io_buffer()?;
    loop {
        ensure_before_deadline_at(deadline, now())?;
        let count = source_file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        ensure_before_deadline_at(deadline, now())?;
        length = length
            .checked_add(u64::try_from(count)?)
            .ok_or("source length overflow")?;
        if length > maximum {
            return Err(
                format!("source exceeds the configured {maximum}-byte input budget").into(),
            );
        }
        let bytes = buffer
            .get(..count)
            .ok_or("source read exceeded its fixed buffer")?;
        hasher.update(bytes);
        snapshot_file.write_all(bytes)?;
        ensure_before_deadline_at(deadline, now())?;
    }
    snapshot_file.flush()?;
    ensure_before_deadline_at(deadline, now())?;
    if length != source_file.metadata()?.len() {
        return Err("source changed while its private snapshot was being created".into());
    }
    source_file.seek(SeekFrom::Start(0))?;
    Ok(Snapshot {
        source_path: source_path.to_owned(),
        source_file,
        file: snapshot_file,
        path: snapshot_path,
        identity: SourceIdentity {
            label: super::super::label(source_path, fallback_label).to_owned(),
            length,
            sha256: format!("{:x}", hasher.finalize()),
        },
    })
}

pub(super) fn ensure_before_deadline(deadline: Instant) -> Result<(), process::ProcessError> {
    ensure_before_deadline_at(deadline, Instant::now())
}

fn ensure_before_deadline_at(deadline: Instant, now: Instant) -> Result<(), process::ProcessError> {
    if now >= deadline {
        Err(process::ProcessError::TimedOut)
    } else {
        Ok(())
    }
}

/// Verify both the open source object and its current path against the initial digest
pub(super) fn verify_source_unchanged(
    open_file: &mut (impl Read + Seek),
    source_path: &Path,
    expected_hash: &str,
    expected_length: u64,
) -> io::Result<()> {
    let opened_hash = hash_file(open_file, expected_length)?;
    let mut current_path = crate::input::regular(source_path)?;
    let path_hash = hash_file(&mut current_path, expected_length)?;
    if opened_hash.0 != expected_length
        || path_hash.0 != expected_length
        || opened_hash.1 != expected_hash
        || path_hash.1 != expected_hash
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "source bytes changed while TShark was running",
        ));
    }
    Ok(())
}

pub(super) fn hash_file(file: &mut (impl Read + Seek), maximum: u64) -> io::Result<(u64, String)> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = crate::input::io_buffer()?;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(u64::try_from(count).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("source length overflow"))?;
        if length > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source bytes changed while TShark was running",
            ));
        }
        hasher.update(
            buffer
                .get(..count)
                .ok_or_else(|| io::Error::other("source read exceeded its fixed buffer"))?,
        );
    }
    Ok((length, format!("{:x}", hasher.finalize())))
}
