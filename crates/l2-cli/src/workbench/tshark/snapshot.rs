use super::{model::SourceIdentity, process, secure_files::Workspace};
use l2_workbench::job::{Job, JobError};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Instant,
};

#[cfg(all(test, target_os = "linux"))]
#[path = "../../../tests/workbench/tshark/snapshot.rs"]
mod tests;

pub(super) struct Snapshot {
    pub(super) original: Option<(PathBuf, crate::input::InputFile)>,
    pub(super) file: File,
    pub(super) path: PathBuf,
    pub(super) identity: SourceIdentity,
}

#[derive(Clone, Copy)]
pub(super) struct HashControl<'a> {
    pub(super) deadline: Instant,
    pub(super) job: Option<&'a Job>,
}

impl HashControl<'_> {
    fn check(self) -> io::Result<()> {
        check_cancelled(self.job).map_err(io::Error::other)?;
        ensure_before_deadline(self.deadline)
            .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error))
    }
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
    let (snapshot_file, snapshot_path, length, digest) = copy_snapshot(
        &mut source_file,
        directory,
        snapshot_name,
        maximum,
        deadline,
        &mut now,
        None,
    )?;
    if length != source_file.metadata()?.len() {
        return Err("source changed while its private snapshot was being created".into());
    }
    source_file.seek(SeekFrom::Start(0))?;
    Ok(Snapshot {
        original: Some((source_path.to_owned(), source_file)),
        file: snapshot_file,
        path: snapshot_path,
        identity: SourceIdentity {
            label: super::super::label(source_path, fallback_label).to_owned(),
            length,
            sha256: digest,
        },
    })
}

pub(super) fn snapshot_retained(
    source_file: &mut File,
    identity: &SourceIdentity,
    directory: &Workspace,
    deadline: Instant,
    job: Option<&Job>,
) -> Result<Snapshot, Box<dyn Error>> {
    check_cancelled(job)?;
    ensure_before_deadline(deadline)?;
    if source_file.metadata()?.len() != identity.length {
        return Err("retained source length changed".into());
    }
    source_file.seek(SeekFrom::Start(0))?;
    let (file, path, length, digest) = copy_snapshot(
        source_file,
        directory,
        "capture.bin",
        identity.length,
        deadline,
        &mut Instant::now,
        job,
    )?;
    // The file may be writable elsewhere, so bind the copied bytes to the indexed digest
    if length != identity.length || digest != identity.sha256 {
        return Err("retained source bytes changed after indexing".into());
    }
    Ok(Snapshot {
        original: None,
        file,
        path,
        identity: identity.clone(),
    })
}

fn copy_snapshot(
    source_file: &mut impl Read,
    directory: &Workspace,
    snapshot_name: &str,
    maximum: u64,
    deadline: Instant,
    now: &mut impl FnMut() -> Instant,
    job: Option<&Job>,
) -> Result<(File, PathBuf, u64, String), Box<dyn Error>> {
    check_cancelled(job)?;
    let snapshot_path = directory.path().join(snapshot_name);
    let mut snapshot_file = directory.create_file(std::ffi::OsStr::new(snapshot_name))?;
    let mut writer = l2_workbench::storage::SparseWriter::new(&mut snapshot_file, maximum)?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = crate::input::io_buffer()?;
    loop {
        check_cancelled(job)?;
        ensure_before_deadline_at(deadline, now())?;
        let count = source_file.read(&mut buffer)?;
        check_cancelled(job)?;
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
        check_cancelled(job)?;
        writer.write_all(bytes)?;
        check_cancelled(job)?;
        ensure_before_deadline_at(deadline, now())?;
    }
    check_cancelled(job)?;
    writer.flush()?;
    check_cancelled(job)?;
    writer.finish()?;
    check_cancelled(job)?;
    ensure_before_deadline_at(deadline, now())?;
    Ok((
        snapshot_file,
        snapshot_path,
        length,
        format!("{:x}", hasher.finalize()),
    ))
}

fn check_cancelled(job: Option<&Job>) -> Result<(), JobError> {
    job.map_or(Ok(()), Job::check_cancelled)
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
    control: HashControl<'_>,
) -> io::Result<()> {
    let opened_hash = hash_file(open_file, expected_length, control)?;
    let mut current_path = crate::input::regular(source_path)?;
    let path_hash = hash_file(&mut current_path, expected_length, control)?;
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

pub(super) fn hash_file(
    file: &mut (impl Read + Seek),
    maximum: u64,
    control: HashControl<'_>,
) -> io::Result<(u64, String)> {
    control.check()?;
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = crate::input::io_buffer()?;
    loop {
        control.check()?;
        let count = file.read(&mut buffer)?;
        control.check()?;
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
    control.check()?;
    Ok((length, format!("{:x}", hasher.finalize())))
}
