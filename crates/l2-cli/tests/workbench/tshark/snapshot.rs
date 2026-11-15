use super::{HashControl, SourceIdentity, Workspace, copy_snapshot, hash_file, snapshot_retained};
use l2_workbench::job::{Job, JobError};
use std::{
    error::Error,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    time::{Duration, Instant},
};

struct CancellingReader<'a> {
    file: File,
    job: &'a Job,
    reads: usize,
    cancel_after: usize,
}

impl Read for CancellingReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let limit = buffer.len().min(4);
        let chunk = buffer
            .get_mut(..limit)
            .ok_or_else(|| io::Error::other("invalid read buffer"))?;
        let count = self.file.read(chunk)?;
        self.reads += 1;
        if self.reads == self.cancel_after {
            self.job.request_cancel();
        }
        Ok(count)
    }
}

impl Seek for CancellingReader<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

#[derive(Default)]
struct GrowingReader {
    reads: usize,
}

impl Read for GrowingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let Some(byte) = buffer.first_mut() else {
            return Ok(0);
        };
        *byte = b'x';
        self.reads += 1;
        Ok(1)
    }
}

impl Seek for GrowingReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        if matches!(position, SeekFrom::Start(0)) {
            Ok(0)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid fixture seek",
            ))
        }
    }
}

struct FailingReader;

impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "fixture read",
        ))
    }
}

impl Seek for FailingReader {
    fn seek(&mut self, _position: SeekFrom) -> io::Result<u64> {
        Ok(0)
    }
}

#[test]
fn hash_cancellation() -> Result<(), Box<dyn Error>> {
    for source_bytes in [b"abcdefgh".as_slice(), b"abcd".as_slice()] {
        let parent = tempfile::tempdir()?;
        let source = parent.path().join("source");
        fs::write(&source, source_bytes)?;
        let job = Job::new("hash cancellation");
        let mut reader = CancellingReader {
            file: File::open(source)?,
            job: &job,
            reads: 0,
            cancel_after: 2,
        };
        let error = hash_file(
            &mut reader,
            1024,
            HashControl {
                deadline: Instant::now() + Duration::from_secs(2),
                job: Some(&job),
            },
        )
        .err()
        .ok_or("cancelled hash succeeded")?;
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<JobError>()),
            Some(&JobError::Cancelled)
        );
        assert_eq!(reader.reads, 2);
    }
    Ok(())
}

#[test]
fn hash_deadline_and_growth() -> Result<(), Box<dyn Error>> {
    let mut reader = GrowingReader::default();
    let expired = hash_file(
        &mut reader,
        3,
        HashControl {
            deadline: Instant::now(),
            job: None,
        },
    )
    .err()
    .ok_or("expired hash succeeded")?;
    assert_eq!(expired.kind(), io::ErrorKind::TimedOut);
    assert_eq!(reader.reads, 0);

    let limit = hash_file(
        &mut reader,
        3,
        HashControl {
            deadline: Instant::now() + Duration::from_secs(2),
            job: None,
        },
    )
    .err()
    .ok_or("unbounded hash succeeded")?;
    assert_eq!(limit.kind(), io::ErrorKind::InvalidData);
    assert_eq!(reader.reads, 4);
    Ok(())
}

#[test]
fn hash_read_error() -> Result<(), Box<dyn Error>> {
    let error = hash_file(
        &mut FailingReader,
        3,
        HashControl {
            deadline: Instant::now() + Duration::from_secs(2),
            job: None,
        },
    )
    .err()
    .ok_or("failed read was accepted")?;
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    Ok(())
}

#[test]
fn retained_copy_cancellation() -> Result<(), Box<dyn Error>> {
    for source_bytes in [b"abcdefgh".as_slice(), b"abcd".as_slice()] {
        let parent = tempfile::tempdir()?;
        let source = parent.path().join("source");
        fs::write(&source, source_bytes)?;
        let workspace = Workspace::new(Some(parent.path()))?;
        let workspace_path = fs::canonicalize(workspace.path())?;
        let job = Job::new("retained copy cancellation");
        let mut reader = CancellingReader {
            file: File::open(source)?,
            job: &job,
            reads: 0,
            cancel_after: 2,
        };

        let result = copy_snapshot(
            &mut reader,
            &workspace,
            "capture.bin",
            1024,
            Instant::now() + Duration::from_secs(2),
            &mut Instant::now,
            Some(&job),
        );
        let error = result.err().ok_or("cancelled copy succeeded")?;
        assert_eq!(error.downcast_ref::<JobError>(), Some(&JobError::Cancelled));
        assert_eq!(reader.reads, 2);
        assert_eq!(fs::read(workspace.path().join("capture.bin"))?, b"abcd");
        drop(workspace);
        assert!(!workspace_path.exists());
    }
    Ok(())
}

#[test]
fn retained_copy_job_states() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let source = parent.path().join("source");
    fs::write(&source, b"capture")?;
    let identity = SourceIdentity {
        label: "capture".into(),
        length: 7,
        sha256: l2_workbench::sha256(b"capture"),
    };
    let job = Job::new("retained copy");
    let workspace = Workspace::new(Some(parent.path()))?;
    let mut file = File::open(&source)?;
    let snapshot = snapshot_retained(
        &mut file,
        &identity,
        &workspace,
        Instant::now() + Duration::from_secs(2),
        Some(&job),
    )?;
    assert_eq!(fs::read(&snapshot.path)?, b"capture");
    assert_eq!(snapshot.identity.sha256, identity.sha256);
    drop(snapshot);
    drop(workspace);

    let workspace = Workspace::new(Some(parent.path()))?;
    job.request_cancel();
    let error = snapshot_retained(
        &mut file,
        &identity,
        &workspace,
        Instant::now() + Duration::from_secs(2),
        Some(&job),
    )
    .err()
    .ok_or("pre-cancelled copy succeeded")?;
    assert_eq!(error.downcast_ref::<JobError>(), Some(&JobError::Cancelled));
    assert!(!workspace.path().join("capture.bin").exists());
    Ok(())
}
