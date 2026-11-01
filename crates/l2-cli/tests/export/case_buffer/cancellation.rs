//! Cancel at the snapshot codec and ordered wait boundaries

use super::{
    BufferedResult, MIB, TestResult, assert_previous_and_clean, case_for_index, old_destination,
};
use crate::{export::processing::process_ordered, publish};
use l2_workbench::{
    evidence::CaseSnapshotLimits,
    job::{Job, JobError, MemoryBudget},
};
use std::{
    cell::Cell,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    sync::{Mutex, mpsc},
    time::Duration,
};

struct CancelOnWrite<'a> {
    file: &'a mut File,
    job: &'a Job,
    observed: &'a Cell<bool>,
    transferred: &'a Cell<usize>,
}

impl Write for CancelOnWrite<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let chunk = if self.observed.get() {
            bytes
        } else {
            bytes
                .get(..bytes.len().min(4096))
                .ok_or_else(|| io::Error::other("invalid write range"))?
        };
        let written = self.file.write(chunk)?;
        self.transferred.set(self.transferred.get() + written);
        if written > 0 && !self.observed.replace(true) {
            self.job.request_cancel();
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

struct CancelOnRead<'a> {
    file: &'a mut File,
    job: &'a Job,
    observed: &'a Cell<bool>,
    transferred: &'a Cell<usize>,
}

impl Read for CancelOnRead<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = if self.observed.get() {
            bytes.len()
        } else {
            bytes.len().min(4096)
        };
        let chunk = bytes
            .get_mut(..count)
            .ok_or_else(|| io::Error::other("invalid read range"))?;
        let read = self.file.read(chunk)?;
        self.transferred.set(self.transferred.get() + read);
        if read > 0 && !self.observed.replace(true) {
            self.job.request_cancel();
        }
        Ok(read)
    }
}

struct FailAndCancel<'a>(&'a Job);

impl Write for FailAndCancel<'_> {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        self.0.request_cancel();
        Err(io::Error::other("simulated storage failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn storage_error_is_preserved_when_cancellation_was_not_observed() -> TestResult {
    let memory = MemoryBudget::new(32 * u64::try_from(MIB)?);
    let job = Job::new("storage error before cancellation check");
    let case = case_for_index(&memory, 0, MIB)?;
    let limits = CaseSnapshotLimits::new(8 * u64::try_from(MIB)?, 8 * u64::try_from(MIB)?);
    let mut graph = Vec::new();
    let mut blobs = FailAndCancel(&job);
    let result = crate::case_snapshot::with_cancellation(Some(&job), |cancellation| {
        let mut graph = cancellation.wrap(&mut graph);
        let mut blobs = cancellation.wrap(&mut blobs);
        crate::case_snapshot::write_streams(
            &mut graph,
            &mut blobs,
            &case.case,
            limits,
            Some(&memory),
        )
    });
    let error = result.err().ok_or("storage error was lost")?;
    assert!(job.is_cancelled());
    assert!(matches!(
        error.downcast_ref::<l2_workbench::evidence::EvidenceError>(),
        Some(l2_workbench::evidence::EvidenceError::WriteFailed)
    ));
    Ok(())
}

#[test]
fn already_cancelled_spills_and_restores_release_cases_and_private_files() -> TestResult {
    let root = tempfile::tempdir()?;
    let memory = MemoryBudget::new(32 * u64::try_from(MIB)?);
    let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build()?;
    let limits = CaseSnapshotLimits::new(8 * u64::try_from(MIB)?, 8 * u64::try_from(MIB)?);
    let buffered = BufferedResult::spill(
        case_for_index(&memory, 0, MIB)?,
        root.path(),
        limits,
        Some(&memory),
        None,
    )?;
    let job = Job::new("cancel before handoff");
    job.request_cancel();
    let error = buffered
        .restore(&pool, Some(&memory), Some(&job))
        .err()
        .ok_or("cancelled restore succeeded")?;
    assert_eq!(error.downcast_ref::<JobError>(), Some(&JobError::Cancelled));
    let error = BufferedResult::spill(
        case_for_index(&memory, 1, MIB)?,
        root.path(),
        limits,
        Some(&memory),
        Some(&job),
    )
    .err()
    .ok_or("cancelled spill succeeded")?;
    assert_eq!(error.downcast_ref::<JobError>(), Some(&JobError::Cancelled));
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    Ok(())
}

#[test]
fn cancellation_during_snapshot_write_keeps_old_output_and_removes_private_files() -> TestResult {
    let root = tempfile::tempdir()?;
    let (destination, prepared) = old_destination(root.path())?;
    let memory = MemoryBudget::new(32 * u64::try_from(MIB)?);
    let job = Job::new("cancel snapshot write");
    let observed = Cell::new(false);
    let transferred = Cell::new(0);
    let completed = Cell::new(false);
    let limits = CaseSnapshotLimits::new(8 * u64::try_from(MIB)?, 8 * u64::try_from(MIB)?);
    let outcome = publish::replace_directory_with_precommit(
        &prepared,
        |staging| {
            let case = case_for_index(&memory, 0, MIB)?;
            let mut graph = tempfile::tempfile_in(staging)?;
            let mut blobs = tempfile::tempfile_in(staging)?;
            let mut writer = CancelOnWrite {
                file: &mut blobs,
                job: &job,
                observed: &observed,
                transferred: &transferred,
            };
            crate::case_snapshot::with_cancellation(Some(&job), |cancellation| {
                let mut graph = cancellation.wrap(&mut graph);
                let mut writer = cancellation.wrap(&mut writer);
                crate::case_snapshot::write_streams(
                    &mut graph,
                    &mut writer,
                    &case.case,
                    limits,
                    Some(&memory),
                )
            })?;
            completed.set(true);
            Ok(())
        },
        || job.check_cancelled().map_err(Into::into),
    );
    assert!(observed.get());
    assert!(job.is_cancelled());
    assert_eq!(transferred.get(), 4096);
    assert!(
        !completed.get(),
        "snapshot writing continued to completion after cancellation"
    );
    let Err(publish::DirectoryPublishError::BeforePublication(error)) = outcome else {
        return Err("cancellation did not stop publication".into());
    };
    assert_eq!(error.downcast_ref::<JobError>(), Some(&JobError::Cancelled));
    assert_previous_and_clean(root.path(), &destination, &memory)?;
    println!(
        "cancellation=write codec_completed_after_request={}",
        completed.get()
    );
    Ok(())
}

#[test]
fn cancellation_during_snapshot_read_keeps_old_output_and_removes_private_files() -> TestResult {
    let root = tempfile::tempdir()?;
    let (destination, prepared) = old_destination(root.path())?;
    let memory = MemoryBudget::new(32 * u64::try_from(MIB)?);
    let job = Job::new("cancel snapshot read");
    let observed = Cell::new(false);
    let transferred = Cell::new(0);
    let completed = Cell::new(false);
    let limits = CaseSnapshotLimits::new(8 * u64::try_from(MIB)?, 8 * u64::try_from(MIB)?);
    let outcome = publish::replace_directory_with_precommit(
        &prepared,
        |staging| {
            let buffered = BufferedResult::spill(
                case_for_index(&memory, 0, MIB)?,
                staging,
                limits,
                Some(&memory),
                None,
            )?;
            let BufferedResult::Snapshot {
                mut graph,
                mut blobs,
                usage,
                limits,
                ..
            } = buffered
            else {
                return Err("snapshot was not spilled".into());
            };
            graph.seek(SeekFrom::Start(0))?;
            blobs.seek(SeekFrom::Start(0))?;
            let mut reader = CancelOnRead {
                file: &mut blobs,
                job: &job,
                observed: &observed,
                transferred: &transferred,
            };
            let restored = crate::case_snapshot::with_cancellation(Some(&job), |cancellation| {
                let mut graph = cancellation.wrap(&mut graph);
                let mut reader = cancellation.wrap(&mut reader);
                crate::case_snapshot::read_streams(
                    &mut graph,
                    &mut reader,
                    usage,
                    limits,
                    Some(&memory),
                )
            })?;
            completed.set(true);
            drop(restored);
            Ok(())
        },
        || job.check_cancelled().map_err(Into::into),
    );
    assert!(observed.get());
    assert!(job.is_cancelled());
    assert_eq!(transferred.get(), 4096);
    assert!(
        !completed.get(),
        "snapshot reading continued to completion after cancellation"
    );
    let Err(publish::DirectoryPublishError::BeforePublication(error)) = outcome else {
        return Err("cancellation did not stop publication".into());
    };
    assert_eq!(error.downcast_ref::<JobError>(), Some(&JobError::Cancelled));
    assert_previous_and_clean(root.path(), &destination, &memory)?;
    println!(
        "cancellation=read codec_completed_after_request={}",
        completed.get()
    );
    Ok(())
}

#[test]
fn cancellation_while_waiting_for_prefix_discards_spills_and_preserves_old_output() -> TestResult {
    let root = tempfile::tempdir()?;
    let (destination, prepared) = old_destination(root.path())?;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build()?;
    let memory = MemoryBudget::new(32 * u64::try_from(MIB)?);
    let job = Job::new("cancel ordered wait");
    let limits = CaseSnapshotLimits::new(8 * u64::try_from(MIB)?, 8 * u64::try_from(MIB)?);
    let (later_ready, receiver) = mpsc::channel();
    let receiver = Mutex::new(receiver);
    let mut emitted = 0;
    let outcome = publish::replace_directory_with_precommit(
        &prepared,
        |staging| {
            process_ordered(
                &pool,
                vec![0_usize, 1],
                |_, _| Ok(Some(())),
                |index, ()| {
                    if index == 0 {
                        receiver
                            .lock()
                            .map_err(|error| error.to_string())?
                            .recv_timeout(Duration::from_secs(20))
                            .map_err(|error| error.to_string())?;
                    }
                    let result =
                        case_for_index(&memory, index, MIB).map_err(|error| error.to_string())?;
                    let buffered = if index == 0 {
                        BufferedResult::Resident(Box::new(result))
                    } else {
                        BufferedResult::spill(result, staging, limits, Some(&memory), Some(&job))
                            .map_err(|error| error.to_string())?
                    };
                    let observation = buffered
                        .observe(&memory)
                        .map_err(|error| error.to_string())?;
                    if index == 1 {
                        job.request_cancel();
                        later_ready.send(()).map_err(|error| error.to_string())?;
                    }
                    Ok::<_, String>((buffered, observation))
                },
                |(buffered, observation)| {
                    drop(observation);
                    drop(buffered.restore(&pool, Some(&memory), Some(&job))?);
                    emitted += 1;
                    Ok(())
                },
            )?;
            Ok(())
        },
        || job.check_cancelled().map_err(Into::into),
    );
    assert!(job.is_cancelled());
    assert_eq!(emitted, 0);
    assert!(matches!(
        outcome,
        Err(publish::DirectoryPublishError::BeforePublication(_))
    ));
    assert_previous_and_clean(root.path(), &destination, &memory)?;
    let observed = memory.snapshot()?.buffered_cases;
    assert_eq!(observed.spilled_cases, 1);
    println!(
        "cancellation=ordered_wait spilled_cases={} peak_snapshot_bytes={} completed_waits={}",
        observed.spilled_cases, observed.peak_snapshot_bytes, observed.completed_waits
    );
    Ok(())
}
