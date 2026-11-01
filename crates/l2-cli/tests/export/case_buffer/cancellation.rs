//! Cancel at the snapshot codec and ordered wait boundaries

use super::{
    BufferedResult, MIB, TestResult, assert_previous_and_clean, case_for_index, old_destination,
};
use crate::{export::processing::process_ordered, publish};
use l2_workbench::{
    evidence::CaseSnapshotLimits,
    job::{Job, MemoryBudget},
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
        if read > 0 && !self.observed.replace(true) {
            self.job.request_cancel();
        }
        Ok(read)
    }
}

#[test]
fn cancellation_during_snapshot_write_keeps_old_output_and_removes_private_files() -> TestResult {
    let root = tempfile::tempdir()?;
    let (destination, prepared) = old_destination(root.path())?;
    let memory = MemoryBudget::new(32 * u64::try_from(MIB)?);
    let job = Job::new("cancel snapshot write");
    let observed = Cell::new(false);
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
            };
            crate::case_snapshot::write_streams(
                &mut graph,
                &mut writer,
                &case.case,
                limits,
                Some(&memory),
            )?;
            completed.set(true);
            Ok(())
        },
        || job.check_cancelled().map_err(Into::into),
    );
    assert!(observed.get());
    assert!(job.is_cancelled());
    assert!(matches!(
        outcome,
        Err(publish::DirectoryPublishError::BeforePublication(_))
    ));
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
            };
            let restored = crate::case_snapshot::read_streams(
                &mut graph,
                &mut reader,
                usage,
                limits,
                Some(&memory),
            )?;
            completed.set(true);
            drop(restored);
            Ok(())
        },
        || job.check_cancelled().map_err(Into::into),
    );
    assert!(observed.get());
    assert!(job.is_cancelled());
    assert!(matches!(
        outcome,
        Err(publish::DirectoryPublishError::BeforePublication(_))
    ));
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
                        BufferedResult::spill(result, staging, limits, Some(&memory))
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
                    drop(buffered.restore(&pool, Some(&memory))?);
                    Ok(())
                },
            )?;
            Ok(())
        },
        || job.check_cancelled().map_err(Into::into),
    );
    assert!(job.is_cancelled());
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
