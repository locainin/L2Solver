//! Exercise checkpoint snapshot writes through the real quota ledger

use crate::case_snapshot;
use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits, CaseSnapshotUsage, EvidenceError},
    job::{
        Job, JobError, JobSnapshot, MemoryBudget, MemoryClass, MemoryError,
        cache::{
            Cache, CacheError, CacheReadPolicy, ExecutionCheckpointLimits, Lease, SourceIdentity,
            StageKey, StageStatus,
        },
    },
};
use serde_json::json;
use std::{
    cell::Cell,
    error::Error,
    io::{self, Write},
    sync::mpsc,
    time::Duration,
};

const MIB: u64 = 1024 * 1024;

fn many_small_blobs() -> Result<Case, Box<dyn Error>> {
    let mut case = Case::new();
    for index in 0_u64..1024 {
        let mut bytes = [0x5a; 128];
        bytes
            .get_mut(..8)
            .ok_or("blob fixture is too small")?
            .copy_from_slice(&index.to_le_bytes());
        case.add_bytes_node("sample", &bytes, Vec::new(), json!({}))?;
    }
    Ok(case)
}

fn test_key(name: &str) -> Result<StageKey, CacheError> {
    StageKey::new(
        name,
        1,
        "test",
        &json!({}),
        &SourceIdentity::from_sha256("c".repeat(64))?,
        &[],
    )
}

fn save_test_case(
    lease: &mut Lease,
    snapshot: &JobSnapshot,
    case: &Case,
) -> Result<(), CacheError> {
    lease.save_active(snapshot, store_limits(), |writer| {
        let (graph, blobs, _) = writer.streams();
        let usage = case_snapshot::with_cancellation(None, |cancellation| {
            case_snapshot::write_streams(
                graph,
                blobs,
                case,
                CaseSnapshotLimits::new(MIB, MIB),
                None,
                cancellation,
            )
        })
        .map_err(|_| CacheError::CorruptCheckpoint)?;
        Ok(json!({ "usage": usage }))
    })
}

const fn store_limits() -> ExecutionCheckpointLimits {
    ExecutionCheckpointLimits {
        max_encoded_bytes: 4 * MIB,
        max_executor_bytes: MIB,
        max_metadata_bytes: MIB,
    }
}

#[test]
fn checkpoint_batches_small_blobs_without_repeated_quota_updates() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let cache = Cache::open_at(
        root.path().join("cache"),
        root.path().join("state"),
        8 * MIB,
    )?;
    let database = rusqlite::Connection::open(root.path().join("state/cache.sqlite3"))?;
    database.execute_batch(
        "CREATE TABLE reservation_audit (updates INTEGER NOT NULL);
         INSERT INTO reservation_audit VALUES (0);
         CREATE TRIGGER count_refills AFTER UPDATE OF bytes ON execution_reservations
         BEGIN UPDATE reservation_audit SET updates = updates + 1; END;",
    )?;
    let key = test_key("small_blob_snapshot")?;
    let limits = CaseSnapshotLimits::new(4 * MIB, 4 * MIB);
    let store_limits = store_limits();
    let case = many_small_blobs()?;
    let mut expected_graph = Vec::new();
    let mut expected_blobs = Vec::new();
    let expected_usage = case.write_snapshot(&mut expected_graph, &mut expected_blobs, limits)?;
    let memory = MemoryBudget::new(16 * MIB);
    let job = Job::new("small blob checkpoint");
    let snapshot = job.snapshot()?;
    let mut lease = cache.lease(&key)?;

    lease.save_active(&snapshot, store_limits, |writer| {
        let usage = case_snapshot::with_cancellation(Some(&job), |cancellation| {
            let (graph, blobs, state) = writer.streams();
            let mut state = cancellation.wrap(state);
            let usage = case_snapshot::write_streams(
                graph,
                blobs,
                &case,
                limits,
                Some(&memory),
                cancellation,
            )?;
            state.write_all(b"cursor")?;
            Ok(usage)
        })
        .map_err(|_| CacheError::CorruptCheckpoint)?;
        Ok(json!({ "usage": usage }))
    })?;

    let updates: u64 = database.query_row("SELECT updates FROM reservation_audit", [], |row| {
        row.get(0)
    })?;
    println!("checkpoint_reservation_updates={updates}");
    assert!(
        updates <= 20,
        "small blobs required {updates} reservation updates"
    );
    let mut active = lease
        .load_active(store_limits)?
        .ok_or("checkpoint was not committed")?;
    let usage: CaseSnapshotUsage = serde_json::from_value(active.metadata()["usage"].clone())?;
    assert_eq!(usage, expected_usage);
    let (graph, blobs, state) = active.streams();
    let mut actual_graph = Vec::new();
    let mut actual_blobs = Vec::new();
    let mut actual_state = Vec::new();
    graph.read_to_end(&mut actual_graph)?;
    blobs.read_to_end(&mut actual_blobs)?;
    state.read_to_end(&mut actual_state)?;
    assert_eq!(actual_graph, expected_graph);
    assert_eq!(actual_blobs, expected_blobs);
    assert_eq!(actual_state, b"cursor");
    let restored = case_snapshot::read_streams(
        &mut actual_graph.as_slice(),
        &mut actual_blobs.as_slice(),
        usage,
        limits,
        Some(&memory),
    )?;
    assert_eq!(restored, case);
    drop(restored);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn insufficient_snapshot_memory_fails_before_writing() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    case.add_bytes_node("sample", &[1; 128], Vec::new(), json!({}))?;
    for (limit, used, requested) in [
        (16 * 1024, 0, 32 * 1024),
        (2 * MIB + 16 * 1024, 32 * 1024, 2 * MIB),
    ] {
        let budget = MemoryBudget::new(limit);
        let mut graph = Vec::new();
        let mut blobs = Vec::new();
        let result = case_snapshot::with_cancellation(None, |cancellation| {
            case_snapshot::write_streams(
                &mut graph,
                &mut blobs,
                &case,
                CaseSnapshotLimits::new(MIB, MIB),
                Some(&budget),
                cancellation,
            )
        });
        let error = result
            .err()
            .ok_or("snapshot unexpectedly succeeded with insufficient memory")?;
        assert_eq!(
            crate::memory_error::find(error.as_ref()),
            Some(MemoryError::Limit {
                limit,
                used,
                requested,
            })
        );
        assert_eq!(graph, [0_u8; 0]);
        assert_eq!(blobs, [0_u8; 0]);
        assert_eq!(budget.snapshot()?.used_bytes, 0);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum WriteFault {
    Error,
    ErrorAndCancel,
    Flush,
    Zero,
    Cancel,
}

struct FaultWriter<'a> {
    inner: &'a mut dyn Write,
    job: &'a Job,
    attempts: &'a Cell<usize>,
    flush_attempts: &'a Cell<usize>,
    fault: WriteFault,
}

fn injected_storage_error() -> io::Error {
    #[cfg(unix)]
    {
        io::Error::from_raw_os_error(libc::ENOSPC)
    }
    #[cfg(not(unix))]
    {
        io::Error::other("injected storage failure")
    }
}

impl Write for FaultWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let attempt = self.attempts.get();
        self.attempts.set(attempt + 1);
        if attempt == 0 {
            match self.fault {
                WriteFault::Error => return Err(injected_storage_error()),
                WriteFault::ErrorAndCancel => {
                    self.job.request_cancel();
                    return Err(injected_storage_error());
                }
                WriteFault::Zero => return Ok(0),
                WriteFault::Cancel => {
                    let first = bytes
                        .get(..bytes.len().min(1))
                        .ok_or_else(|| io::Error::other("invalid fault fixture range"))?;
                    let written = self.inner.write(first)?;
                    self.job.request_cancel();
                    return Ok(written);
                }
                WriteFault::Flush => {}
            }
        }
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_attempts.set(self.flush_attempts.get() + 1);
        if matches!(self.fault, WriteFault::Flush) {
            return Err(injected_storage_error());
        }
        self.inner.flush()
    }
}

fn assert_snapshot_failure(
    fault: WriteFault,
    failure: &(dyn Error + 'static),
) -> Result<(), Box<dyn Error>> {
    match fault {
        WriteFault::Error | WriteFault::ErrorAndCancel | WriteFault::Flush => {
            let error = crate::memory_error::find_map(failure, |cause| {
                cause
                    .downcast_ref::<io::Error>()
                    .map(|error| (error.kind(), error.raw_os_error()))
            })
            .ok_or("storage error was not preserved")?;
            #[cfg(unix)]
            assert_eq!(error.1, Some(libc::ENOSPC));
            #[cfg(not(unix))]
            assert_eq!(error.0, io::ErrorKind::Other);
        }
        WriteFault::Cancel => assert_eq!(
            failure.downcast_ref::<JobError>(),
            Some(&JobError::Cancelled)
        ),
        WriteFault::Zero => return Err("unexpected write-zero fixture".into()),
    }
    Ok(())
}

#[test]
fn failed_or_cancelled_snapshot_does_not_retry_and_preserves_previous_generation()
-> Result<(), Box<dyn Error>> {
    for fault in [
        WriteFault::Error,
        WriteFault::ErrorAndCancel,
        WriteFault::Flush,
        WriteFault::Cancel,
    ] {
        let root = tempfile::tempdir()?;
        let cache = Cache::open_at(
            root.path().join("cache"),
            root.path().join("state"),
            8 * MIB,
        )?;
        let key = test_key("failed_buffered_snapshot")?;
        let mut lease = cache.lease(&key)?;
        let baseline = Job::new("previous checkpoint").snapshot()?;
        lease.save_active(&baseline, store_limits(), |writer| {
            writer.streams().2.write_all(b"previous")?;
            Ok(json!({ "generation": 1 }))
        })?;
        let prior_bytes = cache.stats()?.entry_bytes;
        let job = Job::new("failed checkpoint");
        let memory = MemoryBudget::new(16 * MIB);
        let mut case = Case::new();
        case.add_bytes_node("sample", &[2; 128], Vec::new(), json!({}))?;
        let attempts = Cell::new(0);
        let flush_attempts = Cell::new(0);
        let mut failure = None;
        let result = lease.save_active(&baseline, store_limits(), |writer| {
            let encoded = case_snapshot::with_cancellation(Some(&job), |cancellation| {
                let (graph, blobs, _) = writer.streams();
                let mut injected = FaultWriter {
                    inner: blobs,
                    job: &job,
                    attempts: &attempts,
                    flush_attempts: &flush_attempts,
                    fault,
                };
                case_snapshot::write_streams(
                    graph,
                    &mut injected,
                    &case,
                    CaseSnapshotLimits::new(MIB, MIB),
                    Some(&memory),
                    cancellation,
                )
            });
            match encoded {
                Ok(_) => Ok(json!({ "generation": 2 })),
                Err(error) => {
                    failure = Some(error);
                    Err(CacheError::CorruptCheckpoint)
                }
            }
        });
        assert!(matches!(result, Err(CacheError::CorruptCheckpoint)));
        let failure = failure.ok_or("snapshot failure was not captured")?;
        assert_snapshot_failure(fault, failure.as_ref())?;
        assert_eq!(attempts.get(), 1, "buffered data was retried after failure");
        if matches!(fault, WriteFault::Flush) {
            assert_eq!(flush_attempts.get(), 1, "the failed flush was retried");
        }
        assert_eq!(cache.stats()?.entry_bytes, prior_bytes);
        assert_eq!(memory.snapshot()?.used_bytes, 0);
        let mut active = lease
            .load_active(store_limits())?
            .ok_or("previous checkpoint was lost")?;
        assert_eq!(active.metadata(), &json!({ "generation": 1 }));
        let mut state = Vec::new();
        active.streams().2.read_to_end(&mut state)?;
        assert_eq!(state, b"previous");
    }
    Ok(())
}

#[test]
fn graph_writer_failure_does_not_retry_when_the_encoder_drops() -> Result<(), Box<dyn Error>> {
    let case = many_small_blobs()?;
    for fault in [WriteFault::Error, WriteFault::Zero] {
        let job = Job::new("graph write failure");
        let attempts = Cell::new(0);
        let flush_attempts = Cell::new(0);
        let mut destination = io::sink();
        let mut graph = FaultWriter {
            inner: &mut destination,
            job: &job,
            attempts: &attempts,
            flush_attempts: &flush_attempts,
            fault,
        };
        let result = case_snapshot::with_cancellation(Some(&job), |cancellation| {
            case_snapshot::write_streams(
                &mut graph,
                &mut io::sink(),
                &case,
                CaseSnapshotLimits::new(4 * MIB, 4 * MIB),
                None,
                cancellation,
            )
        });
        let failure = result.err().ok_or("the graph writer fault was lost")?;
        assert_eq!(
            failure.downcast_ref::<EvidenceError>(),
            Some(&EvidenceError::WriteFailed),
            "the graph codec did not report a write failure"
        );
        assert_eq!(
            attempts.get(),
            1,
            "the graph writer was retried after failure"
        );
    }
    Ok(())
}

struct ObserveFlushMemory<'a> {
    budget: &'a MemoryBudget,
    observed: &'a Cell<Option<u64>>,
}

impl Write for ObserveFlushMemory<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let snapshot = self.budget.snapshot().map_err(io::Error::other)?;
        self.observed.set(Some(snapshot.used(MemoryClass::Cache)));
        Ok(())
    }
}

#[test]
fn codec_scratch_is_released_before_the_final_blob_flush() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    case.add_bytes_node("sample", &[5; 128], Vec::new(), json!({}))?;
    let budget = MemoryBudget::new(8 * MIB);
    let observed = Cell::new(None);
    let mut blobs = ObserveFlushMemory {
        budget: &budget,
        observed: &observed,
    };
    case_snapshot::with_cancellation(None, |cancellation| {
        case_snapshot::write_streams(
            &mut io::sink(),
            &mut blobs,
            &case,
            CaseSnapshotLimits::new(MIB, MIB),
            Some(&budget),
            cancellation,
        )
    })?;
    let during_flush = observed.get().ok_or("blob stream was not flushed")?;
    assert!(during_flush > 0, "live stream buffers must remain charged");
    assert!(
        during_flush < 2 * MIB,
        "codec scratch remained charged during flush"
    );
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn buffered_small_snapshot_does_not_evict_for_unused_quota() -> Result<(), Box<dyn Error>> {
    let key = test_key("small_buffered_snapshot")?;
    let job = Job::new("small checkpoint");
    let snapshot = job.snapshot()?;
    let mut case = Case::new();
    case.add_bytes_node("sample", &[4; 128], Vec::new(), json!({}))?;

    // Measure the exact checkpoint so the tight quota has only one spare byte
    let probe_root = tempfile::tempdir()?;
    let probe = Cache::open_at(
        probe_root.path().join("cache"),
        probe_root.path().join("state"),
        8 * MIB,
    )?;
    let mut probe_lease = probe.lease(&key)?;
    save_test_case(&mut probe_lease, &snapshot, &case)?;
    drop(probe_lease);
    let checkpoint_bytes = probe.stats()?.entry_bytes;
    assert!(
        checkpoint_bytes + 1 < 4_096,
        "fixture must reject spare credit"
    );
    let quota = 5_000 + checkpoint_bytes + 1;

    let root = tempfile::tempdir()?;
    let cache = Cache::open_at(root.path().join("cache"), root.path().join("state"), quota)?;
    let existing_key = test_key("existing_result")?;
    let existing = cache.lease(&existing_key)?;
    std::fs::write(existing.directory().join("result"), [3; 5_000])?;
    drop(existing.commit(StageStatus::Complete, json!({}))?);
    let mut lease = cache.lease(&key)?;
    save_test_case(&mut lease, &snapshot, &case)?;
    assert!(
        cache
            .lookup(&existing_key, CacheReadPolicy::CompleteOnly)?
            .is_some(),
        "unused reservation credit must not evict an existing result"
    );
    assert_eq!(cache.stats()?.entry_bytes, quota - 1);
    Ok(())
}

struct PauseAfterWrite<'a> {
    inner: &'a mut dyn Write,
    ready: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    paused: bool,
}

impl Write for PauseAfterWrite<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(bytes)?;
        if !self.paused {
            self.paused = true;
            self.ready
                .send(())
                .map_err(|_| io::Error::other("checkpoint observer disconnected"))?;
            self.release
                .recv()
                .map_err(|_| io::Error::other("checkpoint release disconnected"))?;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[test]
fn concurrent_buffered_snapshots_cannot_overcommit_tight_quota() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let cache = Cache::open_at(root.path().join("cache"), root.path().join("state"), 20_000)?;
    let first_key = test_key("first_buffered_writer")?;
    let second_key = test_key("second_buffered_writer")?;
    let mut first_case = Case::new();
    first_case.add_bytes_node("first", &[1; 12_000], Vec::new(), json!({}))?;
    let mut second_case = Case::new();
    second_case.add_bytes_node("second", &[2; 12_000], Vec::new(), json!({}))?;
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let first_cache = cache.clone();
    let writer = std::thread::spawn(move || -> Result<(), CacheError> {
        let mut lease = first_cache.lease(&first_key)?;
        let snapshot = Job::new("first checkpoint")
            .snapshot()
            .map_err(|_| CacheError::InvalidInput("job snapshot failed"))?;
        lease.save_active(&snapshot, store_limits(), |writer| {
            let (graph, blobs, _) = writer.streams();
            let mut paused = PauseAfterWrite {
                inner: blobs,
                ready: ready_tx,
                release: release_rx,
                paused: false,
            };
            let usage = case_snapshot::with_cancellation(None, |cancellation| {
                case_snapshot::write_streams(
                    graph,
                    &mut paused,
                    &first_case,
                    CaseSnapshotLimits::new(MIB, MIB),
                    None,
                    cancellation,
                )
            })
            .map_err(|_| CacheError::CorruptCheckpoint)?;
            Ok(json!({ "usage": usage }))
        })
    });
    ready_rx.recv_timeout(Duration::from_secs(20))?;
    assert!(cache.stats()?.entry_bytes >= 12_000);
    assert!(cache.stats()?.entry_bytes <= 20_000);
    let mut second = cache.lease(&second_key)?;
    let second_result = second.save_active(
        &Job::new("second checkpoint").snapshot()?,
        store_limits(),
        |writer| {
            let (graph, blobs, _) = writer.streams();
            let usage = case_snapshot::with_cancellation(None, |cancellation| {
                case_snapshot::write_streams(
                    graph,
                    blobs,
                    &second_case,
                    CaseSnapshotLimits::new(MIB, MIB),
                    None,
                    cancellation,
                )
            })
            .map_err(|_| CacheError::CorruptCheckpoint)?;
            Ok(json!({ "usage": usage }))
        },
    );
    release_tx.send(())?;
    writer.join().map_err(|_| "checkpoint writer panicked")??;
    assert!(matches!(
        second_result,
        Err(CacheError::QuotaExceeded { .. })
    ));
    assert!(cache.stats()?.entry_bytes <= 20_000);
    Ok(())
}
