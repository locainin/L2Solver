use super::*;
use crate::result_directory::ResultKind;
use l2_workbench::job::cache::SourceIdentity;
use l2_workbench::job::{Counter, Phase};
use serde_json::json;

#[test]
fn job_checkpoint_does_not_replay_a_cases_uncommitted_progress() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        1024 * 1024,
    )?;
    let identity = ResultIdentity {
        kind: ResultKind::Extract,
        algorithm_version: 2,
        source: SourceIdentity::from_sha256("a".repeat(64))?,
        settings: json!({"profile":"normal"}),
    };
    let job = Job::new("live extraction");
    let writer = CheckpointWriter::start(&cache, &identity, &job, false)?;
    let case_job = job.work_scope(&"b".repeat(64))?;
    job.increment(Counter::Packets, 13)?;
    case_job.increment(Counter::CandidatesExamined, 17)?;
    let committed_work = case_job.work_snapshot()?;
    case_job.increment(Counter::CandidatesExamined, 100)?;
    writer.finish(false)?;

    let resumed = Job::new("resumed extraction");
    let writer = CheckpointWriter::start(&cache, &identity, &resumed, false)?;
    let case_job = resumed.work_scope(&"b".repeat(64))?;
    case_job.restore_work(committed_work)?;
    let snapshot = resumed.snapshot()?;
    assert_eq!(
        snapshot.counters.get(&Counter::CandidatesExamined),
        Some(&17)
    );
    assert_eq!(snapshot.counters.get(&Counter::Packets), Some(&13));
    writer.finish(true)?;
    Ok(())
}

#[test]
fn interrupted_job_restores_cumulative_work_and_replays_cached_stages() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let cache = Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        1024 * 1024,
    )?;
    let identity = ResultIdentity {
        kind: ResultKind::Extract,
        algorithm_version: 2,
        source: SourceIdentity::from_sha256("0".repeat(64))?,
        settings: json!({"profile":"normal"}),
    };
    let original = Job::new("original");
    let checkpoint = CheckpointWriter::start(&cache, &identity, &original, false)?;
    original.start(Phase::TransformDiscovery, None)?;
    original.increment(Counter::CandidatesExamined, 17)?;
    original.request_cancel();
    checkpoint.finish(false)?;
    let resumed = Job::new("resumed");
    let writer = CheckpointWriter::start(&cache, &identity, &resumed, false)?;
    let snapshot = resumed.snapshot()?;
    assert_eq!(
        snapshot.created_at_unix_ms,
        original.snapshot()?.created_at_unix_ms
    );
    assert_eq!(
        snapshot.counters.get(&Counter::CandidatesExamined),
        Some(&17)
    );
    assert!(!resumed.is_cancelled());
    assert_eq!(
        snapshot
            .phase(Phase::TransformDiscovery)
            .map(|phase| phase.state),
        Some(PhaseState::Pending)
    );
    writer.finish(true)?;
    Ok(())
}

#[test]
fn checkpoint_restores_saved_work_while_live_preparation_stays_visible()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        1024 * 1024,
    )?;
    let identity = ResultIdentity {
        kind: ResultKind::Extract,
        algorithm_version: 2,
        source: SourceIdentity::from_sha256("4".repeat(64))?,
        settings: json!({}),
    };
    let saved = Job::new("saved job");
    let writer = CheckpointWriter::start(&cache, &identity, &saved, false)?;
    saved.start(Phase::TransformDiscovery, None)?;
    saved.increment(Counter::CandidatesExamined, 17)?;
    writer.finish(false)?;

    let live = Job::new("live job");
    live.start(Phase::Preparation, Some(5))?;
    live.set_current(Phase::Preparation, "opening cache")?;
    live.advance(Phase::Preparation, 2)?;
    live.increment(Counter::CacheHits, 3)?;
    std::thread::sleep(Duration::from_millis(10));
    let before = live.snapshot()?;
    let writer = CheckpointWriter::start(&cache, &identity, &live, false)?;
    let minimum_elapsed = before
        .phase(Phase::Preparation)
        .ok_or("preparation is missing")?
        .elapsed_ms;
    assert_checkpoint_preparation(&live.snapshot()?, minimum_elapsed)?;
    let connection = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let persisted: String =
        connection.query_row("SELECT snapshot_json FROM checkpoints", [], |row| {
            row.get(0)
        })?;
    let persisted: l2_workbench::job::JobSnapshot = serde_json::from_str(&persisted)?;
    assert_checkpoint_preparation(&persisted, minimum_elapsed)?;
    writer.finish(false)?;
    Ok(())
}

fn assert_checkpoint_preparation(
    snapshot: &l2_workbench::job::JobSnapshot,
    minimum_elapsed: u64,
) -> Result<(), Box<dyn Error>> {
    let preparation = snapshot
        .phase(Phase::Preparation)
        .ok_or("preparation is missing")?;
    assert_eq!(snapshot.current_phase, Some(Phase::Preparation));
    assert_eq!(preparation.state, PhaseState::InProgress);
    assert_eq!(preparation.completed, 2);
    assert_eq!(preparation.total, Some(5));
    assert_eq!(preparation.message.as_deref(), Some("opening cache"));
    assert!(preparation.elapsed_ms >= minimum_elapsed);
    assert_eq!(snapshot.counters.get(&Counter::CacheHits), Some(&3));
    assert_eq!(
        snapshot.counters.get(&Counter::CandidatesExamined),
        Some(&17)
    );
    assert_eq!(
        snapshot
            .phase(Phase::TransformDiscovery)
            .map(|phase| phase.state),
        Some(PhaseState::Pending)
    );
    Ok(())
}

#[test]
fn fresh_checkpoint_rejects_discovery_or_scoped_work_before_cache_start()
-> Result<(), Box<dyn Error>> {
    for scoped in [false, true] {
        let temporary = tempfile::tempdir()?;
        let state_root = temporary.path().join("state");
        let cache = Cache::open_at(temporary.path().join("cache"), &state_root, 1024 * 1024)?;
        let identity = ResultIdentity {
            kind: ResultKind::Extract,
            algorithm_version: 2,
            source: SourceIdentity::from_sha256("5".repeat(64))?,
            settings: json!({}),
        };
        let live = Job::new("live job");
        let worker = if scoped {
            live.start(Phase::Preparation, None)?;
            let worker = live.work_scope(&"a".repeat(64))?;
            worker.increment(Counter::CandidatesExamined, 3)?;
            Some(worker)
        } else {
            live.start(Phase::TransformDiscovery, None)?;
            None
        };
        assert!(matches!(
            CheckpointWriter::start(&cache, &identity, &live, false),
            Err(CheckpointError::Job(JobError::RestoreAfterStart))
        ));
        let connection = rusqlite::Connection::open(state_root.join("cache.sqlite3"))?;
        let count: u64 =
            connection.query_row("SELECT COUNT(*) FROM checkpoints", [], |row| row.get(0))?;
        assert_eq!(count, 0);
        if let Some(worker) = worker {
            assert_eq!(
                worker
                    .snapshot()?
                    .counters
                    .get(&Counter::CandidatesExamined),
                Some(&3)
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn background_checkpoint_write_failure_remains_a_cache_error() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache_root = temporary.path().join("cache");
    let cache = Cache::open_at(&cache_root, temporary.path().join("state"), 1024 * 1024)?;
    let identity = ResultIdentity {
        kind: ResultKind::Extract,
        algorithm_version: 2,
        source: SourceIdentity::from_sha256("2".repeat(64))?,
        settings: json!({}),
    };
    let job = Job::new("checkpoint worker failure");
    let checkpoint = CheckpointWriter::start(&cache, &identity, &job, false)?;
    std::fs::rename(&cache_root, temporary.path().join("moved-cache"))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while checkpoint
        .worker
        .as_ref()
        .is_some_and(|worker| !worker.is_finished())
        && std::time::Instant::now() < deadline
    {
        // Wait for the real periodic writer instead of relying on a fixed delay
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        checkpoint
            .worker
            .as_ref()
            .is_some_and(JoinHandle::is_finished),
        "checkpoint worker did not observe the removed cache"
    );
    assert!(matches!(
        checkpoint.finish(false),
        Err(CheckpointError::Cache(_))
    ));
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Eq, PartialEq)]
enum CheckpointRace {
    Cancel,
    Discovery,
    Preparation,
}

#[cfg(target_os = "linux")]
#[test]
fn checkpoint_preview_preserves_preparation_but_rejects_live_discovery_and_cancellation()
-> Result<(), Box<dyn Error>> {
    for (action, active_checkpoint) in [
        (CheckpointRace::Cancel, false),
        (CheckpointRace::Cancel, true),
        (CheckpointRace::Discovery, false),
        (CheckpointRace::Discovery, true),
        (CheckpointRace::Preparation, false),
        (CheckpointRace::Preparation, true),
    ] {
        exercise_checkpoint_start_race(action, active_checkpoint)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn exercise_checkpoint_start_race(
    action: CheckpointRace,
    active_checkpoint: bool,
) -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let state_root = temporary.path().join("state");
    let cache = Cache::open_at(temporary.path().join("cache"), &state_root, 1024 * 1024)?;
    let identity = ResultIdentity {
        kind: ResultKind::Extract,
        algorithm_version: 2,
        source: SourceIdentity::from_sha256("3".repeat(64))?,
        settings: json!({}),
    };
    let saved = Job::new("saved job");
    saved.increment(Counter::CacheHits, 5)?;
    CheckpointWriter::start(&cache, &identity, &saved, false)?.finish(!active_checkpoint)?;

    let connection = rusqlite::Connection::open(state_root.join("cache.sqlite3"))?;
    let key: String = connection.query_row("SELECT key FROM checkpoints", [], |row| row.get(0))?;
    let checkpoint_lock = std::fs::canonicalize(&state_root)?
        .join("locks")
        .join(format!("{key}.lock"));
    connection.execute_batch("BEGIN IMMEDIATE")?;
    let live = Job::new("live job");
    if action == CheckpointRace::Cancel {
        live.start(Phase::Preparation, None)?;
        live.set_current(Phase::Preparation, "opening cache")?;
    }
    let (result_sender, result_receiver) = std::sync::mpsc::channel();
    let test_cache = cache;
    let test_identity = identity;
    let test_job = live.clone();
    let thread = std::thread::spawn(move || {
        let result = CheckpointWriter::start(&test_cache, &test_identity, &test_job, false);
        let outcome = match result {
            Err(CheckpointError::Job(error)) => Err(Some(error)),
            Err(_) => Err(None),
            Ok(writer) => writer.finish(false).map_err(|_| None),
        };
        let _ = result_sender.send(outcome);
    });
    wait_for_checkpoint_write(&checkpoint_lock)?;
    let expected = apply_checkpoint_race(action, &live)?;
    connection.execute_batch("COMMIT")?;
    assert_eq!(
        result_receiver.recv_timeout(Duration::from_secs(10))?,
        expected
    );
    thread
        .join()
        .map_err(|_| "checkpoint startup thread panicked")?;
    assert_checkpoint_race_result(action, active_checkpoint, &live)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn wait_for_checkpoint_write(checkpoint_lock: &std::path::Path) -> Result<(), Box<dyn Error>> {
    // The open key lock shows that preview finished and the database write is waiting
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    while std::time::Instant::now() < deadline {
        let waiting = std::fs::read_dir("/proc/self/fd")?
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read_link(entry.path()).ok())
            .any(|path| path == checkpoint_lock);
        if waiting {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err("checkpoint writer did not reach the locked database".into())
}

#[cfg(target_os = "linux")]
fn apply_checkpoint_race(
    action: CheckpointRace,
    live: &Job,
) -> Result<Result<(), Option<JobError>>, Box<dyn Error>> {
    match action {
        CheckpointRace::Cancel => {
            live.request_cancel();
            Ok(Err(Some(JobError::Cancelled)))
        }
        CheckpointRace::Discovery => {
            live.start(Phase::TransformDiscovery, None)?;
            Ok(Err(Some(JobError::RestoreAfterStart)))
        }
        CheckpointRace::Preparation => {
            live.start(Phase::Preparation, Some(3))?;
            live.set_current(Phase::Preparation, "opening cache")?;
            live.advance(Phase::Preparation, 1)?;
            live.increment(Counter::CacheHits, 2)?;
            let visible = live.snapshot()?;
            assert_eq!(
                visible.phase(Phase::Preparation).map(|phase| phase.state),
                Some(PhaseState::InProgress)
            );
            assert_eq!(
                visible
                    .phase(Phase::Preparation)
                    .and_then(|phase| phase.message.as_deref()),
                Some("opening cache")
            );
            Ok(Ok(()))
        }
    }
}

#[cfg(target_os = "linux")]
fn assert_checkpoint_race_result(
    action: CheckpointRace,
    active_checkpoint: bool,
    live: &Job,
) -> Result<(), Box<dyn Error>> {
    let after = live.snapshot()?;
    if action == CheckpointRace::Preparation {
        assert_eq!(
            after.label,
            if active_checkpoint {
                "saved job"
            } else {
                "live job"
            }
        );
        assert_eq!(after.current_phase, Some(Phase::Preparation));
        assert_eq!(
            after.phase(Phase::Preparation).map(|phase| phase.completed),
            Some(1)
        );
        assert_eq!(
            after.counters.get(&Counter::CacheHits),
            Some(if active_checkpoint { &7 } else { &2 })
        );
    } else {
        assert_eq!(after.label, "live job");
    }
    if action == CheckpointRace::Cancel {
        assert!(after.cancel_requested);
        assert_eq!(
            after.phase(Phase::Preparation).map(|phase| phase.state),
            Some(PhaseState::InProgress)
        );
    }
    Ok(())
}
