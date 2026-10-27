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
#[test]
fn worker_stops_if_live_job_changes_after_checkpoint_preview() -> Result<(), Box<dyn Error>> {
    for cancel in [false, true] {
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
        CheckpointWriter::start(&cache, &identity, &saved, false)?.finish(false)?;

        let connection = rusqlite::Connection::open(state_root.join("cache.sqlite3"))?;
        let key: String =
            connection.query_row("SELECT key FROM checkpoints", [], |row| row.get(0))?;
        let checkpoint_lock = std::fs::canonicalize(&state_root)?
            .join("locks")
            .join(format!("{key}.lock"));
        connection.execute_batch("BEGIN IMMEDIATE")?;
        let live = Job::new("live job");
        let (result_sender, result_receiver) = std::sync::mpsc::channel();
        let test_cache = cache.clone();
        let test_identity = identity.clone();
        let test_job = live.clone();
        let thread = std::thread::spawn(move || {
            let result = CheckpointWriter::start(&test_cache, &test_identity, &test_job, false);
            let outcome = match result {
                Err(CheckpointError::Job(error)) => Some(error),
                Err(_) => None,
                Ok(writer) => {
                    let _ = writer.finish(false);
                    None
                }
            };
            let _ = result_sender.send(outcome);
        });

        // The open key lock shows that preview finished and the database write is waiting
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        let mut waiting = false;
        while std::time::Instant::now() < deadline {
            waiting = std::fs::read_dir("/proc/self/fd")?
                .filter_map(Result::ok)
                .filter_map(|entry| std::fs::read_link(entry.path()).ok())
                .any(|path| path == checkpoint_lock);
            if waiting {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if !waiting {
            connection.execute_batch("ROLLBACK")?;
            return Err("checkpoint writer did not reach the locked database".into());
        }
        let expected = if cancel {
            live.request_cancel();
            JobError::Cancelled
        } else {
            live.start(Phase::Preparation, None)?;
            JobError::RestoreAfterStart
        };
        connection.execute_batch("COMMIT")?;
        let actual = result_receiver.recv_timeout(Duration::from_secs(10))?;
        assert_eq!(actual, Some(expected));
        thread
            .join()
            .map_err(|_| "checkpoint startup thread panicked")?;
        assert_eq!(live.snapshot()?.label, "live job");
    }
    Ok(())
}
