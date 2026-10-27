use super::*;
use crate::result_directory::ResultKind;
use l2_workbench::job::{
    CacheFallbackKind, CacheStage, Counter, JobError, Phase, PhaseOutcome, PhaseState,
    cache::SourceIdentity,
};
use serde_json::json;
#[cfg(unix)]
use std::{fs, io};

#[test]
fn checkpoint_memory_pressure_is_preserved_in_optional_and_strict_modes()
-> Result<(), Box<dyn Error>> {
    for strict_cache in [false, true] {
        let temporary = tempfile::tempdir()?;
        let cache = Cache::open_at(
            temporary.path().join("cache"),
            temporary.path().join("state"),
            1024 * 1024,
        )?;
        let memory = l2_workbench::job::MemoryBudget::new(1);
        cache.attach_memory_budget(memory.clone())?;
        let job = Job::new("checkpoint admission");
        let options = RecoveryOptions {
            strict_cache,
            ..RecoveryOptions::default()
        };
        let error = RecoveryCache::from_cache(cache, &identity()?, &options, &job)
            .err()
            .ok_or("memory pressure was silently treated as an optional cache miss")?;
        assert!(crate::memory_error::find(error.as_ref()).is_some());
        assert!(job.snapshot()?.cache_fallbacks.records().is_empty());
        assert_eq!(memory.snapshot()?.used_bytes, 0);
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn checkpoint_start_failure_disables_optional_cache_and_keeps_strict_failure()
-> Result<(), Box<dyn Error>> {
    for strict in [false, true] {
        let temporary = tempfile::tempdir()?;
        let cache_root = temporary.path().join("cache");
        let cache = Cache::open_at(&cache_root, temporary.path().join("state"), 1024 * 1024)?;
        fs::rename(&cache_root, temporary.path().join("moved-cache"))?;
        let job = Job::new("start failure");
        let options = RecoveryOptions {
            strict_cache: strict,
            ..RecoveryOptions::default()
        };
        let result = RecoveryCache::from_cache(cache, &identity()?, &options, &job);
        if strict {
            assert!(
                result.is_err(),
                "strict mode accepted an unavailable checkpoint"
            );
        } else {
            let cache = result?;
            assert!(
                cache.cache().is_none(),
                "an unavailable cache must not be reused"
            );
            assert_checkpoint_fallback(&job)?;
            cache.finish(Ok(()), &job)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn checkpoint_finish_failure_respects_strict_mode_and_preserves_operation_error()
-> Result<(), Box<dyn Error>> {
    for strict in [false, true] {
        for operation_failed in [false, true] {
            let temporary = tempfile::tempdir()?;
            let cache_root = temporary.path().join("cache");
            let cache = Cache::open_at(&cache_root, temporary.path().join("state"), 1024 * 1024)?;
            let job = Job::new("finish failure");
            let options = RecoveryOptions {
                strict_cache: strict,
                ..RecoveryOptions::default()
            };
            let session = RecoveryCache::from_cache(cache, &identity()?, &options, &job)?;
            fs::rename(&cache_root, temporary.path().join("moved-cache"))?;
            let operation = if operation_failed {
                Err(io::Error::other("original operation error").into())
            } else {
                Ok(())
            };
            let result = session.finish(operation, &job);
            if operation_failed {
                let error = result.err().ok_or("operation error was lost")?;
                assert!(
                    error.to_string().contains("original operation error"),
                    "{error}"
                );
                if strict {
                    assert!(
                        error
                            .source()
                            .is_some_and(|source| source.to_string() == "original operation error"),
                        "original error must remain in the error chain: {error}"
                    );
                }
            } else if strict {
                assert!(result.is_err(), "strict mode accepted a failed checkpoint");
            } else {
                result?;
            }
            if !strict {
                assert_checkpoint_fallback(&job)?;
            }
        }
    }
    Ok(())
}

#[test]
fn reopening_cache_keeps_preparation_visible_and_restores_saved_counters()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache_root = temporary.path().join("cache");
    let state_root = temporary.path().join("state");
    let original_cache = Cache::open_at(&cache_root, &state_root, 1024 * 1024)?;
    let saved = Job::new("saved recovery");
    saved.increment(Counter::Records, 9)?;
    CheckpointWriter::start(&original_cache, &identity()?, &saved, false)?.finish(false)?;
    drop(original_cache);

    let live = Job::new("resuming recovery");
    live.start(Phase::Preparation, None)?;
    live.set_current(Phase::Preparation, "opening cache")?;
    live.increment(Counter::CacheMisses, 1)?;
    let visible = live.snapshot()?;
    assert_eq!(
        visible.phase(Phase::Preparation).map(|phase| phase.state),
        Some(PhaseState::InProgress)
    );
    let cache = Cache::open_at(&cache_root, &state_root, 1024 * 1024)?;
    let session =
        RecoveryCache::from_cache(cache, &identity()?, &RecoveryOptions::default(), &live)?;
    let restored = live.snapshot()?;
    let preparation = restored
        .phase(Phase::Preparation)
        .ok_or("preparation is missing")?;
    assert_eq!(preparation.state, PhaseState::InProgress);
    assert_eq!(preparation.message.as_deref(), Some("opening cache"));
    assert_eq!(restored.counters.get(&Counter::Records), Some(&9));
    assert_eq!(restored.counters.get(&Counter::CacheMisses), Some(&1));
    live.finish(Phase::Preparation, PhaseOutcome::Completed)?;
    session.finish(Ok(()), &live)?;
    Ok(())
}

#[test]
fn checkpoint_restoration_cannot_hide_a_job_state_error() -> Result<(), Box<dyn Error>> {
    for strict in [false, true] {
        let temporary = tempfile::tempdir()?;
        let cache = Cache::open_at(
            temporary.path().join("cache"),
            temporary.path().join("state"),
            1024 * 1024,
        )?;
        let options = RecoveryOptions {
            strict_cache: strict,
            ..RecoveryOptions::default()
        };
        let identity = identity()?;
        let original = Job::new("saved job");
        RecoveryCache::from_cache(cache.clone(), &identity, &options, &original)?
            .finish(Ok(()), &original)?;
        // Save an active checkpoint so that the next run attempts restoration
        let checkpoint = CheckpointWriter::start(&cache, &identity, &original, false)?;
        checkpoint.finish(false)?;
        let running = Job::new("running job");
        running.start(Phase::TransformDiscovery, None)?;
        let Err(error) = RecoveryCache::from_cache(cache, &identity, &options, &running) else {
            return Err("restoring over live job state should fail".into());
        };
        assert_eq!(
            error.downcast_ref::<JobError>(),
            Some(&JobError::RestoreAfterStart)
        );
        assert!(running.snapshot()?.cache_fallbacks.records().is_empty());
    }
    Ok(())
}

#[test]
fn invalid_recovery_identity_is_not_downgraded_to_a_cache_fallback() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        1024 * 1024,
    )?;
    let mut invalid_identity = identity()?;
    invalid_identity.source = SourceIdentity::Sha256("invalid digest".to_owned());
    let job = Job::new("invalid identity");
    let result =
        RecoveryCache::from_cache(cache, &invalid_identity, &RecoveryOptions::default(), &job);
    assert!(result.is_err(), "invalid identity must remain an error");
    assert!(job.snapshot()?.cache_fallbacks.records().is_empty());
    Ok(())
}

#[test]
fn failed_initial_write_does_not_restore_saved_progress() -> Result<(), Box<dyn Error>> {
    for strict in [false, true] {
        let temporary = tempfile::tempdir()?;
        let state_root = temporary.path().join("state");
        let cache = Cache::open_at(temporary.path().join("cache"), &state_root, 1024 * 1024)?;
        let identity = identity()?;
        let saved = Job::new("saved job");
        saved.increment(Counter::CandidatesExamined, u64::MAX)?;
        CheckpointWriter::start(&cache, &identity, &saved, false)?.finish(false)?;
        let connection = rusqlite::Connection::open(state_root.join("cache.sqlite3"))?;
        let snapshot: String =
            connection.query_row("SELECT snapshot_json FROM checkpoints", [], |row| {
                row.get(0)
            })?;
        let mut snapshot: serde_json::Value = serde_json::from_str(&snapshot)?;
        *snapshot
            .get_mut("elapsed_ms")
            .ok_or("missing saved elapsed time")? = serde_json::json!(86_400_000_u64);
        connection.execute(
            "UPDATE checkpoints SET snapshot_json = ?1",
            [snapshot.to_string()],
        )?;
        connection.execute_batch("CREATE TRIGGER reject_checkpoint BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT, 'checkpoint write rejected'); END;")?;
        drop(connection);

        let live = Job::new("fresh live job");
        live.increment(Counter::Files, 3)?;
        live.record_cache_fallback(
            CacheStage::ArtifactAnalysis,
            CacheFallbackKind::LookupFailed,
            format_args!("existing fallback"),
        )?;
        let before = live.snapshot()?;
        let options = RecoveryOptions {
            strict_cache: strict,
            ..RecoveryOptions::default()
        };
        let result = RecoveryCache::from_cache(cache, &identity, &options, &live);
        if strict {
            assert!(
                result.is_err(),
                "strict checkpoint write failure must propagate"
            );
        } else {
            let session = result?;
            assert!(session.cache().is_none());
            session.finish(Ok(()), &live)?;
            assert_checkpoint_fallback(&live)?;
        }
        let after = live.snapshot()?;
        assert_eq!(after.label, before.label);
        assert_eq!(after.created_at_unix_ms, before.created_at_unix_ms);
        assert_eq!(after.phases, before.phases);
        assert_eq!(after.counters, before.counters);
        assert!(
            after.elapsed_ms < 86_400_000,
            "saved elapsed time leaked into the live job"
        );
        assert!(
            after
                .cache_fallbacks
                .records()
                .iter()
                .any(|record| record.stage() == CacheStage::ArtifactAnalysis
                    && record.kind() == CacheFallbackKind::LookupFailed
                    && record.count() == 1)
        );
        live.increment(Counter::CandidatesExamined, 1)?;
    }
    Ok(())
}

#[test]
fn malformed_checkpoint_phases_fall_back_without_changing_live_state() -> Result<(), Box<dyn Error>>
{
    for corruption in ["missing", "duplicate", "invalid progress"] {
        for strict in [false, true] {
            let temporary = tempfile::tempdir()?;
            let state_root = temporary.path().join("state");
            let cache = Cache::open_at(temporary.path().join("cache"), &state_root, 1024 * 1024)?;
            let identity = identity()?;
            let saved = Job::new("saved job");
            saved.increment(Counter::CandidatesExamined, 23)?;
            CheckpointWriter::start(&cache, &identity, &saved, false)?.finish(false)?;
            let connection = rusqlite::Connection::open(state_root.join("cache.sqlite3"))?;
            let snapshot: String =
                connection.query_row("SELECT snapshot_json FROM checkpoints", [], |row| {
                    row.get(0)
                })?;
            let mut snapshot: serde_json::Value = serde_json::from_str(&snapshot)?;
            let phases = snapshot
                .get_mut("phases")
                .and_then(serde_json::Value::as_array_mut)
                .ok_or("missing saved phases")?;
            match corruption {
                "missing" => phases.clear(),
                "duplicate" => {
                    let first = phases.first().cloned().ok_or("missing first phase")?;
                    *phases.get_mut(1).ok_or("missing second phase")? = first;
                }
                _ => {
                    let first = phases.first_mut().ok_or("missing first phase")?;
                    *first
                        .get_mut("progress_percent")
                        .ok_or("missing progress")? = serde_json::json!(101);
                }
            }
            connection.execute(
                "UPDATE checkpoints SET snapshot_json = ?1",
                [snapshot.to_string()],
            )?;
            drop(connection);
            let live = Job::new("fresh live job");
            live.increment(Counter::Files, 3)?;
            let before = live.snapshot()?;
            let options = RecoveryOptions {
                strict_cache: strict,
                ..RecoveryOptions::default()
            };
            let result = RecoveryCache::from_cache(cache, &identity, &options, &live);
            if strict {
                let error = result
                    .err()
                    .ok_or("strict mode accepted a malformed checkpoint")?;
                assert!(
                    error
                        .to_string()
                        .contains("saved job checkpoint is corrupt"),
                    "{error}"
                );
            } else {
                let session = result?;
                assert!(session.cache().is_none());
                session.finish(Ok(()), &live)?;
                assert_checkpoint_fallback(&live)?;
            }
            let after = live.snapshot()?;
            assert_eq!(after.label, before.label);
            assert_eq!(after.created_at_unix_ms, before.created_at_unix_ms);
            assert_eq!(after.phases, before.phases);
            assert_eq!(after.counters, before.counters);
            live.start(Phase::Preparation, None)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn cancellation_is_preserved_when_checkpoint_finish_fails() -> Result<(), Box<dyn Error>> {
    for strict in [false, true] {
        let temporary = tempfile::tempdir()?;
        let cache_root = temporary.path().join("cache");
        let cache = Cache::open_at(&cache_root, temporary.path().join("state"), 1024 * 1024)?;
        let job = Job::new("cancelled job");
        let options = RecoveryOptions {
            strict_cache: strict,
            ..RecoveryOptions::default()
        };
        let session = RecoveryCache::from_cache(cache, &identity()?, &options, &job)?;
        fs::rename(&cache_root, temporary.path().join("moved-cache"))?;
        job.request_cancel();
        let error = session
            .finish(Ok(()), &job)
            .err()
            .ok_or("cancellation was ignored")?;
        let cancellation = if strict {
            error
                .source()
                .and_then(|source| source.downcast_ref::<JobError>())
        } else {
            error.downcast_ref::<JobError>()
        };
        assert_eq!(cancellation, Some(&JobError::Cancelled));
        if !strict {
            assert_checkpoint_fallback(&job)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn real_full_filesystem_preserves_prior_checkpoint_and_respects_strict_mode()
-> Result<(), Box<dyn Error>> {
    use std::io::Write;

    let Some(base) = std::env::var_os("L2_TEST_ENOSPC_ROOT") else {
        eprintln!("checkpoint ENOSPC test needs an isolated small filesystem");
        return Ok(());
    };
    for strict in [false, true] {
        let temporary = tempfile::tempdir_in(&base)?;
        let cache = Cache::open_at(
            temporary.path().join("cache"),
            temporary.path().join("state"),
            1024 * 1024,
        )?;
        let identity = identity()?;
        let saved = Job::new("saved progress");
        saved.increment(Counter::Files, 11)?;
        CheckpointWriter::start(&cache, &identity, &saved, false)?.finish(false)?;

        // Fill only the isolated tmpfs and keep the file open during the failed write
        let filler_path = temporary.path().join("space-filler");
        let mut filler = fs::File::create(&filler_path)?;
        let block = [0_u8; 8 * 1024];
        let mut full = false;
        for _ in 0..512 {
            if let Err(error) = filler.write_all(&block) {
                assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
                full = true;
                break;
            }
        }
        assert!(full, "the isolated filesystem did not report ENOSPC");
        let live = Job::new("fresh progress");
        let options = RecoveryOptions {
            strict_cache: strict,
            ..RecoveryOptions::default()
        };
        let result = RecoveryCache::from_cache(cache.clone(), &identity, &options, &live);
        if strict {
            assert!(result.is_err(), "strict mode accepted a full filesystem");
        } else {
            let session = result?;
            assert!(session.cache().is_none(), "full cache was not disabled");
            assert_checkpoint_fallback(&live)?;
            session.finish(Ok(()), &live)?;
        }
        assert_eq!(live.snapshot()?.counters.get(&Counter::Files), Some(&0));
        drop(filler);
        fs::remove_file(filler_path)?;

        // Once space is freed, the last committed checkpoint must still load
        let resumed = Job::new("resumed progress");
        let writer = CheckpointWriter::start(&cache, &identity, &resumed, false)?;
        assert_eq!(resumed.snapshot()?.counters.get(&Counter::Files), Some(&11));
        writer.finish(false)?;
    }
    Ok(())
}

fn identity() -> Result<ResultIdentity, Box<dyn Error>> {
    Ok(ResultIdentity {
        kind: ResultKind::Extract,
        algorithm_version: 2,
        source: SourceIdentity::from_sha256("0".repeat(64))?,
        settings: json!({}),
    })
}

fn assert_checkpoint_fallback(job: &Job) -> Result<(), Box<dyn Error>> {
    let snapshot = job.snapshot()?;
    let records = snapshot.cache_fallbacks.records();
    assert!(
        records
            .iter()
            .any(|record| record.stage() == CacheStage::Checkpoint
                && record.kind() == CacheFallbackKind::CacheUnavailable
                && record.count() == 1),
        "checkpoint fallback missing: {records:?}"
    );
    Ok(())
}
