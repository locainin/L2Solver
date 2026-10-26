use std::error::Error;
use std::io;
use std::thread;
use std::time::Duration;

use l2_workbench::job::{
    Counter, Job, JobError, JobSnapshot, Phase, PhaseOutcome, PhaseSnapshot, PhaseState,
};

type TestResult = Result<(), Box<dyn Error>>;

fn phase(snapshot: &JobSnapshot, phase: Phase) -> Result<&PhaseSnapshot, io::Error> {
    snapshot
        .phase(phase)
        .ok_or_else(|| io::Error::other("expected phase is missing"))
}

#[test]
fn snapshots_track_phase_progress_and_elapsed_time() -> TestResult {
    let job = Job::new("capture recovery");

    job.start(Phase::Ingestion, Some(4))?;
    job.advance(Phase::Ingestion, 1)?;
    job.increment(Counter::Bytes, 128)?;
    thread::sleep(Duration::from_millis(10));

    let snapshot = job.snapshot()?;
    let ingestion = phase(&snapshot, Phase::Ingestion)?;

    assert_eq!(snapshot.label, "capture recovery");
    assert_eq!(ingestion.state, PhaseState::InProgress);
    assert_eq!(ingestion.completed, 1);
    assert_eq!(ingestion.total, Some(4));
    assert_eq!(ingestion.progress_percent, Some(25));
    assert!(ingestion.elapsed_ms > 0);
    assert_eq!(snapshot.counters.get(&Counter::Bytes), Some(&128));
    Ok(())
}

#[test]
fn discovery_with_unknown_work_has_no_percentage_or_eta() -> TestResult {
    let job = Job::new("record discovery");

    job.start(Phase::FramingRecordDiscovery, None)?;
    job.advance(Phase::FramingRecordDiscovery, 500)?;

    let snapshot = job.snapshot()?;
    let discovery = phase(&snapshot, Phase::FramingRecordDiscovery)?;

    assert_eq!(discovery.completed, 500);
    assert_eq!(discovery.progress_percent, None);
    assert_eq!(discovery.eta_seconds, None);
    Ok(())
}

#[test]
fn known_work_produces_an_eta_only_after_a_measured_interval() -> TestResult {
    let job = Job::new("bounded work");
    job.start(Phase::Ingestion, Some(10))?;
    job.advance(Phase::Ingestion, 1)?;

    let early_snapshot = job.snapshot()?;
    let early_ingestion = phase(&early_snapshot, Phase::Ingestion)?;
    assert_eq!(early_ingestion.eta_seconds, None);

    let mut checkpoint = early_snapshot;
    let checkpoint_ingestion = checkpoint
        .phases
        .iter_mut()
        .find(|phase| phase.phase == Phase::Ingestion)
        .ok_or_else(|| io::Error::other("ingestion phase should be in the checkpoint"))?;
    checkpoint_ingestion.elapsed_ms = 1_000;

    let resumed = Job::new("bounded work");
    resumed.restore(checkpoint)?;
    resumed.start(Phase::Ingestion, Some(10))?;
    let measured_snapshot = resumed.snapshot()?;
    let measured_ingestion = phase(&measured_snapshot, Phase::Ingestion)?;

    assert!(measured_ingestion.rate_per_second.is_some());
    assert_eq!(measured_ingestion.eta_seconds, Some(9));
    Ok(())
}

#[test]
fn record_work_updates_the_global_counter_and_active_phase_together() -> TestResult {
    let job = Job::new("counted candidate search");
    job.start(Phase::TransformDiscovery, None)?;
    job.start(Phase::Expansion, None)?;
    job.record_work(Phase::TransformDiscovery, Counter::CandidatesExamined, 7)?;

    let snapshot = job.snapshot()?;
    let discovery = phase(&snapshot, Phase::TransformDiscovery)?;
    assert_eq!(discovery.completed, 7);
    assert_eq!(snapshot.current_phase, Some(Phase::TransformDiscovery));
    assert_eq!(
        snapshot.counters.get(&Counter::CandidatesExamined),
        Some(&7)
    );
    Ok(())
}

#[test]
fn record_work_counts_standalone_work_without_starting_an_inactive_phase() -> TestResult {
    let job = Job::new("inactive candidate search");

    job.record_work(Phase::TransformDiscovery, Counter::CandidatesExamined, 3)?;

    let snapshot = job.snapshot()?;
    let discovery = phase(&snapshot, Phase::TransformDiscovery)?;
    assert_eq!(discovery.state, PhaseState::Pending);
    assert_eq!(discovery.completed, 0);
    assert_eq!(snapshot.current_phase, None);
    assert_eq!(
        snapshot.counters.get(&Counter::CandidatesExamined),
        Some(&3)
    );
    Ok(())
}

#[test]
fn record_work_overflow_does_not_partially_update_either_measurement() -> TestResult {
    let counter_overflow_job = Job::new("candidate counter overflow");
    counter_overflow_job.start(Phase::TransformDiscovery, None)?;
    counter_overflow_job.advance(Phase::TransformDiscovery, 5)?;
    counter_overflow_job.increment(Counter::CandidatesExamined, u64::MAX)?;
    assert_eq!(
        counter_overflow_job.record_work(Phase::TransformDiscovery, Counter::CandidatesExamined, 1),
        Err(JobError::CounterOverflow(Counter::CandidatesExamined))
    );
    let counter_overflow = counter_overflow_job.snapshot()?;
    assert_eq!(
        phase(&counter_overflow, Phase::TransformDiscovery)?.completed,
        5
    );
    assert_eq!(
        counter_overflow.counters.get(&Counter::CandidatesExamined),
        Some(&u64::MAX)
    );

    let phase_overflow_job = Job::new("phase count overflow");
    phase_overflow_job.start(Phase::TransformDiscovery, None)?;
    phase_overflow_job.advance(Phase::TransformDiscovery, u64::MAX)?;
    assert_eq!(
        phase_overflow_job.record_work(Phase::TransformDiscovery, Counter::CandidatesExamined, 1),
        Err(JobError::PhaseOverflow(Phase::TransformDiscovery))
    );
    let phase_overflow = phase_overflow_job.snapshot()?;
    assert_eq!(
        phase(&phase_overflow, Phase::TransformDiscovery)?.completed,
        u64::MAX
    );
    assert_eq!(
        phase_overflow.counters.get(&Counter::CandidatesExamined),
        Some(&0)
    );
    Ok(())
}

#[test]
fn bounded_phase_progress_never_exceeds_one_hundred_percent() -> TestResult {
    let job = Job::new("bounded ingestion");

    job.start(Phase::Ingestion, Some(2))?;
    job.advance(Phase::Ingestion, 3)?;

    let snapshot = job.snapshot()?;
    let ingestion = phase(&snapshot, Phase::Ingestion)?;

    assert_eq!(ingestion.completed, 3);
    assert_eq!(ingestion.progress_percent, Some(100));
    assert_eq!(ingestion.eta_seconds, None);
    Ok(())
}

#[test]
fn setting_an_absolute_count_does_not_double_count_replayed_work() -> TestResult {
    let job = Job::new("replayed work");
    job.start(Phase::Ingestion, Some(10))?;
    job.set_completed(Phase::Ingestion, 4)?;
    job.set_completed(Phase::Ingestion, 4)?;

    let snapshot = job.snapshot()?;
    assert_eq!(phase(&snapshot, Phase::Ingestion)?.completed, 4);
    Ok(())
}

#[test]
fn setting_current_selects_the_phase_reported_in_the_snapshot() -> TestResult {
    let job = Job::new("interleaved discovery");
    job.start(Phase::Expansion, None)?;
    job.start(Phase::TransformDiscovery, None)?;

    job.set_current(Phase::Expansion, "expanding validated containers")?;

    let snapshot = job.snapshot()?;
    assert_eq!(snapshot.current_phase, Some(Phase::Expansion));
    assert_eq!(
        phase(&snapshot, Phase::Expansion)?.message.as_deref(),
        Some("expanding validated containers")
    );
    assert_eq!(
        phase(&snapshot, Phase::TransformDiscovery)?.state,
        PhaseState::InProgress
    );
    Ok(())
}

#[test]
fn restore_rejects_replacing_live_phase_progress() -> TestResult {
    let job = Job::new("active recovery");
    job.start(Phase::Preparation, Some(2))?;
    let snapshot = job.snapshot()?;

    assert_eq!(job.restore(snapshot), Err(JobError::RestoreAfterStart));
    assert_eq!(
        phase(&job.snapshot()?, Phase::Preparation)?.state,
        PhaseState::InProgress
    );
    Ok(())
}

#[test]
fn overflowing_counts_return_errors_without_wrapping() -> TestResult {
    let job = Job::new("overflow checks");
    job.start(Phase::Ingestion, Some(u64::MAX))?;
    job.advance(Phase::Ingestion, u64::MAX)?;
    assert_eq!(
        job.advance(Phase::Ingestion, 1),
        Err(JobError::PhaseOverflow(Phase::Ingestion))
    );

    job.increment(Counter::Bytes, u64::MAX)?;
    assert_eq!(
        job.increment(Counter::Bytes, 1),
        Err(JobError::CounterOverflow(Counter::Bytes))
    );

    let snapshot = job.snapshot()?;
    assert_eq!(phase(&snapshot, Phase::Ingestion)?.completed, u64::MAX);
    assert_eq!(snapshot.counters.get(&Counter::Bytes), Some(&u64::MAX));
    Ok(())
}

#[test]
fn cancellation_is_visible_in_the_snapshot_and_cooperative_check() -> TestResult {
    let job = Job::new("cancelled recovery");
    job.request_cancel();

    assert!(job.is_cancelled());
    assert!(matches!(job.check_cancelled(), Err(JobError::Cancelled)));
    assert!(job.snapshot()?.cancel_requested);
    Ok(())
}

#[test]
fn snapshots_round_trip_through_json() -> TestResult {
    let job = Job::new("snapshot round trip");
    job.start(Phase::Preparation, Some(1))?;
    job.advance(Phase::Preparation, 1)?;
    job.finish(Phase::Preparation, PhaseOutcome::Completed)?;

    let snapshot = job.snapshot()?;
    let json = serde_json::to_string(&snapshot)?;
    let restored: JobSnapshot = serde_json::from_str(&json)?;

    assert_eq!(restored, snapshot);
    Ok(())
}

#[test]
fn restoring_an_interrupted_job_preserves_counts_and_elapsed_time() -> TestResult {
    let previous = Job::new("resumable recovery");
    previous.start(Phase::Ingestion, Some(8))?;
    previous.advance(Phase::Ingestion, 3)?;
    thread::sleep(Duration::from_millis(10));
    let checkpoint = previous.snapshot()?;
    let prior_job_elapsed = checkpoint.elapsed_ms;
    let prior_elapsed = phase(&checkpoint, Phase::Ingestion)?.elapsed_ms;

    let resumed = Job::new("resumable recovery");
    let watched_handle = resumed.clone();
    resumed.increment(Counter::CacheHits, 1)?;
    resumed.restore(checkpoint.clone())?;
    let pending = resumed.snapshot()?;
    assert!(!pending.cancel_requested);
    assert_eq!(
        phase(&watched_handle.snapshot()?, Phase::Ingestion)?.completed,
        3
    );
    assert!(pending.elapsed_ms >= prior_job_elapsed);
    let ingestion = phase(&pending, Phase::Ingestion)?;
    assert_eq!(ingestion.state, PhaseState::Pending);
    assert_eq!(ingestion.completed, 3);
    assert!(ingestion.elapsed_ms >= prior_elapsed);
    assert_eq!(pending.counters.get(&Counter::CacheHits), Some(&1));

    let mut old_cancelled_snapshot = checkpoint.clone();
    old_cancelled_snapshot.cancel_requested = true;
    let fresh_invocation = Job::new("fresh invocation");
    fresh_invocation.restore(old_cancelled_snapshot)?;
    assert!(!fresh_invocation.is_cancelled());

    let cancelled_during_lookup = Job::new("cancelled during lookup");
    cancelled_during_lookup.request_cancel();
    cancelled_during_lookup.restore(checkpoint)?;
    assert!(cancelled_during_lookup.is_cancelled());

    resumed.start(Phase::Ingestion, Some(8))?;
    resumed.set_completed(Phase::Ingestion, 3)?;
    resumed.advance(Phase::Ingestion, 5)?;
    resumed.finish(Phase::Ingestion, PhaseOutcome::Completed)?;

    let completed = resumed.snapshot()?;
    let ingestion = phase(&completed, Phase::Ingestion)?;
    assert_eq!(ingestion.completed, 8);
    assert_eq!(ingestion.progress_percent, Some(100));
    assert!(ingestion.elapsed_ms >= prior_elapsed);
    Ok(())
}

#[test]
fn cloned_job_handles_share_counter_updates_across_threads() -> TestResult {
    let job = Job::new("concurrent counters");
    let workers = (0..4)
        .map(|_| {
            let job = job.clone();
            thread::spawn(move || {
                for _ in 0..100 {
                    job.increment(Counter::CandidatesExamined, 1)?;
                }
                Ok::<(), JobError>(())
            })
        })
        .collect::<Vec<_>>();

    for worker in workers {
        worker
            .join()
            .map_err(|_| io::Error::other("counter worker panicked"))??;
    }

    let snapshot = job.snapshot()?;
    assert_eq!(
        snapshot.counters.get(&Counter::CandidatesExamined),
        Some(&400)
    );
    Ok(())
}

#[path = "job/cache.rs"]
mod cache;

#[path = "job/cache_fallback.rs"]
mod cache_fallback;
