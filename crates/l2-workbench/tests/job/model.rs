use super::{Counter, Job, JobError, Phase, PhaseOutcome, PhaseState, TestResult, phase};
use std::{thread, time::Duration};

#[test]
fn restore_preserves_live_preparation_and_continues_its_clock() -> TestResult {
    let saved = Job::new("saved job");
    saved.start(Phase::Preparation, Some(20))?;
    saved.advance(Phase::Preparation, 4)?;
    saved.increment(Counter::CacheHits, 5)?;
    saved.start(Phase::TransformDiscovery, None)?;
    saved.advance(Phase::TransformDiscovery, 9)?;
    let mut checkpoint = saved.snapshot()?;
    let preparation = checkpoint
        .phases
        .iter_mut()
        .find(|item| item.phase == Phase::Preparation)
        .ok_or("missing saved preparation")?;
    preparation.elapsed_ms = 200;

    let live = Job::new("live job");
    live.start(Phase::Preparation, Some(12))?;
    live.set_current(Phase::Preparation, "opening cache")?;
    live.advance(Phase::Preparation, 3)?;
    live.increment(Counter::CacheHits, 2)?;
    thread::sleep(Duration::from_millis(10));
    let before = live.snapshot()?;
    live.request_cancel();
    live.restore(checkpoint)?;
    let after = live.snapshot()?;
    let active = phase(&after, Phase::Preparation)?;
    assert_eq!(after.current_phase, Some(Phase::Preparation));
    assert_eq!(active.state, PhaseState::InProgress);
    assert_eq!(active.completed, 7);
    assert_eq!(active.total, Some(12));
    assert_eq!(active.message.as_deref(), Some("opening cache"));
    assert!(active.elapsed_ms >= 200 + phase(&before, Phase::Preparation)?.elapsed_ms);
    assert_eq!(after.counters.get(&Counter::CacheHits), Some(&7));
    assert!(after.cancel_requested);
    assert!(live.is_cancelled());
    assert_eq!(
        phase(&after, Phase::TransformDiscovery)?.state,
        PhaseState::Pending
    );
    assert_eq!(phase(&after, Phase::TransformDiscovery)?.completed, 9);
    thread::sleep(Duration::from_millis(10));
    assert!(phase(&live.snapshot()?, Phase::Preparation)?.elapsed_ms > active.elapsed_ms);
    live.finish(Phase::Preparation, PhaseOutcome::Cancelled)?;
    Ok(())
}

#[test]
fn restore_rejects_active_scoped_work_while_preparation_runs() -> TestResult {
    let saved = Job::new("saved job").snapshot()?;
    let live = Job::new("live job");
    live.start(Phase::Preparation, None)?;
    let worker = live.work_scope(&"a".repeat(64))?;
    worker.increment(Counter::CandidatesExamined, 3)?;
    assert_eq!(live.restore(saved), Err(JobError::RestoreAfterStart));
    let snapshot = live.snapshot()?;
    assert_eq!(
        phase(&snapshot, Phase::Preparation)?.state,
        PhaseState::InProgress
    );
    assert_eq!(
        snapshot.counters.get(&Counter::CandidatesExamined),
        Some(&3)
    );
    Ok(())
}

#[test]
fn preparation_restore_overflow_leaves_live_job_unchanged() -> TestResult {
    let saved = Job::new("saved job");
    saved.start(Phase::Preparation, None)?;
    saved.advance(Phase::Preparation, u64::MAX)?;
    let live = Job::new("live job");
    live.start(Phase::Preparation, None)?;
    live.advance(Phase::Preparation, 1)?;
    live.increment(Counter::CacheMisses, 2)?;
    assert_eq!(
        live.restore(saved.snapshot()?),
        Err(JobError::PhaseOverflow(Phase::Preparation))
    );
    let snapshot = live.snapshot()?;
    assert_eq!(snapshot.label, "live job");
    assert_eq!(phase(&snapshot, Phase::Preparation)?.completed, 1);
    assert_eq!(snapshot.counters.get(&Counter::CacheMisses), Some(&2));
    Ok(())
}

#[test]
fn restore_rejects_finished_preparation_or_other_finished_pipeline_work() -> TestResult {
    let saved = Job::new("saved job").snapshot()?;
    for completed in [Phase::Preparation, Phase::Ingestion] {
        let live = Job::new("live job");
        live.start(completed, None)?;
        live.finish(completed, PhaseOutcome::Completed)?;
        if completed != Phase::Preparation {
            live.start(Phase::Preparation, None)?;
        }
        assert_eq!(
            live.restore(saved.clone()),
            Err(JobError::RestoreAfterStart)
        );
        assert_eq!(
            phase(&live.snapshot()?, completed)?.state,
            PhaseState::Completed
        );
    }
    Ok(())
}

#[test]
fn restore_rejects_active_discovery_even_when_preparation_is_current() -> TestResult {
    let saved = Job::new("saved job").snapshot()?;
    let live = Job::new("live job");
    live.start(Phase::TransformDiscovery, None)?;
    live.advance(Phase::TransformDiscovery, 8)?;
    live.start(Phase::Preparation, None)?;
    assert_eq!(live.snapshot()?.current_phase, Some(Phase::Preparation));
    assert_eq!(live.restore(saved), Err(JobError::RestoreAfterStart));
    let snapshot = live.snapshot()?;
    assert_eq!(phase(&snapshot, Phase::TransformDiscovery)?.completed, 8);
    assert_eq!(
        phase(&snapshot, Phase::Preparation)?.state,
        PhaseState::InProgress
    );
    Ok(())
}
