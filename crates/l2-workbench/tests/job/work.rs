use std::{error::Error, thread};

use l2_workbench::job::{
    Counter, Job, Phase, RecoveryTransition, RecoveryTransitionOutcome, RecoveryTransitionRecord,
    RecoveryTransitionStage, WorkSnapshot,
};

type TestResult = Result<(), Box<dyn Error>>;

fn counter(job: &Job, counter: Counter) -> Result<u64, Box<dyn Error>> {
    Ok(job.snapshot()?.counters.get(&counter).copied().unwrap_or(0))
}

#[test]
fn work_restore_replaces_only_its_own_counters() -> TestResult {
    let job = Job::new("independent concurrent cases");
    job.increment(Counter::Bytes, 7)?;
    let first = job.work_scope(&"a".repeat(64))?;
    let second = job.work_scope(&"b".repeat(64))?;
    first.increment(Counter::CandidatesExamined, 5)?;
    let first_committed = first.work_snapshot()?;
    assert_eq!(first_committed.counter(Counter::CandidatesExamined), 5);
    first.increment(Counter::CandidatesExamined, 100)?;
    second.increment(Counter::CandidatesExamined, 11)?;
    first.restore_work(first_committed.clone())?;
    first.restore_work(first_committed)?;

    assert_eq!(counter(&job, Counter::CandidatesExamined)?, 16);
    assert_eq!(counter(&job, Counter::Bytes)?, 7);
    assert_eq!(counter(&second, Counter::CandidatesExamined)?, 16);
    Ok(())
}

#[test]
fn durable_job_snapshot_excludes_work_saved_in_case_generations() -> TestResult {
    let job = Job::new("checkpoint contributions");
    job.increment(Counter::Packets, 17)?;
    let work = job.work_scope(&"c".repeat(64))?;
    work.increment(Counter::CandidatesExamined, 31)?;
    let saved_work = work.work_snapshot()?;
    let saved_job = job.checkpoint_snapshot()?;
    assert_eq!(
        saved_job.counters.get(&Counter::CandidatesExamined),
        Some(&0)
    );
    assert_eq!(saved_job.counters.get(&Counter::Packets), Some(&17));

    let resumed = Job::new("fresh process");
    resumed.restore(saved_job)?;
    let restored_work = resumed.work_scope(&"c".repeat(64))?;
    restored_work.restore_work(saved_work)?;
    restored_work.increment(Counter::CandidatesExamined, 2)?;
    assert_eq!(counter(&resumed, Counter::CandidatesExamined)?, 33);
    assert_eq!(counter(&resumed, Counter::Packets)?, 17);
    Ok(())
}

#[test]
fn dropping_the_last_work_handle_keeps_displayed_totals_out_of_global_checkpoint() -> TestResult {
    let job = Job::new("completed case");
    {
        let work = job.work_scope(&"d".repeat(64))?;
        let alias = work.clone();
        work.increment(Counter::Records, 23)?;
        drop(work);
        alias.increment(Counter::Records, 1)?;
    }
    assert_eq!(counter(&job, Counter::Records)?, 24);
    assert_eq!(
        job.checkpoint_snapshot()?.counters.get(&Counter::Records),
        Some(&0)
    );
    Ok(())
}

#[test]
fn restoring_a_different_work_identity_is_rejected_without_changing_progress() -> TestResult {
    let job = Job::new("mismatched generation");
    let first = job.work_scope(&"e".repeat(64))?;
    let second = job.work_scope(&"f".repeat(64))?;
    first.increment(Counter::Transforms, 3)?;
    second.increment(Counter::Transforms, 7)?;
    assert!(first.restore_work(second.work_snapshot()?).is_err());
    assert_eq!(counter(&job, Counter::Transforms)?, 10);
    assert!(job.work_snapshot().is_err());
    assert!(job.work_scope("unbounded capture-controlled name").is_err());
    Ok(())
}

#[test]
fn scope_restore_rejects_counter_overflow_without_partial_changes() -> TestResult {
    let job = Job::new("bounded cumulative totals");
    job.increment(Counter::CandidatesExamined, 1)?;
    let work = job.work_scope(&"0".repeat(64))?;
    work.increment(Counter::CandidatesExamined, 2)?;
    let mut encoded = serde_json::to_value(work.work_snapshot()?)?;
    let value = encoded
        .get_mut("counts")
        .and_then(|counts| counts.get_mut("counters"))
        .and_then(|counters| counters.get_mut("candidates_examined"))
        .ok_or_else(|| std::io::Error::other("expected candidate counter is missing"))?;
    *value = serde_json::json!(u64::MAX);
    let over_limit: WorkSnapshot = serde_json::from_value(encoded)?;
    assert!(work.restore_work(over_limit).is_err());
    assert_eq!(counter(&job, Counter::CandidatesExamined)?, 3);
    Ok(())
}

#[test]
fn concurrent_work_updates_are_isolated_and_share_cancellation() -> TestResult {
    let job = Job::new("concurrent work");
    let first = job.work_scope(&"1".repeat(64))?;
    let second = job.work_scope(&"2".repeat(64))?;
    thread::scope(|threads| -> TestResult {
        let mut workers = Vec::new();
        for work in [&first, &second] {
            workers.push(threads.spawn(move || {
                for _ in 0..1_000 {
                    work.increment(Counter::CandidatesExamined, 1)?;
                }
                Ok::<_, l2_workbench::job::JobError>(())
            }));
        }
        for worker in workers {
            worker
                .join()
                .map_err(|_| std::io::Error::other("counter worker panicked"))??;
        }
        Ok(())
    })?;
    assert_eq!(counter(&job, Counter::CandidatesExamined)?, 2_000);
    job.request_cancel();
    assert!(first.check_cancelled().is_err());
    assert!(second.check_cancelled().is_err());
    Ok(())
}

#[test]
fn phase_work_restore_preserves_other_workers_and_base_progress() -> TestResult {
    let job = Job::new("independent phase work");
    job.start(Phase::TransformDiscovery, None)?;
    job.advance(Phase::TransformDiscovery, 10)?;
    let first = job.work_scope(&"3".repeat(64))?;
    let second = job.work_scope(&"4".repeat(64))?;
    first.record_work(Phase::TransformDiscovery, Counter::CandidatesExamined, 7)?;
    let committed = first.work_snapshot()?;
    assert_eq!(committed.phase_work(Phase::TransformDiscovery), 7);
    first.record_work(Phase::TransformDiscovery, Counter::CandidatesExamined, 100)?;
    second.record_work(Phase::TransformDiscovery, Counter::CandidatesExamined, 11)?;
    first.restore_work(committed)?;
    let snapshot = job.snapshot()?;
    assert_eq!(
        snapshot
            .phase(Phase::TransformDiscovery)
            .map(|phase| phase.completed),
        Some(28)
    );
    assert_eq!(
        job.checkpoint_snapshot()?
            .phase(Phase::TransformDiscovery)
            .map(|phase| phase.completed),
        Some(10)
    );
    Ok(())
}

#[test]
fn transition_restore_recomputes_aggregate_without_double_counting() -> TestResult {
    let job = Job::new("scoped transition summaries");
    let first = job.work_scope(&"5".repeat(64))?;
    let second = job.work_scope(&"6".repeat(64))?;
    let before = first.work_snapshot()?;
    let event = RecoveryTransition {
        stage: RecoveryTransitionStage::Assembly,
        outcome: RecoveryTransitionOutcome::Derived,
        sample: None,
    };
    first.record_recovery_transition(event)?;
    second.record_recovery_transition(event)?;
    first.restore_work(before)?;
    assert_eq!(
        job.snapshot()?
            .recovery_transitions
            .records()
            .first()
            .map(RecoveryTransitionRecord::count),
        Some(1)
    );
    drop(second);
    assert_eq!(
        job.snapshot()?
            .recovery_transitions
            .records()
            .first()
            .map(RecoveryTransitionRecord::count),
        Some(1)
    );
    assert!(
        job.checkpoint_snapshot()?
            .recovery_transitions
            .records()
            .is_empty()
    );
    Ok(())
}

#[test]
fn root_counter_overflow_cannot_invalidate_an_active_contribution() -> TestResult {
    let job = Job::new("root update overflow");
    let work = job.work_scope(&"7".repeat(64))?;
    work.increment(Counter::Records, 1)?;
    assert!(job.increment(Counter::Records, u64::MAX).is_err());
    assert_eq!(counter(&job, Counter::Records)?, 1);
    Ok(())
}

#[test]
fn root_phase_replacement_rejects_an_overflow_with_scoped_work() -> TestResult {
    let job = Job::new("root phase replacement overflow");
    job.start(Phase::TransformDiscovery, None)?;
    let work = job.work_scope(&"8".repeat(64))?;
    work.advance(Phase::TransformDiscovery, 1)?;
    assert!(
        job.set_completed(Phase::TransformDiscovery, u64::MAX)
            .is_err()
    );
    assert_eq!(
        job.snapshot()?
            .phase(Phase::TransformDiscovery)
            .map(|phase| phase.completed),
        Some(1)
    );
    Ok(())
}
