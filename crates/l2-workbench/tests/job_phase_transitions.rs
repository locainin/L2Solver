use std::{error::Error, io};

use l2_workbench::job::{
    Job, JobError, JobSnapshot, Phase, PhaseOutcome, PhaseSnapshot, PhaseState,
};

type TestResult = Result<(), Box<dyn Error>>;

fn phase(snapshot: &JobSnapshot, phase: Phase) -> Result<&PhaseSnapshot, io::Error> {
    snapshot
        .phase(phase)
        .ok_or_else(|| io::Error::other("expected phase is missing"))
}

#[test]
fn zero_work_phase_reaches_one_hundred_percent_only_when_completed() -> TestResult {
    let job = Job::new("zero work");
    job.start(Phase::Ingestion, Some(0))?;

    let running = job.snapshot()?;
    assert_eq!(
        phase(&running, Phase::Ingestion)?.state,
        PhaseState::InProgress
    );
    assert_eq!(phase(&running, Phase::Ingestion)?.progress_percent, Some(0));

    job.finish(Phase::Ingestion, PhaseOutcome::Completed)?;
    let completed = job.snapshot()?;
    assert_eq!(
        phase(&completed, Phase::Ingestion)?.state,
        PhaseState::Completed
    );
    assert_eq!(
        phase(&completed, Phase::Ingestion)?.progress_percent,
        Some(100)
    );
    Ok(())
}

#[test]
fn finish_requires_running_work_or_an_unstarted_skip() -> TestResult {
    let pending = Job::new("pending stage");
    assert_eq!(
        pending.finish(Phase::Ingestion, PhaseOutcome::Completed),
        Err(JobError::PhaseNotInProgress(Phase::Ingestion))
    );
    pending.finish(Phase::Ingestion, PhaseOutcome::Skipped)?;
    assert_eq!(
        phase(&pending.snapshot()?, Phase::Ingestion)?.state,
        PhaseState::Skipped
    );
    assert_eq!(
        pending.finish(Phase::Ingestion, PhaseOutcome::Completed),
        Err(JobError::PhaseNotInProgress(Phase::Ingestion))
    );

    let running = Job::new("running stage");
    running.start(Phase::Ingestion, None)?;
    running.finish(Phase::Ingestion, PhaseOutcome::Skipped)?;
    assert_eq!(
        phase(&running.snapshot()?, Phase::Ingestion)?.state,
        PhaseState::Skipped
    );
    Ok(())
}

#[test]
fn restore_rejects_a_target_with_a_skipped_stage_and_no_current_phase() -> TestResult {
    let source = Job::new("pending source");
    let snapshot = source.snapshot()?;

    let target = Job::new("restore target");
    target.finish(Phase::Ingestion, PhaseOutcome::Skipped)?;
    let target_snapshot = target.snapshot()?;
    assert_eq!(target_snapshot.current_phase, None);
    assert_eq!(
        phase(&target_snapshot, Phase::Ingestion)?.state,
        PhaseState::Skipped
    );
    assert_eq!(target.restore(snapshot), Err(JobError::RestoreAfterStart));
    Ok(())
}

#[test]
fn restore_rejects_a_target_when_every_stage_was_skipped() -> TestResult {
    let source = Job::new("pending source");
    let snapshot = source.snapshot()?;

    let target = Job::new("fully skipped target");
    // A job with no current phase can still contain completed stage decisions
    for phase in [
        Phase::Preparation,
        Phase::Ingestion,
        Phase::Reconstruction,
        Phase::NativeExtraction,
        Phase::FramingRecordDiscovery,
        Phase::TransformDiscovery,
        Phase::AssemblyValidation,
        Phase::Expansion,
        Phase::Reports,
        Phase::Publication,
    ] {
        target.finish(phase, PhaseOutcome::Skipped)?;
    }

    let target_snapshot = target.snapshot()?;
    assert_eq!(target_snapshot.current_phase, None);
    assert!(
        target_snapshot
            .phases
            .iter()
            .all(|phase| phase.state == PhaseState::Skipped)
    );
    assert_eq!(target.restore(snapshot), Err(JobError::RestoreAfterStart));
    Ok(())
}
