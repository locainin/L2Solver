use super::*;
use crate::arguments::RecoveryProfile;
use l2_workbench::{
    derivation::Operation,
    evidence::Case,
    job::{Job, Phase, PhaseState},
    recovery::RecoveryTask,
};
use std::error::Error;

#[test]
fn cancelled_job_stops_recovery_before_policy_scans_or_case_mutation() -> Result<(), Box<dyn Error>>
{
    let mut case = Case::new();
    let job = Job::new("cancelled recovery");
    job.request_cancel();

    let error = recover_case_with_job(&mut case, RecoveryProfile::Fast, 1024 * 1024, Some(&job))
        .err()
        .ok_or("cancelled recovery unexpectedly completed")?;

    assert!(error.to_string().contains("cancellation was requested"));
    assert!(case.nodes().is_empty());
    assert_eq!(
        job.snapshot()?
            .phase(Phase::FramingRecordDiscovery)
            .map(|phase| phase.state),
        Some(PhaseState::Pending),
    );
    Ok(())
}

#[test]
fn job_aware_recovery_accepts_profile_and_memory_limits() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let job = Job::new("empty capture");
    let summary = recover_case_with_job(
        &mut case,
        RecoveryProfile::Fast,
        8 * 1024 * 1024,
        Some(&job),
    )?;

    assert!(summary.case_evidence_collection_complete);
    assert!(case.nodes().is_empty());
    Ok(())
}

#[test]
fn transform_progress_never_displays_literal_operation_parameters() -> Result<(), Box<dyn Error>> {
    let job = Job::new("redacted transform progress");
    job.start(Phase::AssemblyValidation, None)?;
    let task = RecoveryTask::transform(Operation::XorRepeat {
        key: vec![0xca, 0xfe, 0xba, 0xbe],
        offset: 0,
    });

    JobProgress::new(job.clone()).begin_candidate(&task)?;

    let snapshot = job.snapshot()?;
    assert_eq!(
        snapshot
            .phase(Phase::AssemblyValidation)
            .and_then(|phase| phase.message.as_deref()),
        Some("running transform")
    );
    assert!(!serde_json::to_string(&snapshot)?.contains("202,254,186,190"));
    Ok(())
}
