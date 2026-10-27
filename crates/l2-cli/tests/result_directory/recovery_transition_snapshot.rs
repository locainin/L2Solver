use super::deserialize_job_snapshot;
use l2_workbench::job::{
    Job, JobSnapshot, RecoveryTransition, RecoveryTransitionOutcome, RecoveryTransitionSample,
    RecoveryTransitionSourceRange, RecoveryTransitionStage,
};
use serde::Deserialize;
use std::error::Error;

#[derive(Deserialize)]
struct Envelope {
    #[serde(deserialize_with = "deserialize_job_snapshot")]
    job: JobSnapshot,
}

#[test]
fn maximum_transition_categories_round_trip_through_bounded_manifest_reader()
-> Result<(), Box<dyn Error>> {
    let job = Job::new("bounded transition snapshot");
    let stages = [
        RecoveryTransitionStage::Cohort,
        RecoveryTransitionStage::Framing,
        RecoveryTransitionStage::Transform,
        RecoveryTransitionStage::Schema,
        RecoveryTransitionStage::Assembly,
        RecoveryTransitionStage::Validation,
        RecoveryTransitionStage::Expansion,
        RecoveryTransitionStage::Publication,
    ];
    let outcomes = [
        RecoveryTransitionOutcome::Derived,
        RecoveryTransitionOutcome::ReportRetained,
        RecoveryTransitionOutcome::Hypothesis,
        RecoveryTransitionOutcome::Validated,
        RecoveryTransitionOutcome::Contradicted,
        RecoveryTransitionOutcome::InputContradicted,
        RecoveryTransitionOutcome::BudgetExhausted,
        RecoveryTransitionOutcome::WorkOmitted,
        RecoveryTransitionOutcome::Unsupported,
    ];
    let sample = RecoveryTransitionSample {
        candidate_index: 4,
        input_node_id: 5,
        input_blob_sha256: [1; 32],
        input_batch_sha256: [2; 32],
        task_sha256: [3; 32],
        input_count: 2,
        source_range: Some(RecoveryTransitionSourceRange {
            source_sha256: [4; 32],
            packet: Some(5),
            offset: 6,
            length: 7,
        }),
        evidence_node_id: Some(8),
    };
    for stage in stages {
        for outcome in outcomes {
            job.record_recovery_transition(RecoveryTransition {
                stage,
                outcome,
                sample: Some(sample),
            })?;
        }
    }
    let snapshot = job.snapshot()?;
    let wire = serde_json::to_vec(&serde_json::json!({"job": snapshot}))?;
    let decoded: Envelope = serde_json::from_slice(&wire)?;
    assert_eq!(
        decoded.job.recovery_transitions,
        snapshot.recovery_transitions
    );
    Ok(())
}
