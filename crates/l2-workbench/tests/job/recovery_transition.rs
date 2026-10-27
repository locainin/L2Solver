use l2_workbench::job::{
    Job, JobSnapshot, RecoveryTransition, RecoveryTransitionOutcome, RecoveryTransitionSample,
    RecoveryTransitionStage,
};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

const fn sample(candidate_index: u64) -> RecoveryTransitionSample {
    RecoveryTransitionSample {
        candidate_index,
        input_node_id: 7,
        input_blob_sha256: [0x42; 32],
        input_batch_sha256: [0x24; 32],
        task_sha256: [0x13; 32],
        source_range: None,
        input_count: 2,
        evidence_node_id: Some(11),
    }
}

#[test]
fn transition_summary_distinguishes_contradictions_from_unfinished_work() -> TestResult {
    let job = Job::new("diagnostic transitions");
    for outcome in [
        RecoveryTransitionOutcome::Contradicted,
        RecoveryTransitionOutcome::WorkOmitted,
        RecoveryTransitionOutcome::Contradicted,
    ] {
        job.record_recovery_transition(RecoveryTransition {
            stage: RecoveryTransitionStage::Assembly,
            outcome,
            sample: Some(sample(4)),
        })?;
    }
    let snapshot = job.snapshot()?;
    let records = snapshot.recovery_transitions.records();
    assert_eq!(records.len(), 2);
    assert!(records.iter().any(|record| {
        record.stage() == RecoveryTransitionStage::Assembly
            && record.outcome() == RecoveryTransitionOutcome::Contradicted
            && record.count() == 2
            && record.sample() == Some(&sample(4))
    }));
    assert!(records.iter().any(|record| {
        record.outcome() == RecoveryTransitionOutcome::WorkOmitted && record.count() == 1
    }));
    Ok(())
}

#[test]
fn checkpoint_round_trip_preserves_bounded_transition_summaries() -> TestResult {
    let original = Job::new("transition checkpoint");
    original.record_recovery_transition(RecoveryTransition {
        stage: RecoveryTransitionStage::Schema,
        outcome: RecoveryTransitionOutcome::Hypothesis,
        sample: Some(sample(8)),
    })?;
    let encoded = serde_json::to_vec(&original.snapshot()?)?;
    let decoded: JobSnapshot = serde_json::from_slice(&encoded)?;
    let resumed = Job::new("resumed");
    resumed.restore(decoded)?;
    assert_eq!(
        resumed.snapshot()?.recovery_transitions,
        original.snapshot()?.recovery_transitions
    );
    Ok(())
}

#[test]
fn duplicate_transition_categories_are_rejected_when_loading_a_checkpoint() -> TestResult {
    let job = Job::new("invalid transition checkpoint");
    job.record_recovery_transition(RecoveryTransition {
        stage: RecoveryTransitionStage::Schema,
        outcome: RecoveryTransitionOutcome::Hypothesis,
        sample: Some(sample(2)),
    })?;
    let mut wire = serde_json::to_value(job.snapshot()?)?;
    let records = wire
        .pointer_mut("/recovery_transitions/records")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("missing transition records")?;
    records.push(records.first().ok_or("missing sample record")?.clone());
    assert!(serde_json::from_value::<JobSnapshot>(wire).is_err());
    Ok(())
}

#[test]
fn checkpoint_rejects_invalid_transition_digest() -> TestResult {
    let job = Job::new("invalid transition digest");
    job.record_recovery_transition(RecoveryTransition {
        stage: RecoveryTransitionStage::Schema,
        outcome: RecoveryTransitionOutcome::Hypothesis,
        sample: Some(sample(4)),
    })?;
    let mut wire = serde_json::to_value(job.snapshot()?)?;
    *wire
        .pointer_mut("/recovery_transitions/records/0/sample/input_blob_sha256")
        .ok_or("missing input digest")? = serde_json::json!("A".repeat(64));
    assert!(serde_json::from_value::<JobSnapshot>(wire).is_err());
    Ok(())
}
