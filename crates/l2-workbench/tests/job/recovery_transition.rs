use l2_workbench::job::{
    Job, JobSnapshot, RecoveryCandidateSample, RecoveryTransition, RecoveryTransitionOutcome,
    RecoveryTransitionSample, RecoveryTransitionStage,
};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

const fn sample(candidate_index: u64) -> RecoveryTransitionSample {
    RecoveryTransitionSample::Candidate(RecoveryCandidateSample {
        candidate_index,
        input_node_id: 7,
        input_blob_sha256: [0x42; 32],
        input_batch_sha256: [0x24; 32],
        task_sha256: [0x13; 32],
        source_range: None,
        input_count: 2,
        evidence_node_id: Some(11),
    })
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
        .pointer_mut("/recovery_transitions/records/0/sample/detail/input_blob_sha256")
        .ok_or("missing input digest")? = serde_json::json!("A".repeat(64));
    assert!(serde_json::from_value::<JobSnapshot>(wire).is_err());
    Ok(())
}

#[test]
fn cohort_and_publication_samples_keep_typed_source_and_artifact_identities() -> TestResult {
    use l2_workbench::job::{
        RecoveryArtifactSample, RecoveryCohortReason, RecoveryCohortSample,
        RecoveryPublicationSample,
    };
    let job = Job::new("source and artifact diagnostics");
    let cohort = RecoveryTransitionSample::Cohort(RecoveryCohortSample {
        source_sha256: Some([0x31; 32]),
        input_node_id: Some(17),
        input_blob_sha256: Some([0x42; 32]),
        input_count: 3,
        candidate_index: None,
        input_batch_sha256: None,
        task_sha256: None,
        reason: RecoveryCohortReason::MissingContext,
    });
    let publication = RecoveryTransitionSample::Publication(RecoveryPublicationSample {
        source_set_sha256: Some([0x31; 32]),
        source_basis: l2_workbench::job::RecoveryPublicationSourceBasis::StagedManifest,
        artifact: Some(RecoveryArtifactSample {
            sha256: [0x52; 32],
            byte_length: 7,
        }),
        artifact_count: Some(1),
    });
    for (stage, outcome, sample) in [
        (
            RecoveryTransitionStage::Framing,
            RecoveryTransitionOutcome::CohortOmitted,
            cohort,
        ),
        (
            RecoveryTransitionStage::Publication,
            RecoveryTransitionOutcome::Published,
            publication,
        ),
    ] {
        job.record_recovery_transition(RecoveryTransition {
            stage,
            outcome,
            sample: Some(sample),
        })?;
    }
    let snapshot = job.snapshot()?;
    let wire = serde_json::to_value(&snapshot)?;
    let records = wire
        .pointer("/recovery_transitions/records")
        .and_then(serde_json::Value::as_array)
        .ok_or("transition records are missing")?;
    assert!(records.iter().any(|record| {
        record
            .pointer("/sample/kind")
            .and_then(serde_json::Value::as_str)
            == Some("cohort")
    }));
    assert!(records.iter().any(|record| {
        record
            .pointer("/sample/kind")
            .and_then(serde_json::Value::as_str)
            == Some("publication")
    }));
    let restored: JobSnapshot = serde_json::from_value(wire)?;
    assert_eq!(restored.recovery_transitions, snapshot.recovery_transitions);
    Ok(())
}

#[test]
fn source_qualified_cohort_example_wins_independently_of_event_order() -> TestResult {
    use l2_workbench::job::{RecoveryCohortReason, RecoveryCohortSample};
    let unqualified = RecoveryTransitionSample::Cohort(RecoveryCohortSample {
        source_sha256: None,
        input_node_id: Some(1),
        input_blob_sha256: None,
        input_count: 1,
        candidate_index: None,
        input_batch_sha256: None,
        task_sha256: None,
        reason: RecoveryCohortReason::MissingSource,
    });
    let qualified = RecoveryTransitionSample::Cohort(RecoveryCohortSample {
        source_sha256: Some([7; 32]),
        input_node_id: Some(2),
        input_blob_sha256: Some([8; 32]),
        input_count: 1,
        candidate_index: None,
        input_batch_sha256: None,
        task_sha256: None,
        reason: RecoveryCohortReason::MissingContext,
    });
    let first = Job::new("forward cohort updates");
    let second = Job::new("reverse cohort updates");
    for (job, samples) in [
        (&first, [unqualified, qualified]),
        (&second, [qualified, unqualified]),
    ] {
        for sample in samples {
            job.record_recovery_transition(RecoveryTransition {
                stage: RecoveryTransitionStage::Framing,
                outcome: RecoveryTransitionOutcome::CohortOmitted,
                sample: Some(sample),
            })?;
        }
    }
    let first = first.snapshot()?.recovery_transitions;
    let second = second.snapshot()?.recovery_transitions;
    assert_eq!(first, second);
    assert_eq!(
        first.records().first().and_then(|record| record.sample()),
        Some(&qualified)
    );
    Ok(())
}
