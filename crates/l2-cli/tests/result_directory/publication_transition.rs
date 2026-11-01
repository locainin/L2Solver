use super::{Fixture, TestResult};
use crate::{
    publish,
    result_directory::{ResultDirectory, ResultKind},
};
use l2_workbench::job::{
    Counter, Job, MemoryBudget, MemoryClass, MemoryError, RecoveryCandidateSample,
    RecoveryFunnelAdmission, RecoveryFunnelAttribution, RecoveryFunnelEvent,
    RecoveryFunnelIdentity, RecoveryFunnelInput, RecoveryFunnelRegistration,
    RecoveryPublicationSample, RecoveryPublicationSourceBasis, RecoveryTransition,
    RecoveryTransitionOutcome, RecoveryTransitionSample, RecoveryTransitionStage,
    cache::SourceIdentity,
};
use serde_json::Value;
use std::{fs, io};

fn sample(job: &Job, outcome: RecoveryTransitionOutcome) -> TestResult<RecoveryPublicationSample> {
    let snapshot = job.snapshot()?;
    let record = snapshot
        .recovery_transitions
        .records()
        .iter()
        .find(|record| {
            record.stage() == RecoveryTransitionStage::Publication && record.outcome() == outcome
        })
        .ok_or("publication transition is missing")?;
    match record.sample() {
        Some(RecoveryTransitionSample::Publication(sample)) => Ok(*sample),
        _ => Err("publication identity sample is missing".into()),
    }
}

fn expected_source(fixture: &Fixture) -> TestResult<[u8; 32]> {
    match &fixture.identity.source {
        SourceIdentity::Sha256(digest) => l2_workbench::parse_sha256_digest(digest)
            .ok_or_else(|| "invalid fixture source digest".into()),
        _ => Err("fixture requires a full source digest".into()),
    }
}

fn funnel_candidate(input_node_id: u64) -> RecoveryCandidateSample {
    RecoveryCandidateSample {
        candidate_index: 0,
        input_node_id,
        input_blob_sha256: [1; 32],
        input_batch_sha256: [2; 32],
        task_sha256: [3; 32],
        input_count: 1,
        source_range: None,
        evidence_node_id: None,
    }
}

#[test]
fn successful_atomic_publication_binds_the_exact_artifact_and_source() -> TestResult {
    let fixture = Fixture::new()?;
    let destination = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let job = Job::new("published result");
    let bytes = b"publication transition artifact";
    destination.publish(&fixture.identity, &job, |staging| {
        fixture.write_output(staging, "complete", bytes)
    })?;
    let sample = sample(&job, RecoveryTransitionOutcome::Published)?;
    assert_eq!(sample.source_set_sha256, Some(expected_source(&fixture)?));
    assert_eq!(
        sample.source_basis,
        RecoveryPublicationSourceBasis::StagedManifest
    );
    assert_eq!(sample.artifact_count, Some(1));
    let artifact = sample.artifact.ok_or("published artifact is missing")?;
    assert_eq!(
        artifact.sha256,
        l2_workbench::parse_sha256_digest(&l2_workbench::sha256(bytes))
            .ok_or("invalid artifact digest")?
    );
    assert_eq!(artifact.byte_length, u64::try_from(bytes.len())?);
    assert_eq!(fs::read(fixture.output.join("artifact.bin"))?, bytes);
    Ok(())
}

#[test]
fn small_receipt_publishes_with_a_bounded_memory_budget() -> TestResult {
    let fixture = Fixture::new()?;
    let destination = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let memory = MemoryBudget::new(3 * 1024 * 1024);
    let job = Job::with_memory_budget("small publication receipt", &memory);
    let bytes = b"small receipt artifact";
    destination.publish(&fixture.identity, &job, |staging| {
        fixture.write_output(staging, "complete", bytes)
    })?;
    assert_eq!(fs::read(fixture.output.join("artifact.bin"))?, bytes);
    ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn receipt_validation_reports_a_typed_memory_limit_without_publishing() -> TestResult {
    let fixture = Fixture::new()?;
    let destination = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let limit = 3 * 1024 * 1024;
    let memory = MemoryBudget::new(limit);
    let occupied = memory.try_reserve(MemoryClass::Base, limit)?;
    let job = Job::with_memory_budget("receipt under pressure", &memory);
    let error = destination
        .publish(&fixture.identity, &job, |staging| {
            fixture.write_output(staging, "complete", b"unpublished artifact")
        })
        .err()
        .ok_or("publication should report the exhausted budget")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert!(!fixture.output.exists());
    drop(occupied);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn publication_retains_funnel_counts_when_candidate_details_exceed_receipt_limits() -> TestResult {
    let fixture = Fixture::new()?;
    let destination = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let job = Job::new("bounded publication receipt");
    let worker = job.work_scope(&format!("{:064x}", 3))?;
    let input = RecoveryFunnelInput {
        node_id: 20,
        session_node_id: 30,
    };
    let mut candidate = funnel_candidate(input.node_id);
    worker.register_recovery_cohort(RecoveryFunnelRegistration {
        identity: RecoveryFunnelIdentity {
            source_sha256: [4; 32],
            cohort_sha256: [5; 32],
        },
        inputs: &[input],
        total_inputs: 1,
        admission: RecoveryFunnelAdmission::Admitted(&candidate),
    })?;
    for index in 0..140_u8 {
        candidate.candidate_index = u64::from(index) + 1;
        candidate.task_sha256 = [index; 32];
        worker.record_recovery_funnel_candidate(RecoveryFunnelEvent {
            stage: RecoveryTransitionStage::Schema,
            outcome: RecoveryTransitionOutcome::Hypothesis,
            candidate: &candidate,
            input_nodes: &[input.node_id],
            parent_candidates: &[],
            attribution_complete: true,
            attribution: RecoveryFunnelAttribution::CandidateAndParents,
            validated_artifact_sha256: None,
        })?;
    }
    worker.increment(Counter::CandidatesExamined, 140)?;
    let bytes = b"bounded receipt artifact";
    destination.publish(&fixture.identity, &job, |staging| {
        fixture.write_output(staging, "complete", bytes)
    })?;

    assert_eq!(fs::read(fixture.output.join("artifact.bin"))?, bytes);
    ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let manifest: Value = serde_json::from_slice(&fs::read(fixture.output.join("manifest.json"))?)?;
    assert_eq!(
        manifest.pointer("/l2solver_result/job/counters/candidates_examined"),
        Some(&Value::from(140))
    );
    let schema = manifest
        .pointer("/l2solver_result/job/recovery_transitions/cohorts/0/stages")
        .and_then(Value::as_array)
        .and_then(|stages| {
            stages
                .iter()
                .find(|stage| stage.get("stage").and_then(Value::as_str) == Some("schema"))
        })
        .ok_or("schema stage is missing from the publication receipt")?;
    assert_eq!(schema.get("observed_candidates"), Some(&Value::from(140)));
    assert_eq!(
        schema.get("candidates_with_survivors"),
        Some(&Value::from(140))
    );
    assert_eq!(schema.get("omitted_candidates"), Some(&Value::from(0)));
    assert_eq!(
        manifest.pointer(
            "/l2solver_result/job/recovery_transitions/cohorts/0/checkpoint_omitted_hypotheses"
        ),
        Some(&Value::from(141))
    );
    Ok(())
}

#[test]
fn publication_reports_omitted_cohorts_when_the_compact_receipt_is_still_too_large() -> TestResult {
    let fixture = Fixture::new()?;
    let destination = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let job = Job::new("large bounded publication receipt");
    let worker = job.work_scope(&format!("{:064x}", 4))?;
    for index in 0..64_u8 {
        let inputs = (0..128_u64)
            .map(|offset| RecoveryFunnelInput {
                node_id: u64::from(index) * 128 + offset + 1,
                session_node_id: u64::from(index) * 128 + offset + 1,
            })
            .collect::<Vec<_>>();
        let first = inputs.first().ok_or("cohort input is missing")?;
        let candidate = funnel_candidate(first.node_id);
        worker.register_recovery_cohort(RecoveryFunnelRegistration {
            identity: RecoveryFunnelIdentity {
                source_sha256: [4; 32],
                cohort_sha256: [index; 32],
            },
            total_inputs: inputs.len(),
            inputs: &inputs,
            admission: RecoveryFunnelAdmission::Admitted(&candidate),
        })?;
    }
    worker.increment(Counter::Cohorts, 64)?;
    worker.record_recovery_transition(RecoveryTransition {
        stage: RecoveryTransitionStage::Schema,
        outcome: RecoveryTransitionOutcome::Hypothesis,
        sample: None,
    })?;
    let bytes = b"large bounded receipt artifact";
    destination.publish(&fixture.identity, &job, |staging| {
        fixture.write_output(staging, "complete", bytes)
    })?;

    assert_eq!(fs::read(fixture.output.join("artifact.bin"))?, bytes);
    ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let manifest: Value = serde_json::from_slice(&fs::read(fixture.output.join("manifest.json"))?)?;
    assert_eq!(
        manifest.pointer("/l2solver_result/job/counters/cohorts"),
        Some(&Value::from(64))
    );
    assert!(
        manifest
            .pointer("/l2solver_result/job/recovery_transitions/records")
            .and_then(Value::as_array)
            .is_some_and(|records| records.iter().any(|record| {
                record.get("stage").and_then(Value::as_str) == Some("schema")
                    && record.get("outcome").and_then(Value::as_str) == Some("hypothesis")
            }))
    );
    assert_eq!(
        manifest.pointer(
            "/l2solver_result/job/recovery_transitions/funnel_omission_reasons/receipt_size"
        ),
        Some(&Value::from(64))
    );
    assert_eq!(
        manifest.pointer(
            "/l2solver_result/job/recovery_transitions/funnel_omission_reasons/checkpoint_size"
        ),
        Some(&Value::from(0))
    );
    assert_eq!(
        manifest.pointer(
            "/l2solver_result/job/recovery_transitions/funnel_omission_reasons/memory_admission"
        ),
        Some(&Value::from(0))
    );
    Ok(())
}

#[test]
fn failed_writer_reports_unpublished_without_claiming_an_artifact() -> TestResult {
    let fixture = Fixture::new()?;
    let destination = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let job = Job::new("failed result");
    let result = destination.publish(&fixture.identity, &job, |_staging| {
        Err::<(), _>(io::Error::other("synthetic writer failure").into())
    });
    assert!(result.is_err());
    assert!(!fixture.output.exists());
    let sample = sample(&job, RecoveryTransitionOutcome::PublicationFailed)?;
    assert_eq!(sample.source_set_sha256, Some(expected_source(&fixture)?));
    assert_eq!(
        sample.source_basis,
        RecoveryPublicationSourceBasis::RequestedIdentity
    );
    assert_eq!(sample.artifact, None);
    assert_eq!(sample.artifact_count, None);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn committed_directory_with_failed_parent_sync_is_reported_as_durability_uncertain() -> TestResult {
    let fixture = Fixture::new()?;
    let destination = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let job = Job::new("uncertain durability");
    publish::test_hooks::TEST_FAULT
        .with(|slot| slot.set(Some(publish::test_hooks::TestFault::DirectorySync)));
    let bytes = b"committed before sync failure";
    let result = destination.publish(&fixture.identity, &job, |staging| {
        fixture.write_output(staging, "complete", bytes)
    });
    assert!(result.is_err());
    assert_eq!(fs::read(fixture.output.join("artifact.bin"))?, bytes);
    let sample = sample(
        &job,
        RecoveryTransitionOutcome::PublishedDurabilityUncertain,
    )?;
    assert_eq!(sample.source_set_sha256, Some(expected_source(&fixture)?));
    assert_eq!(
        sample.artifact.map(|artifact| artifact.sha256),
        l2_workbench::parse_sha256_digest(&l2_workbench::sha256(bytes))
    );
    Ok(())
}

#[test]
fn uncertain_replacement_is_typed_without_retaining_its_private_path() -> TestResult {
    let job = Job::new("uncertain replacement");
    let result: Result<(), publish::DirectoryPublishError> = Err(
        publish::DirectoryPublishError::PublishedReplacementUncertain {
            source: io::Error::other("synthetic replacement uncertainty"),
            retained_path: std::path::PathBuf::from("private-recovery-name"),
        },
    );
    let observation = crate::publication_transition::initial_sample(None);
    crate::publication_transition::record_result(&job, &result, observation);
    let recorded = sample(
        &job,
        RecoveryTransitionOutcome::PublishedReplacementUncertain,
    )?;
    assert_eq!(recorded.source_set_sha256, None);
    assert!(!serde_json::to_string(&job.snapshot()?)?.contains("private-recovery-name"));
    Ok(())
}
