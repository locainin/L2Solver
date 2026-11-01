use super::recovery_transition::sample;
use l2_workbench::job::{
    Job, RecoveryCandidateSample, RecoveryFunnelAdmission, RecoveryTransition,
    RecoveryTransitionOutcome, RecoveryTransitionSample, RecoveryTransitionStage,
};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;
type CohortFixture = (Job, Vec<Job>, Vec<RecoveryCandidateSample>);

#[test]
fn source_registration_without_an_admission_outcome_stays_unknown() -> TestResult {
    use l2_workbench::job::{
        RecoveryFunnelIdentity, RecoveryFunnelInput, RecoveryFunnelRegistration,
    };
    let job = Job::new("unresolved cohort admission");
    let input = RecoveryFunnelInput {
        node_id: 20,
        session_node_id: 30,
    };
    job.register_recovery_cohort(RecoveryFunnelRegistration {
        identity: RecoveryFunnelIdentity {
            source_sha256: [1; 32],
            cohort_sha256: [2; 32],
        },
        inputs: &[input],
        total_inputs: 1,
        admission: RecoveryFunnelAdmission::Unknown,
    })?;
    let wire = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    let cohort = wire.pointer("/cohorts/0").ok_or("cohort is missing")?;
    assert_eq!(cohort.get("sessions"), Some(&serde_json::json!([30])));
    assert_eq!(
        cohort.get("last_viable_stage"),
        Some(&serde_json::json!(null))
    );
    let stage = cohort
        .get("stages")
        .and_then(serde_json::Value::as_array)
        .and_then(|stages| {
            stages
                .iter()
                .find(|stage| stage.get("stage") == Some(&serde_json::json!("cohort")))
        })
        .ok_or("cohort stage is missing")?;
    assert_eq!(
        stage.get("candidates_with_survivors"),
        Some(&serde_json::json!(0))
    );
    assert_eq!(stage.get("omitted_candidates"), Some(&serde_json::json!(0)));
    assert_eq!(
        stage.get("search_complete_within_plan"),
        Some(&serde_json::json!(null))
    );
    Ok(())
}

fn independently_validated_cohorts() -> Result<CohortFixture, Box<dyn Error>> {
    use l2_workbench::job::{
        RecoveryFunnelAttribution, RecoveryFunnelEvent, RecoveryFunnelIdentity,
        RecoveryFunnelInput, RecoveryFunnelRegistration,
    };
    let job = Job::new("independently validated cohorts");
    let mut workers = Vec::new();
    let mut candidates = Vec::new();
    for index in 1..=2_u8 {
        let worker = job.work_scope(&format!("{index:064x}"))?;
        let input = RecoveryFunnelInput {
            node_id: u64::from(index) + 20,
            session_node_id: u64::from(index) + 30,
        };
        let RecoveryTransitionSample::Candidate(base) = sample(u64::from(index)) else {
            return Err("test candidate is missing".into());
        };
        let candidate = RecoveryCandidateSample {
            input_node_id: input.node_id,
            input_blob_sha256: [index; 32],
            input_batch_sha256: [index; 32],
            task_sha256: [index + 2; 32],
            input_count: 1,
            ..base
        };
        worker.register_recovery_cohort(RecoveryFunnelRegistration {
            identity: RecoveryFunnelIdentity {
                source_sha256: [1; 32],
                cohort_sha256: [2; 32],
            },
            inputs: &[input],
            total_inputs: 1,
            admission: RecoveryFunnelAdmission::Admitted(&candidate),
        })?;
        worker.record_recovery_funnel_candidate(RecoveryFunnelEvent {
            stage: RecoveryTransitionStage::Validation,
            outcome: RecoveryTransitionOutcome::Validated,
            candidate: &candidate,
            input_nodes: &[input.node_id],
            parent_candidates: &[],
            attribution_complete: true,
            attribution: RecoveryFunnelAttribution::CandidateAndParents,
            validated_artifact_sha256: Some(candidate.input_blob_sha256),
        })?;
        workers.push(worker);
        candidates.push(candidate);
    }
    Ok((job, workers, candidates))
}

fn record_publication(
    job: &Job,
    artifact: Option<l2_workbench::job::RecoveryArtifactSample>,
    artifact_count: Option<u64>,
) -> TestResult {
    use l2_workbench::job::{RecoveryPublicationSample, RecoveryPublicationSourceBasis};
    job.record_recovery_transition(RecoveryTransition {
        stage: RecoveryTransitionStage::Publication,
        outcome: RecoveryTransitionOutcome::Published,
        sample: Some(RecoveryTransitionSample::Publication(
            RecoveryPublicationSample {
                source_set_sha256: None,
                source_basis: RecoveryPublicationSourceBasis::Unavailable,
                artifact,
                artifact_count,
            },
        )),
    })?;
    Ok(())
}

fn assert_publication_is_a_lower_bound(wire: &serde_json::Value) -> TestResult {
    let stage = wire
        .get("funnel_stages")
        .and_then(serde_json::Value::as_array)
        .and_then(|stages| {
            stages
                .iter()
                .find(|stage| stage.get("stage") == Some(&serde_json::json!("publication")))
        })
        .ok_or("publication stage is missing")?;
    assert_eq!(
        stage.get("counts_are_lower_bounds"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(
        wire.pointer("/publication_attribution/complete"),
        Some(&serde_json::json!(false))
    );
    Ok(())
}

#[test]
fn one_sample_from_a_published_set_reports_the_unrepresented_artifact() -> TestResult {
    use l2_workbench::job::RecoveryArtifactSample;
    let (job, _workers, candidates) = independently_validated_cohorts()?;
    record_publication(
        &job,
        Some(RecoveryArtifactSample {
            sha256: candidates
                .first()
                .ok_or("candidate is missing")?
                .input_blob_sha256,
            byte_length: 5,
        }),
        Some(2),
    )?;
    let wire = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    assert_publication_is_a_lower_bound(&wire)?;
    assert_eq!(
        wire.pointer("/publication_attribution/basis"),
        Some(&serde_json::json!("artifact_digest")),
        "a matching digest establishes published bytes, not source lineage"
    );
    assert_eq!(
        wire.pointer("/publication_attribution/unrepresented_artifacts_at_least"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        wire.pointer("/publication_attribution/unrepresented_events"),
        Some(&serde_json::json!(0))
    );
    let stages = wire
        .get("cohorts")
        .and_then(serde_json::Value::as_array)
        .ok_or("cohorts missing")?;
    assert_eq!(
        stages
            .iter()
            .filter(
                |cohort| cohort.get("last_viable_stage") == Some(&serde_json::json!("publication"))
            )
            .count(),
        1
    );
    assert_eq!(
        stages
            .iter()
            .filter(
                |cohort| cohort.get("last_viable_stage") == Some(&serde_json::json!("validation"))
            )
            .count(),
        1
    );
    Ok(())
}

#[test]
fn collapsed_publication_events_do_not_claim_complete_cross_scope_attribution() -> TestResult {
    use l2_workbench::job::RecoveryArtifactSample;
    let (job, _workers, candidates) = independently_validated_cohorts()?;
    for candidate in candidates {
        record_publication(
            &job,
            Some(RecoveryArtifactSample {
                sha256: candidate.input_blob_sha256,
                byte_length: 5,
            }),
            Some(1),
        )?;
    }
    let wire = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    assert_publication_is_a_lower_bound(&wire)?;
    assert_eq!(
        wire.pointer("/publication_attribution/unrepresented_events"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        wire.pointer("/publication_attribution/artifact_count_unknown_events"),
        Some(&serde_json::json!(1))
    );
    Ok(())
}

#[test]
fn missing_artifact_examples_distinguish_known_omissions_from_unknown_counts() -> TestResult {
    for (count, omitted, unknown) in [(Some(2), 2, 0), (None, 0, 1)] {
        let (job, _workers, _candidates) = independently_validated_cohorts()?;
        record_publication(&job, None, count)?;
        let wire = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
        assert_publication_is_a_lower_bound(&wire)?;
        assert_eq!(
            wire.pointer("/publication_attribution/unrepresented_artifacts_at_least"),
            Some(&serde_json::json!(omitted))
        );
        assert_eq!(
            wire.pointer("/publication_attribution/artifact_count_unknown_events"),
            Some(&serde_json::json!(unknown))
        );
    }
    Ok(())
}

#[test]
fn failed_publication_reports_unrepresented_artifacts_without_claiming_success() -> TestResult {
    use l2_workbench::job::{
        RecoveryArtifactSample, RecoveryPublicationSample, RecoveryPublicationSourceBasis,
    };
    let (job, _workers, candidates) = independently_validated_cohorts()?;
    job.record_recovery_transition(RecoveryTransition {
        stage: RecoveryTransitionStage::Publication,
        outcome: RecoveryTransitionOutcome::PublicationFailed,
        sample: Some(RecoveryTransitionSample::Publication(
            RecoveryPublicationSample {
                source_set_sha256: None,
                source_basis: RecoveryPublicationSourceBasis::Unavailable,
                artifact: Some(RecoveryArtifactSample {
                    sha256: candidates
                        .first()
                        .ok_or("candidate is missing")?
                        .input_blob_sha256,
                    byte_length: 5,
                }),
                artifact_count: Some(2),
            },
        )),
    })?;
    let wire = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    assert_publication_is_a_lower_bound(&wire)?;
    assert_eq!(
        wire.pointer("/publication_attribution/unrepresented_artifacts_at_least"),
        Some(&serde_json::json!(1))
    );
    let cohorts = wire
        .get("cohorts")
        .and_then(serde_json::Value::as_array)
        .ok_or("cohorts missing")?;
    assert!(cohorts.iter().all(|cohort| {
        cohort.get("last_viable_stage") == Some(&serde_json::json!("validation"))
    }));
    Ok(())
}

#[test]
fn contradictory_empty_set_and_artifact_sample_remain_unknown() -> TestResult {
    use l2_workbench::job::RecoveryArtifactSample;
    let (job, _workers, candidates) = independently_validated_cohorts()?;
    record_publication(
        &job,
        Some(RecoveryArtifactSample {
            sha256: candidates
                .first()
                .ok_or("candidate is missing")?
                .input_blob_sha256,
            byte_length: 5,
        }),
        Some(0),
    )?;
    let wire = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    assert_publication_is_a_lower_bound(&wire)?;
    assert_eq!(
        wire.pointer("/publication_attribution/artifact_count_unknown_events"),
        Some(&serde_json::json!(1))
    );
    let cohorts = wire
        .get("cohorts")
        .and_then(serde_json::Value::as_array)
        .ok_or("cohorts missing")?;
    assert!(cohorts.iter().all(|cohort| {
        cohort.get("last_viable_stage") == Some(&serde_json::json!("validation"))
    }));
    Ok(())
}

#[test]
fn an_exact_or_empty_publication_set_has_complete_sample_coverage() -> TestResult {
    use l2_workbench::job::RecoveryArtifactSample;
    for has_artifact in [true, false] {
        let (job, _workers, candidates) = independently_validated_cohorts()?;
        let artifact = has_artifact.then_some(RecoveryArtifactSample {
            sha256: candidates
                .first()
                .ok_or("candidate is missing")?
                .input_blob_sha256,
            byte_length: 5,
        });
        record_publication(&job, artifact, Some(u64::from(has_artifact)))?;
        let wire = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
        assert_eq!(
            wire.pointer("/publication_attribution/complete"),
            Some(&serde_json::json!(true))
        );
        let stage = wire
            .get("funnel_stages")
            .and_then(serde_json::Value::as_array)
            .and_then(|stages| {
                stages
                    .iter()
                    .find(|stage| stage.get("stage") == Some(&serde_json::json!("publication")))
            })
            .ok_or("publication stage is missing")?;
        assert_eq!(
            stage.get("counts_are_lower_bounds"),
            Some(&serde_json::json!(false))
        );
    }
    Ok(())
}

#[test]
fn compacted_validation_identities_leave_publication_correlation_unknown() -> TestResult {
    use l2_workbench::job::{
        RecoveryArtifactSample, RecoveryFunnelIdentity, RecoveryFunnelInput,
        RecoveryFunnelRegistration, WorkSnapshot,
    };
    let (_job, workers, candidates) = independently_validated_cohorts()?;
    let worker = workers.first().ok_or("worker is missing")?;
    let inputs = (1000..1256)
        .map(|node_id| RecoveryFunnelInput {
            node_id,
            session_node_id: 31,
        })
        .collect::<Vec<_>>();
    worker.register_recovery_cohort(RecoveryFunnelRegistration {
        identity: RecoveryFunnelIdentity {
            source_sha256: [1; 32],
            cohort_sha256: [2; 32],
        },
        inputs: &inputs,
        total_inputs: inputs.len(),
        admission: RecoveryFunnelAdmission::Unknown,
    })?;
    let saved = worker.work_snapshot()?;
    let projected = serde_json::to_value(saved.checkpoint_view(8 * 1024))?;
    assert_eq!(
        projected.pointer("/counts/recovery_transitions/checkpoint_projection_version"),
        Some(&serde_json::json!(1)),
        "the test must exercise compact projection"
    );
    let resumed = Job::new("compacted validation");
    let resumed_worker = resumed.work_scope(&format!("{:064x}", 1_u8))?;
    resumed_worker.restore_work(serde_json::from_value::<WorkSnapshot>(projected)?)?;
    record_publication(
        &resumed,
        Some(RecoveryArtifactSample {
            sha256: candidates
                .first()
                .ok_or("candidate is missing")?
                .input_blob_sha256,
            byte_length: 5,
        }),
        Some(1),
    )?;
    let wire = serde_json::to_value(resumed.snapshot()?.recovery_transitions)?;
    assert_publication_is_a_lower_bound(&wire)?;
    assert_eq!(
        wire.pointer("/publication_attribution/validation_identities_unavailable"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(
        wire.pointer("/cohorts/0/last_viable_stage"),
        Some(&serde_json::json!("validation"))
    );
    Ok(())
}

#[test]
fn minimal_checkpoint_preserves_known_publication_omissions() -> TestResult {
    use l2_workbench::job::{RecoveryArtifactSample, WorkSnapshot};
    let (_job, workers, candidates) = independently_validated_cohorts()?;
    let worker = workers.first().ok_or("worker is missing")?;
    record_publication(
        worker,
        Some(RecoveryArtifactSample {
            sha256: candidates
                .first()
                .ok_or("candidate is missing")?
                .input_blob_sha256,
            byte_length: 5,
        }),
        Some(2),
    )?;
    let saved = worker.work_snapshot()?;
    let projected = serde_json::to_value(saved.checkpoint_view(0))?;
    assert_eq!(
        projected.pointer(
            "/counts/recovery_transitions/publication_attribution/unrepresented_artifacts_at_least"
        ),
        Some(&serde_json::json!(1)),
        "a minimal checkpoint must preserve a demonstrated missing artifact"
    );
    let resumed = Job::new("minimal publication checkpoint");
    let resumed_worker = resumed.work_scope(&format!("{:064x}", 1_u8))?;
    resumed_worker.restore_work(serde_json::from_value::<WorkSnapshot>(projected)?)?;
    let wire = serde_json::to_value(resumed.snapshot()?.recovery_transitions)?;
    assert_eq!(
        wire.pointer("/publication_attribution/unrepresented_artifacts_at_least"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        wire.pointer("/publication_attribution/complete"),
        Some(&serde_json::json!(false))
    );
    Ok(())
}
