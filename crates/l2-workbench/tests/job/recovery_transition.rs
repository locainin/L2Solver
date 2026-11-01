use l2_workbench::job::{
    Job, JobSnapshot, RecoveryCandidateSample, RecoveryFunnelAdmission, RecoveryTransition,
    RecoveryTransitionOutcome, RecoveryTransitionSample, RecoveryTransitionStage,
};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

pub const fn sample(candidate_index: u64) -> RecoveryTransitionSample {
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
fn empty_funnel_does_not_enlarge_legacy_checkpoint_summaries() -> TestResult {
    let job = Job::new("empty funnel");
    let summary = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    assert_eq!(summary, serde_json::json!({"records": []}));
    Ok(())
}

#[test]
fn funnel_admission_is_bounded_across_all_active_work_scopes() -> TestResult {
    use l2_workbench::job::{
        RecoveryFunnelIdentity, RecoveryFunnelInput, RecoveryFunnelRegistration,
    };
    let job = Job::new("aggregate funnel admission");
    let inputs = [RecoveryFunnelInput {
        node_id: 20,
        session_node_id: 30,
    }];
    let mut workers = Vec::new();
    for index in 0..80_u64 {
        let scope = job.work_scope(&format!("{index:064x}"))?;
        scope.register_recovery_cohort(RecoveryFunnelRegistration {
            identity: RecoveryFunnelIdentity {
                source_sha256: [1; 32],
                cohort_sha256: [2; 32],
            },
            inputs: &inputs,
            total_inputs: 1,
            admission: RecoveryFunnelAdmission::Unknown,
        })?;
        workers.push(scope);
    }
    let mut active_cohorts = 0_usize;
    for worker in &workers {
        let contribution = serde_json::to_value(worker.work_snapshot()?)?;
        active_cohorts += contribution
            .pointer("/counts/recovery_transitions/cohorts")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
    }
    assert_eq!(
        active_cohorts, 64,
        "live work contributions must obey the job-wide cap before snapshot merging"
    );
    let wire = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    assert_eq!(
        wire.get("cohorts")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(64)
    );
    assert_eq!(
        wire.get("funnel_omitted_events"),
        Some(&serde_json::json!(16))
    );
    assert_eq!(
        wire.pointer("/funnel_omission_reasons/cohort_limit"),
        Some(&serde_json::json!(16))
    );
    drop(workers);
    Ok(())
}

#[test]
fn funnel_memory_pressure_omits_diagnostics_without_stopping_work() -> TestResult {
    use l2_workbench::job::{
        MemoryBudget, RecoveryFunnelIdentity, RecoveryFunnelInput, RecoveryFunnelRegistration,
    };
    let budget = MemoryBudget::new(0);
    let job = Job::with_memory_budget("funnel memory denial", &budget);
    let inputs = [RecoveryFunnelInput {
        node_id: 20,
        session_node_id: 30,
    }];
    job.register_recovery_cohort(RecoveryFunnelRegistration {
        identity: RecoveryFunnelIdentity {
            source_sha256: [1; 32],
            cohort_sha256: [2; 32],
        },
        inputs: &inputs,
        total_inputs: 1,
        admission: RecoveryFunnelAdmission::Unknown,
    })?;
    let wire = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    assert_eq!(
        wire.get("funnel_omitted_events"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        wire.pointer("/funnel_omission_reasons/memory_admission"),
        Some(&serde_json::json!(1))
    );
    assert!(wire.get("cohorts").is_none());
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn diagnostic_association_limit_leaves_search_completeness_unknown() -> TestResult {
    use l2_workbench::job::{
        RecoveryFunnelIdentity, RecoveryFunnelInput, RecoveryFunnelRegistration,
    };
    let job = Job::new("diagnostic association limit");
    let identity = RecoveryFunnelIdentity {
        source_sha256: [1; 32],
        cohort_sha256: [2; 32],
    };
    let inputs = [RecoveryFunnelInput {
        node_id: 20,
        session_node_id: 30,
    }];
    let RecoveryTransitionSample::Candidate(candidate) = sample(4) else {
        return Err("test candidate sample is missing".into());
    };
    job.register_recovery_cohort(RecoveryFunnelRegistration {
        identity,
        inputs: &inputs,
        total_inputs: 2,
        admission: RecoveryFunnelAdmission::Admitted(&candidate),
    })?;
    job.record_recovery_funnel_cohort_candidate(
        identity,
        RecoveryTransitionStage::Schema,
        RecoveryTransitionOutcome::SearchCompleteWithinPlan,
        candidate,
    )?;
    let summary = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    let stages = summary
        .pointer("/cohorts/0/stages")
        .and_then(serde_json::Value::as_array)
        .ok_or("schema stage is missing")?;
    let schema = stages
        .iter()
        .find(|stage| stage.get("stage") == Some(&serde_json::json!("schema")))
        .ok_or("schema stage is missing")?;
    assert_eq!(
        schema.get("omitted_candidates"),
        Some(&serde_json::json!(0))
    );
    assert_eq!(
        schema.get("search_complete_within_plan"),
        Some(&serde_json::Value::Null)
    );
    Ok(())
}

#[test]
fn funnel_memory_charge_survives_work_scope_retirement_and_releases_with_job() -> TestResult {
    use l2_workbench::job::{
        MemoryBudget, RecoveryFunnelIdentity, RecoveryFunnelInput, RecoveryFunnelRegistration,
    };
    let budget = MemoryBudget::new(64 * 1024 * 1024);
    let job = Job::with_memory_budget("funnel memory lifetime", &budget);
    let worker = job.work_scope(&"1".repeat(64))?;
    let inputs = [RecoveryFunnelInput {
        node_id: 20,
        session_node_id: 30,
    }];
    worker.register_recovery_cohort(RecoveryFunnelRegistration {
        identity: RecoveryFunnelIdentity {
            source_sha256: [1; 32],
            cohort_sha256: [2; 32],
        },
        inputs: &inputs,
        total_inputs: 1,
        admission: RecoveryFunnelAdmission::Unknown,
    })?;
    let charged = budget.snapshot()?.used_bytes;
    assert!(charged > 0);
    drop(worker);
    assert_eq!(budget.snapshot()?.used_bytes, charged);
    drop(job);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn restoring_scoped_funnel_under_pressure_drops_only_diagnostics_and_reports_omission() -> TestResult
{
    use l2_workbench::job::{
        MemoryBudget, RecoveryFunnelIdentity, RecoveryFunnelInput, RecoveryFunnelRegistration,
    };
    let identity = "1".repeat(64);
    let first = Job::new("saved funnel");
    let saved_worker = first.work_scope(&identity)?;
    let inputs = [RecoveryFunnelInput {
        node_id: 20,
        session_node_id: 30,
    }];
    saved_worker.register_recovery_cohort(RecoveryFunnelRegistration {
        identity: RecoveryFunnelIdentity {
            source_sha256: [1; 32],
            cohort_sha256: [2; 32],
        },
        inputs: &inputs,
        total_inputs: 1,
        admission: RecoveryFunnelAdmission::Unknown,
    })?;
    let saved = saved_worker.work_snapshot()?;
    let budget = MemoryBudget::new(0);
    let resumed = Job::with_memory_budget("resumed funnel", &budget);
    let worker = resumed.work_scope(&identity)?;
    worker.restore_work(saved)?;
    let wire = serde_json::to_value(resumed.snapshot()?.recovery_transitions)?;
    assert!(wire.get("cohorts").is_none());
    assert_eq!(
        wire.get("funnel_omitted_events"),
        Some(&serde_json::json!(1))
    );
    Ok(())
}

#[test]
fn restoring_root_funnel_under_pressure_drops_only_diagnostics_and_reports_omission() -> TestResult
{
    use l2_workbench::job::{
        MemoryBudget, RecoveryFunnelIdentity, RecoveryFunnelInput, RecoveryFunnelRegistration,
    };
    let first = Job::new("saved root funnel");
    let inputs = [RecoveryFunnelInput {
        node_id: 20,
        session_node_id: 30,
    }];
    first.register_recovery_cohort(RecoveryFunnelRegistration {
        identity: RecoveryFunnelIdentity {
            source_sha256: [1; 32],
            cohort_sha256: [2; 32],
        },
        inputs: &inputs,
        total_inputs: 1,
        admission: RecoveryFunnelAdmission::Unknown,
    })?;
    let saved = first.snapshot()?;
    let budget = MemoryBudget::new(0);
    let resumed = Job::with_memory_budget("resumed root funnel", &budget);
    resumed.restore(saved)?;
    let wire = serde_json::to_value(resumed.snapshot()?.recovery_transitions)?;
    assert!(wire.get("cohorts").is_none());
    assert_eq!(
        wire.get("funnel_omitted_events"),
        Some(&serde_json::json!(1))
    );
    Ok(())
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

#[test]
fn cohort_funnel_follows_parent_candidates_and_separates_limits_from_rejections() -> TestResult {
    use l2_workbench::job::{
        RecoveryFunnelEvent, RecoveryFunnelIdentity, RecoveryFunnelInput,
        RecoveryFunnelRegistration,
    };
    let job = Job::new("cohort funnel");
    let identity = RecoveryFunnelIdentity {
        source_sha256: [1; 32],
        cohort_sha256: [2; 32],
    };
    let inputs = [RecoveryFunnelInput {
        node_id: 20,
        session_node_id: 30,
    }];
    let RecoveryTransitionSample::Candidate(first) = sample(4) else {
        return Err("test candidate sample is missing".into());
    };
    job.register_recovery_cohort(RecoveryFunnelRegistration {
        identity,
        inputs: &inputs,
        total_inputs: 1,
        admission: RecoveryFunnelAdmission::Admitted(&first),
    })?;
    for (stage, outcome, candidate, origins, parents) in [
        (
            RecoveryTransitionStage::Schema,
            RecoveryTransitionOutcome::Hypothesis,
            first,
            vec![20],
            vec![],
        ),
        (
            RecoveryTransitionStage::Assembly,
            RecoveryTransitionOutcome::Contradicted,
            RecoveryCandidateSample {
                candidate_index: 5,
                task_sha256: [5; 32],
                ..first
            },
            vec![99],
            vec![4],
        ),
        (
            RecoveryTransitionStage::Assembly,
            RecoveryTransitionOutcome::WorkOmitted,
            RecoveryCandidateSample {
                candidate_index: 6,
                task_sha256: [6; 32],
                ..first
            },
            vec![99],
            vec![4],
        ),
        (
            RecoveryTransitionStage::Assembly,
            RecoveryTransitionOutcome::Unsupported,
            RecoveryCandidateSample {
                candidate_index: 7,
                task_sha256: [7; 32],
                ..first
            },
            vec![99],
            vec![4],
        ),
    ] {
        job.record_recovery_funnel_candidate(RecoveryFunnelEvent {
            stage,
            outcome,
            candidate: &candidate,
            input_nodes: &origins,
            parent_candidates: &parents,
            attribution_complete: true,
            attribution: l2_workbench::job::RecoveryFunnelAttribution::CandidateAndParents,
            validated_artifact_sha256: None,
        })?;
    }
    let wire = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    assert_funnel_rejections_and_omissions(&wire)
}

fn assert_funnel_rejections_and_omissions(wire: &serde_json::Value) -> TestResult {
    let cohort = wire.pointer("/cohorts/0").ok_or("cohort missing")?;
    assert_eq!(cohort.get("sessions"), Some(&serde_json::json!([30])));
    assert_eq!(
        cohort.get("last_viable_stage"),
        Some(&serde_json::json!("schema"))
    );
    let assembly = cohort
        .get("stages")
        .and_then(serde_json::Value::as_array)
        .and_then(|stages| {
            stages
                .iter()
                .find(|stage| stage.get("stage") == Some(&serde_json::json!("assembly")))
        })
        .ok_or("assembly stage missing")?;
    assert_eq!(
        assembly.get("rejected_candidates"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        assembly.get("omitted_candidates"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        assembly.get("unsupported_candidates"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        assembly.get("search_complete_within_plan"),
        Some(&serde_json::json!(false))
    );
    let totals = wire
        .get("funnel_stages")
        .and_then(serde_json::Value::as_array)
        .ok_or("cohort totals missing")?;
    let totals = totals
        .iter()
        .find(|stage| stage.get("stage") == Some(&serde_json::json!("assembly")))
        .ok_or("assembly totals missing")?;
    assert_eq!(
        totals.get("cohorts_with_rejections"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        totals.get("cohorts_with_omissions"),
        Some(&serde_json::json!(1))
    );
    Ok(())
}

#[test]
fn cohort_funnel_checkpoint_restores_and_rejects_unbounded_session_lists() -> TestResult {
    use l2_workbench::job::{
        RecoveryFunnelIdentity, RecoveryFunnelInput, RecoveryFunnelRegistration,
    };
    let job = Job::new("funnel checkpoint");
    let inputs = [RecoveryFunnelInput {
        node_id: 7,
        session_node_id: 9,
    }];
    job.register_recovery_cohort(RecoveryFunnelRegistration {
        identity: RecoveryFunnelIdentity {
            source_sha256: [1; 32],
            cohort_sha256: [2; 32],
        },
        inputs: &inputs,
        total_inputs: 1,
        admission: RecoveryFunnelAdmission::Unknown,
    })?;
    let snapshot = job.snapshot()?;
    let mut wire = serde_json::to_value(&snapshot)?;
    let restored: JobSnapshot = serde_json::from_value(wire.clone())?;
    assert_eq!(restored.recovery_transitions, snapshot.recovery_transitions);
    let sessions = wire
        .pointer_mut("/recovery_transitions/cohorts/0/sessions")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("sessions missing")?;
    sessions.extend((10..140).map(serde_json::Value::from));
    assert!(
        serde_json::from_value::<JobSnapshot>(wire).is_err(),
        "checkpoint inputs must stay bounded"
    );
    Ok(())
}

#[test]
fn shared_discovery_candidate_does_not_copy_one_cohorts_result_to_another() -> TestResult {
    use l2_workbench::job::{
        RecoveryFunnelIdentity, RecoveryFunnelInput, RecoveryFunnelRegistration,
    };
    let job = Job::new("shared discovery candidate");
    let RecoveryTransitionSample::Candidate(candidate) = sample(4) else {
        return Err("test candidate sample is missing".into());
    };
    let identities = [
        RecoveryFunnelIdentity {
            source_sha256: [1; 32],
            cohort_sha256: [2; 32],
        },
        RecoveryFunnelIdentity {
            source_sha256: [1; 32],
            cohort_sha256: [3; 32],
        },
    ];
    for (index, identity) in identities.into_iter().enumerate() {
        let inputs = [RecoveryFunnelInput {
            node_id: 20 + u64::try_from(index)?,
            session_node_id: 30 + u64::try_from(index)?,
        }];
        job.register_recovery_cohort(RecoveryFunnelRegistration {
            identity,
            inputs: &inputs,
            total_inputs: 1,
            admission: RecoveryFunnelAdmission::Admitted(&candidate),
        })?;
    }
    job.record_recovery_funnel_cohort_candidate(
        identities
            .first()
            .copied()
            .ok_or("first cohort is missing")?,
        RecoveryTransitionStage::Schema,
        RecoveryTransitionOutcome::Hypothesis,
        candidate,
    )?;
    let wire = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    let cohorts = wire
        .get("cohorts")
        .and_then(serde_json::Value::as_array)
        .ok_or("cohorts missing")?;
    for (index, cohort) in cohorts.iter().enumerate() {
        let stages = cohort
            .get("stages")
            .and_then(serde_json::Value::as_array)
            .ok_or("stages missing")?;
        let schema = stages
            .iter()
            .find(|stage| stage.get("stage") == Some(&serde_json::json!("schema")))
            .ok_or("schema stage missing")?;
        assert_eq!(
            schema.get("candidates_with_survivors"),
            Some(&serde_json::json!(i32::from(index == 0)))
        );
    }
    Ok(())
}

#[test]
fn publication_is_attributed_only_when_the_exact_validated_artifact_is_listed() -> TestResult {
    use l2_workbench::job::{
        RecoveryArtifactSample, RecoveryFunnelEvent, RecoveryFunnelIdentity, RecoveryFunnelInput,
        RecoveryFunnelRegistration, RecoveryPublicationSample, RecoveryPublicationSourceBasis,
    };
    let job = Job::new("published artifact funnel");
    let RecoveryTransitionSample::Candidate(candidate) = sample(4) else {
        return Err("test candidate sample is missing".into());
    };
    let inputs = [RecoveryFunnelInput {
        node_id: 20,
        session_node_id: 30,
    }];
    job.register_recovery_cohort(RecoveryFunnelRegistration {
        identity: RecoveryFunnelIdentity {
            source_sha256: [1; 32],
            cohort_sha256: [2; 32],
        },
        inputs: &inputs,
        total_inputs: 1,
        admission: RecoveryFunnelAdmission::Admitted(&candidate),
    })?;
    job.record_recovery_funnel_candidate(RecoveryFunnelEvent {
        stage: RecoveryTransitionStage::Validation,
        outcome: RecoveryTransitionOutcome::Validated,
        candidate: &candidate,
        input_nodes: &[20],
        parent_candidates: &[],
        attribution_complete: true,
        attribution: l2_workbench::job::RecoveryFunnelAttribution::CandidateAndParents,
        validated_artifact_sha256: Some(candidate.input_blob_sha256),
    })?;
    let publication = RecoveryPublicationSample {
        source_set_sha256: None,
        source_basis: RecoveryPublicationSourceBasis::Unavailable,
        artifact: Some(RecoveryArtifactSample {
            sha256: candidate.input_blob_sha256,
            byte_length: 5,
        }),
        artifact_count: Some(2),
    };
    job.record_recovery_transition(RecoveryTransition {
        stage: RecoveryTransitionStage::Publication,
        outcome: RecoveryTransitionOutcome::Published,
        sample: Some(RecoveryTransitionSample::Publication(publication)),
    })?;
    let wire = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    assert_eq!(
        wire.pointer("/cohorts/0/last_viable_stage"),
        Some(&serde_json::json!("publication"))
    );
    Ok(())
}

#[test]
fn publication_does_not_treat_a_partially_validated_input_as_the_validated_artifact() -> TestResult
{
    use l2_workbench::job::{
        RecoveryArtifactSample, RecoveryFunnelAttribution, RecoveryFunnelEvent,
        RecoveryFunnelIdentity, RecoveryFunnelInput, RecoveryFunnelRegistration,
        RecoveryPublicationSample, RecoveryPublicationSourceBasis,
    };
    let job = Job::new("partial validation publication");
    let RecoveryTransitionSample::Candidate(candidate) = sample(4) else {
        return Err("test candidate sample is missing".into());
    };
    let inputs = [RecoveryFunnelInput {
        node_id: 20,
        session_node_id: 30,
    }];
    job.register_recovery_cohort(RecoveryFunnelRegistration {
        identity: RecoveryFunnelIdentity {
            source_sha256: [1; 32],
            cohort_sha256: [2; 32],
        },
        inputs: &inputs,
        total_inputs: 1,
        admission: RecoveryFunnelAdmission::Admitted(&candidate),
    })?;
    job.record_recovery_funnel_candidate(RecoveryFunnelEvent {
        stage: RecoveryTransitionStage::Validation,
        outcome: RecoveryTransitionOutcome::Validated,
        candidate: &candidate,
        input_nodes: &[20],
        parent_candidates: &[],
        attribution_complete: true,
        attribution: RecoveryFunnelAttribution::CandidateAndParents,
        validated_artifact_sha256: None,
    })?;
    let publication = RecoveryPublicationSample {
        source_set_sha256: None,
        source_basis: RecoveryPublicationSourceBasis::Unavailable,
        artifact: Some(RecoveryArtifactSample {
            sha256: candidate.input_blob_sha256,
            byte_length: 5,
        }),
        artifact_count: Some(1),
    };
    job.record_recovery_transition(RecoveryTransition {
        stage: RecoveryTransitionStage::Publication,
        outcome: RecoveryTransitionOutcome::Published,
        sample: Some(RecoveryTransitionSample::Publication(publication)),
    })?;
    let wire = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    assert_eq!(
        wire.pointer("/cohorts/0/last_viable_stage"),
        Some(&serde_json::json!("validation"))
    );
    assert_eq!(
        wire.pointer("/publication_attribution/validation_identities_unavailable"),
        Some(&serde_json::json!(true)),
        "a validation of only a subrange cannot supply exact publication identity"
    );
    Ok(())
}

#[test]
fn same_case_local_session_numbers_in_different_work_scopes_remain_distinct() -> TestResult {
    use l2_workbench::job::{
        RecoveryFunnelIdentity, RecoveryFunnelInput, RecoveryFunnelRegistration,
    };
    let job = Job::new("independent cases");
    let first = job.work_scope(&"1".repeat(64))?;
    let second = job.work_scope(&"2".repeat(64))?;
    let identity = RecoveryFunnelIdentity {
        source_sha256: [1; 32],
        cohort_sha256: [2; 32],
    };
    let inputs = [RecoveryFunnelInput {
        node_id: 20,
        session_node_id: 30,
    }];
    for worker in [&first, &second] {
        worker.register_recovery_cohort(RecoveryFunnelRegistration {
            identity,
            inputs: &inputs,
            total_inputs: 1,
            admission: RecoveryFunnelAdmission::Unknown,
        })?;
    }
    let wire = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    assert_eq!(
        wire.get("cohorts")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    Ok(())
}

#[test]
fn input_contradiction_is_attributed_only_to_its_own_cohort() -> TestResult {
    use l2_workbench::job::{
        RecoveryFunnelAttribution, RecoveryFunnelEvent, RecoveryFunnelIdentity,
        RecoveryFunnelInput, RecoveryFunnelRegistration,
    };
    let job = Job::new("rejected input provenance");
    let RecoveryTransitionSample::Candidate(candidate) = sample(4) else {
        return Err("test candidate sample is missing".into());
    };
    for index in 0..2_u64 {
        let identity = RecoveryFunnelIdentity {
            source_sha256: [1; 32],
            cohort_sha256: [u8::try_from(index + 2)?; 32],
        };
        let inputs = [RecoveryFunnelInput {
            node_id: 20 + index,
            session_node_id: 30 + index,
        }];
        job.register_recovery_cohort(RecoveryFunnelRegistration {
            identity,
            inputs: &inputs,
            total_inputs: 1,
            admission: RecoveryFunnelAdmission::Admitted(&candidate),
        })?;
    }
    job.record_recovery_funnel_candidate(RecoveryFunnelEvent {
        stage: RecoveryTransitionStage::Assembly,
        outcome: RecoveryTransitionOutcome::InputContradicted,
        candidate: &candidate,
        input_nodes: &[20],
        parent_candidates: &[],
        attribution_complete: true,
        attribution: RecoveryFunnelAttribution::ExactInputs,
        validated_artifact_sha256: None,
    })?;
    let wire = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    let cohorts = wire
        .get("cohorts")
        .and_then(serde_json::Value::as_array)
        .ok_or("cohorts missing")?;
    for (index, cohort) in cohorts.iter().enumerate() {
        let stages = cohort
            .get("stages")
            .and_then(serde_json::Value::as_array)
            .ok_or("stages missing")?;
        let assembly = stages
            .iter()
            .find(|stage| stage.get("stage") == Some(&serde_json::json!("assembly")))
            .ok_or("assembly missing")?;
        assert_eq!(
            assembly.get("rejected_candidates"),
            Some(&serde_json::json!(0))
        );
        assert_eq!(
            assembly.get("input_contradictions"),
            Some(&serde_json::json!(i32::from(index == 0)))
        );
    }
    Ok(())
}
