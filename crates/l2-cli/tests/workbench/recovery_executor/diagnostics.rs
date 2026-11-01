use super::{funnel_candidate_outcome, validated_full_input_digest};
use l2_workbench::{evidence::Case, job::RecoveryCandidateSample};
use serde_json::json;
use std::error::Error;

#[test]
fn empty_framing_receipt_does_not_advance_the_cohort() -> Result<(), Box<dyn Error>> {
    use l2_workbench::{
        job::RecoveryTransitionOutcome, protocol::FramingKind, recovery::RecoveryTask,
    };
    let mut case = Case::new();
    let empty = case.add_bytes_node(
        "framing_receipt",
        b"empty",
        Vec::new(),
        json!({"frame_count":0}),
    )?;
    let populated = case.add_bytes_node(
        "framing_receipt",
        b"one",
        Vec::new(),
        json!({"frame_count":1}),
    )?;
    let missing = case.add_bytes_node("framing_receipt", b"unknown", Vec::new(), json!({}))?;
    let task = RecoveryTask::MaterializeFraming(FramingKind::FixedSize { bytes: 7 });
    assert_eq!(
        funnel_candidate_outcome(
            &case,
            &task,
            RecoveryTransitionOutcome::Derived,
            Some(empty)
        ),
        RecoveryTransitionOutcome::ReportRetained
    );
    assert_eq!(
        funnel_candidate_outcome(
            &case,
            &task,
            RecoveryTransitionOutcome::Derived,
            Some(missing)
        ),
        RecoveryTransitionOutcome::ReportRetained
    );
    assert_eq!(
        funnel_candidate_outcome(
            &case,
            &task,
            RecoveryTransitionOutcome::Derived,
            Some(populated)
        ),
        RecoveryTransitionOutcome::Derived
    );
    Ok(())
}

#[test]
fn empty_or_incomplete_record_groups_do_not_advance_full_session_assembly()
-> Result<(), Box<dyn Error>> {
    use l2_workbench::{
        job::RecoveryTransitionOutcome,
        protocol::{
            ByteField, ByteOrder, IntegerField, RecordCount, RecordLengthMeaning, RecordSchema,
        },
        recovery::RecoveryTask,
    };
    let mut case = Case::new();
    let empty = case.add_bytes_node(
        "record_parse_receipt",
        b"empty",
        Vec::new(),
        json!({"group_count":0,"complete_group_count":0,"incomplete_group_count":0}),
    )?;
    let partial = case.add_bytes_node(
        "record_parse_receipt",
        b"partial",
        Vec::new(),
        json!({"group_count":1,"complete_group_count":0,"incomplete_group_count":1}),
    )?;
    let complete = case.add_bytes_node(
        "record_parse_receipt",
        b"complete",
        Vec::new(),
        json!({"group_count":1,"complete_group_count":1,"incomplete_group_count":0}),
    )?;
    let task = RecoveryTask::AssembleRecords(RecordSchema {
        records_offset: 0,
        count: RecordCount::UntilEnd,
        identifier: ByteField {
            offset: 0,
            width: 1,
        },
        sequence: IntegerField {
            offset: 1,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 2,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        data_offset: 3,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: None,
    });
    for node in [empty, partial] {
        assert_eq!(
            funnel_candidate_outcome(&case, &task, RecoveryTransitionOutcome::Derived, Some(node)),
            RecoveryTransitionOutcome::ReportRetained,
            "an empty or incomplete group is only a receipt"
        );
    }
    assert_eq!(
        funnel_candidate_outcome(
            &case,
            &task,
            RecoveryTransitionOutcome::Derived,
            Some(complete)
        ),
        RecoveryTransitionOutcome::Derived
    );
    Ok(())
}

#[test]
fn publication_identity_requires_a_full_input_validation_range() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let bytes = b"abcd";
    let input_node_id = case.add_bytes_node("test_input", bytes, Vec::new(), json!({}))?;
    let full = case.add_bytes_node(
        "test_receipt",
        b"full",
        Vec::new(),
        json!({"range":{"offset":0,"length":4}}),
    )?;
    let partial = case.add_bytes_node(
        "test_receipt",
        b"partial",
        Vec::new(),
        json!({"range":{"offset":1,"length":2}}),
    )?;
    let digest = l2_workbench::parse_sha256_digest(&l2_workbench::sha256(bytes))
        .ok_or("invalid test digest")?;
    let sample = RecoveryCandidateSample {
        candidate_index: 0,
        input_node_id,
        input_blob_sha256: digest,
        input_batch_sha256: [2; 32],
        task_sha256: [3; 32],
        source_range: None,
        input_count: 1,
        evidence_node_id: Some(full),
    };
    assert_eq!(validated_full_input_digest(&case, sample), Some(digest));
    assert_eq!(
        validated_full_input_digest(
            &case,
            RecoveryCandidateSample {
                evidence_node_id: Some(partial),
                ..sample
            }
        ),
        None
    );
    assert_eq!(
        validated_full_input_digest(
            &case,
            RecoveryCandidateSample {
                input_count: 2,
                ..sample
            }
        ),
        None
    );
    Ok(())
}

#[test]
fn coordinator_denial_does_not_claim_cohort_admission_after_checkpoint()
-> Result<(), Box<dyn Error>> {
    use super::super::{JobProgress, RecoveryPlan, normal_policy, test_support};
    use super::{FunnelCohortKey, register_funnel_cohort};
    use l2_workbench::{
        job::{Job, RecoveryFunnelInput, WorkSnapshot},
        protocol::Direction,
        recovery::{EnqueueOutcome, RecoveryResource, RecoveryTask},
    };

    let (mut case, first_frame) = test_support::record_case()?;
    let session = case.add_node("tcp_episode", None, Vec::new(), json!({}))?;
    let mut frames = vec![first_frame];
    for _ in 1..256 {
        frames.push(case.add_bytes_node(
            "custom_protocol_frame",
            &[0x21, 0, 1, b'x'],
            Vec::new(),
            json!({}),
        )?);
    }
    let plan = RecoveryPlan::default();
    let mut policy = normal_policy(&case)?;
    policy.resources.max_candidates = 1;
    policy.resources.max_inputs_per_candidate = frames.len();
    let job = Job::new("coordinator denial");
    let worker = job.work_scope(&"a".repeat(64))?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    executor.job = Some(JobProgress::new(worker.clone()));
    assert!(matches!(
        executor.coordinator.enqueue_nodes(
            executor.case,
            &[first_frame],
            RecoveryTask::StructuralValidation,
        )?,
        EnqueueOutcome::Queued(_)
    ));
    let denied = executor.coordinator.enqueue_nodes(
        executor.case,
        &frames,
        RecoveryTask::RecordDiscovery,
    )?;
    assert!(matches!(
        denied,
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::CandidateCount,
            ..
        }
    ));
    let source_id = format!("sha256:{}", l2_workbench::sha256(b"denied source"));
    register_funnel_cohort(
        &executor,
        FunnelCohortKey {
            source_id: &source_id,
            scope: "scope",
            endpoints: "endpoints",
            direction: Direction::FirstToSecond,
        },
        frames.iter().copied().map(|node_id| RecoveryFunnelInput {
            node_id,
            session_node_id: session,
        }),
        frames.len(),
        denied,
    )?;
    drop(executor);

    let saved = worker.work_snapshot()?;
    let projected = serde_json::to_value(saved.checkpoint_view(8 * 1024))?;
    assert_eq!(
        projected.pointer("/counts/recovery_transitions/checkpoint_projection_version"),
        Some(&json!(1)),
        "the test must exercise compact projection"
    );
    let mut false_admission = projected.clone();
    *false_admission
        .pointer_mut("/counts/recovery_transitions/cohorts/0/stages/0/candidates_with_survivors")
        .ok_or("cohort stage is missing")? = json!(1);
    *false_admission
        .pointer_mut("/counts/recovery_transitions/cohorts/0/last_viable_stage")
        .ok_or("last viable stage is missing")? = json!("cohort");
    assert!(
        serde_json::from_value::<WorkSnapshot>(false_admission.clone()).is_err(),
        "an omitted enqueue cannot substantiate an admitted survivor on restore"
    );
    false_admission
        .pointer_mut("/counts/recovery_transitions/cohorts/0/hypotheses")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("cohort hypotheses are missing")?
        .push(json!({
            "stage":"schema",
            "candidate_index":1,
            "input_batch_sha256":"0".repeat(64),
            "task_sha256":"1".repeat(64),
            "input_blob_sha256":"2".repeat(64),
            "validated_artifact_sha256":null,
            "outcomes":4,
            "evidence_node_id":null,
        }));
    assert!(
        serde_json::from_value::<WorkSnapshot>(false_admission).is_err(),
        "a hypothesis from another stage cannot substantiate cohort admission"
    );
    let resumed = Job::new("resumed denial");
    let resumed_worker = resumed.work_scope(&"a".repeat(64))?;
    resumed_worker.restore_work(serde_json::from_value::<WorkSnapshot>(projected)?)?;
    let wire = serde_json::to_value(resumed.snapshot()?.recovery_transitions)?;
    let cohort = wire.pointer("/cohorts/0").ok_or("cohort is missing")?;
    assert_eq!(cohort.get("last_viable_stage"), Some(&json!(null)));
    assert_eq!(
        cohort.pointer("/admission_omissions/resource_exhausted"),
        Some(&json!(true))
    );
    let cohort_stage = cohort
        .get("stages")
        .and_then(serde_json::Value::as_array)
        .and_then(|stages| {
            stages
                .iter()
                .find(|stage| stage.get("stage") == Some(&json!("cohort")))
        })
        .ok_or("cohort stage is missing")?;
    assert_eq!(
        cohort_stage.get("candidates_with_survivors"),
        Some(&json!(0))
    );
    assert_eq!(cohort_stage.get("omitted_candidates"), Some(&json!(1)));
    assert_eq!(
        cohort_stage.get("search_complete_within_plan"),
        Some(&json!(false))
    );
    Ok(())
}

#[test]
fn cycle_skip_stays_distinct_from_resource_denial_for_an_admitted_cohort()
-> Result<(), Box<dyn Error>> {
    use super::super::{JobProgress, RecoveryPlan, normal_policy, test_support};
    use super::{FunnelCohortKey, register_funnel_cohort};
    use l2_workbench::{
        job::{Job, RecoveryFunnelInput},
        protocol::Direction,
        recovery::{EnqueueOutcome, RecoveryTask},
    };

    let (mut case, frame) = test_support::record_case()?;
    let session = case.add_node("tcp_episode", None, Vec::new(), json!({}))?;
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let job = Job::new("cycle and admission");
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    executor.job = Some(JobProgress::new(job.clone()));
    let admitted = executor.coordinator.enqueue_nodes(
        executor.case,
        &[frame],
        RecoveryTask::RecordDiscovery,
    )?;
    let EnqueueOutcome::Queued(candidate_id) = admitted else {
        return Err("candidate was not admitted".into());
    };
    let source_id = format!("sha256:{}", l2_workbench::sha256(b"cycle source"));
    let key = FunnelCohortKey {
        source_id: &source_id,
        scope: "scope",
        endpoints: "endpoints",
        direction: Direction::FirstToSecond,
    };
    let input = RecoveryFunnelInput {
        node_id: frame,
        session_node_id: session,
    };
    register_funnel_cohort(&executor, key, [input].into_iter(), 1, admitted)?;
    // Feed the coordinator's distinct cycle outcome to the same diagnostic boundary
    register_funnel_cohort(
        &executor,
        key,
        [input].into_iter(),
        1,
        EnqueueOutcome::CycleSkipped { candidate_id },
    )?;
    drop(executor);

    let wire = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    let cohort = wire.pointer("/cohorts/0").ok_or("cohort is missing")?;
    assert_eq!(cohort.get("last_viable_stage"), Some(&json!("cohort")));
    assert_eq!(
        cohort.pointer("/admission_omissions/cycle_skipped"),
        Some(&json!(true))
    );
    assert_eq!(
        cohort.pointer("/admission_omissions/resource_exhausted"),
        Some(&json!(false))
    );
    Ok(())
}
