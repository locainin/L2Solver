use super::{
    RecoveryExecutionOutcome, RecoveryOmission, RecoveryPlan, RecoveryTask,
    drain_candidate_frontier, execute_executor, finish_executor, normal_policy, test_support,
};
use l2_workbench::{
    evidence::Case,
    protocol::{FramingKind, RecordSchema},
    recovery::{EnqueueOutcome, RecoveryCandidateState, RecoveryResource, RecoveryResult},
};
use serde_json::json;
use std::error::Error;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn pending_strict_png_schema_runs_before_raw_framing_fills_candidate_limit() -> TestResult {
    for terminal_sequence in [None, Some(2)] {
        assert_pending_schema_case(terminal_sequence)?;
    }

    Ok(())
}

#[test]
fn evidence_stop_leaves_pending_record_assemblies_unadmitted() -> TestResult {
    let (mut case, frame_node) = test_support::record_case()?;
    let report_node = test_support::add_report(&mut case, "pending strict schema")?;
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    let task = RecoveryTask::FramingDiscovery;
    let outcome = executor
        .coordinator
        .enqueue(executor.case, frame_node, task.clone())?;
    if !matches!(outcome, EnqueueOutcome::Queued(_)) {
        return Err("framing candidate was not admitted".into());
    }
    executor.record_enqueue(outcome, &task, &[frame_node])?;
    executor.defer_record_schema_group(vec![(
        vec![frame_node],
        test_support::test_schema(),
        report_node,
    )])?;
    let expected_stop =
        super::evidence::recent_case_evidence_stop(&[RecoveryOmission::ResourceExhausted {
            task: task.clone(),
            input_node_ids: vec![frame_node],
            resource: RecoveryResource::EvidenceEdges,
            limit: 1,
            used: 1,
            requested: 1,
        }])
        .ok_or("evidence quota stop was not classified")?;
    let mut evidence_stop = Some(expected_stop);
    let mut evidence_stop_reported = false;

    assert_eq!(executor.pending_record_assembly_count, 1);
    assert_eq!(executor.coordinator.candidate_count(), 1);
    drain_candidate_frontier(
        &mut executor,
        &mut evidence_stop,
        &mut evidence_stop_reported,
    )?;

    assert_eq!(executor.pending_record_assembly_count, 1);
    assert_eq!(executor.pending_record_assemblies.len(), 1);
    assert_eq!(executor.coordinator.candidate_count(), 1);
    assert!(matches!(
        executor
            .coordinator
            .candidate(match outcome {
                EnqueueOutcome::Queued(id) => id,
                _ => return Err("framing candidate was not queued".into()),
            })
            .map(l2_workbench::recovery::RecoveryCandidate::state),
        Some(RecoveryCandidateState::Finished {
            result: RecoveryResult::ResourceExhausted {
                resource: RecoveryResource::EvidenceEdges,
                ..
            },
            ..
        })
    ));
    assert!(evidence_stop_reported);

    Ok(())
}

fn assert_pending_schema_case(terminal_sequence: Option<u64>) -> TestResult {
    let (fixture, outcome, max_candidates) = run_pending_schema_case(terminal_sequence)?;
    assert_eq!(outcome.candidate_count, max_candidates);

    let expected_blob = format!("sha256:{}", l2_workbench::sha256(&fixture.png_bytes));
    let Some(object_node) = fixture.case.nodes().iter().find(|node| {
        matches!(node.kind.as_str(), "record_object" | "record_candidate")
            && node.blob.as_deref() == Some(expected_blob.as_str())
    }) else {
        return Err(missing_png_diagnostic(&fixture.case, &outcome).into());
    };
    assert_eq!(
        object_node.kind == "record_object",
        terminal_sequence.is_some()
    );
    assert_eq!(
        object_node
            .details
            .get("assembly_complete")
            .and_then(serde_json::Value::as_bool),
        Some(terminal_sequence.is_some())
    );
    assert_eq!(outcome.validated_artifact_count, 1);
    assert_assembly_candidate(&outcome, &fixture);
    assert_validation_candidate(&outcome, object_node.id);

    Ok(())
}

struct PendingSchemaFixture {
    case: Case,
    png_bytes: Vec<u8>,
    frame_nodes: Vec<u64>,
    schema: RecordSchema,
}

fn run_pending_schema_case(
    terminal_sequence: Option<u64>,
) -> TestResult<(PendingSchemaFixture, RecoveryExecutionOutcome, usize)> {
    let fixture = super::record_discovery_tests::build_session_relative_fixture()?;
    let png_bytes = fixture.plaintext;
    let mut case = Case::new();
    let frame_nodes = add_record_frames(&mut case, &png_bytes)?;
    let report_node = case.add_bytes_node(
        "recovery_record_discovery_report",
        b"strict schema fixture",
        Vec::new(),
        json!({"fixture":"retained strict schema"}),
    )?;
    let raw_run =
        super::tests::mapped_tcp_run(&mut case, &png_bytes, b"raw framing budget fixture")?;

    let plan = RecoveryPlan::default();
    let mut policy = normal_policy(&case)?;
    policy.resources.max_candidates = 32;
    policy.resources.max_frontier = 32;
    let mut schema = test_support::test_schema();
    schema.terminal_sequence = terminal_sequence;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    // Leave room for strict assembly and validation after executor setup
    for bytes in 1..=20 {
        let outcome = executor.coordinator.enqueue(
            executor.case,
            raw_run,
            RecoveryTask::MaterializeFraming(FramingKind::FixedSize { bytes }),
        )?;
        if !matches!(outcome, l2_workbench::recovery::EnqueueOutcome::Queued(_)) {
            return Err("raw framing task was not admitted".into());
        }
    }
    executor.defer_record_schema_group(vec![(frame_nodes.clone(), schema.clone(), report_node)])?;

    execute_executor(&mut executor)?;
    let max_candidates = policy.resources.max_candidates;
    let outcome = finish_executor(executor)?;
    Ok((
        PendingSchemaFixture {
            case,
            png_bytes,
            frame_nodes,
            schema,
        },
        outcome,
        max_candidates,
    ))
}

fn assert_assembly_candidate(outcome: &RecoveryExecutionOutcome, fixture: &PendingSchemaFixture) {
    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::AssembleRecords(fixture.schema.clone())
            && candidate.inputs().len() == fixture.frame_nodes.len()
            && candidate.inputs().iter().all(|input| {
                input
                    .origin_node_ids()
                    .first()
                    .is_some_and(|node_id| fixture.frame_nodes.contains(node_id))
            })
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Derived { .. },
                    ..
                }
            )
    }));
}

fn assert_validation_candidate(outcome: &RecoveryExecutionOutcome, object_node_id: u64) {
    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::StructuralValidation
            && candidate
                .inputs()
                .iter()
                .any(|input| input.origin_node_ids().contains(&object_node_id))
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::ObservedValidation { .. },
                    ..
                }
            )
    }));
}

fn missing_png_diagnostic(case: &Case, outcome: &RecoveryExecutionOutcome) -> String {
    let record_candidates = outcome
        .candidates
        .iter()
        .filter(|candidate| matches!(candidate.task(), RecoveryTask::AssembleRecords(_)))
        .map(l2_workbench::recovery::RecoveryCandidate::state)
        .collect::<Vec<_>>();
    let record_nodes = case
        .nodes()
        .iter()
        .filter(|node| {
            matches!(
                node.kind.as_str(),
                "record_object" | "record_candidate" | "record_group_issue"
            )
        })
        .map(|node| (node.id, node.kind.as_str(), node.blob.as_deref()))
        .collect::<Vec<_>>();
    format!(
        "strict PNG missing; candidates={}, record_candidates={record_candidates:?}, record_nodes={record_nodes:?}",
        outcome.candidate_count
    )
}

fn add_record_frames(case: &mut Case, png_bytes: &[u8]) -> TestResult<Vec<u64>> {
    let mut frames = Vec::new();
    for (sequence, payload) in png_bytes.chunks(24).enumerate() {
        let mut record = Vec::new();
        record.try_reserve_exact(3 + payload.len())?;
        record.push(0x21);
        record.push(u8::try_from(sequence)?);
        record.push(u8::try_from(payload.len())?);
        record.extend_from_slice(payload);
        frames.push(case.add_bytes_node(
            "custom_protocol_frame",
            &record,
            Vec::new(),
            json!({"fixture":"one strict record"}),
        )?);
    }
    Ok(frames)
}
