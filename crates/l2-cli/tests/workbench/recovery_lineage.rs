use super::super::{CaseIndex, Executor, RecoveryPlan, normal_policy};
use super::TransformSlot;
use l2_workbench::{
    derivation::{Base64Alphabet, Base64Padding, Operation, Recipe},
    evidence::{Case, Edge, EvidenceStatus, MAX_EDGES},
    recovery::{
        RecoveryCandidateState, RecoveryCoordinator, RecoveryResource, RecoveryResult, RecoveryTask,
    },
};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    error::Error,
};

type TestResult<T> = Result<T, Box<dyn Error>>;

#[test]
fn contextual_transform_view_edge_quota_rolls_back_with_typed_omission() -> TestResult<()> {
    let mut fixture = finished_shared_transform_fixture()?;
    let mut executor = test_executor(
        &mut fixture.case,
        &fixture.plan,
        fixture.policy,
        fixture.coordinator,
    )?;
    executor.enqueue_transform_cohort(
        fixture.task,
        vec![TransformSlot {
            parent: fixture.candidate,
            input_node: fixture.input_node,
            candidate: fixture.candidate,
        }],
    );

    let before = executor.case.clone();
    let result = executor.flush_transform_cohorts();

    assert!(
        result.is_ok(),
        "view quota is reported as an omission: {result:?}"
    );
    assert_eq!(executor.case.edges().len(), MAX_EDGES - 1);
    assert_eq!(*executor.case, before);
    assert!(executor.case.nodes().iter().all(|node| {
        node.kind != "decoding_output"
            || node
                .details
                .get("shared_transform_receipt")
                .and_then(serde_json::Value::as_u64)
                != Some(fixture.receipt_node)
    }));
    assert!(executor.omissions.iter().any(|omission| matches!(
        omission,
        super::super::RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::Transform(_),
            input_node_ids,
            resource: RecoveryResource::EvidenceEdges,
            limit: MAX_EDGES,
            used,
            requested: 3,
        } if input_node_ids == &[fixture.input_node] && *used == MAX_EDGES - 1
    )));
    assert!(matches!(
        executor
            .coordinator
            .candidate(fixture.candidate)
            .map(l2_workbench::recovery::RecoveryCandidate::state),
        Some(RecoveryCandidateState::Finished {
            result: RecoveryResult::Derived { evidence_node_id },
            ..
        }) if *evidence_node_id == fixture.receipt_node
    ));
    Ok(())
}

struct SharedTransformFixture {
    case: Case,
    plan: RecoveryPlan,
    policy: super::super::RecoveryExecutionPolicy,
    coordinator: RecoveryCoordinator,
    task: RecoveryTask,
    input_node: u64,
    candidate: l2_workbench::recovery::RecoveryCandidateId,
    receipt_node: u64,
}

fn finished_shared_transform_fixture() -> TestResult<SharedTransformFixture> {
    let mut case = Case::new();
    let input = b"ZGVhZA==";
    let input_node = case.add_bytes_node("http_body", input, Vec::new(), json!({}))?;
    let alias_node = case.add_bytes_node("udp_payload", input, Vec::new(), json!({}))?;
    let output_node = case.add_bytes_node("decoding_output", b"dead", Vec::new(), json!({}))?;
    let receipt_node =
        case.add_bytes_node("decoding_receipt", b"receipt", Vec::new(), json!({}))?;
    case.add_edge(Edge {
        from: receipt_node,
        to: input_node,
        relation: "derived_from".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "The receipt records the exact transform input".to_owned(),
    })?;
    case.add_edge(Edge {
        from: receipt_node,
        to: alias_node,
        relation: "derived_from".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "The receipt records the equivalent transform input".to_owned(),
    })?;
    case.add_edge(Edge {
        from: receipt_node,
        to: output_node,
        relation: "produced".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "The receipt records the exact transform output".to_owned(),
    })?;

    let policy = normal_policy(&case)?;
    let plan = RecoveryPlan {
        discover_transforms: true,
        ..RecoveryPlan::default()
    };
    let recipe = Recipe {
        steps: vec![Operation::Base64Decode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        }],
        constraints: Vec::new(),
    };
    let task = RecoveryTask::Transform(recipe);
    let mut coordinator = RecoveryCoordinator::new(policy.resources);
    let l2_workbench::recovery::EnqueueOutcome::Queued(candidate) =
        coordinator.enqueue(&case, input_node, task.clone())?
    else {
        return Err("transform candidate was not queued".into());
    };
    assert_eq!(
        coordinator.enqueue(&case, alias_node, task.clone())?,
        l2_workbench::recovery::EnqueueOutcome::Merged(candidate)
    );
    assert_eq!(coordinator.pop_next()?, Some(candidate));
    coordinator.finish(
        &case,
        candidate,
        RecoveryResult::Derived {
            evidence_node_id: receipt_node,
        },
    )?;
    for _ in case.edges().len()..MAX_EDGES - 1 {
        case.add_edge(Edge {
            from: input_node,
            to: input_node,
            relation: "quota_fixture".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "The fixture leaves one edge slot for contextual view admission".to_owned(),
        })?;
    }

    Ok(SharedTransformFixture {
        case,
        plan,
        policy,
        coordinator,
        task,
        input_node,
        candidate,
        receipt_node,
    })
}

fn test_executor<'a>(
    case: &'a mut Case,
    plan: &'a RecoveryPlan,
    policy: super::super::RecoveryExecutionPolicy,
    coordinator: RecoveryCoordinator,
) -> TestResult<Executor<'a>> {
    let case_index = CaseIndex::new(case)?;
    Ok(Executor {
        case,
        plan,
        policy,
        coordinator,
        case_index,
        candidate_ids: Vec::new(),
        candidate_index: HashSet::new(),
        snapshot_candidates: false,
        job: None,
        validated_artifacts: HashSet::new(),
        transform_cohorts: Vec::new(),
        derived_discovery: super::super::derived_discovery::DerivedDiscovery::default(),
        transform_discoveries: HashMap::default(),
        framing_selection_bases: HashMap::default(),
        transform_proposal_receipts: HashMap::default(),
        framing_discoveries: HashMap::default(),
        record_discoveries: HashMap::default(),
        record_discovery_context_by_report: HashMap::default(),
        deferred_record_discovery_plan: None,
        record_schema_report_links: HashMap::default(),
        record_schema_associations_charged: 0,
        record_phase_work_charged: 0,
        pending_record_assemblies: VecDeque::default(),
        pending_record_suffixes: VecDeque::default(),
        pending_record_assembly_count: 0,
        relational_samples: super::super::relational::RelationalSampleCollections::default(),
        relational_discoveries: HashMap::default(),
        omissions: Vec::new(),
        complete_negative_transform_searches: 0,
        cycle_skips: 0,
    })
}
