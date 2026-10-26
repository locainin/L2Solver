use l2_workbench::{
    evidence::{Case, Edge, EvidenceStatus},
    protocol::{
        ByteField, ByteOrder, IntegerField, RecordCount, RecordLengthMeaning, RecordSchema,
    },
    recovery::{
        EnqueueOutcome, RecoveryCandidateId, RecoveryCoordinator, RecoveryError, RecoveryResource,
        RecoveryResourcePolicy, RecoveryResult, RecoveryTask,
    },
};
use std::error::Error;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const fn policy(max_candidates: usize, max_frontier: usize) -> RecoveryResourcePolicy {
    RecoveryResourcePolicy {
        max_candidates,
        max_frontier,
        max_inputs_per_candidate: 4,
        max_origins_per_candidate: 4,
        max_input_bytes_per_item: 16,
        max_total_input_bytes_per_candidate: 64,
        max_depth: 4,
        max_output_bytes: 64,
        max_work_bytes: 256,
        max_candidate_task_identity_bytes: 16 * 1024,
        max_transform_proposal_identity_bytes: 16 * 1024,
        max_transform_proposal_associations: 8,
        max_parent_links: 16,
        max_lineage_work: 128,
        max_context_aliases: 128,
        max_pending_origin_links: 128,
    }
}

fn input(case: &mut Case) -> TestResult<u64> {
    Ok(case.add_bytes_node(
        "recovery_input",
        b"input",
        Vec::new(),
        serde_json::json!({}),
    )?)
}

fn queued_id(outcome: EnqueueOutcome) -> TestResult<RecoveryCandidateId> {
    match outcome {
        EnqueueOutcome::Queued(id) => Ok(id),
        other => Err(std::io::Error::other(format!("candidate was not queued: {other:?}")).into()),
    }
}

#[test]
fn default_enqueue_and_pop_remain_fifo() -> TestResult {
    let mut case = Case::new();
    let node_id = input(&mut case)?;
    let mut coordinator = RecoveryCoordinator::new(policy(3, 3));
    let first = queued_id(coordinator.enqueue(&case, node_id, RecoveryTask::EmbeddedDiscovery)?)?;
    let second = queued_id(coordinator.enqueue(&case, node_id, RecoveryTask::RecordDiscovery)?)?;

    assert_eq!(coordinator.peek_next_id(), Some(first));
    assert_eq!(coordinator.peek_next_id(), Some(first));
    assert_eq!(coordinator.pop_next(), Ok(Some(first)));
    assert_eq!(coordinator.pop_next(), Ok(Some(second)));
    assert_eq!(coordinator.peek_next_id(), None);

    Ok(())
}

#[test]
fn priority_moves_only_the_new_tail_and_keeps_quota_accounting() -> TestResult {
    let mut case = Case::new();
    let node_id = input(&mut case)?;
    let mut coordinator = RecoveryCoordinator::new(policy(2, 3));
    let first_outcome = coordinator.enqueue(&case, node_id, RecoveryTask::EmbeddedDiscovery)?;
    let first = queued_id(first_outcome)?;
    let second_outcome = coordinator.enqueue(&case, node_id, RecoveryTask::RecordDiscovery)?;
    let second = queued_id(second_outcome)?;

    assert_eq!(
        coordinator.prioritize_newly_queued(&first_outcome),
        Err(RecoveryError::InvariantFailure)
    );
    assert_eq!(coordinator.peek_next_id(), Some(first));
    coordinator.prioritize_newly_queued(&second_outcome)?;

    let merged = coordinator.enqueue(&case, node_id, RecoveryTask::RecordDiscovery)?;
    assert_eq!(merged, EnqueueOutcome::Merged(second));
    coordinator.prioritize_newly_queued(&merged)?;

    let exhausted = coordinator.enqueue(&case, node_id, RecoveryTask::StructuralValidation)?;
    assert!(matches!(
        exhausted,
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::CandidateCount,
            ..
        }
    ));
    coordinator.prioritize_newly_queued(&exhausted)?;
    assert_eq!(coordinator.candidate_count(), 2);
    assert_eq!(coordinator.peek_next_id(), Some(second));
    assert_eq!(coordinator.pop_next(), Ok(Some(second)));
    assert_eq!(coordinator.pop_next(), Ok(Some(first)));
    assert_eq!(coordinator.pop_next(), Ok(None));

    Ok(())
}

#[test]
fn prioritizing_does_not_expand_frontier_capacity() -> TestResult {
    let mut case = Case::new();
    let node_id = input(&mut case)?;
    let mut coordinator = RecoveryCoordinator::new(policy(4, 2));
    let first = queued_id(coordinator.enqueue(&case, node_id, RecoveryTask::EmbeddedDiscovery)?)?;
    let second_outcome = coordinator.enqueue(&case, node_id, RecoveryTask::RecordDiscovery)?;
    let second = queued_id(second_outcome)?;
    coordinator.prioritize_newly_queued(&second_outcome)?;

    let exhausted = coordinator.enqueue(&case, node_id, RecoveryTask::StructuralValidation)?;
    assert!(matches!(
        exhausted,
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::FrontierCount,
            ..
        }
    ));
    assert_eq!(coordinator.candidate_count(), 2);
    assert_eq!(coordinator.peek_next_id(), Some(second));
    assert_eq!(coordinator.pop_next(), Ok(Some(second)));
    assert_eq!(coordinator.pop_next(), Ok(Some(first)));

    Ok(())
}

#[test]
fn newly_queued_children_inherit_priority_only_from_prioritized_parents() -> TestResult {
    let mut case = Case::new();
    let inputs = completion_priority_inputs(&mut case)?;
    let mut coordinator = RecoveryCoordinator::new(policy(6, 6));
    let (ordinary_parent, priority_parent) = completion_parents(&mut coordinator, &case, &inputs)?;

    let blocker_id = queued_id(coordinator.enqueue(
        &case,
        inputs.priority_child,
        RecoveryTask::EmbeddedDiscovery,
    )?)?;

    let ordinary_child = coordinator.enqueue_derived(
        ordinary_parent,
        &case,
        &[inputs.ordinary_child],
        RecoveryTask::StructuralValidation,
    )?;
    coordinator.prioritize_queued_from_parent(&ordinary_child, ordinary_parent)?;
    let ordinary_child_id = queued_id(ordinary_child)?;
    assert_eq!(coordinator.peek_next_id(), Some(blocker_id));
    assert_ordinary_merge_stays_fifo(
        &mut coordinator,
        &case,
        &inputs,
        ordinary_parent,
        ordinary_child_id,
        blocker_id,
    )?;
    assert_priority_merge_moves_queued_child(
        &mut coordinator,
        &case,
        &inputs,
        priority_parent,
        ordinary_child_id,
    )?;

    let priority_child = coordinator.enqueue_derived(
        ordinary_parent,
        &case,
        &[inputs.priority_child],
        RecoveryTask::StructuralValidation,
    )?;
    let priority_child_id = queued_id(priority_child)?;
    assert_eq!(coordinator.pop_next(), Ok(Some(ordinary_child_id)));
    coordinator.finish(&case, ordinary_child_id, RecoveryResult::Omitted)?;
    assert_eq!(coordinator.pop_next(), Ok(Some(blocker_id)));
    coordinator.finish(&case, blocker_id, RecoveryResult::Omitted)?;
    assert_eq!(coordinator.pop_next(), Ok(Some(priority_child_id)));
    assert_running_and_finished_merges_stay_unchanged(
        &mut coordinator,
        &case,
        &inputs,
        priority_parent,
        priority_child_id,
    )?;
    assert_eq!(coordinator.peek_next_id(), None);
    assert_eq!(coordinator.pop_next(), Ok(None));

    Ok(())
}

fn completion_parents(
    coordinator: &mut RecoveryCoordinator,
    case: &Case,
    inputs: &CompletionPriorityInputs,
) -> TestResult<(RecoveryCandidateId, RecoveryCandidateId)> {
    let ordinary_parent = queued_id(coordinator.enqueue(
        case,
        inputs.ordinary_parent_input,
        RecoveryTask::EmbeddedDiscovery,
    )?)?;
    let priority_parent_outcome = coordinator.enqueue(
        case,
        inputs.priority_parent_input,
        RecoveryTask::AssembleRecords(test_schema()),
    )?;
    let priority_parent = queued_id(priority_parent_outcome)?;
    coordinator.prioritize_newly_queued(&priority_parent_outcome)?;
    assert!(candidate_has_priority(coordinator, priority_parent)?);

    finish_derived_parent(coordinator, case, priority_parent, inputs.priority_receipt)?;
    finish_derived_parent(coordinator, case, ordinary_parent, inputs.ordinary_receipt)?;
    assert!(candidate_has_priority(coordinator, priority_parent)?);
    Ok((ordinary_parent, priority_parent))
}

fn assert_ordinary_merge_stays_fifo(
    coordinator: &mut RecoveryCoordinator,
    case: &Case,
    inputs: &CompletionPriorityInputs,
    ordinary_parent: RecoveryCandidateId,
    child_id: RecoveryCandidateId,
    blocker_id: RecoveryCandidateId,
) -> TestResult {
    let merged = coordinator.enqueue_derived(
        ordinary_parent,
        case,
        &[inputs.ordinary_child],
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(merged, EnqueueOutcome::Merged(child_id));
    coordinator.prioritize_queued_from_parent(&merged, ordinary_parent)?;
    assert_eq!(coordinator.peek_next_id(), Some(blocker_id));
    assert!(!candidate_has_priority(coordinator, child_id)?);
    Ok(())
}

fn assert_priority_merge_moves_queued_child(
    coordinator: &mut RecoveryCoordinator,
    case: &Case,
    inputs: &CompletionPriorityInputs,
    priority_parent: RecoveryCandidateId,
    child_id: RecoveryCandidateId,
) -> TestResult {
    let merged = coordinator.enqueue_derived(
        priority_parent,
        case,
        &[inputs.ordinary_child],
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(merged, EnqueueOutcome::Merged(child_id));
    coordinator.prioritize_queued_from_parent(&merged, priority_parent)?;
    assert_eq!(coordinator.peek_next_id(), Some(child_id));
    assert!(candidate_has_priority(coordinator, child_id)?);
    Ok(())
}

fn assert_running_and_finished_merges_stay_unchanged(
    coordinator: &mut RecoveryCoordinator,
    case: &Case,
    inputs: &CompletionPriorityInputs,
    priority_parent: RecoveryCandidateId,
    child_id: RecoveryCandidateId,
) -> TestResult {
    let merged_running = coordinator.enqueue_derived(
        priority_parent,
        case,
        &[inputs.priority_child],
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(merged_running, EnqueueOutcome::Merged(child_id));
    coordinator.prioritize_queued_from_parent(&merged_running, priority_parent)?;
    assert!(!candidate_has_priority(coordinator, child_id)?);
    assert_eq!(coordinator.peek_next_id(), None);
    coordinator.finish(case, child_id, RecoveryResult::Omitted)?;

    let merged_finished = coordinator.enqueue_derived(
        priority_parent,
        case,
        &[inputs.priority_child],
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(merged_finished, EnqueueOutcome::Merged(child_id));
    coordinator.prioritize_queued_from_parent(&merged_finished, priority_parent)?;
    assert!(!candidate_has_priority(coordinator, child_id)?);
    assert_eq!(coordinator.peek_next_id(), None);
    Ok(())
}

fn candidate_has_priority(
    coordinator: &RecoveryCoordinator,
    candidate_id: RecoveryCandidateId,
) -> TestResult<bool> {
    Ok(coordinator
        .candidate(candidate_id)
        .ok_or("candidate is unavailable")?
        .completion_priority())
}

#[test]
fn merged_completion_promotion_stops_at_lineage_budget_without_repeating() -> TestResult {
    let mut case = Case::new();
    let inputs = completion_priority_inputs(&mut case)?;
    let mut resources = policy(6, 6);
    resources.max_lineage_work = 4;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let (ordinary_parent, priority_parent) = completion_parents(&mut coordinator, &case, &inputs)?;

    let blocker_id = queued_id(coordinator.enqueue(
        &case,
        inputs.priority_child,
        RecoveryTask::EmbeddedDiscovery,
    )?)?;
    let assembly_task = RecoveryTask::AssembleRecords(test_schema());
    let target = coordinator.enqueue_derived(
        ordinary_parent,
        &case,
        &[inputs.ordinary_child],
        assembly_task.clone(),
    )?;
    let target_id = queued_id(target)?;
    assert_eq!(coordinator.lineage_work_charged(), 2);
    assert!(
        !coordinator
            .candidate(target_id)
            .ok_or("queued target candidate is unavailable")?
            .completion_priority()
    );
    let merged = coordinator.enqueue_derived(
        priority_parent,
        &case,
        &[inputs.ordinary_child],
        assembly_task,
    )?;
    assert_eq!(merged, EnqueueOutcome::Merged(target_id));
    assert_eq!(coordinator.peek_next_id(), Some(blocker_id));
    let tail_node = case.add_bytes_node("tail", b"tail", Vec::new(), serde_json::json!({}))?;
    let tail_id =
        queued_id(coordinator.enqueue(&case, tail_node, RecoveryTask::EmbeddedDiscovery)?)?;

    // Two inspections fit, but the middle entry cannot move without one more work unit
    coordinator.prioritize_queued_from_parent(&merged, priority_parent)?;
    assert_eq!(coordinator.lineage_work_charged(), 4);
    assert_eq!(coordinator.remaining_lineage_work(), 0);
    assert_eq!(coordinator.peek_next_id(), Some(blocker_id));
    assert_eq!(coordinator.candidate_count(), 5);
    assert!(
        coordinator
            .candidate(target_id)
            .ok_or("queued assembly candidate is unavailable")?
            .completion_priority()
    );

    // The retained marker prevents another partial scan and keeps the child path eligible
    coordinator.prioritize_queued_from_parent(&merged, priority_parent)?;
    assert_eq!(coordinator.lineage_work_charged(), 4);
    assert_eq!(coordinator.peek_next_id(), Some(blocker_id));
    assert_eq!(coordinator.pop_next(), Ok(Some(blocker_id)));
    assert_eq!(coordinator.pop_next(), Ok(Some(target_id)));
    assert_eq!(coordinator.pop_next(), Ok(Some(tail_id)));
    assert_eq!(coordinator.pop_next(), Ok(None));

    Ok(())
}

const fn test_schema() -> RecordSchema {
    RecordSchema {
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
    }
}

struct CompletionPriorityInputs {
    ordinary_parent_input: u64,
    priority_parent_input: u64,
    ordinary_receipt: u64,
    priority_receipt: u64,
    ordinary_child: u64,
    priority_child: u64,
}

fn completion_priority_inputs(case: &mut Case) -> TestResult<CompletionPriorityInputs> {
    let ordinary_parent_input = input(case)?;
    let priority_parent_input = case.add_bytes_node(
        "record_candidate",
        b"record",
        Vec::new(),
        serde_json::json!({}),
    )?;
    let ordinary_receipt = case.add_bytes_node(
        "recovery_receipt",
        b"ordinary receipt",
        Vec::new(),
        serde_json::json!({}),
    )?;
    let priority_receipt = case.add_bytes_node(
        "recovery_receipt",
        b"priority receipt",
        Vec::new(),
        serde_json::json!({}),
    )?;
    let ordinary_child = case.add_bytes_node(
        "ordinary_child",
        b"ordinary",
        Vec::new(),
        serde_json::json!({}),
    )?;
    let priority_child = case.add_bytes_node(
        "record_object",
        b"record object",
        Vec::new(),
        serde_json::json!({}),
    )?;
    add_derived_edge(case, ordinary_receipt, ordinary_parent_input)?;
    add_derived_edge(case, priority_receipt, priority_parent_input)?;
    add_derived_edge(case, ordinary_child, ordinary_receipt)?;
    add_derived_edge(case, ordinary_child, priority_receipt)?;
    add_derived_edge(case, priority_child, ordinary_receipt)?;
    add_derived_edge(case, priority_child, priority_receipt)?;
    Ok(CompletionPriorityInputs {
        ordinary_parent_input,
        priority_parent_input,
        ordinary_receipt,
        priority_receipt,
        ordinary_child,
        priority_child,
    })
}

fn finish_derived_parent(
    coordinator: &mut RecoveryCoordinator,
    case: &Case,
    candidate_id: RecoveryCandidateId,
    receipt_node_id: u64,
) -> TestResult {
    assert_eq!(coordinator.pop_next(), Ok(Some(candidate_id)));
    coordinator.finish(
        case,
        candidate_id,
        RecoveryResult::Derived {
            evidence_node_id: receipt_node_id,
        },
    )?;
    Ok(())
}

fn add_derived_edge(case: &mut Case, child: u64, parent: u64) -> TestResult {
    case.add_edge(Edge {
        from: child,
        to: parent,
        relation: "derived_from".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "fixture provenance".to_owned(),
    })?;
    Ok(())
}
