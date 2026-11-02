use super::super::{
    Executor, RecoveryExecutionError, RecoveryExecutionPolicy, RecoveryOmission, RecoveryPlan,
};
use l2_workbench::{
    evidence::{Case, Edge, EvidenceError, EvidenceStatus, MAX_EDGES},
    recovery::{
        EnqueueOutcome, RecoveryCandidateId, RecoveryCandidateState, RecoveryCoordinator,
        RecoveryError, RecoveryResource, RecoveryResult, RecoveryStage, RecoveryTask,
    },
};
use std::error::Error;

#[derive(Clone, Copy)]
enum CandidateStart {
    Queued,
    Running,
    Finished,
}

fn candidate_id(
    case: &Case,
    coordinator: &mut RecoveryCoordinator,
    input_node: u64,
    start: CandidateStart,
) -> Result<RecoveryCandidateId, Box<dyn Error>> {
    let candidate_id =
        match coordinator.enqueue(case, input_node, RecoveryTask::TransformDiscovery)? {
            EnqueueOutcome::Queued(candidate_id) => candidate_id,
            outcome => {
                return Err(format!("unexpected candidate enqueue outcome: {outcome:?}").into());
            }
        };
    if matches!(start, CandidateStart::Running | CandidateStart::Finished) {
        assert_eq!(coordinator.pop_next()?, Some(candidate_id));
    }
    if matches!(start, CandidateStart::Finished) {
        coordinator.finish(case, candidate_id, RecoveryResult::Unsupported)?;
    }
    Ok(candidate_id)
}

fn executor<'case>(
    case: &'case mut Case,
    plan: &'case RecoveryPlan,
    policy: &RecoveryExecutionPolicy,
    coordinator: RecoveryCoordinator,
) -> Result<Executor<'case>, RecoveryExecutionError> {
    let mut executor = super::super::test_support::build_executor(case, plan, policy)?;
    executor.coordinator = coordinator;
    Ok(executor)
}

fn evidence_quota_error() -> RecoveryExecutionError {
    RecoveryExecutionError::Evidence(EvidenceError::QuotaExceeded {
        field: "edges",
        maximum: MAX_EDGES,
    })
}

#[test]
fn evidence_quota_after_candidate_completion_preserves_terminal_result()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = case.add_bytes_node("input", b"bytes", Vec::new(), serde_json::json!({}))?;
    let plan = RecoveryPlan::default();
    let policy = super::policy();
    let mut coordinator = RecoveryCoordinator::new(policy.resources);
    let candidate = candidate_id(
        &case,
        &mut coordinator,
        input_node,
        CandidateStart::Finished,
    )?;
    let mut executor = executor(&mut case, &plan, &policy, coordinator)?;

    assert!(
        executor
            .stop_after_case_evidence_error(candidate, evidence_quota_error())
            .is_ok()
    );

    let result = executor
        .coordinator
        .candidate(candidate)
        .ok_or(RecoveryError::UnknownCandidate { id: candidate })?;
    assert_eq!(
        result.state(),
        &RecoveryCandidateState::Finished {
            stage: RecoveryStage::TransformDiscovery,
            result: RecoveryResult::Unsupported,
        }
    );
    assert!(matches!(
        executor.omissions.first(),
        Some(RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::TransformDiscovery,
            resource: RecoveryResource::EvidenceEdges,
            ..
        })
    ));
    assert_eq!(executor.omissions.len(), 1);
    Ok(())
}

#[test]
fn evidence_quota_preserves_pending_origin_context_for_finished_work() -> Result<(), Box<dyn Error>>
{
    let mut case = Case::new();
    let input_node = case.add_bytes_node("input", b"bytes", Vec::new(), serde_json::json!({}))?;
    let receipt_node =
        case.add_bytes_node("receipt", b"receipt", Vec::new(), serde_json::json!({}))?;
    let late_origin = case.add_bytes_node("input", b"bytes", Vec::new(), serde_json::json!({}))?;
    let plan = RecoveryPlan::default();
    let policy = super::policy();
    let mut coordinator = RecoveryCoordinator::new(policy.resources);
    let task = RecoveryTask::Transform(super::hex_recipe());
    let candidate = match coordinator.enqueue(&case, input_node, task.clone())? {
        EnqueueOutcome::Queued(candidate) => candidate,
        outcome => return Err(format!("unexpected candidate enqueue outcome: {outcome:?}").into()),
    };
    assert_eq!(coordinator.pop_next()?, Some(candidate));
    case.add_edge(Edge {
        from: receipt_node,
        to: input_node,
        relation: "derived_from".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "test result linkage".to_owned(),
    })?;
    coordinator.finish(
        &case,
        candidate,
        RecoveryResult::Derived {
            evidence_node_id: receipt_node,
        },
    )?;
    assert_eq!(
        coordinator.enqueue(&case, late_origin, task)?,
        EnqueueOutcome::MergedNeedsContext(candidate)
    );
    let mut executor = executor(&mut case, &plan, &policy, coordinator)?;

    assert!(
        executor
            .stop_after_case_evidence_error(candidate, evidence_quota_error())
            .is_ok()
    );

    let result = executor
        .coordinator
        .candidate(candidate)
        .ok_or(RecoveryError::UnknownCandidate { id: candidate })?;
    assert!(matches!(
        result.state(),
        RecoveryCandidateState::ContextPending {
            stage: RecoveryStage::Transform,
            result: RecoveryResult::Derived {
                evidence_node_id: selected,
            },
        } if *selected == receipt_node
    ));
    assert_eq!(executor.omissions.len(), 1);
    Ok(())
}

#[test]
fn evidence_quota_still_rejects_a_candidate_that_never_started() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = case.add_bytes_node("input", b"bytes", Vec::new(), serde_json::json!({}))?;
    let plan = RecoveryPlan::default();
    let policy = super::policy();
    let mut coordinator = RecoveryCoordinator::new(policy.resources);
    let candidate = candidate_id(&case, &mut coordinator, input_node, CandidateStart::Queued)?;
    let mut executor = executor(&mut case, &plan, &policy, coordinator)?;

    let result = executor.stop_after_case_evidence_error(candidate, evidence_quota_error());

    assert!(matches!(
        result,
        Err(RecoveryExecutionError::Coordinator(
            RecoveryError::CandidateNotRunning { id }
        )) if id == candidate
    ));
    assert_eq!(executor.omissions.len(), 0);
    Ok(())
}

#[test]
fn evidence_quota_finishes_a_candidate_while_its_task_is_running() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = case.add_bytes_node("input", b"bytes", Vec::new(), serde_json::json!({}))?;
    let plan = RecoveryPlan::default();
    let policy = super::policy();
    let mut coordinator = RecoveryCoordinator::new(policy.resources);
    let candidate = candidate_id(&case, &mut coordinator, input_node, CandidateStart::Running)?;
    let mut executor = executor(&mut case, &plan, &policy, coordinator)?;

    assert!(
        executor
            .stop_after_case_evidence_error(candidate, evidence_quota_error())
            .is_ok()
    );

    let result = executor
        .coordinator
        .candidate(candidate)
        .ok_or(RecoveryError::UnknownCandidate { id: candidate })?;
    assert!(matches!(
        result.state(),
        RecoveryCandidateState::Finished {
            stage: RecoveryStage::TransformDiscovery,
            result: RecoveryResult::ResourceExhausted {
                resource: RecoveryResource::EvidenceEdges,
                ..
            },
        }
    ));
    assert_eq!(executor.omissions.len(), 1);
    Ok(())
}
