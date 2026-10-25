use super::{RecoveryPlan, RecoveryResourceSummary, finish_executor, normal_policy, test_support};
use l2_workbench::recovery::{
    EnqueueOutcome, RecoveryCandidateState, RecoveryResult, RecoveryTask,
};
use std::error::Error;

type TestResult<T> = Result<T, Box<dyn Error>>;

#[test]
fn global_record_work_exhaustion_finishes_the_running_candidate() -> TestResult<()> {
    let (mut case, input_node_id) = test_support::record_case()?;
    let plan = RecoveryPlan::default();
    let mut policy = normal_policy(&case)?;
    policy.resources.max_work_bytes = 0;
    policy.record_phase_work_limit = 1;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    let task = RecoveryTask::AssembleRecords(test_support::test_schema());
    let enqueue =
        executor
            .coordinator
            .enqueue_nodes(executor.case, &[input_node_id], task.clone())?;
    let candidate_id = match &enqueue {
        EnqueueOutcome::Queued(candidate_id) => *candidate_id,
        _ => return Err("record candidate was not queued".into()),
    };
    executor.record_enqueue(enqueue, &task, &[input_node_id])?;
    assert_eq!(
        executor.coordinator.pop_next()?,
        Some(candidate_id),
        "queued record candidate should become running"
    );

    assert!(!executor.charge_work(candidate_id, &task, &[input_node_id], 1)?);
    let candidate = executor
        .coordinator
        .candidate(candidate_id)
        .ok_or("record candidate is missing")?;
    assert!(matches!(
        candidate.state(),
        RecoveryCandidateState::Finished {
            result: RecoveryResult::ResourceExhausted {
                resource: l2_workbench::recovery::RecoveryResource::WorkBytes,
                limit: 0,
                used: 0,
                requested: 1,
            },
            ..
        }
    ));

    let outcome = finish_executor(executor)?;
    assert_eq!(outcome.candidate_count, 1);
    assert_eq!(outcome.resources.work_charged_bytes, 0);
    assert_eq!(outcome.resources.work_remaining_bytes, 0);
    assert_record_phase_resources(&outcome.resources);
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::AssembleRecords(_),
            input_node_ids,
            resource: l2_workbench::recovery::RecoveryResource::WorkBytes,
            limit: 0,
            used: 0,
            requested: 1,
        } if input_node_ids == &[input_node_id]
    )));
    Ok(())
}

#[test]
fn zero_record_phase_budget_rejects_assembly_before_global_work_charge() -> TestResult<()> {
    let (mut case, input_node_id) = test_support::record_case()?;
    let plan = RecoveryPlan::default();
    let mut policy = normal_policy(&case)?;
    policy.record_phase_work_limit = 0;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    let task = RecoveryTask::AssembleRecords(test_support::test_schema());
    let enqueue =
        executor
            .coordinator
            .enqueue_nodes(executor.case, &[input_node_id], task.clone())?;
    let candidate_id = match &enqueue {
        EnqueueOutcome::Queued(candidate_id) => *candidate_id,
        _ => return Err("record candidate was not queued".into()),
    };
    executor.record_enqueue(enqueue, &task, &[input_node_id])?;
    assert_eq!(executor.coordinator.pop_next()?, Some(candidate_id));

    let global_work_remaining = executor.coordinator.remaining_work_bytes();
    assert!(global_work_remaining > 0);
    assert!(!executor.charge_work(candidate_id, &task, &[input_node_id], 1)?);

    let candidate = executor
        .coordinator
        .candidate(candidate_id)
        .ok_or("record candidate is missing")?;
    assert!(matches!(
        candidate.state(),
        RecoveryCandidateState::Finished {
            result: RecoveryResult::ResourceExhausted {
                resource: l2_workbench::recovery::RecoveryResource::WorkBytes,
                limit: 0,
                used: 0,
                requested: 1,
            },
            ..
        }
    ));
    assert_eq!(
        executor.coordinator.remaining_work_bytes(),
        global_work_remaining
    );

    let outcome = finish_executor(executor)?;
    assert_eq!(outcome.resources.work_charged_bytes, 0);
    assert_eq!(outcome.resources.max_record_phase_work, 0);
    assert_eq!(outcome.resources.record_phase_work_charged, 0);
    assert_eq!(outcome.resources.record_phase_work_remaining, 0);
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::AssembleRecords(_),
            input_node_ids,
            resource: l2_workbench::recovery::RecoveryResource::WorkBytes,
            limit: 0,
            used: 0,
            requested: 1,
        } if input_node_ids == &[input_node_id]
    )));
    Ok(())
}

fn assert_record_phase_resources(resources: &RecoveryResourceSummary) {
    assert_eq!(resources.max_record_phase_work, 1);
    assert_eq!(resources.record_phase_work_charged, 0);
    assert_eq!(resources.record_phase_work_remaining, 1);
}
