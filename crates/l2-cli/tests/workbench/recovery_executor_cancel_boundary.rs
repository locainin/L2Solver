use super::{
    JobProgress, RecoveryPlan, RecoveryTask, drain_candidate_frontier, execute_executor,
    normal_policy, test_support,
};
use l2_workbench::{
    evidence::Case,
    job::Job,
    recovery::{EnqueueOutcome, RecoveryCandidateState},
};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn cancellation_before_scheduling_leaves_the_initial_frontier_empty() -> TestResult {
    let mut case = Case::new();
    case.add_bytes_node(
        "http_body",
        b"unfinished input",
        Vec::new(),
        serde_json::json!({}),
    )?;
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    let job = Job::new("cancel before scheduler initialization");
    job.request_cancel();
    executor.job = Some(JobProgress::new(job));

    let error = execute_executor(&mut executor)
        .err()
        .ok_or("cancelled scheduler unexpectedly ran")?;

    assert!(error.to_string().contains("cancellation was requested"));
    assert_eq!(executor.coordinator.candidate_count(), 0);
    assert_eq!(executor.coordinator.peek_next_id(), None);
    Ok(())
}

#[test]
fn cancellation_keeps_the_next_candidate_queued() -> TestResult {
    let (mut case, input) = test_support::record_case()?;
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    let outcome =
        executor
            .coordinator
            .enqueue(executor.case, input, RecoveryTask::StructuralValidation)?;
    let EnqueueOutcome::Queued(candidate_id) = outcome else {
        return Err("candidate was not queued".into());
    };
    let job = Job::new("cancel before candidate");
    job.request_cancel();
    executor.job = Some(JobProgress::new(job));
    let mut evidence_stop = None;
    let mut evidence_stop_reported = false;

    let error = drain_candidate_frontier(
        &mut executor,
        &mut evidence_stop,
        &mut evidence_stop_reported,
    )
    .err()
    .ok_or("cancelled candidate unexpectedly ran")?;

    assert!(error.to_string().contains("cancellation was requested"));
    assert_eq!(executor.coordinator.peek_next_id(), Some(candidate_id));
    assert_eq!(
        executor
            .coordinator
            .candidate(candidate_id)
            .map(l2_workbench::recovery::RecoveryCandidate::state),
        Some(&RecoveryCandidateState::Queued),
    );
    Ok(())
}

#[test]
fn cancellation_keeps_deferred_record_assembly_unadmitted() -> TestResult {
    let (mut case, input) = test_support::record_case()?;
    let report = test_support::add_report(&mut case, "pending strict schema")?;
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    executor.defer_record_schema_group(vec![(vec![input], test_support::test_schema(), report)])?;
    let job = Job::new("cancel before deferred assembly");
    job.request_cancel();
    executor.job = Some(JobProgress::new(job));
    let candidates_before = executor.coordinator.candidate_count();
    let nodes_before = executor.case.nodes().len();
    let edges_before = executor.case.edges().len();
    let mut evidence_stop = None;
    let mut evidence_stop_reported = false;

    let error = drain_candidate_frontier(
        &mut executor,
        &mut evidence_stop,
        &mut evidence_stop_reported,
    )
    .err()
    .ok_or("cancelled deferred assembly unexpectedly ran")?;

    assert!(error.to_string().contains("cancellation was requested"));
    assert_eq!(executor.pending_record_assembly_count, 1);
    assert_eq!(executor.pending_record_assemblies.len(), 1);
    assert_eq!(executor.coordinator.candidate_count(), candidates_before);
    assert_eq!(executor.case.nodes().len(), nodes_before);
    assert_eq!(executor.case.edges().len(), edges_before);
    Ok(())
}
