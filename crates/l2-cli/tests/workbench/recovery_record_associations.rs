use super::{
    Executor, JobProgress, RecoveryExecutionOutcome, RecoveryPlan, finish_executor, normal_policy,
    test_support,
};
use l2_workbench::{
    evidence::{Case, Edge, EvidenceStatus},
    job::{Counter, Job},
    protocol::RecordSchema,
    recovery::{
        EnqueueOutcome, RecoveryCandidateId, RecoveryCandidateState, RecoveryResult, RecoveryTask,
    },
};
use serde_json::json;
use std::error::Error;

type TestResult<T> = Result<T, Box<dyn Error>>;

fn run_record_with_reports(
    case: &mut Case,
    input_node_id: u64,
    report_node_ids: &[u64],
    late_report_node_id: Option<u64>,
    job: Option<&Job>,
) -> TestResult<RecoveryExecutionOutcome> {
    let plan = RecoveryPlan::default();
    let policy = normal_policy(case)?;
    let schema = test_support::test_schema();
    let mut executor = test_support::build_executor(case, &plan, &policy)?;
    executor.job = job.cloned().map(JobProgress::new);
    let candidate_id =
        enqueue_reported_schema(&mut executor, input_node_id, &schema, report_node_ids)?;
    if executor.coordinator.pop_next()? != Some(candidate_id) {
        return Err("queued record candidate was not selected".into());
    }
    executor.execute_candidate(candidate_id)?;
    if let Some(report_node_id) = late_report_node_id {
        executor.enqueue_record_schema_from_report(&[input_node_id], &schema, report_node_id)?;
    }
    Ok(finish_executor(executor)?)
}

fn enqueue_reported_schema(
    executor: &mut Executor<'_>,
    input_node_id: u64,
    schema: &RecordSchema,
    report_node_ids: &[u64],
) -> TestResult<RecoveryCandidateId> {
    for report_node_id in report_node_ids {
        executor.enqueue_record_schema_from_report(&[input_node_id], schema, *report_node_id)?;
    }
    executor
        .candidate_ids
        .first()
        .copied()
        .ok_or_else(|| "record assembly candidate was not queued".into())
}

fn selected_record_candidate<'a>(
    outcome: &'a RecoveryExecutionOutcome,
    schema: &RecordSchema,
) -> TestResult<&'a l2_workbench::recovery::RecoveryCandidate> {
    let mut candidates = outcome
        .candidates
        .iter()
        .filter(|candidate| candidate.task() == &RecoveryTask::AssembleRecords(schema.clone()));
    let candidate = candidates
        .next()
        .ok_or("record assembly candidate is missing")?;
    if candidates.next().is_some() {
        return Err("duplicate record assembly candidates were retained".into());
    }
    Ok(candidate)
}

fn assert_report_links(case: &Case, report_node_ids: &[u64], receipt_node_id: u64) {
    for report_node_id in report_node_ids {
        assert!(case.edges().iter().any(|edge| {
            edge.from == *report_node_id
                && edge.to == receipt_node_id
                && edge.relation == "record_schema_selected_from"
                && edge.status == EvidenceStatus::Unresolved
        }));
        assert!(!case.edges().iter().any(|edge| {
            edge.from == *report_node_id
                && edge.to == receipt_node_id
                && matches!(edge.relation.as_str(), "record_assembly" | "derived_from")
        }));
    }
}

#[test]
fn multiple_and_late_reports_link_to_one_shared_assembly_receipt() -> TestResult<()> {
    let (mut case, input_node_id) = test_support::record_case()?;
    let reports = [
        test_support::add_report(&mut case, "first report")?,
        test_support::add_report(&mut case, "second report")?,
        test_support::add_report(&mut case, "late report")?,
    ];
    let outcome = run_record_with_reports(
        &mut case,
        input_node_id,
        &reports[..2],
        Some(reports[2]),
        None,
    )?;
    let candidate = selected_record_candidate(&outcome, &test_support::test_schema())?;
    let receipt_node_id = match candidate.state() {
        RecoveryCandidateState::Finished {
            result: RecoveryResult::Derived { evidence_node_id },
            ..
        } => evidence_node_id,
        state => {
            return Err(format!("record assembly did not produce a receipt: {state:?}").into());
        }
    };
    let input_origins = candidate
        .inputs()
        .iter()
        .flat_map(l2_workbench::recovery::RecoveryInput::origin_node_ids)
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(input_origins, [input_node_id]);
    assert_report_links(&case, &reports, *receipt_node_id);
    Ok(())
}

#[test]
fn committed_record_assembly_counts_each_strictly_parsed_record() -> TestResult<()> {
    let (mut case, input_node_id) = test_support::record_case()?;
    let job = Job::new("committed record assembly progress");

    run_without_reports(&mut case, input_node_id, Some(&job))?;

    assert_eq!(
        job.snapshot()?
            .counters
            .get(&Counter::Records)
            .copied()
            .unwrap_or(0),
        1
    );
    Ok(())
}

fn run_without_reports(
    case: &mut Case,
    input_node_id: u64,
    job: Option<&Job>,
) -> TestResult<RecoveryExecutionOutcome> {
    let plan = RecoveryPlan::default();
    let policy = normal_policy(case)?;
    let mut executor = test_support::build_executor(case, &plan, &policy)?;
    executor.job = job.cloned().map(JobProgress::new);
    let task = RecoveryTask::AssembleRecords(test_support::test_schema());
    let enqueue =
        executor
            .coordinator
            .enqueue_nodes(executor.case, &[input_node_id], task.clone())?;
    let candidate_id = match &enqueue {
        EnqueueOutcome::Queued(candidate_id) => *candidate_id,
        _ => return Err("record assembly candidate was not queued".into()),
    };
    executor.record_enqueue(enqueue, &task, &[input_node_id])?;
    if executor.coordinator.pop_next()? != Some(candidate_id) {
        return Err("queued record candidate was not selected".into());
    }
    executor.execute_candidate(candidate_id)?;
    Ok(finish_executor(executor)?)
}

fn fill_edges_to(case: &mut Case, target: usize) -> TestResult<()> {
    let node = case.add_node("edge_quota_fixture", None, Vec::new(), json!({}))?;
    while case.edges().len() < target {
        case.add_edge(Edge {
            from: node,
            to: node,
            relation: "quota_fixture".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "Synthetic edge fills the retained evidence quota".to_owned(),
        })?;
    }
    Ok(())
}

fn assert_edge_quota_failure(
    case: &Case,
    before: &Case,
    outcome: &RecoveryExecutionOutcome,
    input_node_id: u64,
) -> TestResult<()> {
    assert_eq!(case, before, "failed assembly transaction must roll back");
    let candidate = selected_record_candidate(outcome, &test_support::test_schema())?;
    assert!(matches!(
        candidate.state(),
        RecoveryCandidateState::Finished {
            result: RecoveryResult::ResourceExhausted {
                resource: l2_workbench::recovery::RecoveryResource::EvidenceEdges,
                ..
            },
            ..
        }
    ));
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::AssembleRecords(_),
            input_node_ids,
            resource: l2_workbench::recovery::RecoveryResource::EvidenceEdges,
            used,
            requested: 1,
            ..
        } if input_node_ids == &[input_node_id] && *used == before.edges().len()
    )));
    assert!(
        !case
            .nodes()
            .iter()
            .any(|node| node.kind == "record_parse_receipt")
    );
    Ok(())
}

#[test]
fn edge_quota_rolls_back_assembly_and_all_report_association_links() -> TestResult<()> {
    let (mut baseline, baseline_input) = test_support::record_case()?;
    let before_edges = baseline.edges().len();
    run_without_reports(&mut baseline, baseline_input, None)?;
    let assembly_edge_work = baseline
        .edges()
        .len()
        .checked_sub(before_edges)
        .ok_or("record assembly removed edges")?;

    let (mut case, input_node_id) = test_support::record_case()?;
    let reports = [
        test_support::add_report(&mut case, "first report")?,
        test_support::add_report(&mut case, "second report")?,
    ];
    let free_edges = assembly_edge_work
        .checked_add(1)
        .ok_or("record assembly edge allowance overflowed")?;
    let edge_target = l2_workbench::evidence::MAX_EDGES
        .checked_sub(free_edges)
        .ok_or("record assembly edge allowance exceeds Case quota")?;
    fill_edges_to(&mut case, edge_target)?;
    let before = case.clone();
    let job = Job::new("rolled back record assembly progress");
    let outcome = run_record_with_reports(&mut case, input_node_id, &reports, None, Some(&job))?;
    assert_edge_quota_failure(&case, &before, &outcome, input_node_id)?;
    assert_eq!(
        job.snapshot()?
            .counters
            .get(&Counter::Records)
            .copied()
            .unwrap_or(0),
        0
    );
    Ok(())
}
