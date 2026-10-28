use super::super::PROPOSED_BY_REASON;
use super::super::RecoveryExecutionError;
use super::super::{CaseIndex, Executor, RecoveryExecutionPolicy, RecoveryOmission, RecoveryPlan};
use l2_workbench::{
    derivation::{Base64Alphabet, Base64Padding, Operation, Recipe},
    evidence::{Case, Edge, EvidenceError, EvidenceStatus, MAX_EDGES},
    recovery::{RecoveryCoordinator, RecoveryResource, RecoveryResult, RecoveryTask},
};
use std::error::Error;

#[test]
fn terminal_proposal_link_quota_is_aggregated_without_retrying_late_receipts()
-> Result<(), Box<dyn Error>> {
    let mut fixture = ProposalLinkFixture::new()?;
    let [first_report, second_report, third_report, fourth_report] = fixture.reports;
    let candidate_id = fixture.candidate_id;
    let transform_receipt = fixture.transform_receipt;
    let input_node = fixture.input_node;
    let mut executor = fixture.executor()?;

    assert_missing_report_is_fatal(&mut executor, candidate_id, transform_receipt)?;
    link_report(&mut executor, candidate_id, transform_receipt, first_report)?;
    assert!(has_proposal_edge(
        executor.case,
        transform_receipt,
        first_report
    ));
    fill_edge_budget(&mut executor, input_node)?;

    executor.associate_proposal(candidate_id, second_report)?;
    assert_pending_reports(&executor, candidate_id, transform_receipt, &[second_report])?;
    executor.associate_proposal(candidate_id, third_report)?;
    executor.associate_proposal(candidate_id, fourth_report)?;
    executor.associate_proposal(candidate_id, third_report)?;
    assert_pending_reports(
        &executor,
        candidate_id,
        transform_receipt,
        &[second_report, third_report, fourth_report],
    )?;
    assert_aggregate_link_omission(&executor, input_node, 3)?;
    assert_proposal_link_prefix(
        &executor,
        transform_receipt,
        [first_report, second_report, third_report, fourth_report],
    );
    assert_eq!(executor.case.edges().len(), MAX_EDGES);

    executor.link_transform_proposals(candidate_id, transform_receipt)?;
    assert_aggregate_link_omission(&executor, input_node, 3)?;
    Ok(())
}

struct ProposalLinkFixture {
    case: Case,
    plan: RecoveryPlan,
    execution_policy: RecoveryExecutionPolicy,
    coordinator: Option<RecoveryCoordinator>,
    candidate_id: l2_workbench::recovery::RecoveryCandidateId,
    input_node: u64,
    transform_receipt: u64,
    reports: [u64; 4],
}

impl ProposalLinkFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let mut case = Case::new();
        let input_node =
            case.add_bytes_node("source", b"ZGVhZA==", Vec::new(), serde_json::json!({}))?;
        let execution_policy = super::super::policy::normal_policy(&case)?;
        let recipe = Recipe {
            steps: vec![Operation::Base64Decode {
                alphabet: Base64Alphabet::Standard,
                padding: Base64Padding::Required,
            }],
            constraints: Vec::new(),
        };
        let mut coordinator = RecoveryCoordinator::new(execution_policy.resources);
        let candidate_id =
            match coordinator.enqueue(&case, input_node, RecoveryTask::Transform(recipe))? {
                l2_workbench::recovery::EnqueueOutcome::Queued(id) => id,
                outcome => return Err(format!("expected queued candidate, got {outcome:?}").into()),
            };
        assert_eq!(coordinator.pop_next()?, Some(candidate_id));

        let transform_receipt = case.add_bytes_node(
            "recovery_test_receipt",
            b"transform receipt",
            Vec::new(),
            serde_json::json!({}),
        )?;
        case.add_edge(Edge {
            from: transform_receipt,
            to: input_node,
            relation: "derived_from".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "The receipt records one exact operation result".to_owned(),
        })?;
        coordinator.finish(
            &case,
            candidate_id,
            RecoveryResult::Derived {
                evidence_node_id: transform_receipt,
            },
        )?;

        let reports = [
            report_node(&mut case, b"first report")?,
            report_node(&mut case, b"second report")?,
            report_node(&mut case, b"third report")?,
            report_node(&mut case, b"fourth report")?,
        ];
        Ok(Self {
            case,
            plan: RecoveryPlan::default(),
            execution_policy,
            coordinator: Some(coordinator),
            candidate_id,
            input_node,
            transform_receipt,
            reports,
        })
    }

    fn executor(&mut self) -> Result<Executor<'_>, Box<dyn Error>> {
        let case_index = CaseIndex::new(&self.case)?;
        let coordinator = self
            .coordinator
            .take()
            .ok_or_else(|| std::io::Error::other("proposal fixture executor already created"))?;
        Ok(test_executor(
            &mut self.case,
            &self.plan,
            self.execution_policy.clone(),
            coordinator,
            case_index,
        )?)
    }
}

fn assert_missing_report_is_fatal(
    executor: &mut Executor<'_>,
    candidate_id: l2_workbench::recovery::RecoveryCandidateId,
    transform_receipt: u64,
) -> Result<(), Box<dyn Error>> {
    executor
        .transform_proposal_receipts
        .entry(candidate_id)
        .or_default()
        .try_insert(u64::MAX)?;
    assert!(matches!(
        executor.link_transform_proposals(candidate_id, transform_receipt),
        Err(RecoveryExecutionError::Evidence(
            EvidenceError::MissingReference { kind: "node" }
        ))
    ));
    assert!(executor.omissions.is_empty());
    executor.transform_proposal_receipts.remove(&candidate_id);
    Ok(())
}

fn link_report(
    executor: &mut Executor<'_>,
    candidate_id: l2_workbench::recovery::RecoveryCandidateId,
    transform_receipt: u64,
    report_node: u64,
) -> Result<(), Box<dyn Error>> {
    executor
        .transform_proposal_receipts
        .entry(candidate_id)
        .or_default()
        .try_insert(report_node)?;
    executor.link_transform_proposals(candidate_id, transform_receipt)?;
    Ok(())
}

fn fill_edge_budget(executor: &mut Executor<'_>, input_node: u64) -> Result<(), Box<dyn Error>> {
    let remaining_edges = MAX_EDGES.saturating_sub(executor.case.edges().len());
    for _ in 0..remaining_edges {
        executor.case.add_edge(Edge {
            from: input_node,
            to: input_node,
            relation: "quota_fixture".to_owned(),
            status: EvidenceStatus::Unresolved,
            reason: "The fixture fills the remaining evidence edge budget".to_owned(),
        })?;
    }
    Ok(())
}

fn assert_pending_reports(
    executor: &Executor<'_>,
    candidate_id: l2_workbench::recovery::RecoveryCandidateId,
    transform_receipt: u64,
    expected: &[u64],
) -> Result<(), Box<dyn Error>> {
    let pending = executor
        .transform_proposal_receipts
        .get(&candidate_id)
        .and_then(|receipts| receipts.pending_for(transform_receipt))
        .ok_or_else(|| std::io::Error::other("proposal receipt set is missing"))?;
    assert_eq!(pending, expected);
    Ok(())
}

fn assert_aggregate_link_omission(
    executor: &Executor<'_>,
    input_node: u64,
    requested: usize,
) -> Result<(), Box<dyn Error>> {
    let [omission] = executor.omissions.as_slice() else {
        return Err(std::io::Error::other("expected one aggregate proposal omission").into());
    };
    assert!(matches!(
        omission,
        RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::Transform(_),
            input_node_ids,
            resource: RecoveryResource::EvidenceEdges,
            limit: MAX_EDGES,
            used: MAX_EDGES,
            requested: omitted,
        } if input_node_ids == &[input_node] && *omitted == requested
    ));
    Ok(())
}

fn assert_proposal_link_prefix(executor: &Executor<'_>, transform_receipt: u64, reports: [u64; 4]) {
    let [first, second, third, fourth] = reports;
    for (report, expected) in [
        (first, true),
        (second, false),
        (third, false),
        (fourth, false),
    ] {
        assert_eq!(
            has_proposal_edge(executor.case, transform_receipt, report),
            expected
        );
    }
}

fn report_node(case: &mut Case, content: &[u8]) -> Result<u64, Box<dyn Error>> {
    Ok(case.add_bytes_node(
        "recovery_transform_proposal_report",
        content,
        Vec::new(),
        serde_json::json!({}),
    )?)
}

fn has_proposal_edge(case: &Case, from: u64, to: u64) -> bool {
    case.edges().iter().any(|edge| {
        edge.from == from
            && edge.to == to
            && edge.relation == "proposed_by"
            && edge.status == EvidenceStatus::Unresolved
            && edge.reason == PROPOSED_BY_REASON
    })
}

fn test_executor<'a>(
    case: &'a mut Case,
    plan: &'a RecoveryPlan,
    policy: RecoveryExecutionPolicy,
    coordinator: RecoveryCoordinator,
    case_index: CaseIndex,
) -> Result<Executor<'a>, RecoveryExecutionError> {
    let mut executor = super::super::new_executor(case, plan, policy, false, None, None)?;
    executor.coordinator = coordinator;
    executor.case_index = case_index;
    Ok(executor)
}
