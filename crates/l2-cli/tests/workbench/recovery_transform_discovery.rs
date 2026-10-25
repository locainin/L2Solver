use super::super::recover_case;
use super::super::{Executor, RecoveryExecutionPolicy};
use super::{
    RecoveryOmission, RecoveryPlan, RecoveryTask, base64_decode_recipe, blob_id, execute,
    hex_recipe, normal_policy, policy, source,
};
use l2_workbench::{
    evidence::{Case, Edge, EvidenceStatus, MAX_EDGES},
    recovery::{
        RecoveryCandidate, RecoveryCandidateState, RecoveryCoordinator, RecoveryResource,
        RecoveryResult, RecoveryStage,
    },
};
use serde_json::Value;
use std::{collections::BTreeSet, error::Error};

const BASE64_HEX_INPUT: &[u8] = b"ZGVhZA==";

#[test]
fn proposal_receipt_membership_deduplicates_many_values_and_keeps_first_seen_order()
-> Result<(), Box<dyn Error>> {
    let mut receipts = super::super::discovery::OrderedUnique::default();

    for receipt in 0..4096_u64 {
        assert!(receipts.try_insert(receipt)?);
    }
    for receipt in (0..4096_u64).rev() {
        assert!(!receipts.try_insert(receipt)?);
    }

    let expected = (0..4096_u64).collect::<Vec<_>>();
    assert_eq!(receipts.as_slice(), expected.as_slice());
    Ok(())
}

#[test]
fn late_terminal_receipt_linking_only_exposes_associations_added_after_commit()
-> Result<(), Box<dyn Error>> {
    let transform_receipt = 77_u64;
    let mut receipts = super::super::discovery::OrderedProposalReceipts::default();

    let first_batch = (0..4096_u64).collect::<Vec<_>>();
    for receipt in &first_batch {
        assert!(receipts.try_insert(*receipt)?);
    }
    assert_eq!(
        receipts.pending_for(transform_receipt),
        Some(first_batch.as_slice())
    );

    receipts.mark_linked(transform_receipt);
    assert_eq!(receipts.pending_for(transform_receipt), Some(&[][..]));

    let late_batch = (4096..8192_u64).collect::<Vec<_>>();
    for receipt in &late_batch {
        assert!(receipts.try_insert(*receipt)?);
    }
    assert_eq!(
        receipts.pending_for(transform_receipt),
        Some(late_batch.as_slice())
    );

    receipts.mark_linked(transform_receipt);
    assert_eq!(receipts.pending_for(transform_receipt), Some(&[][..]));
    let all_receipts = (0..8192_u64).collect::<Vec<_>>();
    assert_eq!(
        receipts.pending_for(transform_receipt + 1),
        Some(all_receipts.as_slice())
    );
    Ok(())
}

#[test]
fn default_recovery_discovers_a_two_stage_chain_without_promoting_neutral_bytes()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", BASE64_HEX_INPUT)?;

    let outcome = execute(&mut case, &automatic_recovery_plan(), &policy())?;

    let hexadecimal = transform_for(&outcome.candidates, &hex_recipe(), b"dead")?;
    let base64_ids = outcome
        .candidates
        .iter()
        .enumerate()
        .filter_map(|(index, candidate)| {
            let RecoveryTask::Transform(recipe) = candidate.task() else {
                return None;
            };
            let is_base64 = recipe.steps.iter().any(|operation| {
                matches!(
                    operation,
                    l2_workbench::derivation::Operation::Base64Decode { .. }
                )
            });
            (is_base64
                && candidate
                    .inputs()
                    .first()
                    .is_some_and(|input| input.blob_id() == blob_id(BASE64_HEX_INPUT)))
            .then_some(index)
        })
        .collect::<Vec<_>>();
    assert_eq!(base64_ids.len(), 2);
    assert_eq!(
        hexadecimal
            .parent_ids()
            .iter()
            .map(|parent| parent.index())
            .collect::<Vec<_>>(),
        base64_ids
    );
    assert!(matches!(
        hexadecimal.state(),
        RecoveryCandidateState::Finished {
            stage: RecoveryStage::Transform,
            result: RecoveryResult::Derived { .. },
        }
    ));
    assert!(case.blobs().iter().any(|blob| blob.bytes == [0xde, 0xad]));
    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::TransformDiscovery
            && candidate.inputs().first().is_some_and(|input| {
                input.origin_node_ids() == [input_node]
                    && input.blob_id() == blob_id(BASE64_HEX_INPUT)
            })
    }));
    assert_eq!(outcome.validated_artifact_count, 0);
    assert!(!case.nodes().iter().any(|node| node.kind == "artifact"));
    Ok(())
}

#[test]
fn recover_case_runs_default_transform_discovery_without_a_plan() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", BASE64_HEX_INPUT)?;

    let summary = recover_case(&mut case)?;

    let input_blob_id = blob_id(BASE64_HEX_INPUT);
    assert!(case.nodes().iter().any(|node| {
        node.kind == "recovery_transform_proposal_report"
            && node.details.get("input_node_id").and_then(Value::as_u64) == Some(input_node)
            && node.details.get("input_blob_id").and_then(Value::as_str)
                == Some(input_blob_id.as_str())
    }));
    assert!(case.blobs().iter().any(|blob| blob.bytes == [0xde, 0xad]));
    assert_eq!(summary.validated_artifact_count, 0);
    assert!(!case.nodes().iter().any(|node| node.kind == "artifact"));
    Ok(())
}

#[test]
fn complete_negative_transform_search_is_unsupported_and_not_retained_as_evidence()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input = b"not a supported canonical syntax";
    let input_node = source(&mut case, "http_body", input)?;

    let outcome = execute(&mut case, &automatic_recovery_plan(), &policy())?;

    let discovery = outcome
        .candidates
        .iter()
        .find(|candidate| {
            candidate.task() == &RecoveryTask::TransformDiscovery
                && candidate
                    .inputs()
                    .first()
                    .is_some_and(|input| input.origin_node_ids() == [input_node])
        })
        .ok_or("transform discovery candidate is missing")?;
    assert!(matches!(
        discovery.state(),
        RecoveryCandidateState::Finished {
            stage: RecoveryStage::TransformDiscovery,
            result: RecoveryResult::Unsupported,
        }
    ));
    assert_eq!(outcome.complete_negative_transform_searches, 1);
    assert!(
        !case
            .nodes()
            .iter()
            .any(|node| node.kind == "recovery_transform_proposal_report")
    );
    assert_eq!(case.blobs().len(), 1);
    assert!(case.blobs().first().is_some_and(|blob| blob.bytes == input));
    assert!(
        !outcome
            .candidates
            .iter()
            .any(|candidate| matches!(candidate.task(), RecoveryTask::Transform(_)))
    );
    Ok(())
}

#[test]
fn recover_case_reports_complete_negative_transform_search_count() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    source(&mut case, "http_body", b"not a supported canonical syntax")?;

    let summary = recover_case(&mut case)?;

    assert_eq!(summary.complete_negative_transform_searches, 1);
    Ok(())
}

#[test]
fn compact_negative_search_keeps_report_detail_omissions_visible() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", b"not a supported canonical syntax")?;
    let mut bounded = policy();
    bounded.transform_exploration.proposal_budget.max_reports = 0;

    let outcome = execute(&mut case, &automatic_recovery_plan(), &bounded)?;

    assert_eq!(outcome.complete_negative_transform_searches, 1);
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        RecoveryOmission::TransformDiscoveryAnalysis {
            input_node_id,
            omitted_candidates: 0,
            omitted_reports: 7,
        } if *input_node_id == input_node
    )));
    assert!(super::super::search_exhaustive_within_plan(
        &outcome.omissions
    ));
    assert!(!super::super::report_details_complete(&outcome.omissions));
    assert!(
        !case
            .nodes()
            .iter()
            .any(|node| node.kind == "recovery_transform_proposal_report")
    );
    Ok(())
}

#[test]
fn equivalent_transform_keeps_proposal_receipts_for_each_origin() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let http = source(&mut case, "http_body", BASE64_HEX_INPUT)?;
    let udp = source(&mut case, "udp_payload", BASE64_HEX_INPUT)?;

    let outcome = execute(&mut case, &automatic_recovery_plan(), &policy())?;

    let discovery_receipts = [http, udp]
        .into_iter()
        .map(|node_id| discovery_report_node_for_input(&case, &outcome.candidates, node_id))
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq!(discovery_receipts.len(), 2);
    let transform = transform_for(
        &outcome.candidates,
        &base64_decode_recipe(),
        BASE64_HEX_INPUT,
    )?;
    let RecoveryCandidateState::Finished {
        result: RecoveryResult::Derived {
            evidence_node_id: transform_receipt,
        },
        ..
    } = transform.state()
    else {
        return Err("merged transform did not retain a completed receipt".into());
    };
    let associated_receipts = case
        .edges()
        .iter()
        .filter(|edge| {
            edge.from == *transform_receipt
                && edge.relation == "proposed_by"
                && edge.status == EvidenceStatus::Unresolved
        })
        .map(|edge| edge.to)
        .collect::<BTreeSet<_>>();
    assert_eq!(associated_receipts, discovery_receipts);
    let transform_origins = transform
        .inputs()
        .first()
        .ok_or("transform input is missing")?
        .origin_node_ids()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(transform_origins, BTreeSet::from([http, udp]));
    Ok(())
}

#[test]
fn proposal_association_budget_admits_a_prefix_before_scheduling() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", BASE64_HEX_INPUT)?;
    let mut bounded = policy();
    bounded.resources.max_transform_proposal_associations = 1;

    let outcome = execute(&mut case, &automatic_recovery_plan(), &bounded)?;

    let report_node = discovery_report_node_for_input(&case, &outcome.candidates, input_node)?;
    let report = discovery_report_for_input(&case, &outcome.candidates, input_node)?;
    let proposals = report
        .pointer("/proposal_report/proposals")
        .and_then(Value::as_array)
        .ok_or("transform proposal list is missing")?;
    assert_eq!(proposals.len(), 2);
    let first_recipe: l2_workbench::derivation::Recipe = serde_json::from_value(
        proposals
            .first()
            .and_then(|proposal| proposal.get("recipe"))
            .cloned()
            .ok_or("first transform proposal recipe is missing")?,
    )?;
    let omitted_recipe: l2_workbench::derivation::Recipe = serde_json::from_value(
        proposals
            .get(1)
            .and_then(|proposal| proposal.get("recipe"))
            .cloned()
            .ok_or("second transform proposal recipe is missing")?,
    )?;
    let input_transforms = outcome
        .candidates
        .iter()
        .filter(|candidate| {
            matches!(candidate.task(), RecoveryTask::Transform(_))
                && candidate
                    .inputs()
                    .first()
                    .is_some_and(|input| input.blob_id() == blob_id(BASE64_HEX_INPUT))
        })
        .collect::<Vec<_>>();
    assert_eq!(input_transforms.len(), 1);
    let first_transform = input_transforms
        .first()
        .ok_or("retained transform proposal is missing")?;
    assert_eq!(
        first_transform.task(),
        &RecoveryTask::Transform(first_recipe)
    );
    assert_ne!(
        first_transform.task(),
        &RecoveryTask::Transform(omitted_recipe)
    );
    assert_eq!(outcome.resources.max_transform_proposal_associations, 1);
    assert_eq!(outcome.resources.transform_proposal_associations_charged, 1);
    assert_eq!(
        outcome.resources.transform_proposal_associations_remaining,
        0
    );
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        RecoveryOmission::TransformProposalAssociations {
            report_node_id: omitted_report,
            input_node_id: omitted_input,
            used: 1,
            limit: 1,
            requested: 1,
            omitted_count: 1,
        } if *omitted_report == report_node && *omitted_input == input_node
    )));
    Ok(())
}

#[test]
fn late_transform_context_reuses_report_associations() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first_input = source(&mut case, "http_body", BASE64_HEX_INPUT)?;
    let late_input = source(&mut case, "udp_payload", BASE64_HEX_INPUT)?;
    let plan = automatic_recovery_plan();
    let execution_policy: RecoveryExecutionPolicy = policy();
    let (coordinator, discovery_id) = queued_discovery(&case, first_input, &execution_policy)?;
    let mut executor = super::running_executor(&mut case, &plan, &execution_policy, coordinator)?;
    executor.register_transform_discovery_context(discovery_id, None, first_input)?;
    executor.run_transform_discovery(discovery_id, first_input, BASE64_HEX_INPUT.len())?;

    let charged_before_late_context = executor
        .coordinator
        .transform_proposal_associations_charged();
    let candidate_count_before_late_context = executor.coordinator.candidate_count();
    executor.register_transform_discovery_context(discovery_id, None, late_input)?;

    assert_eq!(
        executor
            .coordinator
            .transform_proposal_associations_charged(),
        charged_before_late_context
    );
    assert_eq!(
        executor.coordinator.candidate_count(),
        candidate_count_before_late_context
    );
    let base64_candidate_id = proposal_candidate_id(&executor, &base64_decode_recipe())?;
    assert_eq!(
        proposal_origins(&executor, base64_candidate_id)?,
        BTreeSet::from([first_input, late_input])
    );
    assert!(charged_before_late_context > 0);
    Ok(())
}

fn queued_discovery(
    case: &Case,
    input_node: u64,
    policy: &RecoveryExecutionPolicy,
) -> Result<
    (
        RecoveryCoordinator,
        l2_workbench::recovery::RecoveryCandidateId,
    ),
    Box<dyn Error>,
> {
    let mut coordinator = RecoveryCoordinator::new(policy.resources);
    let candidate_id =
        super::queued(coordinator.enqueue(case, input_node, RecoveryTask::TransformDiscovery)?)?;
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));
    Ok((coordinator, candidate_id))
}

fn proposal_candidate_id(
    executor: &Executor<'_>,
    recipe: &l2_workbench::derivation::Recipe,
) -> Result<l2_workbench::recovery::RecoveryCandidateId, Box<dyn Error>> {
    executor
        .transform_proposal_receipts
        .keys()
        .copied()
        .find(|candidate_id| {
            executor
                .coordinator
                .candidate(*candidate_id)
                .is_some_and(|candidate| {
                    candidate.task() == &RecoveryTask::Transform(recipe.clone())
                })
        })
        .ok_or_else(|| "transform proposal candidate is missing".into())
}

fn proposal_origins(
    executor: &Executor<'_>,
    candidate_id: l2_workbench::recovery::RecoveryCandidateId,
) -> Result<BTreeSet<u64>, Box<dyn Error>> {
    let candidate = executor
        .coordinator
        .candidate(candidate_id)
        .ok_or("transform proposal candidate was not retained")?;
    Ok(candidate
        .inputs()
        .first()
        .ok_or("transform proposal input is missing")?
        .origin_node_ids()
        .iter()
        .copied()
        .collect())
}

#[test]
fn late_proposal_association_updates_an_already_finished_transform_receipt()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", BASE64_HEX_INPUT)?;
    let mut plan = automatic_recovery_plan();
    plan.recipes.push(base64_decode_recipe());

    let outcome = execute(&mut case, &plan, &policy())?;

    let transform = transform_for(
        &outcome.candidates,
        &base64_decode_recipe(),
        BASE64_HEX_INPUT,
    )?;
    let RecoveryCandidateState::Finished {
        result: RecoveryResult::Derived {
            evidence_node_id: transform_receipt,
        },
        ..
    } = transform.state()
    else {
        return Err("explicit Base64 transform did not finish before discovery".into());
    };
    let report_node = discovery_report_node_for_input(&case, &outcome.candidates, input_node)?;
    assert!(case.edges().iter().any(|edge| {
        edge.from == *transform_receipt
            && edge.to == report_node
            && edge.relation == "proposed_by"
            && edge.status == EvidenceStatus::Unresolved
    }));
    Ok(())
}

#[test]
fn proposal_candidate_budget_is_explicit_in_the_retained_report() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", BASE64_HEX_INPUT)?;
    let mut bounded = policy();
    bounded.transform_exploration.proposal_budget.max_candidates = 0;

    let outcome = execute(&mut case, &automatic_recovery_plan(), &bounded)?;

    let report = discovery_report_for_input(&case, &outcome.candidates, input_node)?;
    assert_eq!(report.get("version").and_then(Value::as_u64), Some(1));
    assert_eq!(
        report.pointer("/input/node_id").and_then(Value::as_u64),
        Some(input_node)
    );
    let input_blob_id = blob_id(BASE64_HEX_INPUT);
    assert_eq!(
        report.pointer("/input/blob_id").and_then(Value::as_str),
        Some(input_blob_id.as_str())
    );
    assert_eq!(
        report.pointer("/input/byte_length").and_then(Value::as_u64),
        Some(BASE64_HEX_INPUT.len() as u64)
    );
    assert_eq!(
        report
            .pointer("/scan/operation_count")
            .and_then(Value::as_u64),
        Some(7)
    );
    assert_eq!(
        report
            .pointer("/scan/work_bytes_charged")
            .and_then(Value::as_u64),
        Some(62)
    );
    assert_eq!(
        report
            .pointer("/proposal_budget/max_candidates")
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        report
            .pointer("/proposal_budget/max_reports")
            .and_then(Value::as_u64),
        Some(7)
    );
    assert_eq!(
        report
            .pointer("/proposal_report/omissions/candidates")
            .and_then(Value::as_u64),
        Some(2)
    );
    let assessments = report
        .pointer("/proposal_report/assessments")
        .and_then(Value::as_array)
        .ok_or("discovery report assessments are missing")?;
    assert!(assessments.iter().any(|assessment| {
        assessment
            .pointer("/result/eligible/disposition")
            .and_then(Value::as_str)
            == Some("omitted_by_candidate_budget")
    }));
    assert!(
        !outcome
            .candidates
            .iter()
            .any(|candidate| matches!(candidate.task(), RecoveryTask::Transform(_)))
    );
    Ok(())
}

#[test]
fn report_budget_omissions_do_not_skip_candidate_scanning_or_scheduling()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", BASE64_HEX_INPUT)?;
    let mut bounded = policy();
    bounded.transform_exploration.proposal_budget.max_reports = 0;

    let outcome = execute(&mut case, &automatic_recovery_plan(), &bounded)?;

    let report = discovery_report_for_input(&case, &outcome.candidates, input_node)?;
    assert_eq!(
        report
            .pointer("/proposal_report/omissions/reports")
            .and_then(Value::as_u64),
        Some(7)
    );
    assert_eq!(
        report
            .pointer("/proposal_report/assessments")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        report
            .pointer("/proposal_report/proposals")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    assert!(
        outcome
            .candidates
            .iter()
            .any(|candidate| candidate.task() == &RecoveryTask::Transform(base64_decode_recipe()))
    );
    Ok(())
}

#[test]
fn proposal_scheduling_and_report_bytes_are_deterministic() -> Result<(), Box<dyn Error>> {
    let first = run_signature()?;
    let second = run_signature()?;
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn discovery_scan_stage_limit_is_a_partial_result_without_global_work_charge()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", BASE64_HEX_INPUT)?;
    let mut bounded = policy();
    bounded.transform_exploration.max_scan_work_bytes_per_input = 1;
    // Keep the scan task as the only accepted candidate so global work charges
    // contain only the input read, not the rejected per-input assessment
    bounded.resources.max_candidates = 1;

    let outcome = execute(&mut case, &automatic_recovery_plan(), &bounded)?;

    let discovery = outcome
        .candidates
        .iter()
        .find(|candidate| {
            candidate.task() == &RecoveryTask::TransformDiscovery
                && candidate
                    .inputs()
                    .first()
                    .is_some_and(|input| input.origin_node_ids() == [input_node])
        })
        .ok_or("transform discovery candidate is missing")?;
    assert!(matches!(
        discovery.state(),
        RecoveryCandidateState::Finished {
            stage: RecoveryStage::TransformDiscovery,
            result: RecoveryResult::Omitted,
        }
    ));
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        RecoveryOmission::StageWorkLimit {
            task: RecoveryTask::TransformDiscovery,
            limit: 1,
            work_bytes: 62,
            input_node_ids,
        } if input_node_ids == &[input_node]
    )));
    assert_eq!(
        outcome.resources.work_charged_bytes + outcome.resources.work_remaining_bytes,
        outcome.resources.max_work_bytes
    );
    assert_eq!(outcome.resources.work_charged_bytes, BASE64_HEX_INPUT.len());
    assert!(!outcome.complete);
    Ok(())
}

#[test]
fn transform_discovery_stage_work_limit_marks_search_non_exhaustive() {
    let omission = RecoveryOmission::StageWorkLimit {
        task: RecoveryTask::TransformDiscovery,
        input_node_ids: vec![1],
        limit: 1,
        work_bytes: 62,
    };

    assert!(!super::super::search_exhaustive_within_plan(&[omission]));
}

#[test]
fn edge_quota_does_not_leave_an_unlinked_discovery_report() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", BASE64_HEX_INPUT)?;
    for _ in case.edges().len()..MAX_EDGES {
        case.add_edge(Edge {
            from: input_node,
            to: input_node,
            relation: "quota_fixture".to_owned(),
            status: EvidenceStatus::Unresolved,
            reason: "Fill the bounded edge table for an atomicity regression".to_owned(),
        })?;
    }
    let mut bounded = policy();
    bounded.resources.max_candidates = 1;
    let before = case.clone();

    let outcome = execute(&mut case, &automatic_recovery_plan(), &bounded)?;

    let discovery = outcome
        .candidates
        .iter()
        .find(|candidate| candidate.task() == &RecoveryTask::TransformDiscovery)
        .ok_or("transform discovery candidate is missing")?;
    assert!(matches!(
        discovery.state(),
        RecoveryCandidateState::Finished {
            stage: RecoveryStage::TransformDiscovery,
            result: RecoveryResult::ResourceExhausted {
                resource: l2_workbench::recovery::RecoveryResource::EvidenceEdges,
                limit: MAX_EDGES,
                used: MAX_EDGES,
                requested: 1,
            },
        }
    ));
    assert!(
        !case
            .nodes()
            .iter()
            .any(|node| node.kind == "recovery_transform_proposal_report")
    );
    assert_eq!(
        case, before,
        "failed report retention leaves the Case unchanged"
    );
    assert!(
        !outcome
            .candidates
            .iter()
            .any(|candidate| matches!(candidate.task(), RecoveryTask::Transform(_))),
        "transform recipes are not scheduled without a retained proposal report"
    );
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::TransformDiscovery,
            resource: l2_workbench::recovery::RecoveryResource::EvidenceEdges,
            limit: MAX_EDGES,
            used: MAX_EDGES,
            requested: 1,
            ..
        }
    )));
    assert!(!outcome.complete);
    assert_eq!(outcome.resources.work_charged_bytes, 70);
    Ok(())
}

#[test]
fn node_quota_does_not_leave_an_unpublished_discovery_report() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", BASE64_HEX_INPUT)?;
    while case.nodes().len() < l2_workbench::evidence::MAX_NODES {
        case.add_node("quota_filler", None, Vec::new(), serde_json::json!({}))?;
    }
    let before = case.clone();
    let mut bounded = policy();
    bounded.resources.max_candidates = 1;

    let outcome = execute(&mut case, &automatic_recovery_plan(), &bounded)?;

    let discovery = outcome
        .candidates
        .iter()
        .find(|candidate| candidate.task() == &RecoveryTask::TransformDiscovery)
        .ok_or("transform discovery candidate is missing")?;
    assert!(matches!(
        discovery.state(),
        RecoveryCandidateState::Finished {
            stage: RecoveryStage::TransformDiscovery,
            result: RecoveryResult::ResourceExhausted {
                resource: l2_workbench::recovery::RecoveryResource::EvidenceNodes,
                limit: l2_workbench::evidence::MAX_NODES,
                used: l2_workbench::evidence::MAX_NODES,
                requested: 1,
            },
        }
    ));
    assert_eq!(
        case, before,
        "the failed report publication leaves no node behind"
    );
    assert!(
        !outcome
            .candidates
            .iter()
            .any(|candidate| matches!(candidate.task(), RecoveryTask::Transform(_))),
        "transform recipes are not scheduled without a retained proposal report"
    );
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::TransformDiscovery,
            resource: l2_workbench::recovery::RecoveryResource::EvidenceNodes,
            limit: l2_workbench::evidence::MAX_NODES,
            used: l2_workbench::evidence::MAX_NODES,
            requested: 1,
            input_node_ids,
        } if input_node_ids == &[input_node]
    )));
    assert!(!outcome.complete);
    assert_eq!(outcome.resources.work_charged_bytes, 70);
    Ok(())
}

#[test]
fn late_proposal_link_batch_rolls_back_when_only_one_edge_slot_remains()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", BASE64_HEX_INPUT)?;
    let execution_policy: RecoveryExecutionPolicy = policy();
    let mut coordinator = RecoveryCoordinator::new(execution_policy.resources);
    let candidate_id = super::queued(coordinator.enqueue(
        &case,
        input_node,
        RecoveryTask::Transform(base64_decode_recipe()),
    )?)?;
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));
    let transform_receipt =
        super::finish_derived(&mut case, &mut coordinator, candidate_id, input_node)?;
    let first_report = case.add_bytes_node(
        "recovery_transform_proposal_report",
        b"first proposal report",
        Vec::new(),
        serde_json::json!({}),
    )?;
    let second_report = case.add_bytes_node(
        "recovery_transform_proposal_report",
        b"second proposal report",
        Vec::new(),
        serde_json::json!({}),
    )?;
    for _ in case.edges().len()..MAX_EDGES - 1 {
        case.add_edge(Edge {
            from: input_node,
            to: input_node,
            relation: "quota_fixture".to_owned(),
            status: EvidenceStatus::Unresolved,
            reason: "Leave one evidence edge slot for the atomicity regression".to_owned(),
        })?;
    }

    let mut proposal_receipts = super::super::discovery::OrderedProposalReceipts::default();
    proposal_receipts.try_insert(first_report)?;
    proposal_receipts.try_insert(second_report)?;
    let plan = RecoveryPlan::default();
    let mut executor = super::running_executor(&mut case, &plan, &execution_policy, coordinator)?;
    executor
        .transform_proposal_receipts
        .insert(candidate_id, proposal_receipts);
    let edges_before = executor.case.edges().to_vec();

    let link_result = executor.link_transform_proposals(candidate_id, transform_receipt);

    assert!(link_result.is_ok());
    assert_eq!(executor.case.edges(), edges_before);
    let receipts = executor
        .transform_proposal_receipts
        .get(&candidate_id)
        .ok_or("transform proposal receipts are missing")?;
    assert_eq!(
        receipts.pending_for(transform_receipt),
        Some(&[first_report, second_report][..])
    );
    assert!(executor.omissions.iter().any(|omission| matches!(
        omission,
        RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::Transform(_),
            resource: RecoveryResource::EvidenceEdges,
            limit: MAX_EDGES,
            used,
            requested: 2,
            ..
        } if *used == MAX_EDGES - 1
    )));
    assert!(matches!(
        executor
            .coordinator
            .candidate(candidate_id)
            .map(RecoveryCandidate::state),
        Some(RecoveryCandidateState::Finished {
            result: RecoveryResult::Derived { .. },
            ..
        })
    ));
    Ok(())
}

#[test]
fn normal_work_allowance_covers_context_separate_scans_for_equal_bytes()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    source(&mut case, "http_body", BASE64_HEX_INPUT)?;
    source(&mut case, "udp_payload", BASE64_HEX_INPUT)?;
    let normal = normal_policy(&case)?;

    let outcome = execute(&mut case, &automatic_recovery_plan(), &normal)?;

    assert!(
        outcome.omissions.is_empty(),
        "unexpected omissions: {:?}",
        outcome.omissions
    );
    assert!(outcome.resources.work_charged_bytes <= normal.resources.max_work_bytes);
    let hex = transform_for(&outcome.candidates, &hex_recipe(), b"dead")?;
    assert!(matches!(
        hex.state(),
        RecoveryCandidateState::Finished {
            result: RecoveryResult::Derived { .. },
            ..
        }
    ));
    assert!(case.blobs().iter().any(|blob| blob.bytes == [0xde, 0xad]));
    Ok(())
}

type ScheduleSignature = (Vec<(String, usize, String, Vec<usize>)>, Vec<Vec<u8>>);

fn run_signature() -> Result<ScheduleSignature, Box<dyn Error>> {
    let mut case = Case::new();
    source(&mut case, "http_body", BASE64_HEX_INPUT)?;
    let outcome = execute(&mut case, &automatic_recovery_plan(), &policy())?;
    let schedule = outcome
        .candidates
        .iter()
        .map(|candidate| {
            Ok((
                serde_json::to_string(candidate.task())?,
                candidate.depth(),
                candidate
                    .inputs()
                    .first()
                    .ok_or("candidate input is missing")?
                    .blob_id()
                    .to_owned(),
                candidate
                    .parent_ids()
                    .iter()
                    .map(|parent| parent.index())
                    .collect(),
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let reports = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "recovery_transform_proposal_report")
        .map(|node| {
            let blob_id = node.blob.as_deref().ok_or("report blob is missing")?;
            case.blobs()
                .iter()
                .find(|blob| blob.id == blob_id)
                .map(|blob| blob.bytes.clone())
                .ok_or_else(|| "report blob bytes are missing".into())
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    Ok((schedule, reports))
}

fn transform_for<'a>(
    candidates: &'a [RecoveryCandidate],
    recipe: &l2_workbench::derivation::Recipe,
    input: &[u8],
) -> Result<&'a RecoveryCandidate, Box<dyn Error>> {
    candidates
        .iter()
        .find(|candidate| {
            candidate.task() == &RecoveryTask::Transform(recipe.clone())
                && candidate
                    .inputs()
                    .first()
                    .is_some_and(|entry| entry.blob_id() == blob_id(input))
        })
        .ok_or_else(|| "expected transform candidate is missing".into())
}

fn automatic_recovery_plan() -> RecoveryPlan {
    RecoveryPlan {
        discover_transforms: true,
        ..RecoveryPlan::default()
    }
}

fn discovery_report_for_input(
    case: &Case,
    candidates: &[RecoveryCandidate],
    input_node: u64,
) -> Result<Value, Box<dyn Error>> {
    let node_id = discovery_report_node_for_input(case, candidates, input_node)?;
    let node = case
        .nodes()
        .iter()
        .find(|node| node.id == node_id)
        .ok_or("proposal report node is missing")?;
    let blob_id = node
        .blob
        .as_deref()
        .ok_or("proposal report blob is missing")?;
    let bytes = &case
        .blobs()
        .iter()
        .find(|blob| blob.id == blob_id)
        .ok_or("proposal report bytes are missing")?
        .bytes;
    Ok(serde_json::from_slice(bytes)?)
}

fn discovery_report_node_for_input(
    case: &Case,
    candidates: &[RecoveryCandidate],
    input_node: u64,
) -> Result<u64, Box<dyn Error>> {
    let candidate = candidates
        .iter()
        .find(|candidate| {
            candidate.task() == &RecoveryTask::TransformDiscovery
                && candidate
                    .inputs()
                    .first()
                    .is_some_and(|input| input.origin_node_ids() == [input_node])
        })
        .ok_or("discovery candidate is missing")?;
    let RecoveryCandidateState::Finished {
        stage: RecoveryStage::TransformDiscovery,
        result: RecoveryResult::Hypothesis { node_id },
    } = candidate.state()
    else {
        return Err("discovery candidate did not finish as a hypothesis".into());
    };
    if !case.nodes().iter().any(|node| node.id == *node_id) {
        return Err("proposal report node is missing".into());
    }
    Ok(*node_id)
}
