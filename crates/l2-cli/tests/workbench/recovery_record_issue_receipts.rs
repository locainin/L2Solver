use super::{
    TestResult, build_primary_fixture, decode_report, execute, normal_policy, record_candidate,
    recovery_plan, report_node, report_schemas,
};
use l2_workbench::recovery::{RecoveryCandidateState, RecoveryResult, RecoveryTask};

#[test]
fn discovered_record_receipts_keep_candidates_available_for_validation() -> TestResult<()> {
    let mut fixture = build_primary_fixture()?;
    let policy = normal_policy(&fixture.case)?;
    let outcome = execute(&mut fixture.case, &recovery_plan(), &policy)?;
    let case = &fixture.case;
    let receipts = case
        .edges()
        .iter()
        .filter(|edge| edge.relation == "record_schema_selected_from")
        .map(|edge| edge.to)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        !receipts.is_empty(),
        "the fixture must exercise discovered schemas"
    );
    let receipt_with_groups = receipts
        .iter()
        .find_map(|id| {
            case.node(*id).filter(|node| {
                node.details
                    .get("incomplete_group_count")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|count| count > 0)
            })
        })
        .ok_or("discovered schema produced no incomplete groups")?;
    assert_eq!(
        receipt_with_groups
            .details
            .get("group_issue_representation"),
        Some(&serde_json::json!("parse_receipt"))
    );
    assert!(!case.nodes().iter().any(|node| {
        node.kind == "record_group_issue"
            && node
                .details
                .get("receipt_node")
                .and_then(serde_json::Value::as_u64)
                == Some(receipt_with_groups.id)
    }));
    let candidate = case
        .edges()
        .iter()
        .find_map(|edge| {
            (edge.from == receipt_with_groups.id && edge.relation == "retained_candidate")
                .then(|| case.node(edge.to))
                .flatten()
        })
        .ok_or("receipt did not retain a candidate group")?;
    assert!(
        outcome.candidates.iter().any(|task| {
            task.task() == &RecoveryTask::StructuralValidation
                && task
                    .inputs()
                    .iter()
                    .any(|input| input.origin_node_ids().contains(&candidate.id))
        }),
        "candidate must remain eligible for strict artifact validation"
    );
    Ok(())
}

#[test]
fn caller_supplied_schema_keeps_issue_nodes_when_discovery_selects_it_too() -> TestResult<()> {
    let mut learning = build_primary_fixture()?;
    let learning_policy = normal_policy(&learning.case)?;
    let learned = execute(&mut learning.case, &recovery_plan(), &learning_policy)?;
    let report_id = report_node(record_candidate(&learned, &learning.frame_nodes)?)?;
    let schemas = report_schemas(&decode_report(&learning.case, report_id)?)?;
    let schema = schemas
        .first()
        .cloned()
        .ok_or("fixture has no discovered schema")?;

    let mut fixture = build_primary_fixture()?;
    let mut plan = recovery_plan();
    plan.record_schemas.push(schema.clone());
    let policy = normal_policy(&fixture.case)?;
    let outcome = execute(&mut fixture.case, &plan, &policy)?;
    let receipt_ids = outcome.candidates.iter().filter_map(|candidate| {
        if candidate.task() != &RecoveryTask::AssembleRecords(schema.clone()) {
            return None;
        }
        match candidate.state() {
            RecoveryCandidateState::Finished {
                result: RecoveryResult::Derived { evidence_node_id },
                ..
            } => Some(*evidence_node_id),
            _ => None,
        }
    });
    let receipt = receipt_ids
        .filter_map(|id| fixture.case.node(id))
        .find(|node| {
            node.details
                .get("incomplete_group_count")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|count| count > 0)
                && fixture.case.edges().iter().any(|edge| {
                    edge.to == node.id && edge.relation == "record_schema_selected_from"
                })
        })
        .ok_or("fixture did not merge caller and discovered schema selection")?;
    assert!(receipt.details.get("group_issue_representation").is_none());
    assert!(fixture.case.nodes().iter().any(|node| {
        node.kind == "record_group_issue"
            && node
                .details
                .get("receipt_node")
                .and_then(serde_json::Value::as_u64)
                == Some(receipt.id)
    }));
    Ok(())
}
