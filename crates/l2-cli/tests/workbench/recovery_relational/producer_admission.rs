use super::{application::AppliedCandidates, record_gate::StructuralAdmission, search};
use l2_workbench::{
    job::MemoryBudget,
    protocol::{
        RelationalFit, RelationalFitStatus, RelationalTransformCandidate, RelationalTransformStatus,
    },
};
use serde_json::json;

#[test]
fn positive_producers_are_admitted_and_retained_even_for_deduplicated_reports()
-> Result<(), Box<dyn std::error::Error>> {
    let candidates = (0..3).map(|_| candidate()).collect::<Vec<_>>();
    let applications = applications();
    let denied = MemoryBudget::new(1);
    assert!(
        search::collect_producer_rules(
            &candidates,
            &applications,
            Some(StructuralAdmission {
                memory: &denied,
                maximum: 64 * 1024
            }),
        )
        .is_err()
    );
    assert_eq!(denied.snapshot()?.used_bytes, 0);

    let memory = MemoryBudget::new(64 * 1024);
    assert!(
        search::collect_producer_rules(
            &candidates,
            &applications,
            Some(StructuralAdmission {
                memory: &memory,
                maximum: 1
            }),
        )
        .is_err()
    );
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    let (rules, charge) = search::collect_producer_rules(
        &candidates,
        &applications,
        Some(StructuralAdmission {
            memory: &memory,
            maximum: 64 * 1024,
        }),
    )?;
    assert_eq!(
        rules.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(
        rules.first().ok_or("missing producer")?.1,
        candidates.first().ok_or("missing candidate")?.rule
    );
    assert!(memory.snapshot()?.used_bytes > 0);
    drop(rules);
    drop(charge);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn invalid_positive_producer_index_releases_its_temporary_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let candidates = [candidate()];
    let mut applications = applications();
    *applications
        .application_evidence_checks
        .first_mut()
        .and_then(|check| check.get_mut("candidate_index"))
        .ok_or("missing candidate index")? = json!(999);
    let memory = MemoryBudget::new(64 * 1024);
    assert!(
        search::collect_producer_rules(
            &candidates,
            &applications,
            Some(StructuralAdmission {
                memory: &memory,
                maximum: 64 * 1024
            }),
        )
        .is_err()
    );
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

fn candidate() -> RelationalTransformCandidate {
    let fit = RelationalFit {
        status: RelationalFitStatus::NotEvaluated,
        supported_sessions: Vec::new(),
        contradicted_sessions: Vec::new(),
        unresolved_sessions: Vec::new(),
        checks: Vec::new(),
    };
    RelationalTransformCandidate {
        rule: super::search_budget_tests::expected_session_relative_rule(),
        discovery: fit.clone(),
        heldout: fit,
        status: RelationalTransformStatus::AwaitingAcrossSessionValidation,
    }
}

fn applications() -> AppliedCandidates {
    AppliedCandidates {
        outputs: Vec::new(),
        decoded_frames: Vec::new(),
        accepted_schemas: Vec::new(),
        structural_evidence: Vec::new(),
        application_evidence_checks: vec![
            json!({"candidate_index": 0, "status": "structurally_supported", "artifact_validated": false, "structurally_supported": false}),
            json!({"candidate_index": 1, "status": "artifact_validated", "artifact_validated": true}),
        ],
        aggregate_parser_checks: vec![json!({"candidate_index": 2, "accepted": true})],
        supported_rules: 0,
        applied_rules: 0,
        used_work: 0,
        reason: None,
    }
}
