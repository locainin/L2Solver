use super::{GateStatus, LearningSelection, complete_plan_details, no_candidate_plan};
use l2_workbench::protocol::{
    RecordDiscoveryValidationBasis, RecordSchemaDiscoveryReport, RecordSchemaProposalLimits,
    RecordSchemaProposalReport,
};
use serde_json::Value;

#[test]
fn no_candidate_plan_keeps_omitted_record_view_count() {
    let limits = RecordSchemaProposalLimits::default();
    let selection = LearningSelection {
        indices: Vec::new(),
        omitted_messages: 0,
        session_count: 0,
    };
    let plan = no_candidate_plan(limits, &selection, &proposal(7));

    assert_eq!(
        plan.details.get("omitted_record_views"),
        Some(&Value::from(7))
    );
}

#[test]
fn completed_plan_details_keep_omitted_record_view_count() {
    let discovery = empty_report();
    let proposal = proposal(7);
    let details = complete_plan_details(GateStatus::Contradicted, &discovery, 0, 128, &proposal);

    assert_eq!(details.get("omitted_record_views"), Some(&Value::from(7)));
}

fn proposal(omitted_record_views: usize) -> RecordSchemaProposalReport {
    RecordSchemaProposalReport {
        validation_basis:
            l2_workbench::protocol::RecordSchemaProposalValidationBasis::DiscoveryOnly,
        training_message_count: 1,
        held_out_message_count: 0,
        candidate_space: None,
        candidate_combinations: Some(0),
        examined_field_checks: 0,
        omitted_field_checks: 0,
        examined_pair_checks: 0,
        omitted_pair_checks: 0,
        examined_length_checks: 0,
        omitted_length_checks: 0,
        omitted_record_views,
        repeated_boundary_cues: Vec::new(),
        omitted_schema_combinations: Some(0),
        search_exhaustive_within_plan: false,
        limitations: ["test", "test"],
    }
}

fn empty_report() -> RecordSchemaDiscoveryReport {
    RecordSchemaDiscoveryReport {
        validation_basis: RecordDiscoveryValidationBasis::TrainingOnly,
        candidate_combinations: Some(0),
        examined_combinations: 0,
        unexamined_combinations: Some(0),
        search_exhaustive_within_plan: true,
        report_details_complete: true,
        surviving: Vec::new(),
        omitted_survivors: 0,
        falsifications: Vec::new(),
        falsified_count: 0,
        omitted_falsification_examples: 0,
    }
}
