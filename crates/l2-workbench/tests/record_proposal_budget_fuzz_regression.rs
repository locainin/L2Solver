use l2_workbench::protocol::{
    RecordDiscoveryLimits, RecordLimits, RecordSchemaProposalLimits, propose_record_schema_space,
};
use std::error::Error;

#[test]
fn omitted_length_checks_can_exceed_the_work_budget() -> Result<(), Box<dyn Error>> {
    let first = [0x0a, 0x00, 0x02, 0x0a, 0x0d];
    let second = [0x0a, 0x01, 0x01, 0x0d];
    let held_out = [0x0a, 0x02, 0x00];
    let limits = fuzz_proposal_limits(9);

    let report = propose_record_schema_space(
        &[first.as_slice(), second.as_slice()],
        &[held_out.as_slice()],
        limits,
    )?;

    assert!(report.examined_length_checks <= limits.max_length_checks);
    assert!(report.omitted_length_checks > 0);
    assert!(
        report.examined_length_checks + report.omitted_length_checks > limits.max_length_checks,
        "omitted checks describe the unexamined domain beyond the work budget"
    );
    assert!(!report.search_exhaustive_within_plan);
    Ok(())
}

#[test]
fn omitted_pair_checks_can_exceed_the_work_budget() -> Result<(), Box<dyn Error>> {
    let first = [0x02, 0x00, 0x02, 0x02, 0x00];
    let second = [0x02, 0x01, 0x02, 0x8e, 0x00];
    let held_out = [0x02, 0x02, 0x00];
    let limits = fuzz_proposal_limits(10);

    let report = propose_record_schema_space(
        &[first.as_slice(), second.as_slice()],
        &[held_out.as_slice()],
        limits,
    )?;

    assert!(report.examined_pair_checks <= limits.max_pair_checks);
    assert!(report.omitted_pair_checks > 0);
    assert!(
        report.examined_pair_checks + report.omitted_pair_checks > limits.max_pair_checks,
        "omitted checks describe the unexamined domain beyond the work budget"
    );
    assert!(!report.search_exhaustive_within_plan);
    Ok(())
}

fn fuzz_proposal_limits(input_length: usize) -> RecordSchemaProposalLimits {
    let input_limit = input_length.saturating_add(16).clamp(16, 272);
    let record_limits = RecordLimits {
        max_input_bytes: input_limit,
        max_records: 8,
        max_identifier_bytes: 4,
        max_report_bytes: 4_096,
        max_groups: 4,
        max_output_bytes: input_limit,
        max_issue_examples: 4,
    };
    RecordSchemaProposalLimits {
        discovery: RecordDiscoveryLimits {
            max_candidates: 8,
            max_messages: 3,
            max_survivors: 4,
            max_falsifications: 4,
            record_limits,
        },
        max_field_offset: 8,
        max_field_checks_per_domain: 32,
        max_pair_checks: 32,
        max_length_checks: 32,
    }
}
