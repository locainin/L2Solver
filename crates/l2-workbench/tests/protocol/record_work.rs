use l2_workbench::protocol::{
    ByteField, ByteOrder, IntegerField, ParsedRecord, RecordAssemblyInput, RecordCount,
    RecordDiscoveryLimits, RecordInput, RecordLengthMeaning, RecordLimits, RecordParseReport,
    RecordSchema, RecordSchemaProposalLimits, RecordWorkBudget,
    analyze_record_inputs_with_repeated_boundaries_and_offsets_observed,
};
use std::{error::Error, ops::ControlFlow};

type TestResult = Result<(), Box<dyn Error>>;

const fn schema() -> RecordSchema {
    RecordSchema {
        records_offset: 0,
        count: RecordCount::UntilEnd,
        identifier: ByteField {
            offset: 0,
            width: 2,
        },
        sequence: IntegerField {
            offset: 2,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 3,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        data_offset: 4,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: None,
    }
}

fn record(sequence: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + payload.len());
    bytes.extend_from_slice(b"ID");
    bytes.push(sequence);
    bytes.push(u8::try_from(payload.len()).unwrap_or(u8::MAX));
    bytes.extend_from_slice(payload);
    bytes
}

fn analysis_limits() -> RecordSchemaProposalLimits {
    RecordSchemaProposalLimits {
        discovery: RecordDiscoveryLimits {
            max_candidates: 128,
            max_messages: 16,
            max_survivors: 16,
            max_falsifications: 16,
            record_limits: RecordLimits::default(),
        },
        max_field_offset: 8,
        max_field_checks_per_domain: 128,
        max_pair_checks: 128,
        max_length_checks: 128,
    }
}

#[test]
fn parser_charges_attempts_and_hashes_each_input_once() -> TestResult {
    let bytes = record(0, b"payload");
    let limits = RecordLimits::default();
    let expected_schema = schema();
    let input = RecordInput::new(&bytes);
    let mut fresh_budget = RecordWorkBudget::new(16 * 1024);
    let report = input.parse_with_work(&expected_schema, limits, &mut fresh_budget)?;
    let first_parse_work = fresh_budget.consumed();
    let expected_parse_work = std::mem::size_of::<RecordParseReport>()
        + expected_schema.sequence.width
        + expected_schema.length.width
        + expected_schema.identifier.width
        + 1
        + std::mem::size_of::<ParsedRecord>()
        + bytes.len();
    assert_eq!(first_parse_work, expected_parse_work);

    let before_reuse = fresh_budget.consumed();
    input.parse_with_work(&expected_schema, limits, &mut fresh_budget)?;
    let reused_parse_work = fresh_budget.consumed() - before_reuse;

    let fresh_input = RecordInput::new(&bytes);
    let mut comparison_budget = RecordWorkBudget::new(16 * 1024);
    fresh_input.parse_with_work(&expected_schema, limits, &mut comparison_budget)?;
    let fresh_parse_work = comparison_budget.consumed();

    assert_eq!(first_parse_work, fresh_parse_work);
    assert_eq!(reused_parse_work + bytes.len(), fresh_parse_work);
    RecordAssemblyInput::from_input(&input, &report)?;
    Ok(())
}

#[test]
fn failed_parser_attempt_consumes_work_and_budget_exhaustion_is_distinct() {
    let invalid_bytes = [b'I', b'D', 0, 100, b'x'];
    let input = RecordInput::new(&invalid_bytes);
    let mut attempt_budget = RecordWorkBudget::new(1024);
    let result = input.parse_with_work(&schema(), RecordLimits::default(), &mut attempt_budget);
    assert!(matches!(
        result,
        Err(l2_workbench::protocol::RecordError::TruncatedRecord { .. })
    ));
    assert!(attempt_budget.consumed() > 0);

    let mut exhausted_budget = RecordWorkBudget::new(1);
    let exhausted = RecordInput::new(&invalid_bytes).parse_with_work(
        &schema(),
        RecordLimits::default(),
        &mut exhausted_budget,
    );
    assert!(matches!(
        exhausted,
        Err(l2_workbench::protocol::RecordError::WorkLimitExceeded { .. })
    ));
}

#[test]
fn discovery_work_limit_is_incomplete_not_a_schema_contradiction() -> TestResult {
    let first_bytes = record(0, b"first");
    let second_bytes = record(1, b"second");
    let first = RecordInput::new(&first_bytes);
    let second = RecordInput::new(&second_bytes);
    let training = [&first, &second];
    let view_work = training.len() * std::mem::size_of::<&[u8]>();
    let mut budget = RecordWorkBudget::new(view_work);

    let report = analyze_record_inputs_with_repeated_boundaries_and_offsets_observed(
        &training,
        &[],
        analysis_limits(),
        &[],
        &mut budget,
        |_, _, _, _| ControlFlow::Continue(()),
    )?;

    assert!(report.fixed_layout.proposal.work_limit_reached);
    assert!(!report.fixed_layout.proposal.search_exhaustive_within_plan);
    assert!(report.fixed_layout.discovery.is_none_or(|discovery| {
        discovery.work_limit_reached
            && !discovery.search_exhaustive_within_plan
            && discovery.falsified_count == 0
    }));
    let reported_work = report.fixed_layout.work_bytes.unwrap_or_default()
        + report
            .repeated_boundaries
            .as_ref()
            .and_then(|analysis| analysis.work_bytes)
            .unwrap_or_default();
    assert_eq!(reported_work, budget.consumed());
    assert_eq!(budget.consumed(), view_work);
    Ok(())
}
