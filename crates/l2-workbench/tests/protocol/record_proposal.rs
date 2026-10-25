use l2_workbench::protocol::{
    ByteField, ByteOrder, IntegerField, RecordCount, RecordDiscoveryError, RecordDiscoveryLimits,
    RecordDiscoveryPartition, RecordLengthMeaning, RecordLimits, RecordSchema,
    RecordSchemaDiscoverySpace, RecordSchemaProposalLimits, RecordSchemaProposalValidationBasis,
    analyze_record_schemas, discover_record_schemas, propose_record_schema_space,
};
use std::error::Error;

fn proposal_limits(max_candidates: usize) -> RecordSchemaProposalLimits {
    RecordSchemaProposalLimits {
        discovery: RecordDiscoveryLimits {
            max_candidates,
            max_messages: 32,
            max_survivors: max_candidates,
            max_falsifications: max_candidates,
            record_limits: RecordLimits::default(),
        },
        max_field_offset: 16,
        max_field_checks_per_domain: 2_000,
        max_pair_checks: 20_000,
        max_length_checks: 20_000,
    }
}

fn record(identifier: &[u8], sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(identifier);
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    bytes.extend_from_slice(payload);
    bytes
}

const fn expected_schema() -> RecordSchema {
    RecordSchema {
        records_offset: 0,
        count: RecordCount::UntilEnd,
        identifier: ByteField {
            offset: 0,
            width: 3,
        },
        sequence: IntegerField {
            offset: 3,
            width: 2,
            byte_order: ByteOrder::LittleEndian,
        },
        length: IntegerField {
            offset: 5,
            width: 4,
            byte_order: ByteOrder::BigEndian,
        },
        data_offset: 9,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: None,
    }
}

fn bounded_search_message(sequence: u16, payload_length: usize) -> Vec<u8> {
    interleaved_search_message(*b"\x19\x82", sequence, payload_length)
}

fn interleaved_search_message(
    identifier: [u8; 2],
    sequence: u16,
    payload_length: usize,
) -> Vec<u8> {
    let body_length = 1 + 2 + 2 + 2 + payload_length;
    let mut message = Vec::with_capacity(2 + body_length);
    message.extend_from_slice(&u16::try_from(body_length).unwrap_or(u16::MAX).to_be_bytes());
    message.push(0xd7);
    message.extend_from_slice(&identifier);
    message.extend_from_slice(&sequence.to_be_bytes());
    message.extend_from_slice(
        &u16::try_from(payload_length)
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    message.resize(9 + payload_length, b'x');
    message
}

const fn bounded_search_schema() -> RecordSchema {
    RecordSchema {
        records_offset: 0,
        count: RecordCount::UntilEnd,
        identifier: ByteField {
            offset: 3,
            width: 2,
        },
        sequence: l2_workbench::protocol::IntegerField {
            offset: 5,
            width: 2,
            byte_order: ByteOrder::BigEndian,
        },
        length: l2_workbench::protocol::IntegerField {
            offset: 7,
            width: 2,
            byte_order: ByteOrder::LittleEndian,
        },
        data_offset: 9,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: None,
    }
}

fn projected_candidate_count(space: &RecordSchemaDiscoverySpace) -> Option<usize> {
    [
        space.records_offsets.len(),
        space.counts.len(),
        space.identifier_fields.len(),
        space.sequence_fields.len(),
        space.length_fields.len(),
        space.data_offsets.len(),
        space.length_meanings.len(),
    ]
    .into_iter()
    .try_fold(1_usize, usize::checked_mul)
}

#[test]
fn proposes_unseen_record_layout_and_validates_each_message_without_assembly()
-> Result<(), Box<dyn Error>> {
    let first = record(b"\x19\x82\xd1", 4, b"alpha");
    let second = record(b"\x70\x03\xa4", 8, b"bravo");
    let third = record(b"\x19\x82\xd1", 5, b"alpha-next");
    let fourth = record(b"\x19\x82\xd1", 6, b"alpha-last");
    let held_out = record(b"\x70\x03\xa4", 12, b"delta");
    let training = [
        first.as_slice(),
        second.as_slice(),
        third.as_slice(),
        fourth.as_slice(),
    ];
    let expected = expected_schema();

    let proposal =
        propose_record_schema_space(&training, &[held_out.as_slice()], proposal_limits(100_000))?;
    assert_eq!(
        proposal.validation_basis,
        RecordSchemaProposalValidationBasis::HeldOutMessagesAvailable
    );
    let space = proposal
        .candidate_space
        .as_ref()
        .ok_or("expected a structurally plausible candidate space")?;
    assert!(space.identifier_fields.contains(&expected.identifier));
    assert!(space.sequence_fields.contains(&expected.sequence));
    assert!(space.length_fields.contains(&expected.length));
    assert!(space.data_offsets.contains(&expected.data_offset));
    assert!(space.length_meanings.contains(&expected.length_meaning));

    let discovery = discover_record_schemas(
        &training,
        &[held_out.as_slice()],
        space,
        proposal_limits(100_000).discovery,
    )?;
    let hypothesis = discovery
        .surviving
        .iter()
        .find(|candidate| candidate.schema == expected)
        .ok_or("expected the generated schema to survive held-out parsing")?;
    assert_eq!(hypothesis.held_out_message_count, 1);
    assert_eq!(hypothesis.training_record_count, 4);
    assert_eq!(hypothesis.held_out_record_count, 1);
    Ok(())
}

#[test]
fn reports_discovery_only_without_held_out_messages() -> Result<(), Box<dyn Error>> {
    let first = record(b"\x19\x82\xd1", 4, b"alpha");
    let second = record(b"\x19\x82\xd1", 7, b"beta");
    let report = propose_record_schema_space(
        &[first.as_slice(), second.as_slice()],
        &[],
        proposal_limits(100_000),
    )?;

    assert_eq!(
        report.validation_basis,
        RecordSchemaProposalValidationBasis::DiscoveryOnly
    );
    assert_eq!(report.training_message_count, 2);
    assert_eq!(report.held_out_message_count, 0);
    assert!(report.search_exhaustive_within_plan);
    Ok(())
}

#[test]
fn holdout_parser_falsifies_a_training_only_length_interpretation() -> Result<(), Box<dyn Error>> {
    let first = record(b"\x19\x82\xd1", 4, b"alpha");
    let second = record(b"\x19\x82\xd1", 7, b"beta");
    let mut held_out = record(b"\x19\x82\xd1", 9, b"gamma");
    *held_out.get_mut(8).ok_or("length field byte is missing")? = 20;
    let proposal = propose_record_schema_space(
        &[first.as_slice(), second.as_slice()],
        &[held_out.as_slice()],
        proposal_limits(100_000),
    )?;
    let discovery_only = propose_record_schema_space(
        &[first.as_slice(), second.as_slice()],
        &[],
        proposal_limits(100_000),
    )?;
    assert_eq!(proposal.candidate_space, discovery_only.candidate_space);
    let space = proposal
        .candidate_space
        .as_ref()
        .ok_or("expected candidates from the training messages")?;
    let report = discover_record_schemas(
        &[first.as_slice(), second.as_slice()],
        &[held_out.as_slice()],
        space,
        proposal_limits(100_000).discovery,
    )?;

    assert!(report.surviving.iter().all(|candidate| {
        candidate.schema.identifier
            == ByteField {
                offset: 0,
                width: 3,
            }
            && candidate.schema.sequence.offset == 3
            && candidate.schema.length.offset == 5
    }));
    assert!(report.falsifications.iter().any(|failure| {
        failure.partition == RecordDiscoveryPartition::HeldOut
            && failure.schema.identifier
                == ByteField {
                    offset: 0,
                    width: 3,
                }
            && failure.schema.sequence.offset == 3
            && failure.schema.length.offset == 5
    }));
    Ok(())
}

#[test]
fn random_materialized_bytes_do_not_produce_length_consistent_schemas() -> Result<(), Box<dyn Error>>
{
    let first = (0..24).map(|value| 0x80 + value).collect::<Vec<u8>>();
    let second = (0..24).map(|value| 0xa0 + value).collect::<Vec<u8>>();
    let third = (0..24).map(|value| 0xc0 + value).collect::<Vec<u8>>();
    let report = propose_record_schema_space(
        &[first.as_slice(), second.as_slice(), third.as_slice()],
        &[],
        proposal_limits(100_000),
    )?;

    assert!(report.candidate_space.is_none());
    assert_eq!(report.candidate_combinations, Some(0));
    Ok(())
}

#[test]
fn proposal_order_is_deterministic_and_search_budgets_are_reported() -> Result<(), Box<dyn Error>> {
    let first = record(b"\x19\x82\xd1", 4, b"alpha");
    let second = record(b"\x70\x03\xa4", 8, b"bravo");
    let third = record(b"\x19\x82\xd1", 11, b"omega");
    let messages = [first.as_slice(), second.as_slice(), third.as_slice()];
    let limits = proposal_limits(1);
    let first_report = propose_record_schema_space(&messages, &[], limits)?;
    let second_report = propose_record_schema_space(&messages, &[], limits)?;

    assert_eq!(first_report, second_report);
    assert!(!first_report.search_exhaustive_within_plan);
    assert!(first_report.omitted_schema_combinations.unwrap_or(0) > 0);

    let mut field_limited = proposal_limits(100_000);
    field_limited.max_field_checks_per_domain = 1;
    let field_report = propose_record_schema_space(&messages, &[], field_limited)?;
    assert!(field_report.omitted_field_checks > 0);

    let mut pair_limited = proposal_limits(100_000);
    pair_limited.max_pair_checks = 1;
    let pair_report = propose_record_schema_space(&messages, &[], pair_limited)?;
    assert!(pair_report.omitted_pair_checks > 0);

    let mut length_limited = proposal_limits(100_000);
    length_limited.max_length_checks = 1;
    let length_report = propose_record_schema_space(&messages, &[], length_limited)?;
    assert!(length_report.omitted_length_checks > 0);

    let mut invalid_limits = proposal_limits(1);
    invalid_limits.max_field_checks_per_domain = 0;
    assert_eq!(
        propose_record_schema_space(&messages, &[], invalid_limits),
        Err(RecordDiscoveryError::InvalidLimits)
    );

    let mut message_limited = proposal_limits(100_000);
    message_limited.discovery.max_messages = 2;
    assert_eq!(
        propose_record_schema_space(&messages, &[], message_limited),
        Err(RecordDiscoveryError::TooManyMessages {
            count: messages.len(),
            maximum: 2,
        })
    );
    Ok(())
}

#[test]
fn complete_field_search_reports_every_clipped_layout_once() -> Result<(), Box<dyn Error>> {
    let make_message = |sequence: u16, payload_byte: u8| {
        let mut message = vec![0xa0, 0x31, 0x42];
        message.extend_from_slice(&sequence.to_le_bytes());
        message.extend_from_slice(&3_u32.to_be_bytes());
        message.extend_from_slice(&[payload_byte; 3]);
        message
    };
    let first = make_message(1, b'a');
    let second = make_message(2, b'b');
    let third = make_message(3, b'c');
    let messages = [first.as_slice(), second.as_slice(), third.as_slice()];
    let mut limits = proposal_limits(100_000);
    limits.max_field_offset = 9;
    limits.max_field_checks_per_domain = 10_000;
    limits.discovery.record_limits.max_identifier_bytes = 4;

    let report = propose_record_schema_space(&messages, &[], limits)?;
    let space = report
        .candidate_space
        .as_ref()
        .ok_or("expected a structurally plausible candidate space")?;

    assert!(space.identifier_fields.contains(&ByteField {
        offset: 1,
        width: 2,
    }));
    assert_eq!(report.examined_field_checks, 97);
    assert_eq!(report.omitted_field_checks, 0);
    Ok(())
}

#[test]
fn field_search_clips_offsets_and_widths_to_the_shortest_message() -> Result<(), Box<dyn Error>> {
    let first = [0_u8, 1];
    let second = [2_u8, 3];
    let messages = [first.as_slice(), second.as_slice()];
    let mut limits = proposal_limits(1);
    limits.max_field_offset = usize::MAX;
    limits.max_field_checks_per_domain = 10;
    limits.discovery.record_limits.max_identifier_bytes = 4;

    let report = propose_record_schema_space(&messages, &[], limits)?;

    // Three byte layouts and four endian-aware integer layouts fit these messages
    assert_eq!(report.examined_field_checks, 7);
    assert_eq!(report.omitted_field_checks, 0);
    Ok(())
}

#[test]
fn bounded_identifier_search_reaches_later_offsets_before_wide_fields() -> Result<(), Box<dyn Error>>
{
    let make_message = |prefix: u8, sequence: u16, payload_byte: u8| {
        let payload_length = 1_190_usize;
        let mut message = Vec::with_capacity(1_200);
        message.push(prefix);
        message.extend_from_slice(b"\xa1\xb2\xc3");
        message.extend_from_slice(&sequence.to_le_bytes());
        message.extend_from_slice(
            &u32::try_from(payload_length)
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        message.resize(1_200, payload_byte);
        message
    };
    let first = make_message(0x10, 1, b'a');
    let second = make_message(0x20, 2, b'b');
    let third = make_message(0x30, 3, b'c');
    let messages = [first.as_slice(), second.as_slice(), third.as_slice()];
    let limits = RecordSchemaProposalLimits::default();

    let report = propose_record_schema_space(&messages, &[], limits)?;
    let repeated = propose_record_schema_space(&messages, &[], limits)?;
    let space = report
        .candidate_space
        .as_ref()
        .ok_or("expected the later identifier layout to produce a candidate space")?;

    assert_eq!(report, repeated);
    assert!(space.identifier_fields.contains(&ByteField {
        offset: 1,
        width: 3,
    }));
    // 1,024 byte layouts and all 112 integer layouts fit the existing per-domain budgets
    assert_eq!(report.examined_field_checks, 1_136);
    assert_eq!(report.omitted_field_checks, 18_056);
    assert!(!report.search_exhaustive_within_plan);
    Ok(())
}

#[test]
fn bounded_length_search_reaches_later_header_fields_and_keeps_earlier_fields()
-> Result<(), Box<dyn Error>> {
    let make_message = |sequence: u16, payload_byte: u8| {
        let mut message = Vec::with_capacity(24);
        message.push(23);
        message.extend_from_slice(b"id!");
        message.extend_from_slice(&sequence.to_le_bytes());
        message.push(0x7e);
        message.extend_from_slice(&15_u16.to_be_bytes());
        for _ in 0..15 {
            message.push(payload_byte);
        }
        message
    };
    let first = make_message(1, b'a');
    let second = make_message(2, b'b');
    let third = make_message(3, b'c');
    let messages = [first.as_slice(), second.as_slice(), third.as_slice()];
    let limits = RecordSchemaProposalLimits {
        max_length_checks: 1_024,
        ..RecordSchemaProposalLimits::default()
    };
    let report = propose_record_schema_space(&messages, &[], limits)?;

    let space = report
        .candidate_space
        .as_ref()
        .ok_or("expected a structurally plausible candidate space")?;
    assert!(space.length_fields.contains(&IntegerField {
        offset: 0,
        width: 1,
        byte_order: ByteOrder::BigEndian,
    }));
    assert!(space.length_fields.contains(&IntegerField {
        offset: 7,
        width: 2,
        byte_order: ByteOrder::BigEndian,
    }));
    assert!(space.data_offsets.contains(&1));
    assert!(space.data_offsets.contains(&9));
    assert!(
        space
            .length_meanings
            .contains(&RecordLengthMeaning::PayloadBytes)
    );
    assert_eq!(report.examined_length_checks, 1_024);
    assert_eq!(report.omitted_length_checks, 650);
    assert!(!report.search_exhaustive_within_plan);
    Ok(())
}

#[test]
fn length_search_reports_exact_and_omitted_checks_at_its_budget_boundary()
-> Result<(), Box<dyn Error>> {
    let first = [0, 0, 0];
    let second = [0, 0, 1];
    let messages = [first.as_slice(), second.as_slice()];
    let mut exact_limits = proposal_limits(100_000);
    exact_limits.max_field_offset = 2;
    exact_limits.max_length_checks = 15;
    let exact = propose_record_schema_space(&messages, &[], exact_limits)?;

    assert_eq!(exact.examined_length_checks, 15);
    assert_eq!(exact.omitted_length_checks, 0);
    assert!(exact.search_exhaustive_within_plan);

    let mut bounded_limits = exact_limits;
    bounded_limits.max_length_checks = 14;
    let bounded = propose_record_schema_space(&messages, &[], bounded_limits)?;

    assert_eq!(bounded.examined_length_checks, 14);
    assert_eq!(bounded.omitted_length_checks, 1);
    assert!(!bounded.search_exhaustive_within_plan);
    Ok(())
}

#[test]
fn skips_length_search_when_no_sequence_pair_can_form_a_schema() -> Result<(), Box<dyn Error>> {
    let message = [0_u8; 24];
    let report = propose_record_schema_space(
        &[message.as_slice()],
        &[],
        RecordSchemaProposalLimits::default(),
    )?;

    assert!(report.candidate_space.is_none());
    assert_eq!(report.examined_pair_checks, 0);
    assert_eq!(report.examined_length_checks, 0);
    assert_eq!(report.omitted_length_checks, 0);
    assert!(report.search_exhaustive_within_plan);
    Ok(())
}

#[test]
fn bounded_discovery_reaches_a_supported_later_schema_with_exact_accounting()
-> Result<(), Box<dyn Error>> {
    let first = bounded_search_message(4, 3);
    let second = bounded_search_message(5, 9);
    let third = bounded_search_message(6, 4);
    let fourth = bounded_search_message(7, 8);
    let training = [
        first.as_slice(),
        second.as_slice(),
        third.as_slice(),
        fourth.as_slice(),
    ];
    let limits = proposal_limits(1_024);
    let analysis = analyze_record_schemas(&training, &[], limits)?;
    let proposal = &analysis.proposal;
    let space = proposal
        .candidate_space
        .as_ref()
        .ok_or("expected a structurally plausible candidate space")?;
    let expected = bounded_search_schema();
    assert!(space.identifier_fields.contains(&expected.identifier));
    assert!(space.sequence_fields.contains(&expected.sequence));
    assert!(space.length_fields.contains(&expected.length));
    assert!(space.data_offsets.contains(&expected.data_offset));
    assert!(space.length_meanings.contains(&expected.length_meaning));

    let projected_combinations = projected_candidate_count(space)
        .ok_or("projected combination count should fit in usize")?;
    assert!(projected_combinations > limits.discovery.max_candidates);
    let cartesian = discover_record_schemas(&training, &[], space, limits.discovery)?;
    assert!(
        cartesian
            .surviving
            .iter()
            .all(|candidate| candidate.schema != expected)
    );
    assert_eq!(
        cartesian.candidate_combinations,
        Some(projected_combinations)
    );
    assert_eq!(
        cartesian.examined_combinations,
        limits.discovery.max_candidates
    );
    assert_eq!(
        cartesian.unexamined_combinations,
        Some(projected_combinations - cartesian.examined_combinations)
    );

    let report = analysis
        .discovery
        .as_ref()
        .ok_or("expected strict discovery results")?;
    assert!(
        report
            .surviving
            .iter()
            .any(|candidate| candidate.schema == expected),
        "the bounded search must reach the supported later schema"
    );
    let candidate_combinations = report
        .candidate_combinations
        .ok_or("candidate combination count should fit in usize")?;
    assert_eq!(
        report.examined_combinations,
        limits.discovery.max_candidates
    );
    assert_eq!(
        report.unexamined_combinations,
        Some(candidate_combinations - report.examined_combinations)
    );
    assert!(!report.search_exhaustive_within_plan);
    Ok(())
}

#[test]
fn bounded_discovery_reaches_a_compact_layout_with_interleaved_identifiers()
-> Result<(), Box<dyn Error>> {
    let messages = [
        interleaved_search_message(*b"\x19\x82", 0, 17),
        interleaved_search_message(*b"\x70\x03", 0, 17),
        interleaved_search_message(*b"\x19\x82", 1, 18),
        interleaved_search_message(*b"\x70\x03", 1, 18),
        interleaved_search_message(*b"\x19\x82", 256, 37),
        interleaved_search_message(*b"\x70\x03", 256, 37),
    ];
    let training = messages.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let limits = proposal_limits(1_024);

    let analysis = analyze_record_schemas(&training, &[], limits)?;
    let report = analysis
        .discovery
        .ok_or("expected strict discovery results")?;
    let expected = bounded_search_schema();

    assert!(
        report
            .surviving
            .iter()
            .any(|candidate| candidate.schema == expected),
        "a compact non-overlapping layout must remain reachable within the bounded traversal"
    );
    Ok(())
}
