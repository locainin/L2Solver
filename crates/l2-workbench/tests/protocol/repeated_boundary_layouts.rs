use l2_workbench::protocol::{
    ByteField, ByteOrder, IntegerField, RecordBoundaryCue, RecordCount, RecordInput,
    RecordLengthMeaning, RecordLimits, RecordSchema, RecordSchemaProposalLimits, RecordWorkBudget,
    analyze_record_inputs_with_repeated_boundaries_and_offsets,
    analyze_record_schemas_with_repeated_boundaries, parse_records_with_limits,
};
use std::collections::BTreeSet;

fn bounded_limits() -> RecordSchemaProposalLimits {
    // Keep field and pair limits at production defaults while covering this small length domain
    RecordSchemaProposalLimits {
        max_length_checks: 20_000,
        ..RecordSchemaProposalLimits::default()
    }
}

fn repeated_record(sequence: u16) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(&[0x02, 0xa4]);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&4_u16.to_le_bytes());
    bytes.extend_from_slice(&[0x02, 0x91]);
    bytes.extend_from_slice(&[0x38, 0x02, 0x55, 0x66]);
    bytes
}

fn repeated_message(first_sequence: u16) -> Vec<u8> {
    [
        repeated_record(first_sequence),
        repeated_record(first_sequence + 0x0100),
    ]
    .concat()
}

const fn expected_schema() -> RecordSchema {
    RecordSchema {
        records_offset: 0,
        count: RecordCount::UntilEnd,
        identifier: ByteField {
            offset: 0,
            width: 2,
        },
        sequence: IntegerField {
            offset: 2,
            width: 2,
            byte_order: ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 4,
            width: 2,
            byte_order: ByteOrder::LittleEndian,
        },
        data_offset: 8,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: None,
    }
}

const fn competing_short_schema() -> RecordSchema {
    RecordSchema {
        records_offset: 0,
        count: RecordCount::UntilEnd,
        identifier: ByteField {
            offset: 1,
            width: 1,
        },
        sequence: IntegerField {
            offset: 2,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 0,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        data_offset: 3,
        length_meaning: RecordLengthMeaning::BytesAfterLengthField,
        sequence_base: 0,
        terminal_sequence: None,
    }
}

fn cue_lengths(cues: &[RecordBoundaryCue]) -> BTreeSet<usize> {
    cues.iter()
        .map(|cue| cue.range.end - cue.range.start)
        .collect()
}

#[test]
fn competing_accepted_length_layout_does_not_hide_the_valid_header_layout()
-> Result<(), Box<dyn std::error::Error>> {
    let training_owned = [
        repeated_message(0x0102),
        repeated_message(0x0302),
        repeated_message(0x0502),
        repeated_message(0x0702),
    ];
    let held_out_owned = [repeated_message(0x0902), repeated_message(0x0b02)];
    let training = training_owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let held_out = held_out_owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let expected = expected_schema();
    let competing = competing_short_schema();

    for message in training.iter().chain(&held_out) {
        let parsed = parse_records_with_limits(message, &expected, RecordLimits::default())?;
        assert_eq!(parsed.records().len(), 2, "the declared layout is valid");
        let competing_parsed =
            parse_records_with_limits(message, &competing, RecordLimits::default())?;
        assert_eq!(
            competing_parsed.records().len(),
            8,
            "the independent short layout should parse the complete message"
        );
    }

    let analysis =
        analyze_record_schemas_with_repeated_boundaries(&training, &held_out, bounded_limits())?;
    let repeated = analysis
        .repeated_boundaries
        .as_ref()
        .ok_or("repeated-boundary analysis should be present")?;
    let proposal = &repeated.proposal;
    let candidate_space = proposal
        .candidate_space
        .as_ref()
        .ok_or("accepted length layouts should produce a candidate space")?;
    let lengths = cue_lengths(&proposal.repeated_boundary_cues);

    assert!(candidate_space.length_fields.contains(&expected.length));
    assert!(candidate_space.data_offsets.contains(&expected.data_offset));
    assert!(
        lengths.contains(&3),
        "the competing short layout should be observed"
    );
    assert!(
        lengths.contains(&12),
        "the valid layout boundaries should be observed"
    );
    assert_eq!(proposal.omitted_length_checks, 0);
    assert!(!proposal.work_limit_reached);
    let discovery = repeated
        .discovery
        .as_ref()
        .ok_or("strict discovery should run after bounded length checks")?;
    assert!(
        discovery
            .surviving
            .iter()
            .any(|candidate| candidate.schema == expected),
        "the valid schema should survive even when another accepted length layout adds shorter views; sequence fields={:?}, view lengths={lengths:?}",
        candidate_space.sequence_fields,
    );
    Ok(())
}

#[test]
fn work_limit_reports_current_and_later_unprocessed_layout_views()
-> Result<(), Box<dyn std::error::Error>> {
    let training_owned = [
        repeated_message(0x0102),
        repeated_message(0x0302),
        repeated_message(0x0502),
        repeated_message(0x0702),
    ];
    let inputs = training_owned
        .iter()
        .map(|bytes| RecordInput::new(bytes))
        .collect::<Vec<_>>();
    let input_refs = inputs.iter().collect::<Vec<_>>();
    let mut budget = RecordWorkBudget::new(709_000);
    let report = analyze_record_inputs_with_repeated_boundaries_and_offsets(
        &input_refs,
        &[],
        bounded_limits(),
        &[],
        &mut budget,
    )?;
    let repeated = report
        .repeated_boundaries
        .ok_or("repeated analysis should be present")?;
    let proposal = repeated.proposal;
    let lengths = cue_lengths(&proposal.repeated_boundary_cues);

    assert!(lengths.contains(&3));
    assert!(lengths.contains(&6));
    assert!(lengths.contains(&12));
    assert_eq!(proposal.omitted_length_checks, 0);
    assert!(proposal.work_limit_reached);
    assert!(!proposal.search_exhaustive_within_plan);
    // The accepted partitions use distinct spans here, so every cue is one pending view
    assert_eq!(
        proposal.omitted_record_views,
        proposal.repeated_boundary_cues.len(),
        "each distinct cue range belongs to one unprocessed layout here"
    );
    Ok(())
}
