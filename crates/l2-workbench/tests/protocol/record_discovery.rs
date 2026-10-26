use l2_workbench::protocol::{
    ByteField, ByteOrder, IntegerField, RecordCount, RecordDiscoveryError, RecordDiscoveryLimits,
    RecordDiscoveryValidationBasis, RecordError, RecordLengthMeaning, RecordLimits,
    RecordSchemaDiscoverySpace, discover_record_schemas,
};
use std::error::Error;

fn discovery_space(
    identifiers: Vec<ByteField>,
    sequences: Vec<IntegerField>,
    lengths: Vec<IntegerField>,
    data_offsets: Vec<usize>,
) -> RecordSchemaDiscoverySpace {
    RecordSchemaDiscoverySpace {
        identifier_fields: identifiers,
        sequence_fields: sequences,
        length_fields: lengths,
        records_offsets: vec![0],
        counts: vec![RecordCount::Exact { records: 1 }],
        data_offsets,
        length_meanings: vec![RecordLengthMeaning::PayloadBytes],
        sequence_base: 0,
    }
}

fn append_list(bytes: &mut Vec<u8>, sequences: &[u8]) {
    bytes.extend_from_slice(&[0xa7, 0xe1]);
    for sequence in sequences {
        push_record(bytes, b"R1", *sequence, &[*sequence]);
    }
}

fn list_space() -> RecordSchemaDiscoverySpace {
    let mut space = byte_sequence_space(
        vec![ByteField {
            offset: 0,
            width: 2,
        }],
        vec![ByteOrder::BigEndian],
    );
    space.records_offsets = vec![0, 2];
    space.counts = vec![RecordCount::Exact { records: 2 }, RecordCount::UntilEnd];
    space.sequence_base = 10;
    space
}

fn discovery_limits(max_candidates: usize) -> RecordDiscoveryLimits {
    RecordDiscoveryLimits {
        max_candidates,
        max_messages: 16,
        max_survivors: 16,
        max_falsifications: 16,
        record_limits: RecordLimits::default(),
    }
}

fn push_record(bytes: &mut Vec<u8>, identifier: &[u8], sequence: u8, payload: &[u8]) {
    bytes.extend_from_slice(identifier);
    bytes.push(sequence);
    bytes.push(u8::try_from(payload.len()).unwrap_or(u8::MAX));
    bytes.extend_from_slice(payload);
}

fn byte_sequence_space(
    identifiers: Vec<ByteField>,
    sequence_orders: Vec<ByteOrder>,
) -> RecordSchemaDiscoverySpace {
    discovery_space(
        identifiers,
        sequence_orders
            .into_iter()
            .map(|byte_order| IntegerField {
                offset: 2,
                width: 1,
                byte_order,
            })
            .collect(),
        vec![IntegerField {
            offset: 3,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        }],
        vec![4],
    )
}

#[test]
fn parses_individual_messages_with_interleaved_identifiers() -> Result<(), Box<dyn Error>> {
    let mut first = Vec::new();
    push_record(&mut first, b"A1", 0, b"a0");
    let mut second = Vec::new();
    push_record(&mut second, b"B2", 1, b"b1");
    let mut third = Vec::new();
    push_record(&mut third, b"A1", 1, b"a1");
    let mut fourth = Vec::new();
    push_record(&mut fourth, b"B2", 2, b"b2");
    let mut held_out = Vec::new();
    push_record(&mut held_out, b"A1", 2, b"a2");
    let space = byte_sequence_space(
        vec![ByteField {
            offset: 0,
            width: 2,
        }],
        vec![ByteOrder::BigEndian],
    );

    let report = discover_record_schemas(
        &[&first, &second, &third, &fourth],
        &[&held_out],
        &space,
        discovery_limits(8),
    )?;

    let [hypothesis] = report.surviving.as_slice() else {
        return Err("expected one surviving schema".into());
    };
    assert_eq!(hypothesis.training_message_count, 4);
    assert_eq!(hypothesis.held_out_message_count, 1);
    assert_eq!(hypothesis.training_record_count, 4);
    assert_eq!(hypothesis.held_out_record_count, 1);
    assert_eq!(hypothesis.schema.terminal_sequence, None);
    assert_eq!(report.falsified_count, 0);
    assert_eq!(report.unexamined_combinations, Some(0));
    assert!(report.search_exhaustive_within_plan);
    assert!(report.report_details_complete);
    Ok(())
}

#[test]
fn one_message_with_repeated_records_can_produce_training_only_schema_evidence()
-> Result<(), Box<dyn Error>> {
    let mut message = Vec::new();
    push_record(&mut message, b"A1", 0, b"first");
    push_record(&mut message, b"A1", 1, b"second");
    let space = RecordSchemaDiscoverySpace {
        identifier_fields: vec![ByteField {
            offset: 0,
            width: 2,
        }],
        sequence_fields: vec![IntegerField {
            offset: 2,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        }],
        length_fields: vec![IntegerField {
            offset: 3,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        }],
        records_offsets: vec![0],
        counts: vec![RecordCount::UntilEnd],
        data_offsets: vec![4],
        length_meanings: vec![RecordLengthMeaning::PayloadBytes],
        sequence_base: 0,
    };

    let report = discover_record_schemas(&[message.as_slice()], &[], &space, discovery_limits(8))?;

    assert_eq!(
        report.validation_basis,
        RecordDiscoveryValidationBasis::TrainingOnly
    );
    assert_eq!(report.surviving.len(), 1);
    let hypothesis = report
        .surviving
        .first()
        .ok_or("expected one schema hypothesis")?;
    assert_eq!(hypothesis.training_message_count, 1);
    assert_eq!(hypothesis.training_record_count, 2);
    assert_eq!(hypothesis.held_out_message_count, 0);
    Ok(())
}

#[test]
fn retains_ambiguous_fields() -> Result<(), Box<dyn Error>> {
    let mut first = Vec::new();
    push_record(&mut first, b"A1", 0, b"one");
    let mut second = Vec::new();
    push_record(&mut second, b"B2", 1, b"two");
    let held_out = second.clone();
    let space = byte_sequence_space(
        vec![
            ByteField {
                offset: 0,
                width: 1,
            },
            ByteField {
                offset: 0,
                width: 2,
            },
        ],
        vec![ByteOrder::BigEndian],
    );

    let report = discover_record_schemas(
        &[&first, &second],
        &[&held_out],
        &space,
        discovery_limits(8),
    )?;

    assert_eq!(report.surviving.len(), 2);
    assert_eq!(
        report
            .surviving
            .iter()
            .map(|hypothesis| hypothesis.schema.identifier.width)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    Ok(())
}

#[test]
fn reports_training_only_validation() -> Result<(), Box<dyn Error>> {
    let mut first = Vec::new();
    push_record(&mut first, b"A1", 0, b"one");
    let mut second = Vec::new();
    push_record(&mut second, b"B2", 1, b"two");
    let space = byte_sequence_space(
        vec![
            ByteField {
                offset: 0,
                width: 1,
            },
            ByteField {
                offset: 0,
                width: 2,
            },
        ],
        vec![ByteOrder::BigEndian],
    );

    let report = discover_record_schemas(&[&first, &second], &[], &space, discovery_limits(8))?;

    assert_eq!(
        report.validation_basis,
        RecordDiscoveryValidationBasis::TrainingOnly
    );
    assert_eq!(report.surviving.len(), 2);
    assert!(
        report
            .surviving
            .iter()
            .all(|hypothesis| hypothesis.held_out_message_count == 0)
    );
    Ok(())
}

#[test]
fn keeps_endian_alternatives() -> Result<(), Box<dyn Error>> {
    fn push_wide_record(bytes: &mut Vec<u8>, sequence: u16) {
        bytes.extend_from_slice(b"ID");
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.push(1);
        bytes.push(b'x');
    }

    let mut first = Vec::new();
    push_wide_record(&mut first, 1);
    let mut second = Vec::new();
    push_wide_record(&mut second, 2);
    let held_out = second.clone();
    let space = discovery_space(
        vec![ByteField {
            offset: 0,
            width: 2,
        }],
        [ByteOrder::BigEndian, ByteOrder::LittleEndian]
            .into_iter()
            .map(|byte_order| IntegerField {
                offset: 2,
                width: 2,
                byte_order,
            })
            .collect(),
        vec![IntegerField {
            offset: 4,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        }],
        vec![5],
    );

    let report = discover_record_schemas(
        &[&first, &second],
        &[&held_out],
        &space,
        discovery_limits(8),
    )?;

    assert_eq!(report.surviving.len(), 2);
    let byte_orders = report
        .surviving
        .iter()
        .map(|hypothesis| hypothesis.schema.sequence.byte_order)
        .collect::<Vec<_>>();
    assert_eq!(
        byte_orders,
        vec![ByteOrder::BigEndian, ByteOrder::LittleEndian]
    );
    assert!(report.surviving.iter().all(|hypothesis| {
        hypothesis.training_record_count == 2 && hypothesis.held_out_record_count == 1
    }));
    assert!(
        report
            .surviving
            .iter()
            .all(|hypothesis| hypothesis.schema.terminal_sequence.is_none())
    );
    Ok(())
}

#[test]
fn rejects_truncated_records() -> Result<(), Box<dyn Error>> {
    let mut first = Vec::new();
    push_record(&mut first, b"A1", 0, b"valid");
    let mut truncated = Vec::new();
    truncated.extend_from_slice(b"A1");
    truncated.extend_from_slice(&[1, 3, b'x']);
    let held_out = first.clone();
    let space = byte_sequence_space(
        vec![ByteField {
            offset: 0,
            width: 2,
        }],
        vec![ByteOrder::BigEndian],
    );

    let report = discover_record_schemas(
        &[&first, &truncated],
        &[&held_out],
        &space,
        discovery_limits(8),
    )?;

    assert!(report.surviving.is_empty());
    assert_eq!(report.falsifications.len(), 1);
    let falsification = report
        .falsifications
        .first()
        .ok_or("missing truncation falsification")?;
    assert_eq!(falsification.message_index, 1);
    assert!(
        falsification
            .error
            .to_string()
            .contains("needs an end offset")
    );
    Ok(())
}

#[test]
fn rejects_heldout_contradictions() -> Result<(), Box<dyn Error>> {
    let mut first = Vec::new();
    push_record(&mut first, b"A1", 0, b"valid");
    let mut second = Vec::new();
    push_record(&mut second, b"A1", 1, b"valid");
    let mut held_out = Vec::new();
    held_out.extend_from_slice(b"A1");
    held_out.extend_from_slice(&[2, 2, b'x']);
    let space = byte_sequence_space(
        vec![ByteField {
            offset: 0,
            width: 2,
        }],
        vec![ByteOrder::BigEndian],
    );

    let report = discover_record_schemas(
        &[&first, &second],
        &[&held_out],
        &space,
        discovery_limits(8),
    )?;

    assert!(report.surviving.is_empty());
    assert_eq!(report.falsifications.len(), 1);
    let falsification = report
        .falsifications
        .first()
        .ok_or("missing held-out falsification")?;
    assert_eq!(falsification.partition.as_str(), "held_out");
    assert_eq!(falsification.message_index, 0);
    Ok(())
}

#[test]
fn rejects_trailing_record_bytes() -> Result<(), Box<dyn Error>> {
    let mut first = Vec::new();
    push_record(&mut first, b"A1", 0, b"one");
    let mut second = Vec::new();
    push_record(&mut second, b"A1", 1, b"two");
    let mut trailing = Vec::new();
    trailing.extend_from_slice(b"A1");
    trailing.extend_from_slice(&[2, 1, b'x', b'y']);
    let space = byte_sequence_space(
        vec![ByteField {
            offset: 0,
            width: 2,
        }],
        vec![ByteOrder::BigEndian],
    );

    let report = discover_record_schemas(
        &[&first, &second],
        &[&trailing],
        &space,
        discovery_limits(8),
    )?;

    let falsification = report
        .falsifications
        .first()
        .ok_or("missing trailing-byte falsification")?;
    assert_eq!(falsification.partition.as_str(), "held_out");
    assert!(matches!(
        falsification.error,
        RecordError::TrailingBytes { .. }
    ));
    Ok(())
}

#[test]
fn ignores_unlisted_false_magic() -> Result<(), Box<dyn Error>> {
    let mut first = vec![0xde, 0xad];
    push_record(&mut first, b"A1", 0, b"one");
    let mut second = vec![0xbe, 0xef];
    push_record(&mut second, b"A1", 1, b"two");
    let held_out = second.clone();
    let space = discovery_space(
        vec![ByteField {
            offset: 2,
            width: 2,
        }],
        vec![IntegerField {
            offset: 4,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        }],
        vec![IntegerField {
            offset: 5,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        }],
        vec![6],
    );

    let report = discover_record_schemas(
        &[&first, &second],
        &[&held_out],
        &space,
        discovery_limits(8),
    )?;

    assert_eq!(report.surviving.len(), 1);
    assert_eq!(report.candidate_combinations, Some(1));
    assert_eq!(
        report
            .surviving
            .first()
            .ok_or("missing schema hypothesis")?
            .schema
            .identifier
            .offset,
        2
    );
    Ok(())
}

#[test]
fn reports_candidate_budget() -> Result<(), Box<dyn Error>> {
    let mut first = Vec::new();
    push_record(&mut first, b"A1", 0, b"one");
    let mut second = Vec::new();
    push_record(&mut second, b"B2", 1, b"two");
    let held_out = second.clone();
    let space = byte_sequence_space(
        vec![
            ByteField {
                offset: 0,
                width: 1,
            },
            ByteField {
                offset: 0,
                width: 2,
            },
        ],
        vec![ByteOrder::BigEndian, ByteOrder::LittleEndian],
    );

    let report = discover_record_schemas(
        &[&first, &second],
        &[&held_out],
        &space,
        discovery_limits(2),
    )?;

    assert_eq!(report.examined_combinations, 2);
    assert_eq!(report.candidate_combinations, Some(4));
    assert_eq!(report.unexamined_combinations, Some(2));
    assert!(!report.search_exhaustive_within_plan);
    assert!(report.report_details_complete);
    Ok(())
}

#[test]
fn reports_falsification_omissions() -> Result<(), Box<dyn Error>> {
    let mut first = Vec::new();
    push_record(&mut first, b"A1", 0, b"one");
    let mut second = Vec::new();
    push_record(&mut second, b"B2", 1, b"two");
    let held_out = second.clone();
    let space = byte_sequence_space(
        vec![
            ByteField {
                offset: 0,
                width: 0,
            },
            ByteField {
                offset: 5,
                width: 1,
            },
        ],
        vec![ByteOrder::BigEndian],
    );
    let mut limits = discovery_limits(8);
    limits.max_falsifications = 1;

    let report = discover_record_schemas(&[&first, &second], &[&held_out], &space, limits)?;

    assert_eq!(report.falsified_count, 2);
    assert_eq!(report.falsifications.len(), 1);
    assert_eq!(report.omitted_falsification_examples, 1);
    assert!(report.search_exhaustive_within_plan);
    assert!(!report.report_details_complete);
    Ok(())
}

#[test]
fn reports_search_and_retention_incompleteness_independently() -> Result<(), Box<dyn Error>> {
    let mut first = Vec::new();
    push_record(&mut first, b"A1", 0, b"one");
    let mut second = Vec::new();
    push_record(&mut second, b"B2", 1, b"two");
    let space = byte_sequence_space(
        vec![
            ByteField {
                offset: 0,
                width: 1,
            },
            ByteField {
                offset: 0,
                width: 2,
            },
        ],
        vec![ByteOrder::BigEndian, ByteOrder::LittleEndian],
    );
    let mut limits = discovery_limits(3);
    limits.max_survivors = 1;

    let report = discover_record_schemas(&[&first, &second], &[], &space, limits)?;

    assert_eq!(report.candidate_combinations, Some(4));
    assert_eq!(report.examined_combinations, 3);
    assert_eq!(report.unexamined_combinations, Some(1));
    assert_eq!(report.omitted_survivors, 2);
    assert!(!report.search_exhaustive_within_plan);
    assert!(!report.report_details_complete);
    Ok(())
}

#[test]
fn counts_survivors_omitted_by_the_retention_limit() -> Result<(), Box<dyn Error>> {
    let mut first = Vec::new();
    push_record(&mut first, b"A1", 0, b"one");
    let mut second = Vec::new();
    push_record(&mut second, b"B2", 1, b"two");
    let space = byte_sequence_space(
        vec![
            ByteField {
                offset: 0,
                width: 1,
            },
            ByteField {
                offset: 0,
                width: 2,
            },
        ],
        vec![ByteOrder::BigEndian],
    );
    let mut limits = discovery_limits(8);
    limits.max_survivors = 1;

    let report = discover_record_schemas(&[&first, &second], &[], &space, limits)?;

    assert_eq!(report.surviving.len(), 1);
    assert_eq!(report.omitted_survivors, 1);
    assert!(report.search_exhaustive_within_plan);
    assert!(!report.report_details_complete);
    Ok(())
}

#[test]
fn finds_concatenated_lists() -> Result<(), Box<dyn Error>> {
    let mut first = Vec::new();
    append_list(&mut first, &[10, 12]);
    let mut second = Vec::new();
    append_list(&mut second, &[12, 14, 15]);
    let mut held_out = Vec::new();
    append_list(&mut held_out, &[13]);

    let report = discover_record_schemas(
        &[&first, &second],
        &[&held_out],
        &list_space(),
        discovery_limits(8),
    )?;

    let [hypothesis] = report.surviving.as_slice() else {
        return Err("expected one list schema".into());
    };
    assert_eq!(hypothesis.schema.records_offset, 2);
    assert_eq!(hypothesis.schema.count, RecordCount::UntilEnd);
    assert_eq!(
        report.validation_basis,
        RecordDiscoveryValidationBasis::HeldOutMessages
    );
    assert_eq!(report.candidate_combinations, Some(4));
    assert_eq!(report.examined_combinations, 4);
    assert_eq!(report.unexamined_combinations, Some(0));
    assert!(report.search_exhaustive_within_plan);
    assert!(report.report_details_complete);
    assert_eq!(report.falsified_count, 3);
    assert_eq!(hypothesis.training_record_count, 5);
    assert_eq!(hypothesis.held_out_record_count, 1);
    Ok(())
}

#[test]
fn finds_exact_lists() -> Result<(), Box<dyn Error>> {
    let mut first = Vec::new();
    append_list(&mut first, &[10, 12]);
    let mut second = Vec::new();
    append_list(&mut second, &[14, 15]);
    let held_out = second.clone();
    let mut space = list_space();
    space.records_offsets = vec![2];
    space.counts = vec![RecordCount::Exact { records: 2 }];

    let report = discover_record_schemas(
        &[&first, &second],
        &[&held_out],
        &space,
        discovery_limits(2),
    )?;

    let [hypothesis] = report.surviving.as_slice() else {
        return Err("expected one exact-count schema".into());
    };
    assert_eq!(hypothesis.schema.count, RecordCount::Exact { records: 2 });
    assert_eq!(hypothesis.training_record_count, 4);
    assert_eq!(hypothesis.held_out_record_count, 2);
    Ok(())
}

#[test]
fn same_identifier_and_sequence_values_across_conversations_remain_parse_counts()
-> Result<(), Box<dyn Error>> {
    let conversation_one_first = {
        let mut bytes = Vec::new();
        push_record(&mut bytes, b"A1", 0, b"a0");
        bytes
    };
    let conversation_one_second = {
        let mut bytes = Vec::new();
        push_record(&mut bytes, b"A1", 1, b"a1");
        bytes
    };
    let conversation_two_first = {
        let mut bytes = Vec::new();
        push_record(&mut bytes, b"A1", 0, b"b0");
        bytes
    };
    let conversation_two_second = {
        let mut bytes = Vec::new();
        push_record(&mut bytes, b"A1", 1, b"b1");
        bytes
    };
    let space = byte_sequence_space(
        vec![ByteField {
            offset: 0,
            width: 2,
        }],
        vec![ByteOrder::BigEndian],
    );

    let report = discover_record_schemas(
        &[
            &conversation_one_first,
            &conversation_one_second,
            &conversation_two_first,
            &conversation_two_second,
        ],
        &[],
        &space,
        discovery_limits(8),
    )?;

    let [hypothesis] = report.surviving.as_slice() else {
        return Err("expected the exact record layout to survive".into());
    };
    assert_eq!(hypothesis.training_message_count, 4);
    assert_eq!(hypothesis.training_record_count, 4);
    assert_eq!(hypothesis.held_out_record_count, 0);
    Ok(())
}

#[test]
fn enforces_aggregate_record_and_metadata_budgets_without_assembly() -> Result<(), Box<dyn Error>> {
    let mut first = Vec::new();
    append_list(&mut first, &[10, 11]);
    let mut second = Vec::new();
    append_list(&mut second, &[12, 13]);
    let mut space = list_space();
    space.records_offsets = vec![2];
    space.counts = vec![RecordCount::UntilEnd];

    let record_limits = RecordLimits {
        max_records: 3,
        ..RecordLimits::default()
    };
    let mut limits = discovery_limits(8);
    limits.record_limits = record_limits;
    assert!(matches!(
        discover_record_schemas(&[&first, &second], &[], &space, limits),
        Err(RecordDiscoveryError::RecordOperation(
            RecordError::TooManyRecords { maximum: 3, .. }
        ))
    ));

    let record_metadata_bytes = std::mem::size_of::<l2_workbench::protocol::ParsedRecord>()
        .checked_add(2)
        .ok_or("record metadata size overflowed")?;
    let aggregate_report_limit = record_metadata_bytes
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_sub(1))
        .ok_or("aggregate report limit overflowed")?;
    let mut report_limits = discovery_limits(8);
    report_limits.record_limits.max_report_bytes = aggregate_report_limit;
    assert!(matches!(
        discover_record_schemas(&[&first, &second], &[], &space, report_limits),
        Err(RecordDiscoveryError::RecordOperation(
            RecordError::ReportTooLarge { maximum, .. }
        )) if maximum == aggregate_report_limit
    ));
    Ok(())
}

#[test]
fn rejects_corrupted_lists() -> Result<(), Box<dyn Error>> {
    let mut first = Vec::new();
    append_list(&mut first, &[10, 12]);
    let mut second = Vec::new();
    append_list(&mut second, &[12, 14, 15]);
    let mut corrupted = Vec::new();
    append_list(&mut corrupted, &[10]);
    corrupted.extend_from_slice(b"R1");
    corrupted.extend_from_slice(&[11, 3, b'x']);

    let report = discover_record_schemas(
        &[&first, &second],
        &[&corrupted],
        &list_space(),
        discovery_limits(8),
    )?;

    assert!(report.surviving.is_empty());
    let falsification = report
        .falsifications
        .iter()
        .find(|item| item.schema.records_offset == 2 && item.schema.count == RecordCount::UntilEnd)
        .ok_or("missing list corruption finding")?;
    assert_eq!(falsification.partition.as_str(), "held_out");
    assert_eq!(falsification.message_index, 0);
    assert!(matches!(
        falsification.error,
        RecordError::TruncatedRecord { record: 1, .. }
    ));
    Ok(())
}

#[test]
fn reports_list_budget() -> Result<(), Box<dyn Error>> {
    let mut first = Vec::new();
    append_list(&mut first, &[10, 12]);
    let mut second = Vec::new();
    append_list(&mut second, &[12, 14, 15]);

    let report =
        discover_record_schemas(&[&first, &second], &[], &list_space(), discovery_limits(2))?;

    assert_eq!(report.candidate_combinations, Some(4));
    assert_eq!(report.examined_combinations, 2);
    assert_eq!(report.unexamined_combinations, Some(2));
    assert_eq!(report.falsified_count, 2);
    assert!(!report.search_exhaustive_within_plan);
    assert!(
        report
            .falsifications
            .iter()
            .all(|item| item.schema.records_offset == 0)
    );
    Ok(())
}

#[test]
fn rejects_empty_list_domains() {
    let space = list_space();
    let mut empty_offsets = space.clone();
    empty_offsets.records_offsets.clear();
    let mut empty_counts = space;
    empty_counts.counts.clear();

    assert!(matches!(
        discover_record_schemas(&[], &[], &empty_offsets, discovery_limits(8)),
        Err(RecordDiscoveryError::EmptyDomain {
            field: "records_offsets"
        })
    ));
    assert!(matches!(
        discover_record_schemas(&[], &[], &empty_counts, discovery_limits(8)),
        Err(RecordDiscoveryError::EmptyDomain { field: "counts" })
    ));

    let mut no_survivor_budget = discovery_limits(8);
    no_survivor_budget.max_survivors = 0;
    assert!(matches!(
        discover_record_schemas(&[], &[], &list_space(), no_survivor_budget),
        Err(RecordDiscoveryError::InvalidLimits)
    ));
}

#[test]
fn parser_resource_limits_leave_candidates_unresolved_instead_of_falsified()
-> Result<(), Box<dyn Error>> {
    let mut message = Vec::new();
    push_record(&mut message, b"R1", 0, b"x");
    let mut space = byte_sequence_space(
        vec![ByteField {
            offset: 0,
            width: 2,
        }],
        vec![ByteOrder::BigEndian],
    );
    space.counts = vec![RecordCount::Exact { records: 2 }];
    let mut limits = discovery_limits(1);
    limits.record_limits.max_records = 1;

    let too_many_records = discover_record_schemas(&[message.as_slice()], &[], &space, limits)?;
    assert_unresolved_resource_candidate(&too_many_records);

    space.counts = vec![RecordCount::Exact { records: 1 }];
    limits.record_limits.max_report_bytes = 1;
    let report_limit = discover_record_schemas(&[message.as_slice()], &[], &space, limits)?;
    assert_unresolved_resource_candidate(&report_limit);
    Ok(())
}

fn assert_unresolved_resource_candidate(
    report: &l2_workbench::protocol::RecordSchemaDiscoveryReport,
) {
    assert_eq!(report.resource_limited_candidates, 1);
    assert_eq!(report.examined_combinations, 0);
    assert_eq!(report.unexamined_combinations, Some(1));
    assert_eq!(report.falsified_count, 0);
    assert!(!report.search_exhaustive_within_plan);
    assert!(!report.report_details_complete);
}
