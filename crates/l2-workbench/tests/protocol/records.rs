use l2_workbench::protocol::{
    ByteField, ByteOrder, HeaderParseTemplate, IntegerField, RecordAssemblyInput, RecordCount,
    RecordError, RecordInput, RecordLengthMeaning, RecordLimits, RecordSchema,
    assemble_record_groups, assemble_record_groups_from_inputs, parse_records,
    parse_records_with_limits,
};
use std::error::Error;

const fn counted_payload_schema() -> RecordSchema {
    RecordSchema {
        records_offset: 1,
        count: RecordCount::Field {
            field: IntegerField {
                offset: 0,
                width: 1,
                byte_order: ByteOrder::BigEndian,
            },
        },
        identifier: ByteField {
            offset: 0,
            width: 2,
        },
        sequence: IntegerField {
            offset: 2,
            width: 4,
            byte_order: ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 6,
            width: 4,
            byte_order: ByteOrder::BigEndian,
        },
        data_offset: 10,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: None,
    }
}

fn schema_with_terminal_sequence(
    schema: &RecordSchema,
    terminal_sequence: u64,
) -> Result<RecordSchema, Box<dyn Error>> {
    let mut value = serde_json::to_value(schema)?;
    value
        .as_object_mut()
        .ok_or("record schema is not a JSON object")?
        .insert(
            "terminal_sequence".to_owned(),
            serde_json::json!(terminal_sequence),
        );
    Ok(serde_json::from_value(value)?)
}

fn push_counted_record(bytes: &mut Vec<u8>, identifier: &[u8], sequence: u32, data: &[u8]) {
    bytes.extend_from_slice(identifier);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_be_bytes());
    bytes.extend_from_slice(data);
}

fn explicit_record_case() -> Result<(Vec<u8>, RecordSchema), Box<dyn Error>> {
    let mut bytes = vec![3];
    push_counted_record(&mut bytes, b"A1", 0, b"first");
    push_counted_record(&mut bytes, b"B2", 0, b"other");
    push_counted_record(&mut bytes, b"A1", 1, b"second");
    let schema = schema_with_terminal_sequence(&counted_payload_schema(), 1)?;
    Ok((bytes, schema))
}

const fn one_record_header_schema() -> RecordSchema {
    RecordSchema {
        records_offset: 1,
        count: RecordCount::Field {
            field: IntegerField {
                offset: 0,
                width: 1,
                byte_order: ByteOrder::BigEndian,
            },
        },
        identifier: ByteField {
            offset: 0,
            width: 1,
        },
        sequence: IntegerField {
            offset: 1,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 2,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        data_offset: 3,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: None,
    }
}

fn one_record_frame(
    identifier: u8,
    sequence: u8,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let payload_length = u8::try_from(payload.len())?;
    let mut bytes = Vec::with_capacity(4_usize.saturating_add(payload.len()));
    bytes.extend_from_slice(&[1, identifier, sequence, payload_length]);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn template_for(bytes: &[u8], header_end: usize) -> Result<HeaderParseTemplate, Box<dyn Error>> {
    let limits = RecordLimits::default();
    let input = RecordInput::new(bytes);
    let parsed = input.parse(&one_record_header_schema(), limits)?;
    Ok(parsed
        .header_only_template(&input, header_end, limits)?
        .ok_or("canonical one-record report did not produce a header template")?)
}

#[test]
fn header_template_rebinds_changed_payload_and_assembly_uses_fresh_identity()
-> Result<(), Box<dyn Error>> {
    let limits = RecordLimits::default();
    let schema = one_record_header_schema();
    let original_bytes = one_record_frame(b'X', 0, b"old")?;
    let changed_bytes = one_record_frame(b'X', 0, b"new")?;
    let original_input = RecordInput::new(&original_bytes);
    let original_report = original_input.parse(&schema, limits)?;
    let template = original_report
        .header_only_template(&original_input, 4, limits)?
        .ok_or("header-only schema was not admitted")?;
    let changed_input = RecordInput::new(&changed_bytes);

    let rebound = template.rebind(&changed_input, limits)?;

    assert_eq!(rebound.schema(), &schema);
    assert_eq!(rebound.records(), original_report.records());
    assert_eq!(rebound.input_length(), changed_bytes.len());
    assert_eq!(rebound.input_sha256(), l2_workbench::sha256(&changed_bytes));
    assert_ne!(rebound.input_sha256(), original_report.input_sha256());

    let assembly_input = RecordAssemblyInput::from_input(&changed_input, &rebound)?;
    let assembled = assemble_record_groups_from_inputs(&[assembly_input], limits)?;
    let group = assembled
        .group(b"X")
        .ok_or("rebound record group is missing")?;
    assert_eq!(group.candidate_bytes(), b"new");
    Ok(())
}

#[test]
fn header_template_rejects_changed_header_and_encoded_fields() -> Result<(), Box<dyn Error>> {
    let limits = RecordLimits::default();
    let original_bytes = one_record_frame(b'X', 0, b"old")?;
    let template = template_for(&original_bytes, 4)?;
    let changed_identifier = one_record_frame(b'Y', 0, b"old")?;
    let changed_sequence = one_record_frame(b'X', 1, b"old")?;
    let changed_length = one_record_frame(b'X', 0, b"long")?;

    for changed_bytes in [changed_identifier, changed_sequence, changed_length] {
        let input = RecordInput::new(&changed_bytes);
        assert!(template.rebind(&input, limits).is_err());
    }
    Ok(())
}

#[test]
fn header_template_rejects_changed_count_and_limits() -> Result<(), Box<dyn Error>> {
    let limits = RecordLimits::default();
    let original_bytes = one_record_frame(b'X', 0, b"old")?;
    let template = template_for(&original_bytes, 4)?;
    let mut changed_count = original_bytes.clone();
    *changed_count.get_mut(0).ok_or("count field is missing")? = 2;
    let changed_count_input = RecordInput::new(&changed_count);
    assert!(template.rebind(&changed_count_input, limits).is_err());

    let unchanged_input = RecordInput::new(&original_bytes);
    let changed_limits = RecordLimits {
        max_issue_examples: limits.max_issue_examples.saturating_sub(1),
        ..limits
    };
    assert!(template.rebind(&unchanged_input, changed_limits).is_err());
    Ok(())
}

#[test]
fn header_template_creation_enforces_all_canonical_record_limits() -> Result<(), Box<dyn Error>> {
    let limits = RecordLimits::default();
    let bytes = one_record_frame(b'X', 0, b"old")?;
    let input = RecordInput::new(&bytes);
    let report = input.parse(&one_record_header_schema(), limits)?;

    let zero_group_limit = RecordLimits {
        max_groups: 0,
        ..limits
    };
    assert!(matches!(
        report.header_only_template(&input, 4, zero_group_limit),
        Err(l2_workbench::protocol::RecordError::InvalidLimits)
    ));

    let tight_input_limit = RecordLimits {
        max_input_bytes: bytes.len().saturating_sub(1),
        ..limits
    };
    assert!(matches!(
        report.header_only_template(&input, 4, tight_input_limit),
        Err(l2_workbench::protocol::RecordError::InputTooLarge { .. })
    ));

    let tight_metadata_limit = RecordLimits {
        max_report_bytes: report.metadata_bytes().saturating_sub(1),
        ..limits
    };
    assert!(matches!(
        report.header_only_template(&input, 4, tight_metadata_limit),
        Err(l2_workbench::protocol::RecordError::ReportTooLarge { .. })
    ));

    let wide_bytes = [1, b'X', b'Y', 0, 2, b'a', b'b'];
    let mut wide_schema = one_record_header_schema();
    wide_schema.identifier.width = 2;
    wide_schema.sequence.offset = 2;
    wide_schema.length.offset = 3;
    wide_schema.data_offset = 4;
    let wide_input = RecordInput::new(&wide_bytes);
    let wide_report = wide_input.parse(&wide_schema, limits)?;
    let tight_identifier_limit = RecordLimits {
        max_identifier_bytes: 1,
        ..limits
    };
    assert!(matches!(
        wide_report.header_only_template(&wide_input, 5, tight_identifier_limit),
        Err(l2_workbench::protocol::RecordError::IdentifierTooLarge {
            width: 2,
            maximum: 1
        })
    ));
    Ok(())
}

#[test]
fn header_template_is_not_created_for_multiple_records_or_body_fields() -> Result<(), Box<dyn Error>>
{
    let limits = RecordLimits::default();
    let first = one_record_frame(b'X', 0, b"a")?;
    let second = one_record_frame(b'X', 1, b"b")?;
    let mut multi_record_bytes = vec![2];
    multi_record_bytes.extend_from_slice(first.get(1..).ok_or("first count field is missing")?);
    multi_record_bytes.extend_from_slice(second.get(1..).ok_or("second count field is missing")?);
    let multi_record_schema = one_record_header_schema();
    let multi_record_input = RecordInput::new(&multi_record_bytes);
    let multi_record_report = multi_record_input.parse(&multi_record_schema, limits)?;
    assert!(
        multi_record_report
            .header_only_template(&multi_record_input, 4, limits)?
            .is_none()
    );

    let bytes = [1, b'X', 0, 2, 0, b'a', b'b'];
    let mut body_schema = one_record_header_schema();
    body_schema.data_offset = 4;
    let input = RecordInput::new(&bytes);
    let report = input.parse(&body_schema, limits)?;
    assert!(report.header_only_template(&input, 4, limits)?.is_none());
    Ok(())
}

#[test]
fn parses_explicit_records() -> Result<(), Box<dyn Error>> {
    let (bytes, schema) = explicit_record_case()?;
    let parsed = parse_records(&bytes, &schema)?;
    assert_eq!(parsed.declared_count(), Some(3));
    assert_eq!(parsed.records().len(), 3);
    let first_record = parsed.records().first().ok_or("missing first record")?;
    assert_eq!(first_record.record.start, 1);
    assert_eq!(first_record.payload.start, 11);
    assert_eq!(first_record.identifier, b"A1");
    assert_eq!(first_record.sequence, 0);
    assert_eq!(parsed.input_sha256(), l2_workbench::sha256(&bytes));
    Ok(())
}

#[test]
fn assembles_complete_group() -> Result<(), Box<dyn Error>> {
    let (bytes, schema) = explicit_record_case()?;
    let parsed = parse_records(&bytes, &schema)?;
    let assembled = assemble_record_groups(&bytes, &parsed, RecordLimits::default())?;
    let first = assembled.group(b"A1").ok_or("missing first record group")?;
    let second = assembled
        .group(b"B2")
        .ok_or("missing second record group")?;
    assert!(first.receipt().complete);
    assert_eq!(first.receipt().record_count, 2);
    assert_eq!(first.bytes(), Some(&b"firstsecond"[..]));
    assert!(first.receipt().output_sha256.is_some());
    let [first_part, second_part] = first.receipt().parts.as_slice() else {
        return Err("expected two exact assembly mappings".into());
    };
    assert_eq!(first_part.record_index, 0);
    assert_eq!(first_part.sequence, 0);
    assert_eq!(first_part.input.start, 11);
    assert_eq!(first_part.output.start, 0);
    assert_eq!(first_part.output.end, 5);
    assert_eq!(second_part.record_index, 2);
    assert_eq!(second_part.sequence, 1);
    assert_eq!(second_part.output.start, 5);
    assert_eq!(second_part.output.end, 11);
    assert!(!second.receipt().complete);
    assert_eq!(second.bytes(), None);
    assert_eq!(second.candidate_bytes(), &b"other"[..]);
    Ok(())
}

#[test]
fn reports_explicit_groups() -> Result<(), Box<dyn Error>> {
    let (bytes, schema) = explicit_record_case()?;
    let parsed = parse_records(&bytes, &schema)?;
    let assembled = assemble_record_groups(&bytes, &parsed, RecordLimits::default())?;
    let report: serde_json::Value = serde_json::to_value(assembled.report())?;
    assert_eq!(report.get("terminal_sequence"), Some(&serde_json::json!(1)));
    assert_eq!(
        report
            .get("groups")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    Ok(())
}

#[test]
fn observed_contiguous_without_sequence_candidate() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![2];
    push_counted_record(&mut bytes, b"A1", 0, b"first");
    push_counted_record(&mut bytes, b"A1", 1, b"second");
    let schema = counted_payload_schema();
    let parsed = parse_records(&bytes, &schema)?;

    let assembled = assemble_record_groups(&bytes, &parsed, RecordLimits::default())?;
    let group = assembled.group(b"A1").ok_or("missing candidate group")?;

    assert!(!group.receipt().complete);
    assert_eq!(group.bytes(), None);
    assert_eq!(group.candidate_bytes(), &b"firstsecond"[..]);
    assert_eq!(group.receipt().parts.len(), 2);
    assert_eq!(assembled.report().terminal_sequence, None);
    Ok(())
}

#[test]
fn explicit_terminal_suffix_candidate_bytes() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![2];
    push_counted_record(&mut bytes, b"A1", 0, b"first");
    push_counted_record(&mut bytes, b"A1", 1, b"second");
    let schema = schema_with_terminal_sequence(&counted_payload_schema(), 2)?;
    let parsed = parse_records(&bytes, &schema)?;

    let assembled = assemble_record_groups(&bytes, &parsed, RecordLimits::default())?;
    let group = assembled.group(b"A1").ok_or("missing incomplete group")?;

    assert!(!group.receipt().complete);
    assert_eq!(group.bytes(), None);
    assert_eq!(group.candidate_bytes(), &b"firstsecond"[..]);
    assert_eq!(group.receipt().missing_sequence_count, 1);
    assert_eq!(group.receipt().missing_sequences, vec![2]);
    Ok(())
}

#[test]
fn explicit_terminal_observed_beyond_contract() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![3];
    push_counted_record(&mut bytes, b"A1", 0, b"first");
    push_counted_record(&mut bytes, b"A1", 1, b"second");
    push_counted_record(&mut bytes, b"A1", 2, b"extra");
    let schema = schema_with_terminal_sequence(&counted_payload_schema(), 1)?;
    let parsed = parse_records(&bytes, &schema)?;

    let assembled = assemble_record_groups(&bytes, &parsed, RecordLimits::default())?;
    let group = assembled.group(b"A1").ok_or("missing out-of-range group")?;

    assert!(!group.receipt().complete);
    assert_eq!(group.receipt().missing_sequence_count, 0);
    assert_eq!(group.receipt().sequences_after_terminal, vec![2]);
    assert_eq!(group.candidate_bytes(), b"firstsecondextra");
    Ok(())
}

#[test]
fn little_endian_until_end_supported() -> Result<(), Box<dyn Error>> {
    let schema = RecordSchema {
        records_offset: 0,
        count: RecordCount::UntilEnd,
        identifier: ByteField {
            offset: 0,
            width: 1,
        },
        sequence: IntegerField {
            offset: 1,
            width: 2,
            byte_order: ByteOrder::LittleEndian,
        },
        length: IntegerField {
            offset: 3,
            width: 2,
            byte_order: ByteOrder::LittleEndian,
        },
        data_offset: 5,
        length_meaning: RecordLengthMeaning::WholeRecord,
        sequence_base: 7,
        terminal_sequence: None,
    };
    let bytes = [b'X', 2, 1, 8, 0, b'a', b'b', b'c'];

    let report = parse_records(&bytes, &schema)?;

    let [record] = report.records() else {
        return Err("expected one parsed record".into());
    };
    assert_eq!(record.sequence, 0x0102);
    assert_eq!(record.payload.start, 5);
    assert_eq!(record.payload.end, 8);
    assert_eq!(report.declared_count(), None);
    Ok(())
}

#[test]
fn big_endian_integer_fields_byte() -> Result<(), Box<dyn Error>> {
    let schema = RecordSchema {
        records_offset: 0,
        count: RecordCount::Exact { records: 1 },
        identifier: ByteField {
            offset: 0,
            width: 1,
        },
        sequence: IntegerField {
            offset: 1,
            width: 4,
            byte_order: ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 5,
            width: 2,
            byte_order: ByteOrder::BigEndian,
        },
        data_offset: 7,
        length_meaning: RecordLengthMeaning::WholeRecord,
        sequence_base: 0,
        terminal_sequence: None,
    };
    let bytes = [b'Z', 1, 2, 3, 4, 0, 8, b'x'];

    let report = parse_records(&bytes, &schema)?;

    let [record] = report.records() else {
        return Err("expected one parsed record".into());
    };
    assert_eq!(record.sequence, 0x0102_0304);
    assert_eq!(record.record.end, bytes.len());
    assert_eq!(
        bytes
            .get(record.payload.start..record.payload.end)
            .ok_or("invalid payload range")?,
        &b"x"[..]
    );
    Ok(())
}

#[test]
fn whole_lengths_header_empty_payloads() -> Result<(), Box<dyn Error>> {
    let schema = RecordSchema {
        records_offset: 0,
        count: RecordCount::Exact { records: 1 },
        identifier: ByteField {
            offset: 0,
            width: 1,
        },
        sequence: IntegerField {
            offset: 1,
            width: 2,
            byte_order: ByteOrder::LittleEndian,
        },
        length: IntegerField {
            offset: 3,
            width: 2,
            byte_order: ByteOrder::LittleEndian,
        },
        data_offset: 5,
        length_meaning: RecordLengthMeaning::WholeRecord,
        sequence_base: 0,
        terminal_sequence: None,
    };
    let undersized = [b'X', 2, 1, 4, 0, b'a', b'b', b'c'];
    assert!(matches!(
        parse_records(&undersized, &schema),
        Err(RecordError::InvalidRecordLength {
            record: 0,
            encoded: 4
        })
    ));

    let empty_payload = [b'X', 2, 1, 5, 0];
    let report = parse_records(&empty_payload, &schema)?;
    let [record] = report.records() else {
        return Err("expected one empty-payload record".into());
    };
    assert_eq!(record.payload.start, 5);
    assert_eq!(record.payload.end, 5);
    Ok(())
}

#[test]
fn bytes_length_header_payload() -> Result<(), Box<dyn Error>> {
    let schema = RecordSchema {
        records_offset: 0,
        count: RecordCount::Exact { records: 1 },
        identifier: ByteField {
            offset: 0,
            width: 1,
        },
        sequence: IntegerField {
            offset: 1,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 2,
            width: 2,
            byte_order: ByteOrder::BigEndian,
        },
        data_offset: 6,
        length_meaning: RecordLengthMeaning::BytesAfterLengthField,
        sequence_base: 0,
        terminal_sequence: None,
    };
    let bytes = [b'Q', 0, 0, 5, 0xaa, 0xbb, b'x', b'y', b'z'];

    let report = parse_records(&bytes, &schema)?;

    let [record] = report.records() else {
        return Err("expected one parsed record".into());
    };
    assert_eq!(record.record.end, bytes.len());
    assert_eq!(record.payload.start, 6);
    assert_eq!(record.payload.end, 9);
    Ok(())
}

#[test]
fn parser_invalid_truncation_unconsumed_bytes() {
    let mut invalid = counted_payload_schema();
    invalid.identifier.width = 11;
    assert!(matches!(
        parse_records(&[], &invalid),
        Err(RecordError::InvalidSchema { field }) if field == "identifier"
    ));

    let mut truncated = vec![1];
    push_counted_record(&mut truncated, b"R3", 0, b"payload");
    truncated.pop();
    assert!(matches!(
        parse_records(&truncated, &counted_payload_schema()),
        Err(RecordError::TruncatedRecord { record: 0, .. })
    ));

    let mut trailing = vec![1];
    push_counted_record(&mut trailing, b"R3", 0, b"payload");
    trailing.push(0xff);
    assert!(matches!(
        parse_records(&trailing, &counted_payload_schema()),
        Err(RecordError::TrailingBytes { remaining: 1, .. })
    ));
}

#[test]
fn parser_rejects_invalid_integer_widths() {
    let mut invalid_sequence = counted_payload_schema();
    invalid_sequence.sequence.width = 3;
    assert!(matches!(
        parse_records(&[], &invalid_sequence),
        Err(RecordError::InvalidSchema { field }) if field == "sequence"
    ));

    let mut invalid_length = counted_payload_schema();
    invalid_length.length.width = 3;
    assert!(matches!(
        parse_records(&[], &invalid_length),
        Err(RecordError::InvalidSchema { field }) if field == "length"
    ));

    let mut invalid_count = counted_payload_schema();
    invalid_count.count = RecordCount::Field {
        field: IntegerField {
            offset: 0,
            width: 3,
            byte_order: ByteOrder::BigEndian,
        },
    };
    assert!(matches!(
        parse_records(&[], &invalid_count),
        Err(RecordError::InvalidSchema { field }) if field == "count"
    ));
}

#[test]
fn parser_configured_input_identifier_budgets() {
    let mut bytes = vec![1];
    push_counted_record(&mut bytes, b"L4", 0, b"data");
    let schema = counted_payload_schema();

    let input_limits = RecordLimits {
        max_input_bytes: bytes.len() - 1,
        ..RecordLimits::default()
    };
    assert!(matches!(
        parse_records_with_limits(&bytes, &schema, input_limits),
        Err(RecordError::InputTooLarge { .. })
    ));

    let record_limits = RecordLimits {
        max_records: 0,
        ..RecordLimits::default()
    };
    assert!(matches!(
        parse_records_with_limits(&bytes, &schema, record_limits),
        Err(RecordError::InvalidLimits)
    ));

    let identifier_limits = RecordLimits {
        max_identifier_bytes: 1,
        ..RecordLimits::default()
    };
    assert!(matches!(
        parse_records_with_limits(&bytes, &schema, identifier_limits),
        Err(RecordError::IdentifierTooLarge { .. })
    ));

    let identifier_boundary_limits = RecordLimits {
        max_identifier_bytes: 2,
        ..RecordLimits::default()
    };
    assert!(parse_records_with_limits(&bytes, &schema, identifier_boundary_limits).is_ok());

    let report_limits = RecordLimits {
        max_report_bytes: 1,
        ..RecordLimits::default()
    };
    assert!(matches!(
        parse_records_with_limits(&bytes, &schema, report_limits),
        Err(RecordError::ReportTooLarge { .. })
    ));
}

#[test]
fn parser_declared_reserving_truncated_input() {
    let schema = RecordSchema {
        count: RecordCount::Exact { records: 100_000 },
        ..counted_payload_schema()
    };
    let limits = RecordLimits {
        max_records: 100_000,
        max_report_bytes: 1,
        ..RecordLimits::default()
    };

    assert!(matches!(
        parse_records_with_limits(&[0], &schema, limits),
        Err(RecordError::ReportTooLarge { maximum: 1, .. })
    ));
}

#[test]
fn assembly_duplicates_sequences_values_base() -> Result<(), Box<dyn Error>> {
    let mut schema = counted_payload_schema();
    schema.sequence_base = 2;
    let mut bytes = vec![4];
    push_counted_record(&mut bytes, b"G5", 1, b"before");
    push_counted_record(&mut bytes, b"G5", 2, b"start");
    push_counted_record(&mut bytes, b"G5", 4, b"late");
    push_counted_record(&mut bytes, b"G5", 4, b"again");
    let parsed = parse_records(&bytes, &schema)?;

    let assembled = assemble_record_groups(&bytes, &parsed, RecordLimits::default())?;
    let group = assembled.group(b"G5").ok_or("missing incomplete group")?;

    assert!(!group.receipt().complete);
    assert_eq!(group.bytes(), None);
    assert_eq!(group.receipt().missing_sequence_count, 1);
    assert_eq!(group.receipt().missing_sequences, vec![3]);
    assert_eq!(group.receipt().duplicate_sequences, vec![4]);
    assert_eq!(group.receipt().sequences_before_base, vec![1]);
    assert_eq!(
        group.receipt().output_length,
        Some(b"beforestartlateagain".len())
    );
    assert!(group.receipt().output_sha256.is_some());
    assert_eq!(group.receipt().parts.len(), 4);
    assert_eq!(group.candidate_bytes(), b"beforestartlateagain");
    Ok(())
}

#[test]
fn duplicate_payload_conflict_keeps_candidate_incomplete() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![2];
    push_counted_record(&mut bytes, b"A1", 0, b"archive");
    push_counted_record(&mut bytes, b"A1", 0, b"conflicting payload");
    let schema = schema_with_terminal_sequence(&counted_payload_schema(), 0)?;
    let parsed = parse_records(&bytes, &schema)?;

    let assembled = assemble_record_groups(&bytes, &parsed, RecordLimits::default())?;
    let group = assembled.group(b"A1").ok_or("missing duplicate group")?;

    assert_eq!(group.candidate_bytes(), b"archiveconflicting payload");
    assert_eq!(group.receipt().duplicate_sequences, vec![0]);
    assert!(!group.receipt().complete);
    assert_eq!(group.bytes(), None);
    Ok(())
}

#[test]
fn assembly_first_identifier_exceeds_budget() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![3];
    push_counted_record(&mut bytes, b"A1", 0, b"a");
    push_counted_record(&mut bytes, b"B2", 0, b"b");
    push_counted_record(&mut bytes, b"C3", 0, b"c");
    let parsed = parse_records(&bytes, &counted_payload_schema())?;
    let limits = RecordLimits {
        max_groups: 1,
        ..RecordLimits::default()
    };

    assert!(matches!(
        assemble_record_groups(&bytes, &parsed, limits),
        Err(RecordError::TooManyGroups {
            count: 2,
            maximum: 1
        })
    ));
    Ok(())
}

#[test]
fn duplicate_omission_distinct_values_examples() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![6];
    push_counted_record(&mut bytes, b"D4", 0, b"zero");
    push_counted_record(&mut bytes, b"D4", 1, b"one-a");
    push_counted_record(&mut bytes, b"D4", 1, b"one-b");
    push_counted_record(&mut bytes, b"D4", 2, b"two-a");
    push_counted_record(&mut bytes, b"D4", 2, b"two-b");
    push_counted_record(&mut bytes, b"D4", 2, b"two-c");
    let parsed = parse_records(&bytes, &counted_payload_schema())?;
    let limits = RecordLimits {
        max_issue_examples: 1,
        ..RecordLimits::default()
    };

    let assembled = assemble_record_groups(&bytes, &parsed, limits)?;
    let group = assembled.group(b"D4").ok_or("missing duplicate group")?;

    assert!(!group.receipt().complete);
    assert_eq!(group.bytes(), None);
    assert_eq!(group.receipt().duplicate_sequences, vec![1]);
    assert_eq!(group.receipt().omitted_duplicate_sequences, 1);
    Ok(())
}

#[test]
fn sparse_sequence_without_entire_gap() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![2];
    push_counted_record(&mut bytes, b"H6", 0, b"a");
    push_counted_record(&mut bytes, b"H6", u32::MAX, b"z");
    let schema = schema_with_terminal_sequence(&counted_payload_schema(), u64::from(u32::MAX))?;
    let parsed = parse_records(&bytes, &schema)?;
    let limits = RecordLimits {
        max_issue_examples: 3,
        ..RecordLimits::default()
    };

    let assembled = assemble_record_groups(&bytes, &parsed, limits)?;
    let group = assembled.group(b"H6").ok_or("missing sparse group")?;

    assert_eq!(
        group.receipt().missing_sequence_count,
        u128::from(u32::MAX) - 1
    );
    assert_eq!(group.receipt().missing_sequences, vec![1, 2, 3]);
    assert_eq!(
        group.receipt().omitted_missing_sequences,
        u128::from(u32::MAX) - 4
    );
    Ok(())
}

#[test]
fn assembly_enforces_aggregate_output_budget() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![1];
    push_counted_record(&mut bytes, b"J7", 0, b"large");
    let schema = schema_with_terminal_sequence(&counted_payload_schema(), 0)?;
    let parsed = parse_records(&bytes, &schema)?;
    let limits = RecordLimits {
        max_output_bytes: 4,
        ..RecordLimits::default()
    };

    assert!(matches!(
        assemble_record_groups(&bytes, &parsed, limits),
        Err(RecordError::OutputTooLarge {
            length: 5,
            maximum: 4
        })
    ));
    Ok(())
}

#[test]
fn assembly_different_even_length_unchanged() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![1];
    push_counted_record(&mut bytes, b"K8", 0, b"same-size");
    let parsed = parse_records(&bytes, &counted_payload_schema())?;
    let mut substituted = bytes.clone();
    let last = substituted.last_mut().ok_or("missing payload byte")?;
    *last ^= 1;

    assert!(matches!(
        assemble_record_groups(&substituted, &parsed, RecordLimits::default()),
        Err(RecordError::InvalidReport)
    ));
    Ok(())
}

#[test]
fn ordered_inputs_exact_source_mappings() -> Result<(), Box<dyn Error>> {
    let mut first_bytes = vec![2];
    push_counted_record(&mut first_bytes, b"M9", 0, b"first");
    push_counted_record(&mut first_bytes, b"N0", 0, b"other");
    let mut second_bytes = vec![1];
    push_counted_record(&mut second_bytes, b"M9", 1, b"second");
    let schema = schema_with_terminal_sequence(&counted_payload_schema(), 1)?;
    let first = parse_records(&first_bytes, &schema)?;
    let second = parse_records(&second_bytes, &schema)?;
    let inputs = [
        RecordAssemblyInput::new(&first_bytes, &first),
        RecordAssemblyInput::new(&second_bytes, &second),
    ];

    let assembled = assemble_record_groups_from_inputs(&inputs, RecordLimits::default())?;
    let group = assembled.group(b"M9").ok_or("missing cross-input group")?;

    assert_eq!(group.bytes(), Some(&b"firstsecond"[..]));
    let [first_part, second_part] = group.receipt().parts.as_slice() else {
        return Err("expected two source mappings".into());
    };
    assert_eq!(first_part.input_index, 0);
    assert_eq!(first_part.record_index, 0);
    assert_eq!(first_part.output.start, 0);
    assert_eq!(first_part.output.end, 5);
    assert_eq!(second_part.input_index, 1);
    assert_eq!(second_part.record_index, 0);
    assert_eq!(second_part.output.start, 5);
    assert_eq!(second_part.output.end, 11);
    assert_eq!(
        assembled.report().input_length,
        first_bytes.len() + second_bytes.len()
    );
    Ok(())
}

#[test]
fn assembly_charges_mappings_aggregate_budget() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![2];
    push_counted_record(&mut bytes, b"A1", 0, b"first");
    push_counted_record(&mut bytes, b"A1", 1, b"second");
    let schema = schema_with_terminal_sequence(&counted_payload_schema(), 1)?;
    let parsed = parse_records(&bytes, &schema)?;
    let required_bytes = parsed
        .metadata_bytes()
        .checked_add(std::mem::size_of::<
            l2_workbench::protocol::RecordGroupOutcome,
        >())
        .and_then(|size| size.checked_add(b"A1".len()))
        .and_then(|size| size.checked_add(std::mem::size_of::<[u8; 32]>() * 2))
        .and_then(|size| {
            size.checked_add(2 * std::mem::size_of::<l2_workbench::protocol::RecordAssemblyPart>())
        })
        .ok_or("record report budget size overflowed")?;
    let limits = RecordLimits {
        max_report_bytes: required_bytes - 1,
        ..RecordLimits::default()
    };

    assert!(matches!(
        assemble_record_groups(&bytes, &parsed, limits),
        Err(RecordError::ReportTooLarge { maximum, .. }) if maximum == required_bytes - 1
    ));
    Ok(())
}

#[test]
fn multiple_inputs_aggregate_input_budgets() -> Result<(), Box<dyn Error>> {
    let mut first_bytes = vec![1];
    push_counted_record(&mut first_bytes, b"P1", 0, b"a");
    let mut second_bytes = vec![1];
    push_counted_record(&mut second_bytes, b"P1", 1, b"b");
    let schema = counted_payload_schema();
    let first = parse_records(&first_bytes, &schema)?;
    let second = parse_records(&second_bytes, &schema)?;
    let inputs = [
        RecordAssemblyInput::new(&first_bytes, &first),
        RecordAssemblyInput::new(&second_bytes, &second),
    ];

    let input_limits = RecordLimits {
        max_input_bytes: first_bytes.len() + second_bytes.len() - 1,
        ..RecordLimits::default()
    };
    assert!(matches!(
        assemble_record_groups_from_inputs(&inputs, input_limits),
        Err(RecordError::InputTooLarge { .. })
    ));

    let record_limits = RecordLimits {
        max_records: 1,
        ..RecordLimits::default()
    };
    assert!(matches!(
        assemble_record_groups_from_inputs(&inputs, record_limits),
        Err(RecordError::TooManyRecords {
            count: 2,
            maximum: 1
        })
    ));
    Ok(())
}
