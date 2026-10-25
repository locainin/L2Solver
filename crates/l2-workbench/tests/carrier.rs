use l2_workbench::{
    carrier::{
        Ambiguity, BitOrder, CarrierError, ClockSample, CompositionEncoding, CompositionField,
        CompositionPart, CompositionRecipe, Field, FieldWidth, LengthArithmetic, LengthMeaning,
        NumericByteOrder, OmissionReason, PartialBytePadding, Report, Rule, Sample, SourceReader,
        TimingStatus, compose, derive_composed, extract, search_composed, verify_sample_bytes,
    },
    derivation::{Constraint, DerivationStatus, Operation, Recipe},
    evidence::{ByteMapping, SourceRange},
    hypothesis::{CandidateStatus, Family, SearchPlan},
    measurement::Clock,
};
use std::{
    cell::Cell,
    error::Error,
    fs::File,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    rc::Rc,
};

struct ReadTrackingCursor {
    cursor: Cursor<Vec<u8>>,
    largest_read_request: Rc<Cell<usize>>,
    bytes_read: Rc<Cell<usize>>,
}

impl Read for ReadTrackingCursor {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.largest_read_request
            .set(self.largest_read_request.get().max(output.len()));
        let count = self.cursor.read(output)?;
        self.bytes_read.set(self.bytes_read.get() + count);
        Ok(count)
    }
}

impl Seek for ReadTrackingCursor {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.cursor.seek(position)
    }
}

fn verified_source(bytes: Vec<u8>) -> Result<SourceReader, Box<dyn Error>> {
    let id = format!("sha256:{}", l2_workbench::sha256(&bytes));
    Ok(SourceReader::verify(
        id,
        u64::try_from(bytes.len())?,
        Cursor::new(bytes),
    )?)
}

fn mapping(source: &SourceReader, packet: u64, offset: u64, length: u64) -> ByteMapping {
    ByteMapping {
        offset: 0,
        range: SourceRange {
            source: source.id().to_owned(),
            packet: Some(packet),
            offset,
            length,
        },
    }
}

const fn sample<'a>(
    id: u64,
    event_id: &'a str,
    sequence: u64,
    length: usize,
    mappings: &'a [ByteMapping],
) -> Sample<'a> {
    Sample {
        id,
        event_id: Some(event_id),
        sequence: Some(sequence),
        length,
        mappings,
        time: None,
        ambiguity: Ambiguity::None,
    }
}

#[test]
fn extraction_exact_rules_packet_ranges() -> Result<(), Box<dyn Error>> {
    let bytes = [
        0x00, 0x01, 0x00, 0x02, b'A', b'a', 3, b'W', b'W', b'W', 3, b'c', b'o', b'm', 0,
    ];
    let mut source = verified_source(bytes.to_vec())?;
    let mappings = [mapping(&source, 7, 0, u64::try_from(bytes.len())?)];
    let samples = [sample(1, "event-1", 9, bytes.len(), &mappings)];
    let length_field_rule = Rule::LengthField {
        field: Field {
            offset: 0,
            width: FieldWidth::Two,
            byte_order: NumericByteOrder::BigEndian,
        },
        meaning: LengthMeaning::WholeMessage,
    };
    let order_field_rule = Rule::OrderField {
        field: Field {
            offset: 2,
            width: FieldWidth::Two,
            byte_order: NumericByteOrder::LittleEndian,
        },
    };
    let rules = [
        Rule::Bytes,
        Rule::Bits {
            order: BitOrder::MostSignificantFirst,
        },
        Rule::MessageLength,
        Rule::Sequence,
        length_field_rule.clone(),
        order_field_rule.clone(),
        Rule::DnsLabels {
            offset: 6,
            ascii_case_fold: false,
        },
        Rule::Capitalization,
    ];

    let report = extract(std::slice::from_mut(&mut source), &samples, &rules)?;

    assert!(report.complete);
    assert_eq!(report.observations.len(), 9);
    assert_unsigned_value(&report, &Rule::MessageLength, 15);
    assert_unsigned_value(&report, &Rule::Sequence, 9);
    assert_unsigned_value(&report, &length_field_rule, 1);
    assert_unsigned_value(&report, &order_field_rule, 512);
    assert_dns_label_range(&report)?;
    assert_capitalization_pattern(&report);
    Ok(())
}

fn assert_unsigned_value(report: &Report, rule: &Rule, expected: u64) {
    assert!(report.observations.iter().any(|observation| {
        observation.rule == *rule
            && observation.value.as_ref().is_some_and(|value| {
                matches!(value, l2_workbench::carrier::Value::Unsigned { value } if *value == expected)
            })
    }));
}

fn assert_dns_label_range(report: &Report) -> Result<(), Box<dyn Error>> {
    let label = report
        .observations
        .iter()
        .find(|observation| {
            observation.value.as_ref().is_some_and(|value| {
                matches!(value, l2_workbench::carrier::Value::DnsLabel { raw, .. } if raw == b"WWW")
            })
        })
        .ok_or("DNS label was not retained")?;
    let range = label
        .ranges
        .first()
        .ok_or("DNS label range was not retained")?;
    assert_eq!(range.packet, Some(7));
    assert_eq!(range.offset, 7);
    assert_eq!(range.length, 3);
    Ok(())
}

fn assert_capitalization_pattern(report: &Report) {
    assert!(report.observations.iter().any(|observation| {
        observation.rule == Rule::Capitalization
            && observation.value.as_ref().is_some_and(|value| {
                matches!(value, l2_workbench::carrier::Value::Capitalization { pattern } if pattern == &[1, 0, 1, 1, 1, 0, 0, 0])
            })
    }));
}

#[test]
fn source_verification_hash_unmapped_bytes() -> Result<(), Box<dyn Error>> {
    let bytes = b"verified source".to_vec();
    let wrong_id = format!("sha256:{}", l2_workbench::sha256(b"different source"));
    assert!(
        SourceReader::verify(
            wrong_id,
            u64::try_from(bytes.len())?,
            Cursor::new(bytes.clone())
        )
        .is_err()
    );

    let mut source = verified_source(bytes)?;
    let mappings = [mapping(&source, 1, 0, 3)];
    let incomplete = [sample(1, "event-1", 1, 4, &mappings)];
    assert!(
        extract(
            std::slice::from_mut(&mut source),
            &incomplete,
            &[Rule::Bytes]
        )
        .is_err()
    );

    let left = verified_source(b"a".to_vec())?;
    let right = verified_source(b"b".to_vec())?;
    let overlaps = [mapping(&left, 1, 0, 1), mapping(&right, 1, 0, 1)];
    let conflicting = [sample(2, "event-2", 1, 1, &overlaps)];
    assert!(extract(&mut [left, right], &conflicting, &[Rule::Bytes]).is_err());
    Ok(())
}

#[test]
fn sample_reconstruction_exact_source_range() -> Result<(), Box<dyn Error>> {
    let first_source = verified_source(b"--ab".to_vec())?;
    let second_source = verified_source(b"CD++".to_vec())?;
    let mappings = [
        ByteMapping {
            offset: 0,
            range: SourceRange {
                source: first_source.id().to_owned(),
                packet: Some(3),
                offset: 2,
                length: 2,
            },
        },
        ByteMapping {
            offset: 2,
            range: SourceRange {
                source: second_source.id().to_owned(),
                packet: Some(9),
                offset: 0,
                length: 2,
            },
        },
    ];
    let sample = sample(1, "event-1", 1, 4, &mappings);
    let report = extract(
        &mut [first_source, second_source],
        &[sample],
        &[Rule::Bytes],
    )?;
    let observation = report
        .observations
        .first()
        .ok_or("missing byte observation")?;

    assert!(matches!(
        observation.value.as_ref(),
        Some(l2_workbench::carrier::Value::Bytes { bytes }) if bytes == b"abCD"
    ));
    assert_eq!(observation.ranges.len(), 2);
    assert_eq!(
        observation.ranges.first().and_then(|range| range.packet),
        Some(3)
    );
    assert_eq!(
        observation.ranges.get(1).and_then(|range| range.packet),
        Some(9)
    );
    Ok(())
}

#[test]
fn retained_sample_exact_bytes_disagreement() -> Result<(), Box<dyn Error>> {
    let first_source = verified_source(b"--ab".to_vec())?;
    let second_source = verified_source(b"CD++".to_vec())?;
    let first_mappings = [mapping(&first_source, 3, 2, 2)];
    let second_mappings = [mapping(&second_source, 9, 0, 2)];
    let samples = [
        sample(1, "event-1", 1, 2, &first_mappings),
        sample(2, "event-2", 2, 2, &second_mappings),
    ];
    let mut sources = [first_source, second_source];

    verify_sample_bytes(&mut sources, &samples, &[b"ab", b"CD"])?;
    let mismatch = verify_sample_bytes(&mut sources, &samples, &[b"ab", b"XX"]);

    assert!(matches!(mismatch, Err(CarrierError::SampleContentMismatch)));
    Ok(())
}

#[test]
fn retained_sample_missing_expected() -> Result<(), Box<dyn Error>> {
    let source = verified_source(b"ab".to_vec())?;
    let mappings = [mapping(&source, 3, 0, 2)];
    let samples = [sample(1, "event-1", 1, 2, &mappings)];

    let result = verify_sample_bytes(&mut [source], &samples, &[]);

    assert!(matches!(result, Err(CarrierError::SampleContentMismatch)));
    Ok(())
}

#[path = "carrier/discovery.rs"]
mod discovery;

#[test]
fn source_verification_seekable_sources_bounded() -> Result<(), Box<dyn Error>> {
    const EXPECTED_CHUNK_BYTES: usize = 64 * 1024;
    let bytes = vec![0x5a; EXPECTED_CHUNK_BYTES * 2 + 19];
    let id = format!("sha256:{}", l2_workbench::sha256(&bytes));
    let largest_read_request = Rc::new(Cell::new(0));
    let bytes_read = Rc::new(Cell::new(0));
    let source = SourceReader::verify(
        id,
        u64::try_from(bytes.len())?,
        ReadTrackingCursor {
            cursor: Cursor::new(bytes),
            largest_read_request: Rc::clone(&largest_read_request),
            bytes_read: Rc::clone(&bytes_read),
        },
    )?;

    assert_eq!(
        source.length(),
        u64::try_from(EXPECTED_CHUNK_BYTES * 2 + 19)?
    );
    assert_eq!(largest_read_request.get(), EXPECTED_CHUNK_BYTES);
    assert_eq!(bytes_read.get(), EXPECTED_CHUNK_BYTES * 2 + 19);
    Ok(())
}

#[test]
fn source_identification_once_canonical_identity() -> Result<(), Box<dyn Error>> {
    const BLOCK_BYTES: usize = 64 * 1024;
    let bytes = vec![0xa5; BLOCK_BYTES * 2 + 31];
    let expected_id = format!("sha256:{}", l2_workbench::sha256(&bytes));
    let largest_read_request = Rc::new(Cell::new(0));
    let bytes_read = Rc::new(Cell::new(0));
    let mut cursor = Cursor::new(bytes);
    cursor.seek(SeekFrom::Start(17))?;

    let source = SourceReader::identify(ReadTrackingCursor {
        cursor,
        largest_read_request: Rc::clone(&largest_read_request),
        bytes_read: Rc::clone(&bytes_read),
    })?;

    assert_eq!(source.id(), expected_id);
    assert_eq!(source.length(), u64::try_from(BLOCK_BYTES * 2 + 31)?);
    assert_eq!(largest_read_request.get(), BLOCK_BYTES);
    assert_eq!(bytes_read.get(), BLOCK_BYTES * 2 + 31);
    Ok(())
}

#[test]
fn source_ranges_across_whole_request() -> Result<(), Box<dyn Error>> {
    const BLOCK_BYTES: usize = 64 * 1024;
    let bytes = (0..BLOCK_BYTES)
        .map(|index| u8::try_from(index % 251))
        .collect::<Result<Vec<_>, _>>()?;
    let source_id = format!("sha256:{}", l2_workbench::sha256(&bytes));
    let largest_read_request = Rc::new(Cell::new(0));
    let bytes_read = Rc::new(Cell::new(0));
    let source = SourceReader::verify(
        source_id.clone(),
        u64::try_from(bytes.len())?,
        ReadTrackingCursor {
            cursor: Cursor::new(bytes.clone()),
            largest_read_request: Rc::clone(&largest_read_request),
            bytes_read: Rc::clone(&bytes_read),
        },
    )?;
    let mappings = (0..32_usize)
        .map(|offset| {
            Ok(ByteMapping {
                offset,
                range: SourceRange {
                    source: source_id.clone(),
                    packet: Some(u64::try_from(offset + 1)?),
                    offset: u64::try_from(offset)?,
                    length: 1,
                },
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let samples = [
        sample(1, "first", 1, mappings.len(), &mappings),
        sample(2, "second", 2, mappings.len(), &mappings),
    ];
    let expected = bytes.get(..mappings.len()).ok_or("fixture is too short")?;
    bytes_read.set(0);
    largest_read_request.set(0);

    verify_sample_bytes(&mut [source], &samples, &[expected, expected])?;

    assert_eq!(bytes_read.get(), BLOCK_BYTES);
    assert_eq!(largest_read_request.get(), BLOCK_BYTES);
    Ok(())
}

#[test]
fn source_reader_changed_bytes_verification() -> Result<(), Box<dyn Error>> {
    let original = b"verified range";
    let (mut source, mut writable) = verified_mutable_file_source(original)?;

    writable.seek(SeekFrom::Start(0))?;
    writable.write_all(b"X")?;
    writable.flush()?;
    let mappings = [mapping(&source, 29, 0, u64::try_from(original.len())?)];
    let result = extract(
        std::slice::from_mut(&mut source),
        &[sample(1, "event-changed", 1, original.len(), &mappings)],
        &[Rule::Bytes],
    );

    assert!(matches!(result, Err(CarrierError::SourceChanged)));
    Ok(())
}

#[test]
fn source_reader_length_change_verification() -> Result<(), Box<dyn Error>> {
    let original = b"verified range";
    let (mut source, mut writable) = verified_mutable_file_source(original)?;
    writable.seek(SeekFrom::End(0))?;
    writable.write_all(b"X")?;
    writable.flush()?;
    let mappings = [mapping(&source, 30, 0, u64::try_from(original.len())?)];
    let result = extract(
        std::slice::from_mut(&mut source),
        &[sample(
            1,
            "event-length-change",
            1,
            original.len(),
            &mappings,
        )],
        &[Rule::Bytes],
    );

    assert!(matches!(result, Err(CarrierError::SourceChanged)));
    Ok(())
}

fn verified_mutable_file_source(bytes: &[u8]) -> Result<(SourceReader, File), Box<dyn Error>> {
    let source_id = format!("sha256:{}", l2_workbench::sha256(bytes));
    let mut writable = tempfile::tempfile()?;
    writable.write_all(bytes)?;
    writable.flush()?;
    let source = SourceReader::verify(
        source_id,
        u64::try_from(bytes.len())?,
        writable.try_clone()?,
    )?;
    Ok((source, writable))
}

#[test]
fn source_reader_final_partial_block() -> Result<(), Box<dyn Error>> {
    const BLOCK_BYTES: usize = 64 * 1024;
    let bytes = (0..BLOCK_BYTES * 2 + 19)
        .map(|position| u8::try_from(position % 251))
        .collect::<Result<Vec<_>, _>>()?;
    let mut source = verified_source(bytes.clone())?;
    let offset = BLOCK_BYTES * 2 - 3;
    let length = 22;
    let mappings = [mapping(
        &source,
        31,
        u64::try_from(offset)?,
        u64::try_from(length)?,
    )];
    let report = extract(
        std::slice::from_mut(&mut source),
        &[sample(1, "event-cross-block", 1, length, &mappings)],
        &[Rule::Bytes],
    )?;
    let expected = bytes
        .get(offset..offset + length)
        .ok_or("fixture range was out of bounds")?;

    assert!(matches!(
        report.observations.first().and_then(|observation| observation.value.as_ref()),
        Some(l2_workbench::carrier::Value::Bytes { bytes }) if bytes == expected
    ));
    Ok(())
}

#[test]
fn source_reader_past_verified_length() -> Result<(), Box<dyn Error>> {
    let mut source = verified_source(b"verified".to_vec())?;
    let mappings = [mapping(&source, 32, 7, 2)];
    let result = extract(
        std::slice::from_mut(&mut source),
        &[sample(1, "event-out-of-bounds", 1, 2, &mappings)],
        &[Rule::Bytes],
    );

    assert!(matches!(result, Err(CarrierError::InvalidSourceRange)));
    Ok(())
}

#[test]
fn wide_numeric_fields_unsigned() -> Result<(), Box<dyn Error>> {
    let mut source = verified_source(vec![u8::MAX; 8])?;
    let mappings = [mapping(&source, 6, 0, 8)];
    let samples = [sample(1, "event-1", 1, 8, &mappings)];
    let report = extract(
        std::slice::from_mut(&mut source),
        &samples,
        &[Rule::OrderField {
            field: Field {
                offset: 0,
                width: FieldWidth::Eight,
                byte_order: NumericByteOrder::BigEndian,
            },
        }],
    )?;
    assert!(report.observations.first().is_some_and(|observation| {
        observation.value.as_ref().is_some_and(|value| {
            matches!(
                value,
                l2_workbench::carrier::Value::Unsigned { value: u64::MAX }
            )
        })
    }));
    Ok(())
}

#[test]
fn exact_values_events_ambiguity_retained() -> Result<(), Box<dyn Error>> {
    let first_source = verified_source(b"--shared--".to_vec())?;
    let second_source = verified_source(b"++shared++".to_vec())?;
    let first_map = [mapping(&first_source, 3, 2, 6)];
    let second_map = [mapping(&second_source, 8, 2, 6)];
    let mut first = sample(1, "event-a", 1, 6, &first_map);
    first.ambiguity = Ambiguity::MultipleCandidates;
    let second = sample(2, "event-b", 1, 6, &second_map);
    let report = extract(
        &mut [first_source, second_source],
        &[first, second],
        &[Rule::Bytes, Rule::MessageLength],
    )?;

    let relationship = report
        .relationships
        .iter()
        .find(|relationship| relationship.members.len() == 2)
        .ok_or("cross-source value relationship was not recorded")?;
    assert!(relationship.cross_sources);
    assert!(relationship.cross_events);
    assert_eq!(relationship.ambiguity, Ambiguity::MultipleCandidates);
    assert_eq!(relationship.members.len(), 2);
    assert_ne!(
        relationship.members.first().map(|member| &member.ranges),
        relationship.members.get(1).map(|member| &member.ranges)
    );
    Ok(())
}

#[test]
fn relationship_flags_are_independent() -> Result<(), Box<dyn Error>> {
    let first_source = verified_source(b"--shared--".to_vec())?;
    let second_source = verified_source(b"++shared++".to_vec())?;
    let first_map = [mapping(&first_source, 3, 2, 6)];
    let second_map = [mapping(&second_source, 8, 2, 6)];
    let same_event_samples = [
        sample(1, "shared-event", 1, 6, &first_map),
        sample(2, "shared-event", 2, 6, &second_map),
    ];
    let source_relationship = extract(
        &mut [first_source, second_source],
        &same_event_samples,
        &[Rule::Bytes],
    )?
    .relationships
    .into_iter()
    .next()
    .ok_or("cross-source value relationship was not recorded")?;
    assert!(source_relationship.cross_sources);
    assert!(!source_relationship.cross_events);

    let source = verified_source(b"--shared--".to_vec())?;
    let mappings = [mapping(&source, 3, 2, 6)];
    let cross_event_samples = [
        sample(1, "event-a", 1, 6, &mappings),
        sample(2, "event-b", 2, 6, &mappings),
    ];
    let event_relationship = extract(&mut [source], &cross_event_samples, &[Rule::Bytes])?
        .relationships
        .into_iter()
        .next()
        .ok_or("cross-event value relationship was not recorded")?;
    assert!(!event_relationship.cross_sources);
    assert!(event_relationship.cross_events);
    Ok(())
}

#[test]
fn timing_deltas_exact_clock_scope() -> Result<(), Box<dyn Error>> {
    let shared_clock = Clock::new("capture-a", "scope-a", 10, 6, 0)?;
    let measured = timing_report(shared_clock.clone(), shared_clock)?;
    assert!(measured.observations.iter().any(|observation| {
        observation.value.as_ref().is_some_and(|value| {
            matches!(
                value,
                l2_workbench::carrier::Value::Timing {
                    from_sequence: Some(1),
                    to_sequence: Some(2),
                    from_ticks: Some(10),
                    to_ticks: Some(17),
                    delta_ticks: Some(7),
                    status: TimingStatus::Measured,
                    left_clock: Some(left_clock),
                    right_clock: Some(right_clock),
                    ..
                } if left_clock.id == "capture-a" && right_clock.id == "capture-a"
            )
        })
    }));
    let timing_observation = measured
        .observations
        .first()
        .ok_or("measured timing observation was not retained")?;
    assert_eq!(timing_observation.sample_ids, [1, 2]);
    assert_eq!(
        timing_observation
            .ranges
            .iter()
            .filter_map(|range| range.packet)
            .collect::<Vec<_>>(),
        [1, 2]
    );

    assert_timing_unresolved(
        &timing_report(
            Clock::new("capture-a", "scope-a", 10, 6, 0)?,
            Clock::new("capture-b", "scope-a", 10, 6, 0)?,
        )?,
        TimingStatus::ClockMismatch,
    );
    assert_timing_unresolved(
        &timing_report(
            Clock::new("capture-a", "scope-a", 10, 6, 0)?,
            Clock::new("capture-a", "scope-b", 10, 6, 0)?,
        )?,
        TimingStatus::ScopeMismatch,
    );
    Ok(())
}

fn timing_report(left_clock: Clock, right_clock: Clock) -> Result<Report, Box<dyn Error>> {
    let mut source = verified_source(b"ab".to_vec())?;
    let first_map = [mapping(&source, 1, 0, 1)];
    let second_map = [mapping(&source, 2, 1, 1)];
    let mut first = sample(1, "event-a", 1, 1, &first_map);
    first.time = Some(ClockSample {
        clock: left_clock,
        ticks: Some(10),
    });
    let mut second = sample(2, "event-a", 2, 1, &second_map);
    second.time = Some(ClockSample {
        clock: right_clock,
        ticks: Some(17),
    });
    Ok(extract(
        std::slice::from_mut(&mut source),
        &[first, second],
        &[Rule::Timing],
    )?)
}

fn assert_timing_unresolved(report: &Report, expected: TimingStatus) {
    assert!(report.observations.iter().any(|observation| {
        observation.value.as_ref().is_some_and(|value| {
            matches!(
                value,
                l2_workbench::carrier::Value::Timing {
                    delta_ticks: None,
                    status,
                    ..
                } if *status == expected
            )
        })
    }));
}

#[test]
fn search_derivation_replayable_recipes_constraints() -> Result<(), Box<dyn Error>> {
    let mut source = verified_source(b"6869".to_vec())?;
    let mappings = [mapping(&source, 12, 0, 4)];
    let sample = sample(1, "event-1", 1, 4, &mappings);
    let plan = SearchPlan {
        families: vec![Family::Hex],
        constraints: vec![
            Constraint::Length { bytes: 2 },
            Constraint::Prefix {
                bytes: b"hi".to_vec(),
            },
            Constraint::Sha256 {
                expected_hex: l2_workbench::sha256(b"hi"),
            },
        ],
        max_depth: 1,
        max_candidates: 32,
    };
    let report = extract(std::slice::from_mut(&mut source), &[sample], &[Rule::Bytes])?;
    let composition = compose(
        &report,
        &CompositionRecipe {
            parts: vec![CompositionPart {
                sample_ids: vec![1],
                rule: Rule::Bytes,
                component_index: None,
                field: CompositionField::Bytes,
                encoding: CompositionEncoding::Bytes,
            }],
        },
    )?;
    assert!(composition.receipt().complete);
    assert_eq!(composition.bytes(), Some(b"6869".as_slice()));
    let searched = search_composed(&composition, &plan)?;
    let candidate = searched
        .search
        .candidates
        .iter()
        .find(|candidate| candidate.status == CandidateStatus::ConstraintsSatisfied)
        .ok_or("explicit decode hypothesis did not satisfy all constraints")?;
    assert_eq!(candidate.recipe.steps, [Operation::HexDecode {}]);
    assert_eq!(candidate.constraints.len(), 3);
    assert_eq!(
        report
            .observations
            .first()
            .and_then(|observation| observation.ranges.first())
            .and_then(|range| range.packet),
        Some(12)
    );
    let derived = derive_composed(&composition, &candidate.recipe)?;
    assert_eq!(derived.derivation.status, DerivationStatus::Completed);
    assert_eq!(derived.derivation.output, b"hi");
    assert_eq!(derived.recipe, candidate.recipe);
    Ok(())
}

#[test]
fn byte_carriers_events_range_retained() -> Result<(), Box<dyn Error>> {
    let first_source = verified_source(b"--68".to_vec())?;
    let second_source = verified_source(b"69++".to_vec())?;
    let first_mapping = [mapping(&first_source, 61, 2, 2)];
    let second_mapping = [mapping(&second_source, 62, 0, 2)];
    let samples = [
        sample(8, "event-first", 1, 2, &first_mapping),
        sample(9, "event-second", 1, 2, &second_mapping),
    ];
    let report = extract(&mut [first_source, second_source], &samples, &[Rule::Bytes])?;
    let composition = compose(
        &report,
        &CompositionRecipe {
            parts: vec![
                CompositionPart {
                    sample_ids: vec![8],
                    rule: Rule::Bytes,
                    component_index: None,
                    field: CompositionField::Bytes,
                    encoding: CompositionEncoding::Bytes,
                },
                CompositionPart {
                    sample_ids: vec![9],
                    rule: Rule::Bytes,
                    component_index: None,
                    field: CompositionField::Bytes,
                    encoding: CompositionEncoding::Bytes,
                },
            ],
        },
    )?;

    assert_eq!(composition.bytes(), Some(b"6869".as_slice()));
    assert_eq!(decode_hex(&composition)?, b"hi");
    let packets: Vec<_> = composition
        .receipt()
        .parts
        .iter()
        .filter_map(|part| part.ranges.first().and_then(|range| range.packet))
        .collect();
    assert_eq!(packets, [61, 62]);
    assert_eq!(composition.receipt().parts.len(), 2);
    Ok(())
}

#[test]
fn capitalization_bits_padded_bytes_provenance() -> Result<(), Box<dyn Error>> {
    let mut source = verified_source(b"AbC".to_vec())?;
    let mappings = [mapping(&source, 21, 0, 3)];
    let samples = [sample(4, "event-case", 1, 3, &mappings)];
    let report = extract(
        std::slice::from_mut(&mut source),
        &samples,
        &[Rule::Capitalization],
    )?;
    let outcome = compose(
        &report,
        &CompositionRecipe {
            parts: vec![CompositionPart {
                sample_ids: vec![4],
                rule: Rule::Capitalization,
                component_index: None,
                field: CompositionField::Capitalization,
                encoding: CompositionEncoding::Bits {
                    order: BitOrder::MostSignificantFirst,
                    padding: PartialBytePadding::ZeroFill,
                },
            }],
        },
    )?;

    assert!(outcome.receipt().complete);
    assert_eq!(outcome.bytes(), Some([0xa0].as_slice()));
    let part = outcome
        .receipt()
        .parts
        .first()
        .ok_or("missing part receipt")?;
    assert_eq!(part.logical_bit_length, Some(3));
    assert_eq!(part.ranges.first().and_then(|range| range.packet), Some(21));
    assert_eq!(derive_hex(&outcome)?, b"a0");

    let least_significant = compose(
        &report,
        &CompositionRecipe {
            parts: vec![CompositionPart {
                sample_ids: vec![4],
                rule: Rule::Capitalization,
                component_index: None,
                field: CompositionField::Capitalization,
                encoding: CompositionEncoding::Bits {
                    order: BitOrder::LeastSignificantFirst,
                    padding: PartialBytePadding::OneFill,
                },
            }],
        },
    )?;
    assert_eq!(least_significant.bytes(), Some([0xfd].as_slice()));
    assert!(matches!(
        compose(
            &report,
            &CompositionRecipe {
                parts: vec![CompositionPart {
                    sample_ids: vec![4],
                    rule: Rule::Capitalization,
                    component_index: None,
                    field: CompositionField::Capitalization,
                    encoding: CompositionEncoding::Bits {
                        order: BitOrder::MostSignificantFirst,
                        padding: PartialBytePadding::Reject,
                    },
                }],
            }
        ),
        Err(l2_workbench::carrier::CarrierError::InvalidCompositionEncoding)
    ));
    Ok(())
}

fn derive_hex(
    outcome: &l2_workbench::carrier::CompositionOutcome,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let recipe = Recipe {
        steps: vec![Operation::HexEncode {
            case: l2_workbench::derivation::HexCase::Lower,
        }],
        constraints: Vec::new(),
    };
    Ok(derive_composed(outcome, &recipe)?.derivation.output)
}

fn decode_hex(
    outcome: &l2_workbench::carrier::CompositionOutcome,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let recipe = Recipe {
        steps: vec![Operation::HexDecode {}],
        constraints: Vec::new(),
    };
    Ok(derive_composed(outcome, &recipe)?.derivation.output)
}

#[test]
fn omitted_selected_analysis_shortened_stream() -> Result<(), Box<dyn Error>> {
    let mut source = verified_source(b"6869".to_vec())?;
    let mappings = [mapping(&source, 31, 0, 4)];
    let mut selected = sample(1, "event-incomplete", 1, 4, &mappings);
    selected.sequence = None;
    let report = extract(
        std::slice::from_mut(&mut source),
        &[selected],
        &[Rule::Bytes, Rule::Sequence],
    )?;
    let recipe = CompositionRecipe {
        parts: vec![bytes_part(), sequence_part()],
    };
    let outcome = compose(&report, &recipe)?;

    assert!(!outcome.receipt().complete);
    assert_eq!(outcome.bytes(), None);
    assert!(matches!(
        derive_composed(&outcome, &Recipe::default()),
        Err(l2_workbench::carrier::CarrierError::IncompleteComposition)
    ));
    assert!(matches!(
        search_composed(&outcome, &empty_hex_plan()),
        Err(l2_workbench::carrier::CarrierError::IncompleteComposition)
    ));
    Ok(())
}

#[test]
fn ambiguous_source_provenance_blocks_composition() -> Result<(), Box<dyn Error>> {
    let mut source = verified_source(b"6869".to_vec())?;
    let mappings = [mapping(&source, 32, 0, 4)];
    let mut selected = sample(2, "event-ambiguous", 1, 4, &mappings);
    selected.ambiguity = Ambiguity::MultipleCandidates;
    let report = extract(
        std::slice::from_mut(&mut source),
        &[selected],
        &[Rule::Bytes],
    )?;
    let composition = compose(
        &report,
        &CompositionRecipe {
            parts: vec![CompositionPart {
                sample_ids: vec![2],
                rule: Rule::Bytes,
                component_index: None,
                field: CompositionField::Bytes,
                encoding: CompositionEncoding::Bytes,
            }],
        },
    )?;

    assert!(!composition.receipt().complete);
    assert_eq!(composition.bytes(), None);
    let part = composition
        .receipt()
        .parts
        .first()
        .ok_or("missing part receipt")?;
    assert_eq!(part.ambiguity, Some(Ambiguity::MultipleCandidates));
    assert_eq!(
        part.status,
        l2_workbench::carrier::CompositionPartStatus::Ambiguous
    );
    assert_eq!(part.ranges.first().and_then(|range| range.packet), Some(32));
    Ok(())
}

fn bytes_part() -> CompositionPart {
    CompositionPart {
        sample_ids: vec![1],
        rule: Rule::Bytes,
        component_index: None,
        field: CompositionField::Bytes,
        encoding: CompositionEncoding::Bytes,
    }
}

fn sequence_part() -> CompositionPart {
    CompositionPart {
        sample_ids: vec![1],
        rule: Rule::Sequence,
        component_index: None,
        field: CompositionField::Unsigned,
        encoding: CompositionEncoding::Unsigned {
            width: FieldWidth::One,
            byte_order: NumericByteOrder::BigEndian,
        },
    }
}

fn length_part(encoding: CompositionEncoding) -> CompositionPart {
    CompositionPart {
        sample_ids: vec![1],
        rule: Rule::MessageLength,
        component_index: None,
        field: CompositionField::Unsigned,
        encoding,
    }
}

const fn adjusted_length(operation: LengthArithmetic, operand: u64) -> CompositionEncoding {
    CompositionEncoding::LengthArithmetic {
        operation,
        operand,
        width: FieldWidth::One,
        byte_order: NumericByteOrder::BigEndian,
    }
}

#[test]
fn length_arithmetic_unsigned_byte_encoding() -> Result<(), Box<dyn Error>> {
    let mut source = verified_source(b"abcdefgh".to_vec())?;
    let mappings = [mapping(&source, 70, 0, 8)];
    let rule = Rule::MessageLength;
    let report = extract(
        std::slice::from_mut(&mut source),
        &[sample(1, "event-length", 1, 8, &mappings)],
        std::slice::from_ref(&rule),
    )?;
    let outcome = compose(
        &report,
        &CompositionRecipe {
            parts: vec![length_part(adjusted_length(LengthArithmetic::Subtract, 2))],
        },
    )?;

    assert_eq!(outcome.bytes(), Some([6].as_slice()));
    let part = outcome
        .receipt()
        .parts
        .first()
        .ok_or("missing length receipt")?;
    assert_eq!(part.ranges.first().and_then(|range| range.packet), Some(70));
    Ok(())
}

#[test]
fn length_arithmetic_zero_other_rules() -> Result<(), Box<dyn Error>> {
    let bytes = vec![b'x'; 8];
    let mut source = verified_source(bytes)?;
    let mappings = [mapping(&source, 71, 0, 8)];
    let samples = [sample(1, "event-length", 1, 8, &mappings)];
    let rules = [Rule::MessageLength, Rule::Sequence];
    let report = extract(std::slice::from_mut(&mut source), &samples, &rules)?;

    for encoding in [
        adjusted_length(LengthArithmetic::Subtract, 9),
        adjusted_length(LengthArithmetic::Add, u64::MAX),
        adjusted_length(LengthArithmetic::Divide, 0),
    ] {
        let result = compose(
            &report,
            &CompositionRecipe {
                parts: vec![length_part(encoding)],
            },
        );
        assert!(result.is_err());
    }

    let invalid = CompositionPart {
        sample_ids: vec![1],
        rule: Rule::Sequence,
        component_index: None,
        field: CompositionField::Unsigned,
        encoding: adjusted_length(LengthArithmetic::Add, 1),
    };
    assert!(matches!(
        compose(
            &report,
            &CompositionRecipe {
                parts: vec![invalid]
            }
        ),
        Err(CarrierError::InvalidCompositionEncoding)
    ));
    Ok(())
}

fn empty_hex_plan() -> SearchPlan {
    SearchPlan {
        families: vec![Family::Hex],
        constraints: Vec::new(),
        max_depth: 1,
        max_candidates: 8,
    }
}

#[test]
fn incomparable_timing_projection_stays_partial() -> Result<(), Box<dyn Error>> {
    let mut source = verified_source(b"ab".to_vec())?;
    let mappings = [mapping(&source, 41, 0, 1)];
    let right_mappings = [mapping(&source, 42, 1, 1)];
    let mut first = sample(1, "event-clock", 1, 1, &mappings);
    first.time = Some(clock_sample("clock-a", 10)?);
    let mut second = sample(2, "event-clock", 2, 1, &right_mappings);
    second.time = Some(clock_sample("clock-b", 17)?);
    let report = extract(
        std::slice::from_mut(&mut source),
        &[first, second],
        &[Rule::Timing],
    )?;
    let outcome = compose(
        &report,
        &CompositionRecipe {
            parts: vec![CompositionPart {
                sample_ids: vec![1, 2],
                rule: Rule::Timing,
                component_index: None,
                field: CompositionField::TimingDeltaTicks,
                encoding: CompositionEncoding::Unsigned {
                    width: FieldWidth::One,
                    byte_order: NumericByteOrder::BigEndian,
                },
            }],
        },
    )?;

    assert!(!outcome.receipt().complete);
    assert_eq!(outcome.bytes(), None);
    Ok(())
}

#[test]
fn measured_timing_delta_source_ranges() -> Result<(), Box<dyn Error>> {
    let clock = Clock::new("capture", "scope", 10, 6, 0)?;
    let report = timing_report(clock.clone(), clock)?;
    let composed = compose(
        &report,
        &CompositionRecipe {
            parts: vec![CompositionPart {
                sample_ids: vec![1, 2],
                rule: Rule::Timing,
                component_index: None,
                field: CompositionField::TimingDeltaTicks,
                encoding: CompositionEncoding::Unsigned {
                    width: FieldWidth::One,
                    byte_order: NumericByteOrder::BigEndian,
                },
            }],
        },
    )?;

    assert_eq!(composed.bytes(), Some([7].as_slice()));
    assert_eq!(
        composed
            .receipt()
            .parts
            .first()
            .map(|part| part.ranges.len()),
        Some(2)
    );
    assert!(composed.receipt().complete);
    Ok(())
}

fn clock_sample(id: &str, ticks: u64) -> Result<ClockSample, Box<dyn Error>> {
    Ok(ClockSample {
        clock: Clock::new(id, "scope", 10, 6, 0)?,
        ticks: Some(ticks),
    })
}

#[test]
fn numeric_carrier_error_without_truncation() -> Result<(), Box<dyn Error>> {
    let mut source = verified_source([1, 0].to_vec())?;
    let mappings = [mapping(&source, 43, 0, 2)];
    let rule = Rule::OrderField {
        field: Field {
            offset: 0,
            width: FieldWidth::Two,
            byte_order: NumericByteOrder::BigEndian,
        },
    };
    let report = extract(
        std::slice::from_mut(&mut source),
        &[sample(3, "event-number", 1, 2, &mappings)],
        std::slice::from_ref(&rule),
    )?;

    assert!(matches!(
        compose(
            &report,
            &CompositionRecipe {
                parts: vec![CompositionPart {
                    sample_ids: vec![3],
                    rule,
                    component_index: None,
                    field: CompositionField::Unsigned,
                    encoding: CompositionEncoding::Unsigned {
                        width: FieldWidth::One,
                        byte_order: NumericByteOrder::BigEndian,
                    },
                }],
            }
        ),
        Err(l2_workbench::carrier::CarrierError::CompositionOverflow)
    ));
    Ok(())
}

#[test]
fn numeric_carrier_width_selected_byte() -> Result<(), Box<dyn Error>> {
    let mut source = verified_source([1, 2].to_vec())?;
    let mappings = [mapping(&source, 52, 0, 2)];
    let rule = Rule::OrderField {
        field: Field {
            offset: 0,
            width: FieldWidth::Two,
            byte_order: NumericByteOrder::BigEndian,
        },
    };
    let report = extract(
        std::slice::from_mut(&mut source),
        &[sample(5, "event-order", 1, 2, &mappings)],
        std::slice::from_ref(&rule),
    )?;
    let outcome = compose(
        &report,
        &CompositionRecipe {
            parts: vec![CompositionPart {
                sample_ids: vec![5],
                rule,
                component_index: None,
                field: CompositionField::Unsigned,
                encoding: CompositionEncoding::Unsigned {
                    width: FieldWidth::Two,
                    byte_order: NumericByteOrder::LittleEndian,
                },
            }],
        },
    )?;

    assert_eq!(outcome.bytes(), Some([2, 1].as_slice()));
    assert_eq!(outcome.receipt().output_length, Some(2));
    Ok(())
}

#[test]
fn dns_label_explicit_hex_decoding() -> Result<(), Box<dyn Error>> {
    let mut source = verified_source(vec![4, b'6', b'8', b'6', b'9', 0, 3, b'W', b'W', b'W', 0])?;
    let first_mapping = [mapping(&source, 54, 0, 6)];
    let second_mapping = [mapping(&source, 55, 6, 5)];
    let samples = [
        sample(6, "event-dns-1", 1, 6, &first_mapping),
        sample(7, "event-dns-2", 1, 5, &second_mapping),
    ];
    let rule = Rule::DnsLabels {
        offset: 0,
        ascii_case_fold: true,
    };
    let report = extract(
        std::slice::from_mut(&mut source),
        &samples,
        std::slice::from_ref(&rule),
    )?;
    let raw = compose(
        &report,
        &CompositionRecipe {
            parts: vec![CompositionPart {
                sample_ids: vec![6],
                rule: rule.clone(),
                component_index: Some(0),
                field: CompositionField::DnsRaw,
                encoding: CompositionEncoding::Bytes,
            }],
        },
    )?;
    assert_eq!(raw.bytes(), Some(b"6869".as_slice()));
    assert_eq!(decode_hex(&raw)?, b"hi");

    let folded = compose(
        &report,
        &CompositionRecipe {
            parts: vec![CompositionPart {
                sample_ids: vec![7],
                rule,
                component_index: Some(0),
                field: CompositionField::DnsComparison,
                encoding: CompositionEncoding::Bytes,
            }],
        },
    )?;
    assert_eq!(folded.bytes(), Some(b"www".as_slice()));
    assert_eq!(
        folded
            .receipt()
            .parts
            .first()
            .and_then(|part| part.ranges.first())
            .map(|range| range.offset),
        Some(7)
    );
    Ok(())
}

#[test]
fn compressed_dns_reported_explicit_omission() -> Result<(), Box<dyn Error>> {
    let bytes = [0xc0, 0x0c, 0x00];
    let mut source = verified_source(bytes.to_vec())?;
    let mappings = [mapping(&source, 4, 0, 3)];
    let samples = [sample(1, "event-1", 1, 3, &mappings)];
    let report = extract(
        std::slice::from_mut(&mut source),
        &samples,
        &[Rule::DnsLabels {
            offset: 0,
            ascii_case_fold: true,
        }],
    )?;
    assert!(!report.complete);
    assert!(
        report
            .omissions
            .iter()
            .any(|omission| { omission.reason == OmissionReason::CompressedDnsName })
    );
    Ok(())
}
