use super::{
    ParsedRecord, RecordAssemblyInput, RecordAssemblyOutcome, RecordAssemblyPart, RecordError,
    RecordGroupOutcome, RecordGroupReceipt, RecordLimits, RecordParseReport,
    parse::validate_assembly_limits,
};
use crate::sha256;
use std::collections::{BTreeMap, btree_map::Entry};

/// Group records by opaque identifier and materialize deterministic payload candidates
///
/// Only an explicit terminal sequence can establish complete object boundaries
///
/// # Errors
/// Rejects inconsistent reports, invalid limits, allocation failures, and output overflow
pub fn assemble_record_groups(
    bytes: &[u8],
    parsed: &RecordParseReport,
    limits: RecordLimits,
) -> Result<RecordAssemblyOutcome, RecordError> {
    assemble_record_groups_from_inputs(&[RecordAssemblyInput::new(bytes, parsed)], limits)
}

/// Group records globally across independently parsed inputs
///
/// Input order is preserved as provenance and breaks ties between repeated sequence values
/// while each parse report remains bound to its own complete source bytes
///
/// # Errors
/// Rejects inconsistent reports or layouts, aggregate limit violations, allocation failures,
/// and candidate output overflow
pub fn assemble_record_groups_from_inputs(
    inputs: &[RecordAssemblyInput<'_>],
    limits: RecordLimits,
) -> Result<RecordAssemblyOutcome, RecordError> {
    validate_assembly_limits(limits)?;
    let (input_length, sequence_base, terminal_sequence, mut report_bytes) =
        validate_inputs(inputs, limits)?;
    let grouped = group_inputs(inputs, limits)?;
    let (groups, total_output) = assemble_groups(
        grouped,
        sequence_base,
        terminal_sequence,
        limits,
        &mut report_bytes,
    )?;
    Ok(RecordAssemblyOutcome {
        input_count: inputs.len(),
        input_length,
        output_bytes: total_output,
        terminal_sequence,
        report_bytes,
        groups,
    })
}

fn validate_inputs(
    inputs: &[RecordAssemblyInput<'_>],
    limits: RecordLimits,
) -> Result<(usize, u64, Option<u64>, usize), RecordError> {
    let mut input_length = 0_usize;
    let mut record_count = 0_usize;
    let mut report_bytes = 0_usize;
    let mut common_schema = None;
    for input in inputs {
        validate_report(input.bytes, input.report, limits)?;
        input_length =
            input_length
                .checked_add(input.bytes.len())
                .ok_or(RecordError::InputTooLarge {
                    length: usize::MAX,
                    maximum: limits.max_input_bytes,
                })?;
        if input_length > limits.max_input_bytes {
            return Err(RecordError::InputTooLarge {
                length: input_length,
                maximum: limits.max_input_bytes,
            });
        }
        record_count = record_count.checked_add(input.report.records.len()).ok_or(
            RecordError::TooManyRecords {
                count: u64::MAX,
                maximum: limits.max_records,
            },
        )?;
        if record_count > limits.max_records {
            return Err(RecordError::TooManyRecords {
                count: u64::try_from(record_count).unwrap_or(u64::MAX),
                maximum: limits.max_records,
            });
        }
        report_bytes = report_bytes
            .checked_add(input.report.metadata_bytes())
            .ok_or(RecordError::ReportTooLarge {
                bytes: usize::MAX,
                maximum: limits.max_report_bytes,
            })?;
        if report_bytes > limits.max_report_bytes {
            return Err(RecordError::ReportTooLarge {
                bytes: report_bytes,
                maximum: limits.max_report_bytes,
            });
        }

        // Count sources may differ, but every record field must use one common layout
        if let Some(expected_schema) = common_schema {
            if !same_record_layout(expected_schema, &input.report.schema) {
                return Err(RecordError::InvalidReport);
            }
        } else {
            common_schema = Some(&input.report.schema);
        }
    }
    let sequence_base = common_schema.map_or(0, |schema| schema.sequence_base);
    let terminal_sequence = common_schema.and_then(|schema| schema.terminal_sequence);
    Ok((input_length, sequence_base, terminal_sequence, report_bytes))
}

fn group_inputs<'a>(
    inputs: &'a [RecordAssemblyInput<'a>],
    limits: RecordLimits,
) -> Result<BTreeMap<&'a [u8], Vec<SourcedRecord<'a>>>, RecordError> {
    // Borrow identifier keys so grouping does not make another copy per record
    let mut grouped = BTreeMap::<&'a [u8], Vec<SourcedRecord<'a>>>::new();
    for (input_index, input) in inputs.iter().enumerate() {
        for record in &input.report.records {
            let group_count = grouped.len();
            let group = match grouped.entry(record.identifier.as_slice()) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    if group_count >= limits.max_groups {
                        return Err(RecordError::TooManyGroups {
                            count: group_count.saturating_add(1),
                            maximum: limits.max_groups,
                        });
                    }
                    entry.insert(Vec::new())
                }
            };
            group
                .try_reserve(1)
                .map_err(|_| RecordError::AllocationFailed)?;
            group.push(SourcedRecord {
                input_index,
                bytes: input.bytes,
                record,
            });
        }
    }
    Ok(grouped)
}

fn assemble_groups(
    grouped: BTreeMap<&[u8], Vec<SourcedRecord<'_>>>,
    sequence_base: u64,
    terminal_sequence: Option<u64>,
    limits: RecordLimits,
    report_bytes: &mut usize,
) -> Result<(Vec<RecordGroupOutcome>, usize), RecordError> {
    let group_storage = std::mem::size_of::<RecordGroupOutcome>()
        .checked_mul(grouped.len())
        .ok_or(RecordError::ReportTooLarge {
            bytes: usize::MAX,
            maximum: limits.max_report_bytes,
        })?;
    charge_report_bytes(report_bytes, group_storage, limits)?;

    let mut groups = Vec::new();
    groups
        .try_reserve_exact(grouped.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    let mut total_output = 0_usize;
    for (identifier, mut records) in grouped {
        // Explicit source order makes equal sequence handling reproducible
        records.sort_unstable_by_key(|record| {
            (
                record.record.sequence,
                record.input_index,
                record.record.index,
            )
        });
        let outcome = assemble_group(
            identifier,
            &records,
            sequence_base,
            terminal_sequence,
            limits,
            total_output,
            report_bytes,
        )?;
        total_output = total_output
            .checked_add(outcome.candidate_bytes.len())
            .ok_or(RecordError::OutputTooLarge {
                length: usize::MAX,
                maximum: limits.max_output_bytes,
            })?;
        groups.push(outcome);
    }
    Ok((groups, total_output))
}

#[derive(Clone, Copy)]
struct SourcedRecord<'a> {
    input_index: usize,
    bytes: &'a [u8],
    record: &'a ParsedRecord,
}

fn same_record_layout(left: &super::RecordSchema, right: &super::RecordSchema) -> bool {
    left.records_offset == right.records_offset
        && left.identifier == right.identifier
        && left.sequence == right.sequence
        && left.length == right.length
        && left.data_offset == right.data_offset
        && left.length_meaning == right.length_meaning
        && left.sequence_base == right.sequence_base
        && left.terminal_sequence == right.terminal_sequence
}

fn validate_report(
    bytes: &[u8],
    parsed: &RecordParseReport,
    limits: RecordLimits,
) -> Result<(), RecordError> {
    if bytes.len() > limits.max_input_bytes {
        return Err(RecordError::InputTooLarge {
            length: bytes.len(),
            maximum: limits.max_input_bytes,
        });
    }
    if bytes.len() != parsed.input_length || sha256(bytes) != parsed.input_sha256 {
        return Err(RecordError::InvalidReport);
    }
    if parsed.records.len() > limits.max_records {
        return Err(RecordError::TooManyRecords {
            count: u64::try_from(parsed.records.len()).unwrap_or(u64::MAX),
            maximum: limits.max_records,
        });
    }
    for (expected_index, record) in parsed.records.iter().enumerate() {
        let record_valid = record.index == expected_index
            && record.record.start <= record.payload.start
            && record.payload.start <= record.payload.end
            && record.payload.end == record.record.end
            && record.record.end <= bytes.len()
            && !record.identifier.is_empty()
            && record.identifier.len() <= limits.max_identifier_bytes;
        if !record_valid {
            return Err(RecordError::InvalidReport);
        }
    }
    Ok(())
}

fn charge_report_bytes(
    used: &mut usize,
    additional: usize,
    limits: RecordLimits,
) -> Result<(), RecordError> {
    let total = used
        .checked_add(additional)
        .ok_or(RecordError::ReportTooLarge {
            bytes: usize::MAX,
            maximum: limits.max_report_bytes,
        })?;
    if total > limits.max_report_bytes {
        return Err(RecordError::ReportTooLarge {
            bytes: total,
            maximum: limits.max_report_bytes,
        });
    }
    *used = total;
    Ok(())
}

fn sequence_bounds(records: &[SourcedRecord<'_>]) -> Result<(u64, u64), RecordError> {
    let minimum = records
        .first()
        .map(|record| record.record.sequence)
        .ok_or(RecordError::InvalidReport)?;
    let maximum = records
        .last()
        .map(|record| record.record.sequence)
        .ok_or(RecordError::InvalidReport)?;
    Ok((minimum, maximum))
}

fn assemble_group(
    identifier: &[u8],
    records: &[SourcedRecord<'_>],
    sequence_base: u64,
    terminal_sequence: Option<u64>,
    limits: RecordLimits,
    prior_output: usize,
    report_bytes: &mut usize,
) -> Result<RecordGroupOutcome, RecordError> {
    charge_report_bytes(report_bytes, identifier.len(), limits)?;
    let completion = SequenceCompletion {
        sequence_base,
        terminal_sequence,
    };
    let diagnostics = sequence_diagnostics(records, completion, limits, report_bytes)?;
    let mapping_bytes = std::mem::size_of::<RecordAssemblyPart>()
        .checked_mul(records.len())
        .ok_or(RecordError::ReportTooLarge {
            bytes: usize::MAX,
            maximum: limits.max_report_bytes,
        })?;
    charge_report_bytes(report_bytes, mapping_bytes, limits)?;
    charge_report_bytes(report_bytes, std::mem::size_of::<[u8; 32]>() * 2, limits)?;
    let (candidate_bytes, parts) = materialize(records, limits, prior_output)?;
    let receipt = build_group_receipt(identifier, diagnostics, &candidate_bytes, parts)?;
    Ok(RecordGroupOutcome {
        receipt,
        candidate_bytes,
    })
}

struct GroupDiagnostics {
    record_count: usize,
    sequence_base: u64,
    minimum_sequence: u64,
    maximum_sequence: u64,
    complete: bool,
    missing_sequence_count: u128,
    missing_sequences: Vec<u64>,
    issues: SequenceIssues,
}

fn sequence_diagnostics(
    records: &[SourcedRecord<'_>],
    completion: SequenceCompletion,
    limits: RecordLimits,
    report_bytes: &mut usize,
) -> Result<GroupDiagnostics, RecordError> {
    let (minimum_sequence, maximum_sequence) = sequence_bounds(records)?;
    let issues = sequence_issues(records, completion, limits, report_bytes)?;
    let counts = MissingSequenceCounts {
        maximum_observed_sequence: maximum_sequence,
        unique_in_expected_range: issues.unique_in_expected_range,
    };
    let (missing_sequence_count, missing_sequences) =
        missing_sequences(records, completion, counts, report_bytes, limits)?;
    let complete = completion.terminal_sequence.is_some()
        && issues.before_base_count == 0
        && issues.duplicate_count == 0
        && issues.after_terminal_count == 0
        && missing_sequence_count == 0;
    Ok(GroupDiagnostics {
        record_count: records.len(),
        sequence_base: completion.sequence_base,
        minimum_sequence,
        maximum_sequence,
        complete,
        missing_sequence_count,
        missing_sequences,
        issues,
    })
}

fn build_group_receipt(
    identifier: &[u8],
    diagnostics: GroupDiagnostics,
    candidate_bytes: &[u8],
    parts: Vec<RecordAssemblyPart>,
) -> Result<RecordGroupReceipt, RecordError> {
    let mut identifier_copy = Vec::new();
    identifier_copy
        .try_reserve_exact(identifier.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    identifier_copy.extend_from_slice(identifier);
    let issues = diagnostics.issues;
    Ok(RecordGroupReceipt {
        identifier: identifier_copy,
        record_count: diagnostics.record_count,
        sequence_base: diagnostics.sequence_base,
        minimum_sequence: diagnostics.minimum_sequence,
        maximum_sequence: diagnostics.maximum_sequence,
        complete: diagnostics.complete,
        missing_sequence_count: diagnostics.missing_sequence_count,
        omitted_missing_sequences: diagnostics
            .missing_sequence_count
            .saturating_sub(diagnostics.missing_sequences.len() as u128),
        missing_sequences: diagnostics.missing_sequences,
        omitted_duplicate_sequences: issues
            .duplicate_count
            .saturating_sub(issues.duplicates.len()),
        duplicate_sequences: issues.duplicates,
        omitted_sequences_before_base: issues
            .before_base_count
            .saturating_sub(issues.before_base.len()),
        sequences_before_base: issues.before_base,
        omitted_sequences_after_terminal: issues
            .after_terminal_count
            .saturating_sub(issues.after_terminal.len()),
        sequences_after_terminal: issues.after_terminal,
        output_length: Some(candidate_bytes.len()),
        output_sha256: Some(sha256(candidate_bytes)),
        parts,
    })
}

#[derive(Clone, Copy)]
struct SequenceCompletion {
    sequence_base: u64,
    terminal_sequence: Option<u64>,
}

struct SequenceIssues {
    unique_in_expected_range: u128,
    duplicates: Vec<u64>,
    duplicate_count: usize,
    before_base: Vec<u64>,
    before_base_count: usize,
    after_terminal: Vec<u64>,
    after_terminal_count: usize,
}

fn sequence_issues(
    records: &[SourcedRecord<'_>],
    completion: SequenceCompletion,
    limits: RecordLimits,
    report_bytes: &mut usize,
) -> Result<SequenceIssues, RecordError> {
    let mut unique_in_expected_range = 0_u128;
    let mut duplicates = Vec::new();
    let mut duplicate_count = 0_usize;
    let mut before_base = Vec::new();
    let mut before_base_count = 0_usize;
    let mut after_terminal = Vec::new();
    let mut after_terminal_count = 0_usize;
    let mut previous = None;
    let mut last_duplicate = None;
    for record in records {
        let sequence = record.record.sequence;
        let repeated = previous == Some(sequence);
        if repeated {
            // Count each duplicated value once even after its example is omitted
            if last_duplicate != Some(sequence) {
                duplicate_count = duplicate_count.saturating_add(1);
                retain_example(
                    &mut duplicates,
                    sequence,
                    limits.max_issue_examples,
                    report_bytes,
                    limits,
                )?;
                last_duplicate = Some(sequence);
            }
        } else if sequence < completion.sequence_base {
            before_base_count = before_base_count.saturating_add(1);
            retain_example(
                &mut before_base,
                sequence,
                limits.max_issue_examples,
                report_bytes,
                limits,
            )?;
        } else if completion
            .terminal_sequence
            .is_some_and(|terminal| sequence > terminal)
        {
            after_terminal_count = after_terminal_count.saturating_add(1);
            retain_example(
                &mut after_terminal,
                sequence,
                limits.max_issue_examples,
                report_bytes,
                limits,
            )?;
        } else {
            unique_in_expected_range = unique_in_expected_range.saturating_add(1);
        }
        previous = Some(sequence);
    }

    Ok(SequenceIssues {
        unique_in_expected_range,
        duplicates,
        duplicate_count,
        before_base,
        before_base_count,
        after_terminal,
        after_terminal_count,
    })
}

#[derive(Clone, Copy)]
struct MissingSequenceCounts {
    maximum_observed_sequence: u64,
    unique_in_expected_range: u128,
}

fn missing_sequences(
    records: &[SourcedRecord<'_>],
    completion: SequenceCompletion,
    counts: MissingSequenceCounts,
    report_bytes: &mut usize,
    limits: RecordLimits,
) -> Result<(u128, Vec<u64>), RecordError> {
    let expected_terminal = completion
        .terminal_sequence
        .unwrap_or(counts.maximum_observed_sequence);
    if expected_terminal < completion.sequence_base {
        return Ok((0, Vec::new()));
    }
    let expected_cardinality = u128::from(expected_terminal)
        .saturating_sub(u128::from(completion.sequence_base))
        .saturating_add(1);
    let missing_count = expected_cardinality.saturating_sub(counts.unique_in_expected_range);
    let maximum_examples = limits.max_issue_examples;
    let reserve_count = maximum_examples.min(usize::try_from(missing_count).unwrap_or(usize::MAX));
    let example_bytes = std::mem::size_of::<u64>()
        .checked_mul(reserve_count)
        .ok_or(RecordError::ReportTooLarge {
            bytes: usize::MAX,
            maximum: limits.max_report_bytes,
        })?;
    charge_report_bytes(report_bytes, example_bytes, limits)?;
    let mut examples = Vec::new();
    examples
        .try_reserve_exact(reserve_count)
        .map_err(|_| RecordError::AllocationFailed)?;

    // Walk expected values once and retain only bounded gap examples
    let mut next_expected = Some(completion.sequence_base);
    let mut previous_observed = None;
    for record in records {
        let sequence = record.record.sequence;
        if sequence < completion.sequence_base
            || sequence > expected_terminal
            || previous_observed == Some(sequence)
        {
            previous_observed = Some(sequence);
            continue;
        }
        if let Some(expected) = next_expected {
            append_gap_examples(&mut examples, expected, sequence, false, maximum_examples);
        }
        next_expected = sequence.checked_add(1);
        previous_observed = Some(sequence);
        if examples.len() == maximum_examples && missing_count > maximum_examples as u128 {
            break;
        }
    }
    if examples.len() < maximum_examples
        && let Some(expected) = next_expected.filter(|expected| *expected <= expected_terminal)
    {
        append_gap_examples(
            &mut examples,
            expected,
            expected_terminal,
            true,
            maximum_examples,
        );
    }
    Ok((missing_count, examples))
}

fn retain_example(
    examples: &mut Vec<u64>,
    value: u64,
    maximum: usize,
    report_bytes: &mut usize,
    limits: RecordLimits,
) -> Result<(), RecordError> {
    if examples.len() < maximum {
        charge_report_bytes(report_bytes, std::mem::size_of::<u64>(), limits)?;
        examples
            .try_reserve(1)
            .map_err(|_| RecordError::AllocationFailed)?;
        examples.push(value);
    }
    Ok(())
}

fn append_gap_examples(
    examples: &mut Vec<u64>,
    start: u64,
    end: u64,
    include_end: bool,
    maximum: usize,
) {
    let available = maximum.saturating_sub(examples.len());
    let gap = u128::from(end)
        .saturating_sub(u128::from(start))
        .saturating_add(u128::from(include_end));
    let retain = gap.min(available as u128);
    for delta in 0..retain {
        if let Ok(delta) = u64::try_from(delta)
            && let Some(value) = start.checked_add(delta)
        {
            examples.push(value);
        }
    }
}

fn materialize(
    records: &[SourcedRecord<'_>],
    limits: RecordLimits,
    prior_output: usize,
) -> Result<(Vec<u8>, Vec<RecordAssemblyPart>), RecordError> {
    let mut length = 0_usize;
    for record in records {
        let payload_length = record
            .record
            .payload
            .end
            .checked_sub(record.record.payload.start)
            .ok_or(RecordError::InvalidReport)?;
        length = length
            .checked_add(payload_length)
            .ok_or(RecordError::OutputTooLarge {
                length: usize::MAX,
                maximum: limits.max_output_bytes,
            })?;
    }
    let aggregate = prior_output
        .checked_add(length)
        .ok_or(RecordError::OutputTooLarge {
            length: usize::MAX,
            maximum: limits.max_output_bytes,
        })?;
    if aggregate > limits.max_output_bytes {
        return Err(RecordError::OutputTooLarge {
            length: aggregate,
            maximum: limits.max_output_bytes,
        });
    }

    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| RecordError::AllocationFailed)?;
    let mut parts = Vec::new();
    parts
        .try_reserve_exact(records.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    for record in records {
        let payload = record
            .bytes
            .get(record.record.payload.start..record.record.payload.end)
            .ok_or(RecordError::InvalidReport)?;
        let output_start = output.len();
        output.extend_from_slice(payload);
        parts.push(RecordAssemblyPart {
            input_index: record.input_index,
            record_index: record.record.index,
            sequence: record.record.sequence,
            input: record.record.payload,
            output: crate::protocol::ByteRange {
                start: output_start,
                end: output.len(),
            },
        });
    }
    Ok((output, parts))
}
