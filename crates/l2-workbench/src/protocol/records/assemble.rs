use super::{
    ParsedRecord, RecordAssemblyInput, RecordAssemblyOutcome, RecordAssemblyPart, RecordError,
    RecordGroupOutcome, RecordGroupReceipt, RecordInput, RecordLimits, RecordParseReport,
    model::parsed_record_metadata_bytes, parse::validate_assembly_limits,
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
    let (input_length, sequence_base, terminal_sequence, report_bytes) =
        validate_inputs(inputs, limits)?;
    let mut metadata_inputs = Vec::new();
    metadata_inputs
        .try_reserve_exact(inputs.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    metadata_inputs.extend(inputs.iter().enumerate().map(|(input_index, input)| {
        RecordMetadataInput {
            input_index,
            input_length: input.bytes.len(),
            records: &input.report.records,
        }
    }));
    let prepared = prepare_record_groups_from_validated(
        &metadata_inputs,
        input_length,
        report_bytes,
        sequence_base,
        terminal_sequence,
        limits,
        None,
    )?;
    let mut groups = Vec::new();
    groups
        .try_reserve_exact(prepared.groups.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    for group in prepared.groups {
        let bytes = materialize_layout(inputs, &group.layout, group.output_length)?;
        let mut receipt = group.receipt;
        finish_receipt(&mut receipt, &bytes);
        groups.push(RecordGroupOutcome {
            receipt,
            candidate_bytes: bytes,
        });
    }
    Ok(RecordAssemblyOutcome {
        input_count: inputs.len(),
        input_length: prepared.input_length,
        output_bytes: prepared.output_bytes,
        terminal_sequence,
        report_bytes: prepared.report_bytes,
        groups,
    })
}

/// Parse metadata needed to prepare one shared physical assembly layout
pub(super) struct RecordMetadataInput<'a> {
    pub(super) input_index: usize,
    pub(super) input_length: usize,
    pub(super) records: &'a [ParsedRecord],
}

/// One payload range in an ordered physical assembly layout
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct PhysicalPart {
    pub(super) input_index: usize,
    pub(super) start: usize,
    pub(super) end: usize,
}

/// Semantic receipt and byte ranges for one prepared identifier group
pub(super) struct PreparedGroup {
    pub(super) receipt: RecordGroupReceipt,
    pub(super) layout: Vec<PhysicalPart>,
    pub(super) output_length: usize,
}

/// All group layouts and report accounting prepared without copying payload bytes
pub(super) struct PreparedRecordGroups {
    pub(super) input_length: usize,
    pub(super) output_bytes: usize,
    pub(super) report_bytes: usize,
    pub(super) groups: Vec<PreparedGroup>,
}

/// Bounds plan-specific workspaces while reusing canonical record preparation
pub(super) struct AssemblyPlanBudget {
    retained: usize,
    workspace: usize,
    maximum: usize,
}

impl AssemblyPlanBudget {
    pub(super) fn new(retained_bytes: usize, maximum_bytes: usize) -> Result<Self, RecordError> {
        let budget = Self {
            retained: retained_bytes,
            workspace: 0,
            maximum: maximum_bytes,
        };
        budget.check_additional(0)?;
        Ok(budget)
    }

    pub(super) fn charge_workspace(&mut self, bytes: usize) -> Result<(), RecordError> {
        self.check_additional(bytes)?;
        self.workspace = self.workspace.saturating_add(bytes);
        Ok(())
    }

    pub(super) fn retain(&mut self, bytes: usize) -> Result<(), RecordError> {
        self.check_additional(bytes)?;
        self.retained = self.retained.saturating_add(bytes);
        Ok(())
    }

    pub(super) const fn release_workspace(&mut self, bytes: usize) {
        self.workspace = self.workspace.saturating_sub(bytes);
    }

    pub(super) const fn overflow_error(&self) -> RecordError {
        RecordError::PlanTooLarge {
            bytes: usize::MAX,
            maximum: self.maximum,
        }
    }

    fn check_additional(&self, bytes: usize) -> Result<(), RecordError> {
        let Some(projected) = self
            .retained
            .checked_add(self.workspace)
            .and_then(|total| total.checked_add(bytes))
        else {
            return Err(RecordError::PlanTooLarge {
                bytes: usize::MAX,
                maximum: self.maximum,
            });
        };
        if projected > self.maximum {
            return Err(RecordError::PlanTooLarge {
                bytes: projected,
                maximum: self.maximum,
            });
        }
        Ok(())
    }
}

/// Build canonical sequence ordering, semantic receipts, and physical payload layouts
pub(super) fn prepare_record_groups(
    inputs: &[RecordMetadataInput<'_>],
    sequence_base: u64,
    terminal_sequence: Option<u64>,
    limits: RecordLimits,
    budget: &mut AssemblyPlanBudget,
) -> Result<PreparedRecordGroups, RecordError> {
    let (input_length, report_bytes) = validate_metadata_inputs(inputs, limits, Some(budget))?;
    prepare_record_groups_from_validated(
        inputs,
        input_length,
        report_bytes,
        sequence_base,
        terminal_sequence,
        limits,
        Some(budget),
    )
}

fn prepare_record_groups_from_validated(
    inputs: &[RecordMetadataInput<'_>],
    input_length: usize,
    mut report_bytes: usize,
    sequence_base: u64,
    terminal_sequence: Option<u64>,
    limits: RecordLimits,
    mut plan_budget: Option<&mut AssemblyPlanBudget>,
) -> Result<PreparedRecordGroups, RecordError> {
    let GroupedMetadataInputs {
        groups: grouped,
        workspace_bytes: grouping_workspace,
    } = group_metadata_inputs(inputs, limits, &mut plan_budget)?;
    let prepared_groups = prepare_groups(
        grouped,
        sequence_base,
        terminal_sequence,
        limits,
        &mut report_bytes,
        &mut plan_budget,
    );
    if let Some(budget) = plan_budget {
        budget.release_workspace(grouping_workspace);
    }
    let (groups, output_bytes) = prepared_groups?;
    Ok(PreparedRecordGroups {
        input_length,
        output_bytes,
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
        validate_report(input.bytes, input.report, input.input_sha256, limits)?;
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

fn validate_metadata_inputs(
    inputs: &[RecordMetadataInput<'_>],
    limits: RecordLimits,
    mut plan_budget: Option<&mut AssemblyPlanBudget>,
) -> Result<(usize, usize), RecordError> {
    let mut input_length = 0_usize;
    let mut record_count = 0_usize;
    let mut report_bytes = 0_usize;
    for (expected_input_index, input) in inputs.iter().enumerate() {
        if input.input_index != expected_input_index {
            return Err(RecordError::InvalidReport);
        }
        if input.input_length > limits.max_input_bytes {
            return Err(RecordError::InputTooLarge {
                length: input.input_length,
                maximum: limits.max_input_bytes,
            });
        }
        input_length =
            input_length
                .checked_add(input.input_length)
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
        record_count =
            record_count
                .checked_add(input.records.len())
                .ok_or(RecordError::TooManyRecords {
                    count: u64::MAX,
                    maximum: limits.max_records,
                })?;
        if record_count > limits.max_records {
            return Err(RecordError::TooManyRecords {
                count: u64::try_from(record_count).unwrap_or(u64::MAX),
                maximum: limits.max_records,
            });
        }
        let metadata_bytes = parsed_record_metadata_bytes(input.records);
        if let Some(budget) = plan_budget.as_deref_mut() {
            budget.charge_workspace(metadata_bytes)?;
        }
        report_bytes =
            report_bytes
                .checked_add(metadata_bytes)
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
        validate_record_ranges(input.input_length, input.records, limits)?;
    }
    Ok((input_length, report_bytes))
}

fn validate_record_ranges(
    input_length: usize,
    records: &[ParsedRecord],
    limits: RecordLimits,
) -> Result<(), RecordError> {
    for (expected_index, record) in records.iter().enumerate() {
        let record_valid = record.index == expected_index
            && record.record.start <= record.payload.start
            && record.payload.start <= record.payload.end
            && record.payload.end == record.record.end
            && record.record.end <= input_length
            && !record.identifier.is_empty()
            && record.identifier.len() <= limits.max_identifier_bytes;
        if !record_valid {
            return Err(RecordError::InvalidReport);
        }
    }
    Ok(())
}

struct GroupedMetadataInputs<'a> {
    groups: BTreeMap<&'a [u8], Vec<RecordReference<'a>>>,
    workspace_bytes: usize,
}

fn group_metadata_inputs<'a>(
    inputs: &'a [RecordMetadataInput<'a>],
    limits: RecordLimits,
    plan_budget: &mut Option<&mut AssemblyPlanBudget>,
) -> Result<GroupedMetadataInputs<'a>, RecordError> {
    // Borrow identifier keys so grouping does not make another copy per record
    let mut grouped = BTreeMap::<&'a [u8], Vec<RecordReference<'a>>>::new();
    let mut workspace_bytes = 0_usize;
    for input in inputs {
        for record in input.records {
            let identifier = record.identifier.as_slice();
            let group_count = grouped.len();
            let reference_bytes = std::mem::size_of::<RecordReference<'_>>();
            match grouped.entry(identifier) {
                Entry::Occupied(entry) => {
                    if let Some(budget) = plan_budget.as_deref_mut() {
                        budget.charge_workspace(reference_bytes)?;
                    }
                    workspace_bytes = workspace_bytes.saturating_add(reference_bytes);
                    let group = entry.into_mut();
                    group
                        .try_reserve(1)
                        .map_err(|_| RecordError::AllocationFailed)?;
                    group.push(RecordReference {
                        input_index: input.input_index,
                        record,
                    });
                }
                Entry::Vacant(entry) => {
                    if group_count >= limits.max_groups {
                        return Err(RecordError::TooManyGroups {
                            count: group_count.saturating_add(1),
                            maximum: limits.max_groups,
                        });
                    }
                    let entry_bytes = std::mem::size_of::<&[u8]>()
                        .saturating_add(std::mem::size_of::<Vec<RecordReference<'_>>>())
                        .saturating_add(4_usize.saturating_mul(std::mem::size_of::<usize>()));
                    if let Some(budget) = plan_budget.as_deref_mut() {
                        let new_workspace = entry_bytes
                            .checked_add(reference_bytes)
                            .ok_or_else(|| budget.overflow_error())?;
                        budget.charge_workspace(new_workspace)?;
                    }
                    workspace_bytes = workspace_bytes
                        .saturating_add(entry_bytes)
                        .saturating_add(reference_bytes);
                    let mut references = Vec::new();
                    references
                        .try_reserve_exact(1)
                        .map_err(|_| RecordError::AllocationFailed)?;
                    references.push(RecordReference {
                        input_index: input.input_index,
                        record,
                    });
                    entry.insert(references);
                }
            }
        }
    }
    Ok(GroupedMetadataInputs {
        groups: grouped,
        workspace_bytes,
    })
}

fn prepare_groups(
    grouped: BTreeMap<&[u8], Vec<RecordReference<'_>>>,
    sequence_base: u64,
    terminal_sequence: Option<u64>,
    limits: RecordLimits,
    report_bytes: &mut usize,
    plan_budget: &mut Option<&mut AssemblyPlanBudget>,
) -> Result<(Vec<PreparedGroup>, usize), RecordError> {
    let group_storage = std::mem::size_of::<RecordGroupOutcome>()
        .checked_mul(grouped.len())
        .ok_or(RecordError::ReportTooLarge {
            bytes: usize::MAX,
            maximum: limits.max_report_bytes,
        })?;
    charge_report_bytes(report_bytes, group_storage, limits, plan_budget)?;
    if let Some(budget) = plan_budget.as_deref_mut() {
        let prepared_group_bytes = std::mem::size_of::<PreparedGroup>()
            .checked_mul(grouped.len())
            .ok_or(RecordError::PlanTooLarge {
                bytes: usize::MAX,
                maximum: budget.maximum,
            })?;
        budget.charge_workspace(prepared_group_bytes)?;
    }

    let mut groups = Vec::new();
    groups
        .try_reserve_exact(grouped.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    let mut total_output = 0_usize;
    let completion = SequenceCompletion {
        sequence_base,
        terminal_sequence,
    };
    for (identifier, mut records) in grouped {
        // Explicit source order makes equal sequence handling reproducible
        records.sort_unstable_by_key(|record| {
            (
                record.record.sequence,
                record.input_index,
                record.record.index,
            )
        });
        let group = prepare_group(
            identifier,
            &records,
            completion,
            limits,
            total_output,
            report_bytes,
            plan_budget,
        )?;
        total_output =
            total_output
                .checked_add(group.output_length)
                .ok_or(RecordError::OutputTooLarge {
                    length: usize::MAX,
                    maximum: limits.max_output_bytes,
                })?;
        groups.push(group);
    }
    Ok((groups, total_output))
}

#[derive(Clone, Copy)]
struct RecordReference<'a> {
    input_index: usize,
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
    trusted_input_sha256: Option<&str>,
    limits: RecordLimits,
) -> Result<(), RecordError> {
    if bytes.len() > limits.max_input_bytes {
        return Err(RecordError::InputTooLarge {
            length: bytes.len(),
            maximum: limits.max_input_bytes,
        });
    }
    if bytes.len() != parsed.input_length {
        return Err(RecordError::InvalidReport);
    }
    let digest_matches = trusted_input_sha256.map_or_else(
        || sha256(bytes) == parsed.input_sha256,
        |trusted_digest| trusted_digest == parsed.input_sha256,
    );
    if !digest_matches {
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
    plan_budget: &mut Option<&mut AssemblyPlanBudget>,
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
    if let Some(budget) = plan_budget.as_deref_mut() {
        budget.charge_workspace(additional)?;
    }
    *used = total;
    Ok(())
}

fn sequence_bounds(records: &[RecordReference<'_>]) -> Result<(u64, u64), RecordError> {
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

fn prepare_group(
    identifier: &[u8],
    records: &[RecordReference<'_>],
    completion: SequenceCompletion,
    limits: RecordLimits,
    prior_output: usize,
    report_bytes: &mut usize,
    plan_budget: &mut Option<&mut AssemblyPlanBudget>,
) -> Result<PreparedGroup, RecordError> {
    charge_report_bytes(report_bytes, identifier.len(), limits, plan_budget)?;
    let diagnostics = sequence_diagnostics(records, completion, limits, report_bytes, plan_budget)?;
    let mapping_bytes = std::mem::size_of::<RecordAssemblyPart>()
        .checked_mul(records.len())
        .ok_or(RecordError::ReportTooLarge {
            bytes: usize::MAX,
            maximum: limits.max_report_bytes,
        })?;
    charge_report_bytes(report_bytes, mapping_bytes, limits, plan_budget)?;
    charge_report_bytes(
        report_bytes,
        std::mem::size_of::<[u8; 32]>() * 2,
        limits,
        plan_budget,
    )?;
    let (layout, parts, output_length) =
        prepare_layout(records, limits, prior_output, plan_budget)?;
    let receipt = build_group_receipt(identifier, diagnostics, output_length, parts)?;
    Ok(PreparedGroup {
        receipt,
        layout,
        output_length,
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
    records: &[RecordReference<'_>],
    completion: SequenceCompletion,
    limits: RecordLimits,
    report_bytes: &mut usize,
    plan_budget: &mut Option<&mut AssemblyPlanBudget>,
) -> Result<GroupDiagnostics, RecordError> {
    let (minimum_sequence, maximum_sequence) = sequence_bounds(records)?;
    let issues = sequence_issues(records, completion, limits, report_bytes, plan_budget)?;
    let counts = MissingSequenceCounts {
        maximum_observed_sequence: maximum_sequence,
        unique_in_expected_range: issues.unique_in_expected_range,
    };
    let (missing_sequence_count, missing_sequences) = missing_sequences(
        records,
        completion,
        counts,
        report_bytes,
        limits,
        plan_budget,
    )?;
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
    output_length: usize,
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
        output_length: Some(output_length),
        output_sha256: None,
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
    records: &[RecordReference<'_>],
    completion: SequenceCompletion,
    limits: RecordLimits,
    report_bytes: &mut usize,
    plan_budget: &mut Option<&mut AssemblyPlanBudget>,
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
                    plan_budget,
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
                plan_budget,
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
                plan_budget,
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
    records: &[RecordReference<'_>],
    completion: SequenceCompletion,
    counts: MissingSequenceCounts,
    report_bytes: &mut usize,
    limits: RecordLimits,
    plan_budget: &mut Option<&mut AssemblyPlanBudget>,
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
    charge_report_bytes(report_bytes, example_bytes, limits, plan_budget)?;
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
    plan_budget: &mut Option<&mut AssemblyPlanBudget>,
) -> Result<(), RecordError> {
    if examples.len() < maximum {
        charge_report_bytes(
            report_bytes,
            std::mem::size_of::<u64>(),
            limits,
            plan_budget,
        )?;
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

fn prepare_layout(
    records: &[RecordReference<'_>],
    limits: RecordLimits,
    prior_output: usize,
    plan_budget: &mut Option<&mut AssemblyPlanBudget>,
) -> Result<(Vec<PhysicalPart>, Vec<RecordAssemblyPart>, usize), RecordError> {
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

    if let Some(budget) = plan_budget.as_deref_mut() {
        let layout_bytes = std::mem::size_of::<PhysicalPart>()
            .checked_mul(records.len())
            .ok_or(RecordError::PlanTooLarge {
                bytes: usize::MAX,
                maximum: budget.maximum,
            })?;
        budget.charge_workspace(layout_bytes)?;
    }
    let mut layout = Vec::new();
    layout
        .try_reserve_exact(records.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    let mut parts = Vec::new();
    parts
        .try_reserve_exact(records.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    let mut output_offset = 0_usize;
    for record in records {
        let payload_length = record.record.payload.end - record.record.payload.start;
        let output_end =
            output_offset
                .checked_add(payload_length)
                .ok_or(RecordError::OutputTooLarge {
                    length: usize::MAX,
                    maximum: limits.max_output_bytes,
                })?;
        layout.push(PhysicalPart {
            input_index: record.input_index,
            start: record.record.payload.start,
            end: record.record.payload.end,
        });
        parts.push(RecordAssemblyPart {
            input_index: record.input_index,
            record_index: record.record.index,
            sequence: record.record.sequence,
            input: record.record.payload,
            output: crate::protocol::ByteRange {
                start: output_offset,
                end: output_end,
            },
        });
        output_offset = output_end;
    }
    Ok((layout, parts, length))
}

/// Materialize one prepared layout through the same byte-range path used by the public assembler
pub(super) trait LayoutInputs {
    fn source_bytes(&self, input_index: usize) -> Option<&[u8]>;
}

impl LayoutInputs for [RecordAssemblyInput<'_>] {
    fn source_bytes(&self, input_index: usize) -> Option<&[u8]> {
        self.get(input_index).map(|input| input.bytes)
    }
}

impl LayoutInputs for [RecordInput<'_>] {
    fn source_bytes(&self, input_index: usize) -> Option<&[u8]> {
        self.get(input_index).map(|input| input.bytes)
    }
}

pub(super) fn materialize_layout<I: LayoutInputs + ?Sized>(
    inputs: &I,
    layout: &[PhysicalPart],
    output_length: usize,
) -> Result<Vec<u8>, RecordError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_length)
        .map_err(|_| RecordError::AllocationFailed)?;
    for part in layout {
        let input = inputs
            .source_bytes(part.input_index)
            .ok_or(RecordError::InvalidReport)?;
        let payload = input
            .get(part.start..part.end)
            .ok_or(RecordError::InvalidReport)?;
        output.extend_from_slice(payload);
    }
    if output.len() != output_length {
        return Err(RecordError::InvalidReport);
    }
    Ok(output)
}

pub(super) fn finish_receipt(receipt: &mut RecordGroupReceipt, output: &[u8]) {
    receipt.output_length = Some(output.len());
    receipt.output_sha256 = Some(sha256(output));
}

pub(super) fn finish_receipt_identity(
    receipt: &mut RecordGroupReceipt,
    output_length: usize,
    output_sha256: &str,
) {
    receipt.output_length = Some(output_length);
    receipt.output_sha256 = Some(output_sha256.to_owned());
}
