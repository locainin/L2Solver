use super::super::selected;
use crate::arguments::RecordCountSource;
use l2_workbench::{
    evidence::Case,
    protocol::{
        self, ByteOrder, ByteRange, RecordAssemblyInput, RecordAssemblyOutcome, RecordCount,
        RecordError, RecordLimits, RecordParseReport, RecordSchema,
    },
    sha256,
};
use serde::Serialize;
use std::{error::Error, io};

#[derive(Clone, Debug, Serialize)]
pub(super) struct CountSourceReceipt {
    pub(super) node: u64,
    range: ByteRange,
    byte_order: ByteOrder,
    value: u64,
    range_sha256: String,
}

#[derive(Debug, Serialize)]
struct InputReceipt<'a> {
    input_index: usize,
    input_node: u64,
    input_length: usize,
    input_sha256: &'a str,
    count_source: Option<&'a CountSourceReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parse: Option<&'a RecordParseReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_error: Option<String>,
}

#[derive(Serialize)]
struct RecordsReceipt<'a> {
    /// Single-input compatibility fields remain populated for existing consumers
    input_node: Option<u64>,
    input_length: Option<usize>,
    input_sha256: Option<&'a str>,
    parse: Option<&'a RecordParseReport>,
    inputs: Vec<InputReceipt<'a>>,
    /// Maps each compact assembly input position to its ordered receipt input slot
    assembly_input_indexes: &'a [usize],
    assembly: protocol::RecordAssemblyReport<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    assembly_complete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejected_input_count: Option<usize>,
    interpretation: &'static str,
}

pub(super) struct InputDescriptor {
    pub(super) node: u64,
    pub(super) count_source: Option<CountSourceReceipt>,
    input_length: usize,
    input_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::workbench) struct RejectedInput {
    pub(in crate::workbench) input_index: usize,
    pub(in crate::workbench) input_node_id: u64,
    pub(in crate::workbench) error: RecordError,
}

pub(super) struct Analysis {
    pub(super) inputs: Vec<InputDescriptor>,
    pub(super) assembly_input_indexes: Vec<usize>,
    pub(super) assembly: RecordAssemblyOutcome,
    pub(super) receipt: Vec<u8>,
    pub(super) rejected_inputs: Vec<RejectedInput>,
}

pub(super) fn analyze(
    case: &Case,
    selected_node_ids: &[u64],
    count_source_options: Option<&[RecordCountSource]>,
    schema: &RecordSchema,
    limits: RecordLimits,
) -> Result<Analysis, Box<dyn Error>> {
    validate_count_source_cardinality(selected_node_ids, count_source_options)?;
    let selected_inputs = selected_node_ids
        .iter()
        .map(|node| selected::bytes(case, *node).map(|(_, bytes)| (*node, bytes)))
        .collect::<Result<Vec<_>, _>>()?;
    enforce_aggregate_input_limit(&selected_inputs, limits)?;
    let count_sources = decode_count_sources(case, count_source_options)?;
    let parses = parse_inputs(&selected_inputs, &count_sources, schema, limits)?;
    let assembly_inputs = selected_inputs
        .iter()
        .zip(&parses)
        .map(|((_, bytes), parse)| RecordAssemblyInput::new(bytes, parse))
        .collect::<Vec<_>>();
    let assembly_input_indexes = (0..selected_inputs.len()).collect::<Vec<_>>();
    let assembly = protocol::assemble_record_groups_from_inputs(&assembly_inputs, limits)?;
    let descriptors = describe_inputs(&selected_inputs, count_sources);
    let optional_parses = parses.into_iter().map(Some).collect::<Vec<_>>();
    let receipt = serialize_receipt(
        &descriptors,
        &optional_parses,
        &[],
        &assembly_input_indexes,
        &assembly,
        limits,
    )?;
    Ok(Analysis {
        inputs: descriptors,
        assembly_input_indexes,
        assembly,
        receipt,
        rejected_inputs: Vec::new(),
    })
}

pub(super) fn analyze_recovery(
    case: &Case,
    selected_node_ids: &[u64],
    count_source_options: Option<&[RecordCountSource]>,
    schema: &RecordSchema,
    limits: RecordLimits,
) -> Result<Analysis, Box<dyn Error>> {
    validate_count_source_cardinality(selected_node_ids, count_source_options)?;
    let selected_inputs = selected_node_ids
        .iter()
        .map(|node| selected::bytes(case, *node).map(|(_, bytes)| (*node, bytes)))
        .collect::<Result<Vec<_>, _>>()?;
    enforce_aggregate_input_limit(&selected_inputs, limits)?;
    let count_sources = decode_count_sources(case, count_source_options)?;
    let (parses, rejected_inputs) =
        parse_input_slots(&selected_inputs, &count_sources, schema, limits, true)?;
    let mut assembly_inputs = Vec::new();
    let mut assembly_input_indexes = Vec::new();
    assembly_inputs
        .try_reserve_exact(parses.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    assembly_input_indexes
        .try_reserve_exact(parses.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    for (input_index, ((_, bytes), parse)) in selected_inputs.iter().zip(&parses).enumerate() {
        if let Some(parse) = parse {
            assembly_inputs.push(RecordAssemblyInput::new(bytes, parse));
            assembly_input_indexes.push(input_index);
        }
    }
    let assembly = protocol::assemble_record_groups_from_inputs(&assembly_inputs, limits)?;
    let descriptors = describe_inputs(&selected_inputs, count_sources);
    let receipt = serialize_receipt(
        &descriptors,
        &parses,
        &rejected_inputs,
        &assembly_input_indexes,
        &assembly,
        limits,
    )?;
    Ok(Analysis {
        inputs: descriptors,
        assembly_input_indexes,
        assembly,
        receipt,
        rejected_inputs,
    })
}

fn parse_inputs(
    inputs: &[(u64, &[u8])],
    count_sources: &[CountSourceReceipt],
    schema: &RecordSchema,
    limits: RecordLimits,
) -> Result<Vec<RecordParseReport>, RecordError> {
    let (parses, _) = parse_input_slots(inputs, count_sources, schema, limits, false)?;
    parses
        .into_iter()
        .map(|parse| parse.ok_or(RecordError::InvalidReport))
        .collect()
}

fn parse_input_slots(
    inputs: &[(u64, &[u8])],
    count_sources: &[CountSourceReceipt],
    schema: &RecordSchema,
    limits: RecordLimits,
    continue_after_structural_rejection: bool,
) -> Result<(Vec<Option<RecordParseReport>>, Vec<RejectedInput>), RecordError> {
    // Parse each source independently so bytes cannot spill into another part
    let mut parses = Vec::new();
    parses
        .try_reserve_exact(inputs.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    let mut rejected_inputs = Vec::new();
    let mut records_used = 0_usize;
    let mut report_bytes_used = 0_usize;
    for (input_index, (_, bytes)) in inputs.iter().enumerate() {
        let has_records = part_has_records(bytes, schema, count_sources.get(input_index));
        if records_used >= limits.max_records && has_records != Some(false) {
            return Err(RecordError::TooManyRecords {
                count: u64::try_from(records_used)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
                maximum: limits.max_records,
            });
        }
        if report_bytes_used >= limits.max_report_bytes && has_records != Some(false) {
            return Err(RecordError::ReportTooLarge {
                bytes: limits.max_report_bytes.saturating_add(1),
                maximum: limits.max_report_bytes,
            });
        }

        let mut part_schema = schema.clone();
        if let Some(source) = count_sources.get(input_index) {
            part_schema.count = RecordCount::Exact {
                records: source.value,
            };
        }
        let part_limits = remaining_parse_limits(limits, records_used, report_bytes_used);
        let parse = match protocol::parse_records_with_limits(bytes, &part_schema, part_limits) {
            Ok(parse) => parse,
            Err(error)
                if continue_after_structural_rejection && is_structural_rejection(&error) =>
            {
                rejected_inputs
                    .try_reserve(1)
                    .map_err(|_| RecordError::AllocationFailed)?;
                let input_node_id = inputs
                    .get(input_index)
                    .map(|(node_id, _)| *node_id)
                    .ok_or(RecordError::InvalidReport)?;
                rejected_inputs.push(RejectedInput {
                    input_index,
                    input_node_id,
                    error,
                });
                parses.push(None);
                continue;
            }
            Err(error) => return Err(error),
        };
        records_used =
            records_used
                .checked_add(parse.records().len())
                .ok_or(RecordError::TooManyRecords {
                    count: u64::MAX,
                    maximum: limits.max_records,
                })?;
        if records_used > limits.max_records {
            return Err(RecordError::TooManyRecords {
                count: u64::try_from(records_used).unwrap_or(u64::MAX),
                maximum: limits.max_records,
            });
        }
        report_bytes_used = report_bytes_used
            .checked_add(parse.metadata_bytes())
            .ok_or(RecordError::ReportTooLarge {
                bytes: usize::MAX,
                maximum: limits.max_report_bytes,
            })?;
        if report_bytes_used > limits.max_report_bytes {
            return Err(RecordError::ReportTooLarge {
                bytes: report_bytes_used,
                maximum: limits.max_report_bytes,
            });
        }
        parses.push(Some(parse));
    }
    Ok((parses, rejected_inputs))
}

const fn is_structural_rejection(error: &RecordError) -> bool {
    matches!(
        error,
        RecordError::TruncatedPreamble { .. }
            | RecordError::TruncatedRecord { .. }
            | RecordError::InvalidRecordLength { .. }
            | RecordError::LengthOverflow { .. }
            | RecordError::TrailingBytes { .. }
    )
}

fn part_has_records(
    bytes: &[u8],
    schema: &RecordSchema,
    count_source: Option<&CountSourceReceipt>,
) -> Option<bool> {
    if let Some(source) = count_source {
        return Some(source.value != 0);
    }
    match schema.count {
        RecordCount::UntilEnd => bytes
            .len()
            .checked_sub(schema.records_offset)
            .map(|remaining| remaining != 0),
        RecordCount::Exact { records } => Some(records != 0),
        RecordCount::Field { field } => {
            let end = field.offset.checked_add(field.width)?;
            let count = bytes.get(field.offset..end)?;
            Some(decode_unsigned(count, field.byte_order) != 0)
        }
    }
}

fn describe_inputs(
    selected_inputs: &[(u64, &[u8])],
    count_sources: Vec<CountSourceReceipt>,
) -> Vec<InputDescriptor> {
    let mut count_sources = count_sources.into_iter();
    selected_inputs
        .iter()
        .map(|(node, bytes)| InputDescriptor {
            node: *node,
            count_source: count_sources.next(),
            input_length: bytes.len(),
            input_sha256: sha256(bytes),
        })
        .collect()
}

fn serialize_receipt(
    descriptors: &[InputDescriptor],
    parses: &[Option<RecordParseReport>],
    rejected_inputs: &[RejectedInput],
    assembly_input_indexes: &[usize],
    assembly: &RecordAssemblyOutcome,
    limits: RecordLimits,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let single_input = descriptors.len() == 1 && parses.len() == 1;
    let input_receipt_storage = std::mem::size_of::<InputReceipt<'_>>()
        .checked_mul(descriptors.len())
        .ok_or(RecordError::ReportTooLarge {
            bytes: usize::MAX,
            maximum: limits.max_report_bytes,
        })?;
    let report_storage = assembly
        .report_bytes()
        .checked_add(input_receipt_storage)
        .ok_or(RecordError::ReportTooLarge {
            bytes: usize::MAX,
            maximum: limits.max_report_bytes,
        })?;
    if report_storage > limits.max_report_bytes {
        return Err(RecordError::ReportTooLarge {
            bytes: report_storage,
            maximum: limits.max_report_bytes,
        }
        .into());
    }

    if assembly_input_indexes.len() != assembly.report().input_count
        || assembly_input_indexes
            .iter()
            .any(|input_index| *input_index >= descriptors.len())
    {
        return Err(RecordError::InvalidReport.into());
    }
    let input_receipts = build_input_receipts(descriptors, parses, rejected_inputs, single_input)?;
    let single_descriptor = single_input.then(|| descriptors.first()).flatten();
    let single_parse = single_input
        .then(|| parses.first().and_then(Option::as_ref))
        .flatten();
    let receipt = RecordsReceipt {
        input_node: single_descriptor.map(|input| input.node),
        input_length: single_descriptor.map(|input| input.input_length),
        input_sha256: single_descriptor.map(|input| input.input_sha256.as_str()),
        parse: single_parse,
        inputs: input_receipts,
        assembly_input_indexes,
        assembly: assembly.report(),
        assembly_complete: (!rejected_inputs.is_empty()).then_some(false),
        rejected_input_count: (!rejected_inputs.is_empty()).then_some(rejected_inputs.len()),
        interpretation: "caller_supplied_record_schema",
    };

    // Count first so oversized JSON is rejected before its output buffer is allocated
    let mut counter = CountingWriter {
        maximum: limits.max_report_bytes - report_storage,
        ..CountingWriter::default()
    };
    if let Err(error) = serde_json::to_writer(&mut counter, &receipt) {
        if !counter.exceeded {
            return Err(error.into());
        }
        let attempted_report_bytes = report_storage.saturating_add(counter.bytes);
        return Err(RecordError::ReportTooLarge {
            bytes: attempted_report_bytes,
            maximum: limits.max_report_bytes,
        }
        .into());
    }

    let mut serialized = Vec::new();
    serialized
        .try_reserve_exact(counter.bytes)
        .map_err(|_| RecordError::AllocationFailed)?;
    serde_json::to_writer(&mut serialized, &receipt)?;
    debug_assert_eq!(serialized.len(), counter.bytes);
    Ok(serialized)
}

fn build_input_receipts<'a>(
    descriptors: &'a [InputDescriptor],
    parses: &'a [Option<RecordParseReport>],
    rejected_inputs: &[RejectedInput],
    single_input: bool,
) -> Result<Vec<InputReceipt<'a>>, RecordError> {
    if descriptors.len() != parses.len() {
        return Err(RecordError::InvalidReport);
    }
    let mut receipts = Vec::new();
    receipts
        .try_reserve_exact(descriptors.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    let mut rejected = rejected_inputs.iter().peekable();
    for (input_index, (input, parse)) in descriptors.iter().zip(parses).enumerate() {
        if rejected
            .peek()
            .is_some_and(|item| item.input_index < input_index)
        {
            return Err(RecordError::InvalidReport);
        }
        let parse_error = rejected
            .peek()
            .is_some_and(|item| item.input_index == input_index)
            .then(|| rejected.next().map(|item| format!("{:?}", item.error)))
            .flatten();
        receipts.push(InputReceipt {
            input_index,
            input_node: input.node,
            input_length: input.input_length,
            input_sha256: &input.input_sha256,
            count_source: input.count_source.as_ref(),
            parse: (!single_input).then_some(parse.as_ref()).flatten(),
            parse_error,
        });
    }
    if rejected.next().is_some() {
        return Err(RecordError::InvalidReport);
    }
    Ok(receipts)
}

#[derive(Default)]
struct CountingWriter {
    bytes: usize,
    maximum: usize,
    exceeded: bool,
}

impl io::Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(total) = self.bytes.checked_add(bytes.len()) else {
            self.bytes = usize::MAX;
            self.exceeded = true;
            return Err(io::Error::other("record receipt byte count overflowed"));
        };
        if total > self.maximum {
            self.bytes = total;
            self.exceeded = true;
            return Err(io::Error::other("record receipt exceeds its report budget"));
        }
        self.bytes = total;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn validate_count_source_cardinality(
    selected_node_ids: &[u64],
    count_sources: Option<&[RecordCountSource]>,
) -> Result<(), Box<dyn Error>> {
    if count_sources.is_some_and(|sources| sources.len() != selected_node_ids.len()) {
        return Err(format!(
            "count source count must be zero or match the {} selected input nodes",
            selected_node_ids.len()
        )
        .into());
    }
    Ok(())
}

fn enforce_aggregate_input_limit(
    inputs: &[(u64, &[u8])],
    limits: RecordLimits,
) -> Result<(), RecordError> {
    let length = inputs.iter().try_fold(0_usize, |total, (_, bytes)| {
        total
            .checked_add(bytes.len())
            .ok_or(RecordError::InputTooLarge {
                length: usize::MAX,
                maximum: limits.max_input_bytes,
            })
    })?;
    if length > limits.max_input_bytes {
        return Err(RecordError::InputTooLarge {
            length,
            maximum: limits.max_input_bytes,
        });
    }
    Ok(())
}

fn remaining_parse_limits(
    limits: RecordLimits,
    records_used: usize,
    report_bytes_used: usize,
) -> RecordLimits {
    RecordLimits {
        max_records: limits.max_records.saturating_sub(records_used).max(1),
        max_report_bytes: limits
            .max_report_bytes
            .saturating_sub(report_bytes_used)
            .max(1),
        ..limits
    }
}

fn decode_count_sources(
    case: &Case,
    sources: Option<&[RecordCountSource]>,
) -> Result<Vec<CountSourceReceipt>, Box<dyn Error>> {
    let sources = sources.unwrap_or_default();
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(sources.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    for source in sources {
        let (_, bytes) = selected::bytes(case, source.node)?;
        let end = source
            .offset
            .checked_add(source.width)
            .ok_or("count source range cannot be represented")?;
        let field = bytes.get(source.offset..end).ok_or_else(|| {
            format!(
                "count source node {} range {}..{} exceeds its {} retained bytes",
                source.node,
                source.offset,
                end,
                bytes.len()
            )
        })?;
        decoded.push(CountSourceReceipt {
            node: source.node,
            range: ByteRange {
                start: source.offset,
                end,
            },
            byte_order: source.byte_order,
            value: decode_unsigned(field, source.byte_order),
            range_sha256: l2_workbench::sha256(field),
        });
    }
    Ok(decoded)
}

fn decode_unsigned(bytes: &[u8], byte_order: ByteOrder) -> u64 {
    match byte_order {
        ByteOrder::BigEndian => bytes
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)),
        ByteOrder::LittleEndian => bytes
            .iter()
            .rev()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)),
    }
}
