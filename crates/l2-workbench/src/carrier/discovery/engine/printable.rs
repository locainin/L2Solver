//! Printable-run extraction and exact source-bit mappings

use super::DiscoveryResultSink;
use super::{
    super::{
        model::{DiscoveryError, DiscoverySample, Partition, PrintableRun, SourceBitMapping},
        plan::WorkUnit,
    },
    execution::SummarySpec,
    receipts::clone_string,
};
use crate::{evidence::SourceRange, serialization::CountWriter};
use serde::Serialize;
use std::io::Write;

#[derive(Serialize)]
struct SourceRangeReceiptRef<'a> {
    source: &'a str,
    packet: Option<u64>,
    offset: u64,
    length: u64,
}

#[derive(Serialize)]
struct SourceBitMappingReceiptRef<'a> {
    output_bit_start: usize,
    bit_count: usize,
    source: SourceRangeReceiptRef<'a>,
    source_bit_offset: u8,
    source_stride_bits: u8,
}

#[derive(Serialize)]
struct PrintableRunReceiptRef<'a, 'source> {
    run_id: usize,
    candidate_id: usize,
    partition: Partition,
    unit_index: usize,
    sample_ids: &'a [u64],
    output_offset: usize,
    text: &'a str,
    source_bit_mappings: &'a [SourceBitMappingReceiptRef<'source>],
}

pub(super) struct PrintableRunBudget {
    pub(super) maximum: usize,
    pub(super) used: usize,
    pub(super) next_id: usize,
    pub(super) attempted: usize,
    pub(super) complete: bool,
    pub(super) retain_runs: bool,
}

pub(super) struct PrintableRunContext<'a> {
    pub(super) samples: &'a [DiscoverySample<'a>],
    pub(super) unit_index: usize,
    pub(super) unit: &'a WorkUnit,
    pub(super) output: &'a [u8],
    pub(super) spec: SummarySpec<'a>,
}

pub(super) fn append_printable_runs(
    context: &PrintableRunContext<'_>,
    budget: &mut PrintableRunBudget,
    retained_runs: &mut Vec<PrintableRun>,
    omitted_runs: &mut usize,
    sink: &mut Option<&mut dyn DiscoveryResultSink>,
) -> Result<(), DiscoveryError> {
    let minimum_run_bytes = context.spec.minimum_run_bytes;
    for range in printable_ranges(context.output).filter(|range| range.len() >= minimum_run_bytes) {
        budget.attempted = budget
            .attempted
            .checked_add(1)
            .ok_or(DiscoveryError::InvalidPlan(
                "printable run count overflowed",
            ))?;
        if sink
            .as_ref()
            .is_some_and(|observer| !observer.records_receipts())
        {
            continue;
        }
        let remaining_budget = budget.maximum.saturating_sub(budget.used);
        let (run, encoded_bytes) = build_printable_run(
            context,
            range,
            budget.next_id,
            remaining_budget,
            !retained_runs.is_empty(),
        )?;
        if encoded_bytes.is_none() && sink.is_none() {
            *omitted_runs = omitted_runs
                .checked_add(1)
                .ok_or(DiscoveryError::InvalidSelection)?;
            budget.complete = false;
            continue;
        }
        budget.next_id = budget
            .next_id
            .checked_add(1)
            .ok_or(DiscoveryError::InvalidPlan("printable run ID overflowed"))?;
        if let Some(observer) = sink.as_mut() {
            observer.printable_run(&run)?;
        }
        budget.used = budget
            .used
            .checked_add(encoded_bytes.unwrap_or(0))
            .ok_or(DiscoveryError::InvalidSelection)?;
        if budget.retain_runs {
            retained_runs.push(run);
        }
    }
    Ok(())
}

fn build_printable_run(
    context: &PrintableRunContext<'_>,
    range: std::ops::Range<usize>,
    run_id: usize,
    remaining_budget: usize,
    separator: bool,
) -> Result<(PrintableRun, Option<usize>), DiscoveryError> {
    let SummarySpec {
        width,
        phase,
        start_offset,
        partition,
        candidate_id,
        ..
    } = context.spec;
    let window = source_window(
        range.start,
        range.len(),
        width,
        start_offset,
        context.unit.input_length,
    )?;
    let sample_ids = unit_sample_ids(context.samples, context.unit)?;
    let mappings = source_mappings_for_run(
        context.samples,
        context.unit,
        window.start,
        window.end,
        phase,
        window.start,
    )?;
    let source_text = context
        .output
        .get(range.clone())
        .ok_or(DiscoveryError::InvalidSelection)?;
    let source_text =
        std::str::from_utf8(source_text).map_err(|_| DiscoveryError::InvalidSelection)?;
    let receipt = PrintableRunReceiptRef {
        run_id,
        candidate_id,
        partition,
        unit_index: context.unit_index,
        sample_ids: &sample_ids,
        output_offset: range.start,
        text: source_text,
        source_bit_mappings: &mappings,
    };
    let encoded_bytes = receipt_size(&receipt, remaining_budget, separator);
    let run = PrintableRun {
        run_id,
        candidate_id,
        partition,
        unit_index: context.unit_index,
        sample_ids,
        output_offset: range.start,
        text: clone_string(source_text)?,
        source_bit_mappings: own_source_mappings(&mappings)?,
    };
    Ok((run, encoded_bytes))
}

fn receipt_size(value: &impl Serialize, remaining_budget: usize, separator: bool) -> Option<usize> {
    let mut writer = CountWriter::new(remaining_budget);
    if separator {
        writer.write_all(b",").ok()?;
    }
    serde_json::to_writer(&mut writer, value).ok()?;
    Some(writer.written())
}

fn printable_ranges(output: &[u8]) -> impl Iterator<Item = std::ops::Range<usize>> + '_ {
    output
        .split_inclusive(|byte| !is_printable(*byte))
        .scan(0, |cursor, chunk| {
            let start = *cursor;
            *cursor += chunk.len();
            let length =
                chunk.len() - usize::from(chunk.last().is_some_and(|byte| !is_printable(*byte)));
            Some(start..start + length)
        })
}
fn source_window(
    start: usize,
    length: usize,
    width: u8,
    offset: usize,
    input_length: usize,
) -> Result<std::ops::Range<usize>, DiscoveryError> {
    let error = || DiscoveryError::InvalidPlan("printable source mapping overflowed");
    let beginning = start
        .checked_mul(usize::from(width))
        .and_then(|n| offset.checked_add(n))
        .ok_or_else(error)?;
    let end = start
        .checked_add(length)
        .and_then(|n| n.checked_mul(usize::from(width)))
        .and_then(|n| offset.checked_add(n))
        .ok_or_else(error)?
        .min(input_length);
    Ok(beginning..end)
}
fn unit_sample_ids(
    samples: &[DiscoverySample<'_>],
    unit: &WorkUnit,
) -> Result<Vec<u64>, DiscoveryError> {
    let mut ids = Vec::new();
    ids.try_reserve_exact(unit.sample_indexes.len())
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    for index in &unit.sample_indexes {
        ids.push(
            samples
                .get(*index)
                .ok_or(DiscoveryError::InvalidSelection)?
                .id,
        );
    }
    Ok(ids)
}

fn count_source_mappings(
    samples: &[DiscoverySample<'_>],
    unit: &WorkUnit,
    source_start: usize,
    source_end: usize,
) -> Result<usize, DiscoveryError> {
    let mut count = 0_usize;
    let mut unit_offset = 0_usize;
    for sample_index in &unit.sample_indexes {
        let sample = samples
            .get(*sample_index)
            .ok_or(DiscoveryError::InvalidSelection)?;
        let sample_end = unit_offset
            .checked_add(sample.bytes.len())
            .ok_or(DiscoveryError::InvalidSelection)?;
        let overlap_start = source_start.max(unit_offset);
        let overlap_end = source_end.min(sample_end);
        if overlap_start < overlap_end {
            let local_start = overlap_start - unit_offset;
            let local_end = overlap_end - unit_offset;
            for mapping in &sample.mappings {
                let map_length = usize::try_from(mapping.range.length)
                    .map_err(|_| DiscoveryError::InvalidSelection)?;
                let map_end = mapping
                    .offset
                    .checked_add(map_length)
                    .ok_or(DiscoveryError::InvalidSelection)?;
                if mapping.offset < local_end && local_start < map_end {
                    count = count
                        .checked_add(1)
                        .ok_or(DiscoveryError::InvalidSelection)?;
                }
            }
        }
        unit_offset = sample_end;
    }
    Ok(count)
}

fn source_mappings_for_run<'a>(
    samples: &'a [DiscoverySample<'_>],
    unit: &WorkUnit,
    source_start: usize,
    source_end: usize,
    phase: u8,
    output_start: usize,
) -> Result<Vec<SourceBitMappingReceiptRef<'a>>, DiscoveryError> {
    let mapping_count = count_source_mappings(samples, unit, source_start, source_end)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(mapping_count)
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    let mut unit_offset = 0_usize;
    for sample_index in &unit.sample_indexes {
        let sample = samples
            .get(*sample_index)
            .ok_or(DiscoveryError::InvalidSelection)?;
        let sample_end = unit_offset
            .checked_add(sample.bytes.len())
            .ok_or(DiscoveryError::InvalidSelection)?;
        let overlap_start = source_start.max(unit_offset);
        let overlap_end = source_end.min(sample_end);
        if overlap_start < overlap_end {
            let local_start = overlap_start - unit_offset;
            let local_end = overlap_end - unit_offset;
            for mapping in &sample.mappings {
                let map_length = usize::try_from(mapping.range.length)
                    .map_err(|_| DiscoveryError::InvalidSelection)?;
                let map_end = mapping
                    .offset
                    .checked_add(map_length)
                    .ok_or(DiscoveryError::InvalidSelection)?;
                let byte_start = local_start.max(mapping.offset);
                let byte_end = local_end.min(map_end);
                if byte_start >= byte_end {
                    continue;
                }
                let within_mapping = byte_start - mapping.offset;
                let source_offset = mapping
                    .range
                    .offset
                    .checked_add(
                        u64::try_from(within_mapping)
                            .map_err(|_| DiscoveryError::InvalidSelection)?,
                    )
                    .ok_or(DiscoveryError::InvalidSelection)?;
                let byte_count = byte_end - byte_start;
                result.push(SourceBitMappingReceiptRef {
                    output_bit_start: unit_offset
                        .checked_add(byte_start)
                        .and_then(|absolute| absolute.checked_sub(output_start))
                        .ok_or(DiscoveryError::InvalidSelection)?,
                    bit_count: byte_count,
                    source: SourceRangeReceiptRef {
                        source: &mapping.range.source,
                        packet: mapping.range.packet,
                        offset: source_offset,
                        length: u64::try_from(byte_count)
                            .map_err(|_| DiscoveryError::InvalidSelection)?,
                    },
                    source_bit_offset: phase,
                    source_stride_bits: 8,
                });
            }
        }
        unit_offset = sample_end;
    }
    Ok(result)
}

fn own_source_mappings(
    mappings: &[SourceBitMappingReceiptRef<'_>],
) -> Result<Vec<SourceBitMapping>, DiscoveryError> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(mappings.len())
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    for mapping in mappings {
        owned.push(SourceBitMapping {
            output_bit_start: mapping.output_bit_start,
            bit_count: mapping.bit_count,
            source: SourceRange {
                source: clone_string(mapping.source.source)?,
                packet: mapping.source.packet,
                offset: mapping.source.offset,
                length: mapping.source.length,
            },
            source_bit_offset: mapping.source_bit_offset,
            source_stride_bits: mapping.source_stride_bits,
        });
    }
    Ok(owned)
}

const fn is_printable(byte: u8) -> bool {
    byte >= 0x20 && byte <= 0x7e
}
