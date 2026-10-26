//! Repeated-record boundary search independent of fixed-layout schema proposals

use super::super::model::{RecordSchemaProposalLimits, default_sequence_base};
use super::length_layouts::{LengthLayoutOrder, length_domain_stats, visit_length_layouts};
use super::{
    CandidateGeneration, FieldDomains, LengthFieldMembership, LengthFields, RecordRange,
    SupportedLength, allocation_error, candidate_field_domains, empty_length_fields,
    empty_pair_fields, finish_candidate_generation, sequence_group_candidates, try_charge_work,
    varying_sequence_fields,
};
use crate::protocol::{
    ByteField, ByteOrder, IntegerField, RecordCount, RecordDiscoveryError, RecordError,
    RecordInput, RecordLengthMeaning, RecordLimits, RecordSchema, RecordWorkBudget,
};
use std::collections::HashSet;
use std::ops::ControlFlow;

pub(super) fn generate_candidates(
    training_messages: &[&[u8]],
    training_inputs: &[&RecordInput<'_>],
    limits: RecordSchemaProposalLimits,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<CandidateGeneration, RecordDiscoveryError> {
    let (raw_limits, header_limits) = split_field_check_budget(limits);
    let raw_fields = candidate_field_domains(training_messages, raw_limits, work)?;
    let mut lengths = length_candidates(
        training_messages,
        training_inputs,
        &raw_fields.integer_shapes,
        raw_fields.maximum_offset,
        limits.max_length_checks,
        limits.discovery.record_limits,
        work,
    )?;

    if !lengths.has_repeated_boundaries {
        // A single complete record per message belongs to the established fixed-layout path
        lengths.fields.clear();
        lengths.data_offsets.clear();
        lengths.meanings.clear();
        lengths.supported.clear();
        lengths.record_ranges.clear();
        let pairs = empty_pair_fields(0);
        return finish_candidate_generation(&raw_fields, pairs, lengths, limits, Vec::new(), work);
    }

    let Some(views) = record_views(training_messages, &lengths.record_ranges, work)? else {
        lengths.work_limit_reached = true;
        lengths.omitted_record_views = lengths
            .omitted_record_views
            .checked_add(lengths.record_ranges.len())
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        return finish_candidate_generation(
            &raw_fields,
            empty_pair_fields(0),
            lengths,
            limits,
            Vec::new(),
            work,
        );
    };
    let header_fields = candidate_field_domains(&views, header_limits, work)?;
    let mut fields = raw_fields;
    add_field_check_counts(&mut fields, &header_fields)?;
    fields.work_limit_reached |= header_fields.work_limit_reached;

    let (sequence_fields, sequence_work_limit) =
        varying_sequence_fields(&views, &header_fields.integer_shapes, work)?;
    let mut pairs = sequence_group_candidates(
        &views,
        &header_fields.identifiers,
        &sequence_fields,
        limits.max_pair_checks,
        work,
    )?;
    pairs.work_limit_reached |= sequence_work_limit;
    finish_candidate_generation(&fields, pairs, lengths, limits, Vec::new(), work)
}

const fn split_field_check_budget(
    limits: RecordSchemaProposalLimits,
) -> (RecordSchemaProposalLimits, RecordSchemaProposalLimits) {
    let raw = limits.max_field_checks_per_domain / 2 + limits.max_field_checks_per_domain % 2;
    let header = limits.max_field_checks_per_domain / 2;
    let mut raw_limits = limits;
    raw_limits.max_field_checks_per_domain = raw;
    let mut header_limits = limits;
    header_limits.max_field_checks_per_domain = header;
    (raw_limits, header_limits)
}

fn add_field_check_counts(
    destination: &mut FieldDomains,
    source: &FieldDomains,
) -> Result<(), RecordDiscoveryError> {
    destination.examined_byte_checks = destination
        .examined_byte_checks
        .checked_add(source.examined_byte_checks)
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    destination.omitted_byte_checks = destination
        .omitted_byte_checks
        .checked_add(source.omitted_byte_checks)
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    destination.examined_integer_checks = destination
        .examined_integer_checks
        .checked_add(source.examined_integer_checks)
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    destination.omitted_integer_checks = destination
        .omitted_integer_checks
        .checked_add(source.omitted_integer_checks)
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    Ok(())
}

fn record_views<'a>(
    messages: &'a [&'a [u8]],
    ranges: &[RecordRange],
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<Option<Vec<&'a [u8]>>, RecordDiscoveryError> {
    let view_storage = std::mem::size_of::<&[u8]>()
        .checked_mul(ranges.len())
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    if !try_charge_work(work, view_storage) {
        return Ok(None);
    }
    let mut views = Vec::new();
    views
        .try_reserve_exact(ranges.len())
        .map_err(|_| allocation_error())?;
    for range in ranges {
        let message = messages
            .get(range.message_index)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        let view = message
            .get(range.start..range.end)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        views.push(view);
    }
    Ok(Some(views))
}

fn length_candidates(
    messages: &[&[u8]],
    inputs: &[&RecordInput<'_>],
    fields: &[IntegerField],
    maximum_data_offset: usize,
    maximum_checks: usize,
    record_limits: RecordLimits,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<LengthFields, RecordDiscoveryError> {
    // The visitor keeps a bounded frontier and one temporary priority list
    let total_checks = length_domain_stats(fields, maximum_data_offset)?;
    let workspace_bytes = std::mem::size_of::<usize>()
        .checked_mul(fields.len())
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    if !try_charge_work(work, workspace_bytes) {
        let mut result = empty_length_fields();
        result.omitted_checks = total_checks;
        result.work_limit_reached = true;
        return Ok(result);
    }
    let Some(mut search) = LengthCandidateSearch::new(messages, inputs, record_limits, work)?
    else {
        let mut result = empty_length_fields();
        result.omitted_checks = total_checks;
        result.work_limit_reached = true;
        return Ok(result);
    };
    let (examined_checks, _domain_checks, stopped) = visit_length_layouts(
        fields,
        maximum_data_offset,
        maximum_checks,
        &[],
        LengthLayoutOrder::CompactPrefix,
        &mut |field, data_offset, meaning| search.check_layout(field, data_offset, meaning, work),
    )?;
    search.finish(total_checks, examined_checks, stopped)
}

struct LengthCandidateSearch<'a, 'input> {
    messages: &'a [&'a [u8]],
    inputs: &'a [&'a RecordInput<'input>],
    record_limits: RecordLimits,
    per_message_limits: Vec<usize>,
    maximum_record_views: usize,
    result: LengthFields,
    seen_layout_fields: LengthFieldMembership,
    seen_record_ranges: HashSet<(usize, usize, usize)>,
    incomplete_checks: usize,
}

impl<'a, 'input> LengthCandidateSearch<'a, 'input> {
    fn new(
        messages: &'a [&'a [u8]],
        inputs: &'a [&'a RecordInput<'input>],
        record_limits: RecordLimits,
        work: &mut Option<&mut RecordWorkBudget>,
    ) -> Result<Option<Self>, RecordDiscoveryError> {
        if messages.len() != inputs.len() {
            return Err(RecordDiscoveryError::InvalidLimits);
        }
        let maximum_record_views = maximum_record_views(record_limits);
        let limit_bytes = std::mem::size_of::<usize>()
            .checked_mul(messages.len())
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        if !try_charge_work(work, limit_bytes) {
            return Ok(None);
        }
        let per_message_limits =
            distribute_record_view_limit(maximum_record_views, messages.len())?;
        Ok(Some(Self {
            messages,
            inputs,
            record_limits,
            per_message_limits,
            maximum_record_views,
            result: empty_length_fields(),
            seen_layout_fields: LengthFieldMembership::default(),
            seen_record_ranges: HashSet::new(),
            incomplete_checks: 0,
        }))
    }

    fn check_layout(
        &mut self,
        field: IntegerField,
        data_offset: usize,
        meaning: RecordLengthMeaning,
        work: &mut Option<&mut RecordWorkBudget>,
    ) -> Result<ControlFlow<()>, RecordDiscoveryError> {
        match length_ranges(
            self.inputs,
            field,
            meaning,
            data_offset,
            self.record_limits,
            &self.per_message_limits,
            work,
        )? {
            LengthCheck::Mismatch => Ok(ControlFlow::Continue(())),
            LengthCheck::Incomplete => {
                self.incomplete_checks = self
                    .incomplete_checks
                    .checked_add(1)
                    .ok_or(RecordDiscoveryError::InvalidLimits)?;
                Ok(ControlFlow::Continue(()))
            }
            LengthCheck::WorkLimit => {
                self.result.work_limit_reached = true;
                Ok(ControlFlow::Break(()))
            }
            LengthCheck::Matched { ranges, omitted } => {
                if !try_charge_work(work, std::mem::size_of::<SupportedLength>()) {
                    self.result.work_limit_reached = true;
                    return Ok(ControlFlow::Break(()));
                }
                if !self.retain_layout(field, data_offset, meaning, ranges, omitted, work)? {
                    self.result.work_limit_reached = true;
                    return Ok(ControlFlow::Break(()));
                }
                Ok(ControlFlow::Continue(()))
            }
        }
    }

    fn retain_layout(
        &mut self,
        field: IntegerField,
        data_offset: usize,
        meaning: RecordLengthMeaning,
        ranges: Vec<RecordRange>,
        omitted: usize,
        work: &mut Option<&mut RecordWorkBudget>,
    ) -> Result<bool, RecordDiscoveryError> {
        self.result.retain_layout(
            &mut self.seen_layout_fields,
            SupportedLength {
                field,
                data_offset,
                meaning,
            },
        )?;
        self.result.omitted_record_views = self
            .result
            .omitted_record_views
            .checked_add(omitted)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        if layout_has_repeated_boundaries(&ranges, self.messages.len()) {
            self.result.has_repeated_boundaries = true;
            for range in ranges {
                if !self.retain_record_range(range, work)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn retain_record_range(
        &mut self,
        range: RecordRange,
        work: &mut Option<&mut RecordWorkBudget>,
    ) -> Result<bool, RecordDiscoveryError> {
        let key = (range.message_index, range.start, range.end);
        if self.seen_record_ranges.contains(&key) {
            return Ok(true);
        }
        if self.result.record_ranges.len() == self.maximum_record_views {
            self.result.omitted_record_views = self
                .result
                .omitted_record_views
                .checked_add(1)
                .ok_or(RecordDiscoveryError::InvalidLimits)?;
            return Ok(true);
        }
        let retained_bytes = std::mem::size_of::<RecordRange>()
            .checked_add(std::mem::size_of::<(usize, usize, usize)>())
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        if !try_charge_work(work, retained_bytes) {
            return Ok(false);
        }
        self.seen_record_ranges
            .try_reserve(1)
            .map_err(|_| allocation_error())?;
        self.result
            .record_ranges
            .try_reserve(1)
            .map_err(|_| allocation_error())?;
        self.seen_record_ranges.insert(key);
        self.result.record_ranges.push(range);
        Ok(true)
    }

    fn finish(
        mut self,
        total_checks: usize,
        examined_checks: usize,
        stopped: bool,
    ) -> Result<LengthFields, RecordDiscoveryError> {
        let incomplete = self.incomplete_checks.min(examined_checks);
        self.result.examined_checks = examined_checks.saturating_sub(incomplete);
        self.result.omitted_checks = total_checks
            .checked_sub(self.result.examined_checks)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        self.result.work_limit_reached |= stopped;
        Ok(self.result)
    }
}

fn layout_has_repeated_boundaries(ranges: &[RecordRange], message_count: usize) -> bool {
    if message_count == 0 || ranges.len() <= message_count {
        return false;
    }
    let mut next_message = 0_usize;
    for range in ranges {
        if range.message_index == next_message {
            continue;
        }
        if range.message_index != next_message + 1 {
            return false;
        }
        next_message = range.message_index;
    }
    next_message + 1 == message_count
}

fn maximum_record_views(limits: RecordLimits) -> usize {
    // Reserve room for range storage, de-duplication, and the public cue report
    let bytes_per_view = std::mem::size_of::<RecordRange>().saturating_mul(4);
    let report_limit = limits.max_report_bytes / bytes_per_view.max(1);
    limits.max_records.min(report_limit)
}

fn distribute_record_view_limit(
    maximum: usize,
    message_count: usize,
) -> Result<Vec<usize>, RecordDiscoveryError> {
    if message_count == 0 {
        return Err(RecordDiscoveryError::InvalidLimits);
    }
    let base = maximum / message_count;
    let remainder = maximum % message_count;
    let mut limits = Vec::new();
    limits
        .try_reserve_exact(message_count)
        .map_err(|_| allocation_error())?;
    for message_index in 0..message_count {
        limits.push(base + usize::from(message_index < remainder));
    }
    Ok(limits)
}

enum LengthCheck {
    Mismatch,
    Incomplete,
    WorkLimit,
    Matched {
        ranges: Vec<RecordRange>,
        omitted: usize,
    },
}

fn length_ranges(
    inputs: &[&RecordInput<'_>],
    field: IntegerField,
    meaning: RecordLengthMeaning,
    data_offset: usize,
    record_limits: RecordLimits,
    per_message_limits: &[usize],
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<LengthCheck, RecordDiscoveryError> {
    let probe_schema = RecordSchema {
        records_offset: 0,
        count: RecordCount::UntilEnd,
        identifier: ByteField {
            offset: 0,
            width: 1,
        },
        sequence: IntegerField {
            offset: 0,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        length: field,
        data_offset,
        length_meaning: meaning,
        sequence_base: default_sequence_base(),
        terminal_sequence: None,
    };
    let mut ranges = Vec::new();
    let mut omitted = 0_usize;
    for (message_index, input) in inputs.iter().enumerate() {
        let parsed_result = work.as_deref_mut().map_or_else(
            || input.parse(&probe_schema, record_limits),
            |work| input.parse_with_work(&probe_schema, record_limits, work),
        );
        let parsed = match parsed_result {
            Ok(parsed) => parsed,
            Err(RecordError::WorkLimitExceeded { .. }) => return Ok(LengthCheck::WorkLimit),
            Err(RecordError::TooManyRecords { .. } | RecordError::ReportTooLarge { .. }) => {
                return Ok(LengthCheck::Incomplete);
            }
            Err(RecordError::AllocationFailed) => {
                return Err(RecordDiscoveryError::RecordOperation(
                    RecordError::AllocationFailed,
                ));
            }
            Err(
                error @ (RecordError::InvalidLimits
                | RecordError::InputTooLarge { .. }
                | RecordError::IdentifierTooLarge { .. }
                | RecordError::InvalidSchema { .. }),
            ) => return Err(RecordDiscoveryError::RecordOperation(error)),
            Err(_) => return Ok(LengthCheck::Mismatch),
        };
        if parsed.records().is_empty() {
            return Ok(LengthCheck::Mismatch);
        }
        let message_limit = *per_message_limits
            .get(message_index)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        let retained = parsed.records().len().min(message_limit);
        let range_storage = std::mem::size_of::<RecordRange>()
            .checked_mul(retained)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        if !try_charge_work(work, range_storage) {
            return Ok(LengthCheck::WorkLimit);
        }
        ranges
            .try_reserve(retained)
            .map_err(|_| allocation_error())?;
        for record in parsed.records().iter().take(retained) {
            ranges.push(RecordRange {
                message_index,
                start: record.record.start,
                end: record.record.end,
            });
        }
        omitted = omitted
            .checked_add(parsed.records().len().saturating_sub(retained))
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
    }
    Ok(LengthCheck::Matched { ranges, omitted })
}
