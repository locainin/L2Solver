//! Repeated-record boundary search independent of fixed-layout schema proposals

use super::super::model::{LENGTH_MEANINGS, RecordSchemaProposalLimits, default_sequence_base};
use super::{
    CandidateGeneration, FieldDomains, LengthFieldMembership, LengthFields, RecordRange,
    SupportedLength, allocation_error, candidate_field_domains, empty_length_fields,
    empty_pair_fields, finish_candidate_generation, length_domain_stats, sequence_group_candidates,
    varying_sequence_fields,
};
use crate::protocol::{
    ByteField, ByteOrder, IntegerField, RecordCount, RecordDiscoveryError, RecordError,
    RecordLengthMeaning, RecordLimits, RecordSchema, parse_records_with_limits,
};
use std::collections::HashSet;

pub(super) fn generate_candidates(
    training_messages: &[&[u8]],
    limits: RecordSchemaProposalLimits,
) -> Result<CandidateGeneration, RecordDiscoveryError> {
    let (raw_limits, header_limits) = split_field_check_budget(limits);
    let raw_fields = candidate_field_domains(training_messages, raw_limits)?;
    let mut lengths = length_candidates(
        training_messages,
        &raw_fields.integer_shapes,
        raw_fields.maximum_offset,
        limits.max_length_checks,
        limits.discovery.record_limits,
    )?;

    if !lengths.has_repeated_boundaries {
        // A single complete record per message belongs to the established fixed-layout path
        lengths.fields.clear();
        lengths.data_offsets.clear();
        lengths.meanings.clear();
        lengths.supported.clear();
        lengths.record_ranges.clear();
        let pairs = empty_pair_fields(0);
        return finish_candidate_generation(&raw_fields, pairs, lengths, limits, Vec::new());
    }

    let views = record_views(training_messages, &lengths.record_ranges)?;
    let header_fields = candidate_field_domains(&views, header_limits)?;
    let mut fields = raw_fields;
    add_field_check_counts(&mut fields, &header_fields)?;

    let sequence_fields = varying_sequence_fields(&views, &header_fields.integer_shapes)?;
    let pairs = sequence_group_candidates(
        &views,
        &header_fields.identifiers,
        &sequence_fields,
        limits.max_pair_checks,
    )?;
    finish_candidate_generation(&fields, pairs, lengths, limits, Vec::new())
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
) -> Result<Vec<&'a [u8]>, RecordDiscoveryError> {
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
    Ok(views)
}

fn length_candidates(
    messages: &[&[u8]],
    fields: &[IntegerField],
    maximum_data_offset: usize,
    maximum_checks: usize,
    record_limits: RecordLimits,
) -> Result<LengthFields, RecordDiscoveryError> {
    let (total_checks, _) = length_domain_stats(fields, maximum_data_offset)?;
    let mut search = LengthCandidateSearch::new(messages, record_limits)?;

    // Visit the shortest payload boundaries first so compact headers share the budget fairly
    if maximum_data_offset > 0 {
        'boundaries: for data_offset in 1..=maximum_data_offset {
            for field in fields {
                let field_end = field
                    .offset
                    .checked_add(field.width)
                    .ok_or(RecordDiscoveryError::InvalidLimits)?;
                if field_end > data_offset {
                    continue;
                }
                for meaning in LENGTH_MEANINGS {
                    if search.result.examined_checks == maximum_checks {
                        break 'boundaries;
                    }
                    search.check_layout(*field, data_offset, meaning)?;
                }
            }
        }
    }
    search.finish(total_checks)
}

struct LengthCandidateSearch<'a> {
    messages: &'a [&'a [u8]],
    record_limits: RecordLimits,
    per_message_limits: Vec<usize>,
    maximum_record_views: usize,
    result: LengthFields,
    seen_layout_fields: LengthFieldMembership,
    seen_record_ranges: HashSet<(usize, usize, usize)>,
    incomplete_checks: usize,
}

impl<'a> LengthCandidateSearch<'a> {
    fn new(
        messages: &'a [&'a [u8]],
        record_limits: RecordLimits,
    ) -> Result<Self, RecordDiscoveryError> {
        let maximum_record_views = maximum_record_views(record_limits);
        let per_message_limits =
            distribute_record_view_limit(maximum_record_views, messages.len())?;
        Ok(Self {
            messages,
            record_limits,
            per_message_limits,
            maximum_record_views,
            result: empty_length_fields(),
            seen_layout_fields: LengthFieldMembership::default(),
            seen_record_ranges: HashSet::new(),
            incomplete_checks: 0,
        })
    }

    fn check_layout(
        &mut self,
        field: IntegerField,
        data_offset: usize,
        meaning: RecordLengthMeaning,
    ) -> Result<(), RecordDiscoveryError> {
        self.result.examined_checks = self
            .result
            .examined_checks
            .checked_add(1)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        match length_ranges(
            self.messages,
            field,
            meaning,
            data_offset,
            self.record_limits,
            &self.per_message_limits,
        )? {
            LengthCheck::Mismatch => Ok(()),
            LengthCheck::Incomplete => {
                self.incomplete_checks = self
                    .incomplete_checks
                    .checked_add(1)
                    .ok_or(RecordDiscoveryError::InvalidLimits)?;
                Ok(())
            }
            LengthCheck::Matched { ranges, omitted } => {
                self.retain_layout(field, data_offset, meaning, ranges, omitted)
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
    ) -> Result<(), RecordDiscoveryError> {
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
                self.retain_record_range(range)?;
            }
        }
        Ok(())
    }

    fn retain_record_range(&mut self, range: RecordRange) -> Result<(), RecordDiscoveryError> {
        let key = (range.message_index, range.start, range.end);
        if self.seen_record_ranges.contains(&key) {
            return Ok(());
        }
        if self.result.record_ranges.len() == self.maximum_record_views {
            self.result.omitted_record_views = self
                .result
                .omitted_record_views
                .checked_add(1)
                .ok_or(RecordDiscoveryError::InvalidLimits)?;
            return Ok(());
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
        Ok(())
    }

    fn finish(mut self, total_checks: usize) -> Result<LengthFields, RecordDiscoveryError> {
        self.result.omitted_checks = total_checks
            .checked_sub(self.result.examined_checks)
            .and_then(|unexamined| unexamined.checked_add(self.incomplete_checks))
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
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
    Matched {
        ranges: Vec<RecordRange>,
        omitted: usize,
    },
}

fn length_ranges(
    messages: &[&[u8]],
    field: IntegerField,
    meaning: RecordLengthMeaning,
    data_offset: usize,
    record_limits: RecordLimits,
    per_message_limits: &[usize],
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
    for (message_index, message) in messages.iter().enumerate() {
        let parsed = match parse_records_with_limits(message, &probe_schema, record_limits) {
            Ok(parsed) => parsed,
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
