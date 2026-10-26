//! Infer record-header layouts from training bytes and test schemas on held-out messages
//!
//! A record schema locates the object identifier, sequence number, length field, and payload
//! This search proposes field positions, widths, byte orders, and length meanings that fit
//! the training input, then enumerates compatible layouts in a stable, bounded order
//! Supported field relationships stay together instead of forming an unrestricted product
//!
//! Proposal generation reads training bytes only. The shared strict record parser checks
//! candidate schemas against training and held-out messages, preserving failures and search
//! omissions in the report. Surviving layouts remain hypotheses; record assembly and file
//! validation are later recovery steps

use super::super::discovery::{
    RecordDiscoveryError, RecordSchemaDiscoverySpace, discover_record_schemas_from_candidates,
};
use super::super::{ByteField, IntegerField, RecordCount, RecordError, RecordSchema};
use super::model::{
    INTEGER_WIDTHS, LENGTH_MEANINGS, LIMITATIONS, RecordBoundaryCue, RecordSchemaAnalysisReport,
    RecordSchemaMultiStrategyAnalysisReport, RecordSchemaProposalLimits,
    RecordSchemaProposalReport, RecordSchemaProposalValidationBasis, default_sequence_base,
};
use crate::integer::decode_unsigned;
use crate::protocol::ByteOrder;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::hash::Hash;

mod repeated;

/// Suggest possible record-header fields from training messages within search limits
///
/// Checks field positions, widths, byte orders, identifier/sequence relationships, and candidate
/// length layouts using training bytes only. The report describes the proposed field domains
/// and how much search was completed. Supplied held-out input is recorded as a validation basis
/// Use [`analyze_record_schemas`] to enumerate compatible schemas and check them with the strict
/// parser. Without held-out input, a surviving schema has discovery support only
///
/// # Errors
/// Rejects empty training input, invalid limits, and aggregate message resource excess
pub fn propose_record_schema_space(
    training_messages: &[&[u8]],
    held_out_messages: &[&[u8]],
    limits: RecordSchemaProposalLimits,
) -> Result<RecordSchemaProposalReport, RecordDiscoveryError> {
    limits.validate()?;
    validate_messages(training_messages, held_out_messages, limits)?;
    let generated = generate_candidates(training_messages, limits)?;
    Ok(proposal_report(
        training_messages,
        held_out_messages,
        generated,
    ))
}

/// Infer compatible record schemas and check each against training and held-out messages
///
/// Reuses the supported field pairs and length layouts from one proposal pass. This avoids
/// retrying unrelated field combinations from the report's individual field lists. The shared
/// strict parser checks each complete schema; the result retains surviving hypotheses,
/// falsifications, and search coverage. Record assembly remains a separate operation
///
/// # Errors
/// Rejects empty training input, invalid limits, and aggregate message resource excess
pub fn analyze_record_schemas(
    training_messages: &[&[u8]],
    held_out_messages: &[&[u8]],
    limits: RecordSchemaProposalLimits,
) -> Result<RecordSchemaAnalysisReport, RecordDiscoveryError> {
    limits.validate()?;
    validate_messages(training_messages, held_out_messages, limits)?;
    let generated = generate_candidates(training_messages, limits)?;
    analyze_generated_candidates(training_messages, held_out_messages, limits, generated, &[])
}

/// Analyze fixed-layout and repeated-boundary schemas as separate bounded strategies
///
/// Search and canonical parser budgets are divided between the two strategies. The fixed-layout
/// analysis keeps the established one-record-per-message behavior, while repeated-boundary
/// analysis first uses length fields to locate bounded record views and only then proposes header
/// fields. Each strategy retains its own proposal and parser report so unrelated candidate
/// dimensions are never combined into a synthetic Cartesian search space
///
/// # Errors
/// Rejects empty training input, invalid limits, and aggregate message resource excess
pub fn analyze_record_schemas_with_repeated_boundaries(
    training_messages: &[&[u8]],
    held_out_messages: &[&[u8]],
    limits: RecordSchemaProposalLimits,
) -> Result<RecordSchemaMultiStrategyAnalysisReport, RecordDiscoveryError> {
    analyze_record_schemas_with_repeated_boundaries_and_offsets(
        training_messages,
        held_out_messages,
        limits,
        &[],
    )
}

/// Analyze fixed and repeated-boundary layouts with explicit training-derived payload offsets
///
/// `training_data_offsets` supplies known boundaries from source framing when those boundaries
/// are not inferred by the fixed-layout field search. Values beyond `max_field_offset` are
/// ignored. These offsets affect only fixed-layout schema proposals and must come from training
/// input; held-out frames are checked against the resulting frozen candidates
///
/// # Errors
/// Rejects empty training input, invalid limits, and aggregate message resource excess
pub fn analyze_record_schemas_with_repeated_boundaries_and_offsets(
    training_messages: &[&[u8]],
    held_out_messages: &[&[u8]],
    limits: RecordSchemaProposalLimits,
    training_data_offsets: &[usize],
) -> Result<RecordSchemaMultiStrategyAnalysisReport, RecordDiscoveryError> {
    limits.validate()?;
    validate_messages(training_messages, held_out_messages, limits)?;
    if training_data_offsets.len() > limits.discovery.max_messages {
        return Err(RecordDiscoveryError::InvalidLimits);
    }
    let Some((fixed_limits, repeated_limits)) = split_strategy_limits(limits) else {
        let fixed_layout = analyze_generated_candidates(
            training_messages,
            held_out_messages,
            limits,
            generate_candidates(training_messages, limits)?,
            training_data_offsets,
        )?;
        return Ok(RecordSchemaMultiStrategyAnalysisReport {
            fixed_layout,
            fixed_layout_limits: limits,
            repeated_boundaries: None,
            repeated_boundary_limits: None,
        });
    };

    let fixed_layout = analyze_generated_candidates(
        training_messages,
        held_out_messages,
        fixed_limits,
        generate_candidates(training_messages, fixed_limits)?,
        training_data_offsets,
    )?;
    let repeated_boundaries = analyze_generated_candidates(
        training_messages,
        held_out_messages,
        repeated_limits,
        repeated::generate_candidates(training_messages, repeated_limits)?,
        &[],
    )?;
    Ok(RecordSchemaMultiStrategyAnalysisReport {
        fixed_layout,
        fixed_layout_limits: fixed_limits,
        repeated_boundaries: Some(repeated_boundaries),
        repeated_boundary_limits: Some(repeated_limits),
    })
}

fn analyze_generated_candidates(
    training_messages: &[&[u8]],
    held_out_messages: &[&[u8]],
    limits: RecordSchemaProposalLimits,
    mut generated: CandidateGeneration,
    training_data_offsets: &[usize],
) -> Result<RecordSchemaAnalysisReport, RecordDiscoveryError> {
    if let Some(space) = generated.candidate_space.as_mut() {
        add_training_data_offsets(space, training_data_offsets, limits.max_field_offset)?;
    }
    let discovery = if let Some(space) = generated.candidate_space.as_ref() {
        let mut schemas = generated.schemas(space)?;
        Some(discover_record_schemas_from_candidates(
            training_messages,
            held_out_messages,
            generated.candidate_combinations,
            limits.discovery,
            |_| schemas.next(),
        )?)
    } else {
        None
    };
    let proposal = proposal_report(training_messages, held_out_messages, generated);
    Ok(RecordSchemaAnalysisReport {
        proposal,
        discovery,
    })
}

fn add_training_data_offsets(
    space: &mut RecordSchemaDiscoverySpace,
    offsets: &[usize],
    maximum_offset: usize,
) -> Result<(), RecordDiscoveryError> {
    for offset in offsets
        .iter()
        .copied()
        .filter(|offset| *offset <= maximum_offset)
    {
        if space.data_offsets.contains(&offset) {
            continue;
        }
        space
            .data_offsets
            .try_reserve(1)
            .map_err(|_| RecordDiscoveryError::RecordOperation(RecordError::AllocationFailed))?;
        space.data_offsets.push(offset);
    }
    space.data_offsets.sort_unstable();
    space.data_offsets.dedup();
    Ok(())
}

fn split_strategy_limits(
    limits: RecordSchemaProposalLimits,
) -> Option<(RecordSchemaProposalLimits, RecordSchemaProposalLimits)> {
    let mut fixed = limits;
    let mut repeated = limits;
    split_limit(
        &mut fixed.max_field_checks_per_domain,
        &mut repeated.max_field_checks_per_domain,
    )?;
    split_limit(&mut fixed.max_pair_checks, &mut repeated.max_pair_checks)?;
    split_limit(
        &mut fixed.max_length_checks,
        &mut repeated.max_length_checks,
    )?;
    split_limit(
        &mut fixed.discovery.max_candidates,
        &mut repeated.discovery.max_candidates,
    )?;
    split_limit(
        &mut fixed.discovery.max_survivors,
        &mut repeated.discovery.max_survivors,
    )?;
    split_limit(
        &mut fixed.discovery.max_falsifications,
        &mut repeated.discovery.max_falsifications,
    )?;
    Some((fixed, repeated))
}

fn split_limit(fixed: &mut usize, repeated: &mut usize) -> Option<()> {
    if *fixed < 2 {
        return None;
    }
    let total = *fixed;
    *fixed = total / 2 + total % 2;
    *repeated = total / 2;
    Some(())
}

fn proposal_report(
    training_messages: &[&[u8]],
    held_out_messages: &[&[u8]],
    generated: CandidateGeneration,
) -> RecordSchemaProposalReport {
    let validation_basis = if held_out_messages.is_empty() {
        RecordSchemaProposalValidationBasis::DiscoveryOnly
    } else {
        RecordSchemaProposalValidationBasis::HeldOutMessagesAvailable
    };
    RecordSchemaProposalReport {
        validation_basis,
        training_message_count: training_messages.len(),
        held_out_message_count: held_out_messages.len(),
        candidate_space: generated.candidate_space,
        candidate_combinations: generated.candidate_combinations,
        examined_field_checks: generated.examined_field_checks,
        omitted_field_checks: generated.omitted_field_checks,
        examined_pair_checks: generated.examined_pair_checks,
        omitted_pair_checks: generated.omitted_pair_checks,
        examined_length_checks: generated.examined_length_checks,
        omitted_length_checks: generated.omitted_length_checks,
        omitted_record_views: generated.omitted_record_views,
        repeated_boundary_cues: generated
            .record_ranges
            .into_iter()
            .map(|range| RecordBoundaryCue {
                message_index: range.message_index,
                range: crate::protocol::ByteRange {
                    start: range.start,
                    end: range.end,
                },
            })
            .collect(),
        omitted_schema_combinations: generated.omitted_schema_combinations,
        search_exhaustive_within_plan: generated.search_exhaustive_within_plan,
        limitations: LIMITATIONS,
    }
}

struct CandidateGeneration {
    candidate_space: Option<RecordSchemaDiscoverySpace>,
    supported_pairs: Vec<SupportedPair>,
    supported_lengths: Vec<SupportedLength>,
    compatible_pair_counts: Vec<usize>,
    candidate_combinations: Option<usize>,
    examined_field_checks: usize,
    omitted_field_checks: usize,
    examined_pair_checks: usize,
    omitted_pair_checks: usize,
    examined_length_checks: usize,
    omitted_length_checks: usize,
    omitted_record_views: usize,
    record_ranges: Vec<RecordRange>,
    omitted_schema_combinations: Option<usize>,
    search_exhaustive_within_plan: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SupportedPair {
    identifier: ByteField,
    sequence: IntegerField,
    evidence: SequenceEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SequenceEvidence {
    capture_order_violations: usize,
    ordinal_span_holes: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SupportedLength {
    field: IntegerField,
    data_offset: usize,
    meaning: super::super::RecordLengthMeaning,
}

struct PairFields {
    identifiers: Vec<ByteField>,
    sequences: Vec<IntegerField>,
    supported: Vec<SupportedPair>,
    examined_checks: usize,
    omitted_checks: usize,
}

struct LengthFields {
    fields: Vec<IntegerField>,
    data_offsets: Vec<usize>,
    meanings: Vec<super::super::RecordLengthMeaning>,
    supported: Vec<SupportedLength>,
    record_ranges: Vec<RecordRange>,
    has_repeated_boundaries: bool,
    omitted_record_views: usize,
    examined_checks: usize,
    omitted_checks: usize,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RecordRange {
    message_index: usize,
    start: usize,
    end: usize,
}

struct FieldDomains {
    maximum_offset: usize,
    identifiers: Vec<ByteField>,
    integer_shapes: Vec<IntegerField>,
    examined_byte_checks: usize,
    omitted_byte_checks: usize,
    examined_integer_checks: usize,
    omitted_integer_checks: usize,
}

impl CandidateGeneration {
    fn schemas<'a>(
        &'a self,
        space: &'a RecordSchemaDiscoverySpace,
    ) -> Result<SupportedSchemaIter<'a>, RecordDiscoveryError> {
        let mut rows = BinaryHeap::new();
        rows.try_reserve(self.supported_lengths.len())
            .map_err(|_| allocation_error())?;
        for (length_index, pair_count) in self.compatible_pair_counts.iter().copied().enumerate() {
            if pair_count == 0 {
                continue;
            }
            let pair_index = first_compatible_pair(
                &self.supported_pairs,
                self.supported_lengths
                    .get(length_index)
                    .ok_or(RecordDiscoveryError::InvalidLimits)?,
                0,
            )
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
            rows.push(Reverse((
                length_index
                    .checked_add(pair_index)
                    .ok_or(RecordDiscoveryError::InvalidLimits)?,
                length_index,
                pair_index,
            )));
        }
        Ok(SupportedSchemaIter {
            space,
            pairs: &self.supported_pairs,
            lengths: &self.supported_lengths,
            rows,
        })
    }
}

struct SupportedSchemaIter<'a> {
    space: &'a RecordSchemaDiscoverySpace,
    pairs: &'a [SupportedPair],
    lengths: &'a [SupportedLength],
    rows: BinaryHeap<Reverse<(usize, usize, usize)>>,
}

impl Iterator for SupportedSchemaIter<'_> {
    type Item = RecordSchema;

    fn next(&mut self) -> Option<Self::Item> {
        let Reverse((_, length_index, pair_index)) = self.rows.pop()?;
        let pair = self.pairs.get(pair_index)?;
        let length = self.lengths.get(length_index)?;
        let next_start = pair_index.checked_add(1)?;
        if let Some(next_pair_index) = first_compatible_pair(self.pairs, length, next_start) {
            self.rows.push(Reverse((
                length_index.checked_add(next_pair_index)?,
                length_index,
                next_pair_index,
            )));
        }
        Some(RecordSchema {
            records_offset: *self.space.records_offsets.first()?,
            count: *self.space.counts.first()?,
            identifier: pair.identifier,
            sequence: pair.sequence,
            length: length.field,
            data_offset: length.data_offset,
            length_meaning: length.meaning,
            sequence_base: self.space.sequence_base,
            terminal_sequence: None,
        })
    }
}

fn supported_pair_order(pair: &SupportedPair) -> SupportedPairOrder {
    let identifier_end = pair.identifier.offset.saturating_add(pair.identifier.width);
    let sequence_end = pair.sequence.offset.saturating_add(pair.sequence.width);
    let field_gap = if identifier_end <= pair.sequence.offset {
        pair.sequence.offset - identifier_end
    } else {
        pair.identifier.offset.saturating_sub(sequence_end)
    };
    let span_start = pair.identifier.offset.min(pair.sequence.offset);
    let span_end = identifier_end.max(sequence_end);
    SupportedPairOrder {
        field_gap,
        span_length: span_end.saturating_sub(span_start),
        field_width_sum: pair.identifier.width.saturating_add(pair.sequence.width),
        capture_order_violations: pair.evidence.capture_order_violations,
        ordinal_span_holes: pair.evidence.ordinal_span_holes,
        maximum_field_end: identifier_end.max(sequence_end),
        offset_sum: pair.identifier.offset.saturating_add(pair.sequence.offset),
        identifier_offset: pair.identifier.offset,
        identifier_width: pair.identifier.width,
        sequence_offset: pair.sequence.offset,
        sequence_width: pair.sequence.width,
        sequence_byte_order: byte_order_order(pair.sequence.byte_order),
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SupportedPairOrder {
    field_gap: usize,
    span_length: usize,
    field_width_sum: usize,
    capture_order_violations: usize,
    ordinal_span_holes: u128,
    maximum_field_end: usize,
    offset_sum: usize,
    identifier_offset: usize,
    identifier_width: usize,
    sequence_offset: usize,
    sequence_width: usize,
    sequence_byte_order: u8,
}

fn first_compatible_pair(
    pairs: &[SupportedPair],
    length: &SupportedLength,
    start: usize,
) -> Option<usize> {
    pairs
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(index, pair)| pair_fits_before_data(pair, length.data_offset).then_some(index))
}

fn pair_fits_before_data(pair: &SupportedPair, data_offset: usize) -> bool {
    pair.identifier
        .offset
        .checked_add(pair.identifier.width)
        .is_some_and(|end| end <= data_offset)
        && pair
            .sequence
            .offset
            .checked_add(pair.sequence.width)
            .is_some_and(|end| end <= data_offset)
}

fn compatible_pair_counts(
    pairs: &[SupportedPair],
    lengths: &[SupportedLength],
) -> Result<(Vec<usize>, Option<usize>), RecordDiscoveryError> {
    if pairs.is_empty() || lengths.is_empty() {
        return Ok((Vec::new(), Some(0)));
    }
    let mut compatible_pair_counts = Vec::new();
    compatible_pair_counts
        .try_reserve_exact(lengths.len())
        .map_err(|_| allocation_error())?;
    let mut candidate_count = 0_usize;
    for length in lengths {
        let compatible_pairs = pairs
            .iter()
            .filter(|pair| pair_fits_before_data(pair, length.data_offset))
            .count();
        candidate_count = candidate_count
            .checked_add(compatible_pairs)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        compatible_pair_counts.push(compatible_pairs);
    }
    Ok((compatible_pair_counts, Some(candidate_count)))
}

const fn byte_order_order(order: ByteOrder) -> u8 {
    match order {
        ByteOrder::BigEndian => 0,
        ByteOrder::LittleEndian => 1,
    }
}

const fn length_meaning_order(meaning: super::super::RecordLengthMeaning) -> u8 {
    match meaning {
        super::super::RecordLengthMeaning::PayloadBytes => 0,
        super::super::RecordLengthMeaning::WholeRecord => 1,
        super::super::RecordLengthMeaning::BytesAfterLengthField => 2,
    }
}

fn generate_candidates(
    training_messages: &[&[u8]],
    limits: RecordSchemaProposalLimits,
) -> Result<CandidateGeneration, RecordDiscoveryError> {
    let fields = candidate_field_domains(training_messages, limits)?;
    let sequence_fields = varying_sequence_fields(training_messages, &fields.integer_shapes)?;
    let pair_fields = sequence_group_candidates(
        training_messages,
        &fields.identifiers,
        &sequence_fields,
        limits.max_pair_checks,
    )?;
    // The fixed-layout path avoids length work when semantic fields cannot form a schema
    let length_fields = if pair_fields.supported.is_empty() {
        empty_length_fields()
    } else {
        length_candidates(
            training_messages,
            &fields.integer_shapes,
            fields.maximum_offset,
            limits.max_length_checks,
        )?
    };
    finish_candidate_generation(&fields, pair_fields, length_fields, limits)
}

fn candidate_field_domains(
    training_messages: &[&[u8]],
    limits: RecordSchemaProposalLimits,
) -> Result<FieldDomains, RecordDiscoveryError> {
    let shortest_message = training_messages
        .iter()
        .map(|message| message.len())
        .min()
        .unwrap_or(0);
    let maximum_offset = limits
        .max_field_offset
        .min(shortest_message.saturating_sub(1));
    let (identifier_fields, byte_checks, omitted_byte_checks) = byte_field_candidates(
        training_messages,
        maximum_offset,
        shortest_message,
        limits.discovery.record_limits.max_identifier_bytes,
        limits.max_field_checks_per_domain,
    )?;
    let (integer_shapes, integer_checks, omitted_integer_checks) = integer_field_shapes(
        maximum_offset,
        shortest_message,
        limits.max_field_checks_per_domain,
    )?;
    Ok(FieldDomains {
        maximum_offset,
        identifiers: identifier_fields,
        integer_shapes,
        examined_byte_checks: byte_checks,
        omitted_byte_checks,
        examined_integer_checks: integer_checks,
        omitted_integer_checks,
    })
}

const fn empty_length_fields() -> LengthFields {
    LengthFields {
        fields: Vec::new(),
        data_offsets: Vec::new(),
        meanings: Vec::new(),
        supported: Vec::new(),
        record_ranges: Vec::new(),
        has_repeated_boundaries: false,
        omitted_record_views: 0,
        examined_checks: 0,
        omitted_checks: 0,
    }
}

fn finish_candidate_generation(
    fields: &FieldDomains,
    mut pair_fields: PairFields,
    mut length_fields: LengthFields,
    limits: RecordSchemaProposalLimits,
) -> Result<CandidateGeneration, RecordDiscoveryError> {
    let omitted_pair_checks = pair_fields.omitted_checks;
    let omitted_length_checks = length_fields.omitted_checks;
    let omitted_record_views = length_fields.omitted_record_views;
    let examined_pair_checks = pair_fields.examined_checks;
    let examined_length_checks = length_fields.examined_checks;
    let record_ranges = std::mem::take(&mut length_fields.record_ranges);
    // Compact layouts rank first, with ordinal gaps and capture-order changes retained as evidence
    pair_fields
        .supported
        .sort_unstable_by_key(supported_pair_order);
    let (compatible_pair_counts, candidate_combinations) =
        compatible_pair_counts(&pair_fields.supported, &length_fields.supported)?;
    let supported_pairs = std::mem::take(&mut pair_fields.supported);
    let supported_lengths = std::mem::take(&mut length_fields.supported);
    let candidate_space = candidate_space(pair_fields, length_fields);
    let omitted_schema_combinations =
        candidate_combinations.map(|count| count.saturating_sub(limits.discovery.max_candidates));
    let omitted_field_checks = fields
        .omitted_byte_checks
        .checked_add(fields.omitted_integer_checks)
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    let search_exhaustive_within_plan = omitted_field_checks == 0
        && omitted_pair_checks == 0
        && omitted_length_checks == 0
        && omitted_record_views == 0
        && omitted_schema_combinations == Some(0);
    Ok(CandidateGeneration {
        candidate_space,
        supported_pairs,
        supported_lengths,
        compatible_pair_counts,
        candidate_combinations,
        examined_field_checks: fields
            .examined_byte_checks
            .checked_add(fields.examined_integer_checks)
            .ok_or(RecordDiscoveryError::InvalidLimits)?,
        omitted_field_checks,
        examined_pair_checks,
        omitted_pair_checks,
        examined_length_checks,
        omitted_length_checks,
        omitted_record_views,
        record_ranges,
        omitted_schema_combinations,
        search_exhaustive_within_plan,
    })
}

fn candidate_space(
    pair_fields: PairFields,
    length_fields: LengthFields,
) -> Option<RecordSchemaDiscoverySpace> {
    if pair_fields.identifiers.is_empty()
        || pair_fields.sequences.is_empty()
        || length_fields.fields.is_empty()
        || length_fields.data_offsets.is_empty()
        || length_fields.meanings.is_empty()
    {
        return None;
    }
    Some(RecordSchemaDiscoverySpace {
        records_offsets: vec![0],
        counts: vec![RecordCount::UntilEnd],
        identifier_fields: pair_fields.identifiers,
        sequence_fields: pair_fields.sequences,
        length_fields: length_fields.fields,
        data_offsets: length_fields.data_offsets,
        length_meanings: length_fields.meanings,
        sequence_base: default_sequence_base(),
    })
}

fn validate_messages(
    training_messages: &[&[u8]],
    held_out_messages: &[&[u8]],
    limits: RecordSchemaProposalLimits,
) -> Result<(), RecordDiscoveryError> {
    if training_messages.is_empty() {
        return Err(RecordDiscoveryError::NoTrainingMessages {
            held_out: held_out_messages.len(),
        });
    }
    let message_count = training_messages
        .len()
        .checked_add(held_out_messages.len())
        .ok_or(RecordDiscoveryError::TooManyMessages {
            count: usize::MAX,
            maximum: limits.discovery.max_messages,
        })?;
    if message_count > limits.discovery.max_messages {
        return Err(RecordDiscoveryError::TooManyMessages {
            count: message_count,
            maximum: limits.discovery.max_messages,
        });
    }
    if message_count > limits.discovery.record_limits.max_records {
        return Err(RecordDiscoveryError::RecordOperation(
            RecordError::TooManyRecords {
                count: u64::try_from(message_count).unwrap_or(u64::MAX),
                maximum: limits.discovery.record_limits.max_records,
            },
        ));
    }

    let mut total_bytes = 0_usize;
    for message in training_messages.iter().chain(held_out_messages) {
        if message.len() > limits.discovery.record_limits.max_input_bytes {
            return Err(RecordDiscoveryError::RecordOperation(
                RecordError::InputTooLarge {
                    length: message.len(),
                    maximum: limits.discovery.record_limits.max_input_bytes,
                },
            ));
        }
        total_bytes =
            total_bytes
                .checked_add(message.len())
                .ok_or(RecordDiscoveryError::RecordOperation(
                    RecordError::InputTooLarge {
                        length: usize::MAX,
                        maximum: limits.discovery.record_limits.max_input_bytes,
                    },
                ))?;
        if total_bytes > limits.discovery.record_limits.max_input_bytes {
            return Err(RecordDiscoveryError::RecordOperation(
                RecordError::InputTooLarge {
                    length: total_bytes,
                    maximum: limits.discovery.record_limits.max_input_bytes,
                },
            ));
        }
    }
    Ok(())
}

fn byte_field_candidates(
    messages: &[&[u8]],
    maximum_offset: usize,
    shortest_message: usize,
    maximum_width: usize,
    maximum_checks: usize,
) -> Result<(Vec<ByteField>, usize, usize), RecordDiscoveryError> {
    let total_checks = byte_shape_count(maximum_offset, shortest_message, maximum_width)?;
    let mut fields = Vec::new();
    let mut checks = 0_usize;
    let width_limit = maximum_width.min(shortest_message);
    let Some(maximum_diagonal) = maximum_offset.checked_add(width_limit.saturating_sub(1)) else {
        return Err(RecordDiscoveryError::InvalidLimits);
    };
    // Walk offset and width together so neither dimension can consume the whole budget
    'diagonals: for diagonal in 0..=maximum_diagonal {
        for offset in 0..=diagonal.min(maximum_offset) {
            let Some(width) = diagonal
                .checked_sub(offset)
                .and_then(|value| value.checked_add(1))
            else {
                return Err(RecordDiscoveryError::InvalidLimits);
            };
            if width > width_limit {
                continue;
            }
            if width > shortest_message.saturating_sub(offset) {
                continue;
            }
            if checks == maximum_checks {
                break 'diagonals;
            }
            checks = checks
                .checked_add(1)
                .ok_or(RecordDiscoveryError::InvalidLimits)?;
            let field = ByteField { offset, width };
            if field_repeats(messages, field)? {
                push(&mut fields, field)?;
            }
        }
    }
    Ok((fields, checks, total_checks.saturating_sub(checks)))
}

fn integer_field_shapes(
    maximum_offset: usize,
    shortest_message: usize,
    maximum_checks: usize,
) -> Result<(Vec<IntegerField>, usize, usize), RecordDiscoveryError> {
    let total_checks = integer_shape_count(maximum_offset, shortest_message)?;
    let mut fields = Vec::new();
    let mut checks = 0_usize;
    'offsets: for offset in 0..=maximum_offset {
        for width in INTEGER_WIDTHS {
            if width > shortest_message.saturating_sub(offset) {
                continue;
            }
            let orders = if width == 1 {
                &[ByteOrder::BigEndian][..]
            } else {
                &[ByteOrder::BigEndian, ByteOrder::LittleEndian][..]
            };
            for byte_order in orders {
                if checks == maximum_checks {
                    break 'offsets;
                }
                checks = checks
                    .checked_add(1)
                    .ok_or(RecordDiscoveryError::InvalidLimits)?;
                push(
                    &mut fields,
                    IntegerField {
                        offset,
                        width,
                        byte_order: *byte_order,
                    },
                )?;
            }
        }
    }
    Ok((fields, checks, total_checks.saturating_sub(checks)))
}

fn varying_sequence_fields(
    messages: &[&[u8]],
    fields: &[IntegerField],
) -> Result<Vec<IntegerField>, RecordDiscoveryError> {
    let mut candidates = Vec::new();
    for field in fields {
        let mut first = None;
        let mut varies = false;
        for message in messages {
            let value = decode_field(message, *field).ok_or(RecordDiscoveryError::InvalidLimits)?;
            if first.is_some_and(|initial| initial != value) {
                varies = true;
                break;
            }
            first = Some(value);
        }
        if varies {
            candidates.try_reserve(1).map_err(|_| allocation_error())?;
            candidates.push(*field);
        }
    }
    Ok(candidates)
}

fn sequence_group_candidates(
    messages: &[&[u8]],
    identifiers: &[ByteField],
    sequences: &[IntegerField],
    maximum_checks: usize,
) -> Result<PairFields, RecordDiscoveryError> {
    let total_checks = identifiers
        .len()
        .checked_mul(sequences.len())
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    if identifiers.is_empty() || sequences.is_empty() {
        return Ok(empty_pair_fields(total_checks));
    }

    let mut supported_identifiers = Vec::new();
    let mut supported_sequences = Vec::new();
    let mut supported = Vec::new();
    let mut seen_identifiers = HashSet::new();
    let mut seen_sequences = HashSet::new();
    let mut checks = 0_usize;
    let maximum_diagonal = identifiers
        .len()
        .checked_add(sequences.len())
        .and_then(|length| length.checked_sub(2))
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    // Visit low-index pairs across both domains before expanding either domain alone
    'diagonals: for diagonal in 0..=maximum_diagonal {
        let last_identifier = diagonal.min(identifiers.len() - 1);
        for identifier_index in 0..=last_identifier {
            let sequence_index = diagonal - identifier_index;
            let Some(identifier) = identifiers.get(identifier_index) else {
                continue;
            };
            let Some(sequence) = sequences.get(sequence_index) else {
                continue;
            };
            if checks == maximum_checks {
                break 'diagonals;
            }
            checks = checks
                .checked_add(1)
                .ok_or(RecordDiscoveryError::InvalidLimits)?;
            if fields_overlap(
                *identifier,
                ByteField {
                    offset: sequence.offset,
                    width: sequence.width,
                },
            ) {
                continue;
            }
            let Some(evidence) = sequence_evidence(messages, *identifier, *sequence)? else {
                continue;
            };
            push_unique_by(
                &mut supported_identifiers,
                &mut seen_identifiers,
                *identifier,
                (identifier.offset, identifier.width),
            )?;
            push_unique_by(
                &mut supported_sequences,
                &mut seen_sequences,
                *sequence,
                (
                    sequence.offset,
                    sequence.width,
                    byte_order_order(sequence.byte_order),
                ),
            )?;
            // Unique input dimensions and one visit per index pair make each relation tuple unique
            push(
                &mut supported,
                SupportedPair {
                    identifier: *identifier,
                    sequence: *sequence,
                    evidence,
                },
            )?;
        }
    }
    Ok(PairFields {
        identifiers: supported_identifiers,
        sequences: supported_sequences,
        supported,
        examined_checks: checks,
        omitted_checks: total_checks.saturating_sub(checks),
    })
}

const fn empty_pair_fields(total_checks: usize) -> PairFields {
    PairFields {
        identifiers: Vec::new(),
        sequences: Vec::new(),
        supported: Vec::new(),
        examined_checks: 0,
        omitted_checks: total_checks,
    }
}

struct SequenceTrack {
    first: u64,
    last: u64,
    minimum: u64,
    maximum: u64,
    varies: bool,
    capture_order_violations: usize,
    distinct_values: HashSet<u64>,
}

fn sequence_evidence(
    messages: &[&[u8]],
    identifier: ByteField,
    sequence: IntegerField,
) -> Result<Option<SequenceEvidence>, RecordDiscoveryError> {
    let mut tracks = HashMap::<&[u8], SequenceTrack>::new();
    tracks
        .try_reserve(messages.len())
        .map_err(|_| allocation_error())?;
    for message in messages {
        let id_end = identifier
            .offset
            .checked_add(identifier.width)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        let Some(id) = message.get(identifier.offset..id_end) else {
            return Ok(None);
        };
        let Some(value) = decode_field(message, sequence) else {
            return Ok(None);
        };
        if let Some(track) = tracks.get_mut(id) {
            if value < track.last {
                track.capture_order_violations = track.capture_order_violations.saturating_add(1);
            }
            track.varies |= value != track.first;
            track.last = value;
            track.minimum = track.minimum.min(value);
            track.maximum = track.maximum.max(value);
            track
                .distinct_values
                .try_reserve(1)
                .map_err(|_| allocation_error())?;
            track.distinct_values.insert(value);
        } else {
            let mut distinct_values = HashSet::new();
            distinct_values
                .try_reserve(1)
                .map_err(|_| allocation_error())?;
            distinct_values.insert(value);
            tracks.insert(
                id,
                SequenceTrack {
                    first: value,
                    last: value,
                    minimum: value,
                    maximum: value,
                    varies: false,
                    capture_order_violations: 0,
                    distinct_values,
                },
            );
        }
    }
    let mut evidence = SequenceEvidence {
        capture_order_violations: 0,
        ordinal_span_holes: 0,
    };
    let mut has_varying_group = false;
    for track in tracks.values() {
        has_varying_group |= track.varies;
        evidence.capture_order_violations = evidence
            .capture_order_violations
            .saturating_add(track.capture_order_violations);
        let ordinal_span = u128::from(track.maximum)
            .saturating_sub(u128::from(track.minimum))
            .saturating_add(1);
        let distinct_count = u128::try_from(track.distinct_values.len()).unwrap_or(u128::MAX);
        evidence.ordinal_span_holes = evidence
            .ordinal_span_holes
            .saturating_add(ordinal_span.saturating_sub(distinct_count));
    }
    Ok(has_varying_group.then_some(evidence))
}

fn length_candidates(
    messages: &[&[u8]],
    fields: &[IntegerField],
    maximum_data_offset: usize,
    maximum_checks: usize,
) -> Result<LengthFields, RecordDiscoveryError> {
    let (total_checks, maximum_gap) = length_domain_stats(fields, maximum_data_offset)?;

    let mut length_fields = Vec::new();
    let mut data_offsets = Vec::new();
    let mut meanings = Vec::new();
    let mut supported = Vec::new();
    let mut seen_fields = HashSet::new();
    let mut seen_data_offsets = HashSet::new();
    let mut seen_meanings = HashSet::new();
    let mut checks = 0_usize;

    // Advance every field by one gap before considering larger gaps
    if let Some(maximum_gap) = maximum_gap {
        'gaps: for gap in 0..=maximum_gap {
            for field in fields {
                let field_end = field
                    .offset
                    .checked_add(field.width)
                    .ok_or(RecordDiscoveryError::InvalidLimits)?;
                let Some(remaining_gap) = maximum_data_offset.checked_sub(field_end) else {
                    continue;
                };
                if gap > remaining_gap {
                    continue;
                }
                let data_offset = field_end
                    .checked_add(gap)
                    .ok_or(RecordDiscoveryError::InvalidLimits)?;
                for meaning in LENGTH_MEANINGS {
                    if checks == maximum_checks {
                        break 'gaps;
                    }
                    checks = checks
                        .checked_add(1)
                        .ok_or(RecordDiscoveryError::InvalidLimits)?;
                    if !matches_length(messages, *field, meaning, data_offset) {
                        continue;
                    }
                    push_unique_by(
                        &mut length_fields,
                        &mut seen_fields,
                        *field,
                        (
                            field.offset,
                            field.width,
                            byte_order_order(field.byte_order),
                        ),
                    )?;
                    push_unique_by(
                        &mut data_offsets,
                        &mut seen_data_offsets,
                        data_offset,
                        data_offset,
                    )?;
                    push_unique_by(
                        &mut meanings,
                        &mut seen_meanings,
                        meaning,
                        length_meaning_order(meaning),
                    )?;
                    // The field, gap, and meaning loop visits each supported layout once
                    push(
                        &mut supported,
                        SupportedLength {
                            field: *field,
                            data_offset,
                            meaning,
                        },
                    )?;
                }
            }
        }
    }
    Ok(LengthFields {
        fields: length_fields,
        data_offsets,
        meanings,
        supported,
        record_ranges: Vec::new(),
        has_repeated_boundaries: false,
        omitted_record_views: 0,
        examined_checks: checks,
        omitted_checks: total_checks
            .checked_sub(checks)
            .ok_or(RecordDiscoveryError::InvalidLimits)?,
    })
}

fn length_domain_stats(
    fields: &[IntegerField],
    maximum_data_offset: usize,
) -> Result<(usize, Option<usize>), RecordDiscoveryError> {
    let mut total_checks = 0_usize;
    let mut maximum_gap = None;
    for field in fields {
        let field_end = field
            .offset
            .checked_add(field.width)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        let Some(gap) = maximum_data_offset.checked_sub(field_end) else {
            continue;
        };
        let boundary_count = gap
            .checked_add(1)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        let field_checks = boundary_count
            .checked_mul(LENGTH_MEANINGS.len())
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        total_checks = total_checks
            .checked_add(field_checks)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        maximum_gap = Some(maximum_gap.map_or(gap, |current: usize| current.max(gap)));
    }
    Ok((total_checks, maximum_gap))
}

fn matches_length(
    messages: &[&[u8]],
    field: IntegerField,
    meaning: super::super::RecordLengthMeaning,
    data_offset: usize,
) -> bool {
    let Some(field_end) = field.offset.checked_add(field.width) else {
        return false;
    };
    for message in messages {
        let Some(value) = decode_field(message, field) else {
            return false;
        };
        let expected = match meaning {
            super::super::RecordLengthMeaning::PayloadBytes => {
                let Some(payload_length) = message.len().checked_sub(data_offset) else {
                    return false;
                };
                payload_length
            }
            super::super::RecordLengthMeaning::WholeRecord => message.len(),
            super::super::RecordLengthMeaning::BytesAfterLengthField => {
                let Some(remaining) = message.len().checked_sub(field_end) else {
                    return false;
                };
                remaining
            }
        };
        if usize::try_from(value).ok() != Some(expected) {
            return false;
        }
    }
    true
}

fn field_repeats(messages: &[&[u8]], field: ByteField) -> Result<bool, RecordDiscoveryError> {
    let mut seen = HashSet::<&[u8]>::new();
    seen.try_reserve(messages.len())
        .map_err(|_| allocation_error())?;
    for message in messages {
        let end = field
            .offset
            .checked_add(field.width)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        let Some(value) = message.get(field.offset..end) else {
            return Ok(false);
        };
        if !seen.insert(value) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn decode_field(message: &[u8], field: IntegerField) -> Option<u64> {
    let end = field.offset.checked_add(field.width)?;
    decode_unsigned(
        message.get(field.offset..end)?,
        field.byte_order == ByteOrder::LittleEndian,
    )
}

const fn fields_overlap(left: ByteField, right: ByteField) -> bool {
    let left_end = left.offset.saturating_add(left.width);
    let right_end = right.offset.saturating_add(right.width);
    left.offset < right_end && right.offset < left_end
}

fn byte_shape_count(
    maximum_offset: usize,
    shortest_message: usize,
    maximum_width: usize,
) -> Result<usize, RecordDiscoveryError> {
    let offset_count = maximum_offset
        .checked_add(1)
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    let full_width_offsets = if maximum_width == 0 || shortest_message < maximum_width {
        0
    } else {
        offset_count.min(shortest_message - maximum_width + 1)
    };
    let full_checks = full_width_offsets
        .checked_mul(maximum_width)
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    let remaining_offsets = offset_count.saturating_sub(full_width_offsets);
    let first_remaining = shortest_message.saturating_sub(full_width_offsets);
    let last_remaining = shortest_message.saturating_sub(offset_count.saturating_sub(1));
    let variable_checks = arithmetic_sum(first_remaining, last_remaining, remaining_offsets)?;
    full_checks
        .checked_add(variable_checks)
        .ok_or(RecordDiscoveryError::InvalidLimits)
}

fn integer_shape_count(
    maximum_offset: usize,
    shortest_message: usize,
) -> Result<usize, RecordDiscoveryError> {
    let offset_count = maximum_offset
        .checked_add(1)
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    INTEGER_WIDTHS
        .into_iter()
        .try_fold(0_usize, |total, width| {
            let offsets = if shortest_message < width {
                0
            } else {
                offset_count.min(shortest_message - width + 1)
            };
            let orders = if width == 1 { 1 } else { 2 };
            total
                .checked_add(
                    offsets
                        .checked_mul(orders)
                        .ok_or(RecordDiscoveryError::InvalidLimits)?,
                )
                .ok_or(RecordDiscoveryError::InvalidLimits)
        })
}

fn arithmetic_sum(first: usize, last: usize, count: usize) -> Result<usize, RecordDiscoveryError> {
    if count == 0 {
        return Ok(0);
    }
    let endpoints = first
        .checked_add(last)
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    let (left, right) = if count.is_multiple_of(2) {
        (count / 2, endpoints)
    } else if endpoints.is_multiple_of(2) {
        (count, endpoints / 2)
    } else {
        return Err(RecordDiscoveryError::InvalidLimits);
    };
    left.checked_mul(right)
        .ok_or(RecordDiscoveryError::InvalidLimits)
}

fn push<T>(values: &mut Vec<T>, value: T) -> Result<(), RecordDiscoveryError> {
    values.try_reserve(1).map_err(|_| allocation_error())?;
    values.push(value);
    Ok(())
}

fn push_unique_by<T: Copy, K: Copy + Eq + Hash>(
    values: &mut Vec<T>,
    seen: &mut HashSet<K>,
    value: T,
    key: K,
) -> Result<(), RecordDiscoveryError> {
    if seen.contains(&key) {
        return Ok(());
    }
    seen.try_reserve(1).map_err(|_| allocation_error())?;
    values.try_reserve(1).map_err(|_| allocation_error())?;
    seen.insert(key);
    values.push(value);
    Ok(())
}

const fn allocation_error() -> RecordDiscoveryError {
    RecordDiscoveryError::RecordOperation(RecordError::AllocationFailed)
}
