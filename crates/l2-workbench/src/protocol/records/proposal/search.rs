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
    RecordDiscoveryError, RecordSchemaDiscoverySpace, RecordSchemaHypothesis,
    discover_record_schemas_from_candidates_observed,
    discover_record_schemas_from_candidates_with_work,
};
use super::super::{
    ByteField, IntegerField, RecordCount, RecordError, RecordInput, RecordParseReport,
    RecordSchema, RecordWorkBudget,
};
use super::model::{
    INTEGER_WIDTHS, LIMITATIONS, RecordBoundaryCue, RecordSchemaAnalysisReport,
    RecordSchemaMultiStrategyAnalysisReport, RecordSchemaProposalLimits,
    RecordSchemaProposalReport, RecordSchemaProposalValidationBasis, RecordSchemaStrategy,
    default_sequence_base,
};
use crate::integer::decode_unsigned;
use crate::protocol::ByteOrder;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::hash::Hash;
use std::ops::ControlFlow;

mod length_layouts;
mod repeated;

use length_layouts::{LengthLayoutOrder, visit_length_layouts};

type SurvivorObserver<'observer> = dyn FnMut(
        RecordSchemaStrategy,
        &RecordSchemaHypothesis,
        &[RecordParseReport],
        &[RecordParseReport],
    ) -> ControlFlow<()>
    + 'observer;

#[derive(Clone, Copy)]
struct ProposalInputs<'messages, 'inputs, 'record, 'bytes> {
    training_messages: &'messages [&'bytes [u8]],
    held_out_messages: &'messages [&'bytes [u8]],
    training_inputs: &'inputs [&'record RecordInput<'bytes>],
    held_out_inputs: &'inputs [&'record RecordInput<'bytes>],
}

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
    let inputs = own_inputs(training_messages)?;
    let input_refs = input_refs(&inputs)?;
    let mut work = None;
    let generated = generate_candidates(training_messages, &input_refs, limits, &[], &mut work)?;
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
    let training_inputs = own_inputs(training_messages)?;
    let held_out_inputs = own_inputs(held_out_messages)?;
    let training_refs = input_refs(&training_inputs)?;
    let held_out_refs = input_refs(&held_out_inputs)?;
    let mut work = None;
    let generated = generate_candidates(training_messages, &training_refs, limits, &[], &mut work)?;
    analyze_generated_candidates(
        ProposalInputs {
            training_messages,
            held_out_messages,
            training_inputs: &training_refs,
            held_out_inputs: &held_out_refs,
        },
        limits,
        generated,
        &mut work,
    )
}

/// Analyze fixed-layout and repeated-boundary schemas as separate bounded strategies
///
/// Search and canonical parser budgets are divided between the two strategies. The fixed-layout
/// analysis keeps the established one-record-per-message behavior, while repeated-boundary
/// analysis first uses length fields to locate bounded record views and only then proposes header
/// fields. Each strategy retains its own proposal and parser report so unrelated candidate
/// dimensions are never combined into a synthetic Cartesian search space
///
/// Repeated-boundary layouts use a deterministic compact-prefix priority heuristic. The report's
/// omission counts show when the configured check cap leaves layouts unexamined
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
    validate_training_offsets(training_data_offsets, limits)?;
    let training_inputs = own_inputs(training_messages)?;
    let held_out_inputs = own_inputs(held_out_messages)?;
    let training_refs = input_refs(&training_inputs)?;
    let held_out_refs = input_refs(&held_out_inputs)?;
    let mut work = None;
    analyze_record_schemas_with_repeated_boundaries_and_offsets_validated(
        ProposalInputs {
            training_messages,
            held_out_messages,
            training_inputs: &training_refs,
            held_out_inputs: &held_out_refs,
        },
        limits,
        training_data_offsets,
        None,
        &mut work,
    )
    .map(|(report, _)| report)
}

/// Analyze schemas while exposing each strict survivor before report retention
///
/// The callback receives the canonical parse reports for the exact training and held-out input
/// order. Returning `Break(())` stops candidate search after the current survivor is accounted
/// for; the returned discovery report keeps the remaining combinations marked unexamined
///
/// # Errors
/// Rejects empty training input, invalid limits, and aggregate message resource excess
pub fn analyze_record_schemas_with_repeated_boundaries_and_offsets_observed<F>(
    training_messages: &[&[u8]],
    held_out_messages: &[&[u8]],
    limits: RecordSchemaProposalLimits,
    training_data_offsets: &[usize],
    observer: F,
) -> Result<RecordSchemaMultiStrategyAnalysisReport, RecordDiscoveryError>
where
    F: FnMut(
        RecordSchemaStrategy,
        &RecordSchemaHypothesis,
        &[RecordParseReport],
        &[RecordParseReport],
    ) -> ControlFlow<()>,
{
    limits.validate()?;
    validate_messages(training_messages, held_out_messages, limits)?;
    validate_training_offsets(training_data_offsets, limits)?;
    let training_inputs = own_inputs(training_messages)?;
    let held_out_inputs = own_inputs(held_out_messages)?;
    let training_refs = input_refs(&training_inputs)?;
    let held_out_refs = input_refs(&held_out_inputs)?;
    let mut work = None;
    analyze_record_schemas_with_repeated_boundaries_and_offsets_validated(
        ProposalInputs {
            training_messages,
            held_out_messages,
            training_inputs: &training_refs,
            held_out_inputs: &held_out_refs,
        },
        limits,
        training_data_offsets,
        Some(Box::new(observer)),
        &mut work,
    )
    .map(|(report, _)| report)
}

/// Analyze existing inputs with one work budget without retaining parse reports for a callback
///
/// Input identities are reused by proposal checks, schema validation, and later assembly
/// A work-limited result remains incomplete and cannot falsify an untested schema
///
/// # Errors
/// Rejects empty training input, invalid limits, and aggregate message resource excess
pub fn analyze_record_inputs_with_repeated_boundaries_and_offsets(
    training_inputs: &[&RecordInput<'_>],
    held_out_inputs: &[&RecordInput<'_>],
    limits: RecordSchemaProposalLimits,
    training_data_offsets: &[usize],
    work: &mut RecordWorkBudget,
) -> Result<RecordSchemaMultiStrategyAnalysisReport, RecordDiscoveryError> {
    limits.validate()?;
    validate_input_messages(training_inputs, held_out_inputs, limits)?;
    validate_training_offsets(training_data_offsets, limits)?;
    let mut work = Some(work);
    let input_view_work =
        charge_input_view_storage(training_inputs.len(), held_out_inputs.len(), &mut work)?;
    let training_messages = input_views(training_inputs)?;
    let held_out_messages = input_views(held_out_inputs)?;
    let (mut report, _) = analyze_record_schemas_with_repeated_boundaries_and_offsets_validated(
        ProposalInputs {
            training_messages: &training_messages,
            held_out_messages: &held_out_messages,
            training_inputs,
            held_out_inputs,
        },
        limits,
        training_data_offsets,
        None,
        &mut work,
    )?;
    include_shared_view_work(&mut report, input_view_work)?;
    Ok(report)
}

/// Analyze existing inputs with one work budget and expose strict survivors to a gate
///
/// The same input identities are reused by proposal checks, strict parsing, and later assembly
/// The report marks work-limited searches as incomplete so a budget stop cannot falsify a schema
///
/// # Errors
/// Rejects empty training input, invalid limits, and aggregate message resource excess
pub fn analyze_record_inputs_with_repeated_boundaries_and_offsets_observed<F>(
    training_inputs: &[&RecordInput<'_>],
    held_out_inputs: &[&RecordInput<'_>],
    limits: RecordSchemaProposalLimits,
    training_data_offsets: &[usize],
    work: &mut RecordWorkBudget,
    observer: F,
) -> Result<RecordSchemaMultiStrategyAnalysisReport, RecordDiscoveryError>
where
    F: FnMut(
        RecordSchemaStrategy,
        &RecordSchemaHypothesis,
        &[RecordParseReport],
        &[RecordParseReport],
    ) -> ControlFlow<()>,
{
    limits.validate()?;
    validate_input_messages(training_inputs, held_out_inputs, limits)?;
    validate_training_offsets(training_data_offsets, limits)?;
    let mut work = Some(work);
    let input_view_work =
        charge_input_view_storage(training_inputs.len(), held_out_inputs.len(), &mut work)?;
    let training_messages = input_views(training_inputs)?;
    let held_out_messages = input_views(held_out_inputs)?;
    let (mut report, _) = analyze_record_schemas_with_repeated_boundaries_and_offsets_validated(
        ProposalInputs {
            training_messages: &training_messages,
            held_out_messages: &held_out_messages,
            training_inputs,
            held_out_inputs,
        },
        limits,
        training_data_offsets,
        Some(Box::new(observer)),
        &mut work,
    )?;
    include_shared_view_work(&mut report, input_view_work)?;
    Ok(report)
}

fn include_shared_view_work(
    report: &mut RecordSchemaMultiStrategyAnalysisReport,
    shared_work: usize,
) -> Result<(), RecordDiscoveryError> {
    let fixed_work = report
        .fixed_layout
        .work_bytes
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    report.fixed_layout.work_bytes = Some(
        fixed_work
            .checked_add(shared_work)
            .ok_or(RecordDiscoveryError::InvalidLimits)?,
    );
    Ok(())
}

fn analyze_record_schemas_with_repeated_boundaries_and_offsets_validated(
    inputs: ProposalInputs<'_, '_, '_, '_>,
    limits: RecordSchemaProposalLimits,
    training_data_offsets: &[usize],
    mut observer: Option<Box<SurvivorObserver<'_>>>,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<(RecordSchemaMultiStrategyAnalysisReport, bool), RecordDiscoveryError> {
    let Some((fixed_limits, repeated_limits)) = split_strategy_limits(limits) else {
        return analyze_fixed_layout_only(
            inputs,
            limits,
            training_data_offsets,
            &mut observer,
            work,
        );
    };

    let fixed_work_start = current_work(work);
    let fixed_generated = generate_candidates(
        inputs.training_messages,
        inputs.training_inputs,
        fixed_limits,
        training_data_offsets,
        work,
    )?;
    let (mut fixed_layout, fixed_stopped) = analyze_generated_candidates_with_observer(
        inputs,
        fixed_limits,
        fixed_generated,
        RecordSchemaStrategy::FixedLayout,
        observer.as_deref_mut(),
        work,
    )?;
    fixed_layout.work_bytes = work_delta(fixed_work_start, work);
    if fixed_stopped {
        return Ok((
            RecordSchemaMultiStrategyAnalysisReport {
                fixed_layout,
                fixed_layout_limits: fixed_limits,
                repeated_boundaries: None,
                repeated_boundary_limits: None,
            },
            true,
        ));
    }

    let repeated_work_start = current_work(work);
    let repeated_generated = repeated::generate_candidates(
        inputs.training_messages,
        inputs.training_inputs,
        repeated_limits,
        work,
    )?;
    let (mut repeated_boundaries, repeated_stopped) = analyze_generated_candidates_with_observer(
        inputs,
        repeated_limits,
        repeated_generated,
        RecordSchemaStrategy::RepeatedBoundaries,
        observer.as_deref_mut(),
        work,
    )?;
    repeated_boundaries.work_bytes = work_delta(repeated_work_start, work);
    Ok((
        RecordSchemaMultiStrategyAnalysisReport {
            fixed_layout,
            fixed_layout_limits: fixed_limits,
            repeated_boundaries: Some(repeated_boundaries),
            repeated_boundary_limits: Some(repeated_limits),
        },
        repeated_stopped,
    ))
}

fn analyze_fixed_layout_only(
    inputs: ProposalInputs<'_, '_, '_, '_>,
    limits: RecordSchemaProposalLimits,
    training_data_offsets: &[usize],
    observer: &mut Option<Box<SurvivorObserver<'_>>>,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<(RecordSchemaMultiStrategyAnalysisReport, bool), RecordDiscoveryError> {
    let work_start = current_work(work);
    let generated = generate_candidates(
        inputs.training_messages,
        inputs.training_inputs,
        limits,
        training_data_offsets,
        work,
    )?;
    let (mut fixed_layout, stopped_by_observer) = analyze_generated_candidates_with_observer(
        inputs,
        limits,
        generated,
        RecordSchemaStrategy::FixedLayout,
        observer.as_deref_mut(),
        work,
    )?;
    fixed_layout.work_bytes = work_delta(work_start, work);
    Ok((
        RecordSchemaMultiStrategyAnalysisReport {
            fixed_layout,
            fixed_layout_limits: limits,
            repeated_boundaries: None,
            repeated_boundary_limits: None,
        },
        stopped_by_observer,
    ))
}

fn analyze_generated_candidates(
    inputs: ProposalInputs<'_, '_, '_, '_>,
    limits: RecordSchemaProposalLimits,
    generated: CandidateGeneration,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<RecordSchemaAnalysisReport, RecordDiscoveryError> {
    analyze_generated_candidates_with_observer(
        inputs,
        limits,
        generated,
        RecordSchemaStrategy::FixedLayout,
        None,
        work,
    )
    .map(|(analysis, _)| analysis)
}

fn analyze_generated_candidates_with_observer(
    inputs: ProposalInputs<'_, '_, '_, '_>,
    limits: RecordSchemaProposalLimits,
    generated: CandidateGeneration,
    strategy: RecordSchemaStrategy,
    observer: Option<&mut SurvivorObserver<'_>>,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<(RecordSchemaAnalysisReport, bool), RecordDiscoveryError> {
    let mut observer_stopped = false;
    let discovery = if let Some(space) = generated.candidate_space.as_ref() {
        let mut schemas = generated.schemas(space);
        let discovery = match observer {
            Some(callback) => {
                let observer = callback;
                let (discovery, stopped) = discover_record_schemas_from_candidates_observed(
                    inputs.training_inputs,
                    inputs.held_out_inputs,
                    generated.candidate_combinations,
                    limits.discovery,
                    |_, work| schemas.try_next(work),
                    work.as_deref_mut(),
                    &mut |hypothesis, training_reports, held_out_reports| {
                        observer(strategy, hypothesis, training_reports, held_out_reports)
                    },
                )?;
                observer_stopped = stopped;
                discovery
            }
            None => discover_record_schemas_from_candidates_with_work(
                inputs.training_inputs,
                inputs.held_out_inputs,
                generated.candidate_combinations,
                limits.discovery,
                |_, work| schemas.try_next(work),
                work.as_deref_mut(),
            )?,
        };
        Some(discovery)
    } else {
        None
    };
    let proposal = proposal_report(
        inputs.training_messages,
        inputs.held_out_messages,
        generated,
    );
    Ok((
        RecordSchemaAnalysisReport {
            proposal,
            discovery,
            work_bytes: None,
        },
        observer_stopped,
    ))
}

fn current_work(work: &Option<&mut RecordWorkBudget>) -> Option<usize> {
    work.as_ref().map(|budget| budget.consumed())
}

fn work_delta(start: Option<usize>, work: &Option<&mut RecordWorkBudget>) -> Option<usize> {
    Some(current_work(work)?.saturating_sub(start?))
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

const fn split_limit(fixed: &mut usize, repeated: &mut usize) -> Option<()> {
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
        work_limit_reached: generated.work_limit_reached,
        limitations: LIMITATIONS,
    }
}

struct CandidateGeneration {
    candidate_space: Option<RecordSchemaDiscoverySpace>,
    priority_data_offsets: Vec<usize>,
    supported_pairs: Vec<SupportedPair>,
    supported_lengths: Vec<SupportedLength>,
    compatible_pair_summaries: Vec<CompatiblePairSummary>,
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
    work_limit_reached: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SupportedPair {
    identifier: ByteField,
    sequence: IntegerField,
    evidence: SequenceEvidence,
    // Repeated headers only pair with lengths learned from the same record views
    layout_group: Option<usize>,
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
    // None is the established fixed-layout path; repeated layouts carry their view group
    layout_group: Option<usize>,
}

#[derive(Clone, Copy)]
struct CompatiblePairSummary {
    count: usize,
    first_pair_index: Option<usize>,
}

struct PairFields {
    identifiers: Vec<ByteField>,
    sequences: Vec<IntegerField>,
    supported: Vec<SupportedPair>,
    examined_checks: usize,
    omitted_checks: usize,
    work_limit_reached: bool,
}

#[derive(Default)]
struct PairCheckProgress {
    examined_checks: usize,
    omitted_checks: usize,
    work_limit_reached: bool,
}

#[derive(Default)]
struct SupportedPairCollection {
    identifiers: Vec<ByteField>,
    sequences: Vec<IntegerField>,
    supported: Vec<SupportedPair>,
    seen_identifiers: HashSet<(usize, usize)>,
    seen_sequences: HashSet<(usize, usize, u8)>,
}

impl SupportedPairCollection {
    fn retain(
        &mut self,
        identifier: ByteField,
        sequence: IntegerField,
        evidence: SequenceEvidence,
        layout_group: Option<usize>,
    ) -> Result<(), RecordDiscoveryError> {
        push_unique_by(
            &mut self.identifiers,
            &mut self.seen_identifiers,
            identifier,
            (identifier.offset, identifier.width),
        )?;
        push_unique_by(
            &mut self.sequences,
            &mut self.seen_sequences,
            sequence,
            (
                sequence.offset,
                sequence.width,
                byte_order_order(sequence.byte_order),
            ),
        )?;
        // Unique input dimensions and one visit per index pair make each relation tuple unique
        push(
            &mut self.supported,
            SupportedPair {
                identifier,
                sequence,
                evidence,
                layout_group,
            },
        )
    }

    fn into_pair_fields(
        self,
        examined_checks: usize,
        omitted_checks: usize,
        work_limit_reached: bool,
    ) -> PairFields {
        PairFields {
            identifiers: self.identifiers,
            sequences: self.sequences,
            supported: self.supported,
            examined_checks,
            omitted_checks,
            work_limit_reached,
        }
    }
}

struct LengthFields {
    fields: Vec<IntegerField>,
    data_offsets: Vec<usize>,
    meanings: Vec<super::super::RecordLengthMeaning>,
    supported: Vec<SupportedLength>,
    record_ranges: Vec<RecordRange>,
    view_groups: Vec<RepeatedViewGroup>,
    group_view_count: usize,
    has_repeated_boundaries: bool,
    omitted_record_views: usize,
    examined_checks: usize,
    omitted_checks: usize,
    work_limit_reached: bool,
}

struct RepeatedViewGroup {
    ranges: Vec<RecordRange>,
}

#[derive(Default)]
struct LengthFieldMembership {
    fields: HashSet<(usize, usize, u8)>,
    data_offsets: HashSet<usize>,
    meanings: HashSet<u8>,
}

impl LengthFields {
    fn retain_layout(
        &mut self,
        seen: &mut LengthFieldMembership,
        layout: SupportedLength,
    ) -> Result<(), RecordDiscoveryError> {
        let field = layout.field;
        push_unique_by(
            &mut self.fields,
            &mut seen.fields,
            field,
            (
                field.offset,
                field.width,
                byte_order_order(field.byte_order),
            ),
        )?;
        push_unique_by(
            &mut self.data_offsets,
            &mut seen.data_offsets,
            layout.data_offset,
            layout.data_offset,
        )?;
        push_unique_by(
            &mut self.meanings,
            &mut seen.meanings,
            layout.meaning,
            length_meaning_order(layout.meaning),
        )?;
        // Both strategies visit each field, boundary, and meaning combination once
        push(&mut self.supported, layout)
    }
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
    work_limit_reached: bool,
}

impl CandidateGeneration {
    fn schemas<'a>(&'a self, space: &'a RecordSchemaDiscoverySpace) -> SupportedSchemaIter<'a> {
        SupportedSchemaIter {
            space,
            priority_data_offsets: &self.priority_data_offsets,
            pairs: &self.supported_pairs,
            lengths: &self.supported_lengths,
            pair_summaries: &self.compatible_pair_summaries,
            rows: BinaryHeap::new(),
            initialized: false,
        }
    }
}

struct SupportedSchemaIter<'a> {
    space: &'a RecordSchemaDiscoverySpace,
    priority_data_offsets: &'a [usize],
    pairs: &'a [SupportedPair],
    lengths: &'a [SupportedLength],
    pair_summaries: &'a [CompatiblePairSummary],
    rows: BinaryHeap<Reverse<(usize, usize, usize, usize)>>,
    initialized: bool,
}

impl SupportedSchemaIter<'_> {
    fn try_next(
        &mut self,
        work: &mut Option<&mut RecordWorkBudget>,
    ) -> Result<Option<RecordSchema>, RecordDiscoveryError> {
        if !self.initialized {
            self.initialize(work)?;
        }
        let Some(Reverse((_, _, length_index, pair_index))) = self.rows.peek().copied() else {
            return Ok(None);
        };
        charge_proposal_work(
            work,
            std::mem::size_of::<Reverse<(usize, usize, usize, usize)>>(),
        )?;
        let _ = self.rows.pop();
        let pair = self
            .pairs
            .get(pair_index)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        let length = self
            .lengths
            .get(length_index)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        let next_start = pair_index
            .checked_add(1)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        if let Some(next_pair_index) = first_compatible_pair(self.pairs, length, next_start, work)?
        {
            charge_proposal_work(
                work,
                std::mem::size_of::<Reverse<(usize, usize, usize, usize)>>(),
            )?;
            self.rows.push(Reverse((
                usize::from(
                    self.priority_data_offsets
                        .binary_search(&length.data_offset)
                        .is_err(),
                ),
                length_index
                    .checked_add(next_pair_index)
                    .ok_or(RecordDiscoveryError::InvalidLimits)?,
                length_index,
                next_pair_index,
            )));
        }
        Ok(Some(RecordSchema {
            records_offset: *self
                .space
                .records_offsets
                .first()
                .ok_or(RecordDiscoveryError::InvalidLimits)?,
            count: *self
                .space
                .counts
                .first()
                .ok_or(RecordDiscoveryError::InvalidLimits)?,
            identifier: pair.identifier,
            sequence: pair.sequence,
            length: length.field,
            data_offset: length.data_offset,
            length_meaning: length.meaning,
            sequence_base: self.space.sequence_base,
            terminal_sequence: None,
        }))
    }

    fn initialize(
        &mut self,
        work: &mut Option<&mut RecordWorkBudget>,
    ) -> Result<(), RecordDiscoveryError> {
        let row_storage = self
            .lengths
            .len()
            .checked_mul(std::mem::size_of::<Reverse<(usize, usize, usize, usize)>>())
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        charge_proposal_work(work, row_storage)?;
        self.rows
            .try_reserve_exact(self.lengths.len())
            .map_err(|_| allocation_error())?;
        for (length_index, summary) in self.pair_summaries.iter().enumerate() {
            if summary.count == 0 {
                continue;
            }
            let pair_index = summary
                .first_pair_index
                .ok_or(RecordDiscoveryError::InvalidLimits)?;
            let length = self
                .lengths
                .get(length_index)
                .ok_or(RecordDiscoveryError::InvalidLimits)?;
            charge_proposal_work(
                work,
                std::mem::size_of::<Reverse<(usize, usize, usize, usize)>>(),
            )?;
            self.rows.push(Reverse((
                usize::from(
                    self.priority_data_offsets
                        .binary_search(&length.data_offset)
                        .is_err(),
                ),
                length_index
                    .checked_add(pair_index)
                    .ok_or(RecordDiscoveryError::InvalidLimits)?,
                length_index,
                pair_index,
            )));
        }
        self.initialized = true;
        Ok(())
    }
}

fn supported_pair_order(pair: &SupportedPair, prioritize_evidence: bool) -> SupportedPairOrder {
    let identifier_end = pair.identifier.offset.saturating_add(pair.identifier.width);
    let sequence_end = pair.sequence.offset.saturating_add(pair.sequence.width);
    let field_gap = if identifier_end <= pair.sequence.offset {
        pair.sequence.offset - identifier_end
    } else {
        pair.identifier.offset.saturating_sub(sequence_end)
    };
    let span_start = pair.identifier.offset.min(pair.sequence.offset);
    let span_end = identifier_end.max(sequence_end);
    let (priority_ordinal_span_holes, priority_capture_order_violations) = if prioritize_evidence {
        (
            pair.evidence.ordinal_span_holes,
            pair.evidence.capture_order_violations,
        )
    } else {
        (0, 0)
    };
    let (fallback_capture_order_violations, fallback_ordinal_span_holes) = if prioritize_evidence {
        (0, 0)
    } else {
        (
            pair.evidence.capture_order_violations,
            pair.evidence.ordinal_span_holes,
        )
    };
    SupportedPairOrder {
        layout_group: pair.layout_group,
        priority_ordinal_span_holes,
        priority_capture_order_violations,
        field_gap,
        span_length: span_end.saturating_sub(span_start),
        field_width_sum: pair.identifier.width.saturating_add(pair.sequence.width),
        fallback_capture_order_violations,
        fallback_ordinal_span_holes,
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
    layout_group: Option<usize>,
    priority_ordinal_span_holes: u128,
    priority_capture_order_violations: usize,
    field_gap: usize,
    span_length: usize,
    field_width_sum: usize,
    fallback_capture_order_violations: usize,
    fallback_ordinal_span_holes: u128,
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
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<Option<usize>, RecordDiscoveryError> {
    for (index, pair) in pairs.iter().enumerate().skip(start) {
        charge_proposal_work(work, std::mem::size_of::<SupportedPair>())?;
        if pair.layout_group == length.layout_group
            && pair_fits_before_data(pair, length.data_offset)
        {
            return Ok(Some(index));
        }
    }
    Ok(None)
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
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<Option<(Vec<CompatiblePairSummary>, usize)>, RecordDiscoveryError> {
    if pairs.is_empty() || lengths.is_empty() {
        return Ok(Some((Vec::new(), 0)));
    }
    let summary_bytes = lengths
        .len()
        .checked_mul(std::mem::size_of::<CompatiblePairSummary>())
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    if !try_charge_work(work, summary_bytes) {
        return Ok(None);
    }
    let mut summaries = Vec::new();
    summaries
        .try_reserve_exact(lengths.len())
        .map_err(|_| allocation_error())?;
    let mut candidate_count = 0_usize;
    for length in lengths {
        let mut summary = CompatiblePairSummary {
            count: 0,
            first_pair_index: None,
        };
        for (pair_index, pair) in pairs.iter().enumerate() {
            if !try_charge_work(work, std::mem::size_of::<SupportedPair>()) {
                return Ok(None);
            }
            if pair.layout_group == length.layout_group
                && pair_fits_before_data(pair, length.data_offset)
            {
                summary.count = summary
                    .count
                    .checked_add(1)
                    .ok_or(RecordDiscoveryError::InvalidLimits)?;
                summary.first_pair_index.get_or_insert(pair_index);
            }
        }
        candidate_count = candidate_count
            .checked_add(summary.count)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        summaries.push(summary);
    }
    Ok(Some((summaries, candidate_count)))
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
    training_inputs: &[&RecordInput<'_>],
    limits: RecordSchemaProposalLimits,
    training_data_offsets: &[usize],
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<CandidateGeneration, RecordDiscoveryError> {
    let fields = candidate_field_domains(training_messages, limits, work)?;
    let priority_data_offsets =
        normalized_training_data_offsets(training_data_offsets, fields.maximum_offset)?;
    let (sequence_fields, sequence_work_limit) =
        varying_sequence_fields(training_messages, &fields.integer_shapes, work)?;
    let mut supported_pairs = SupportedPairCollection::default();
    let pair_progress = sequence_group_candidates(
        training_messages,
        &fields.identifiers,
        &sequence_fields,
        limits.max_pair_checks,
        None,
        &mut supported_pairs,
        work,
    )?;
    let mut pair_fields = supported_pairs.into_pair_fields(
        pair_progress.examined_checks,
        pair_progress.omitted_checks,
        pair_progress.work_limit_reached,
    );
    pair_fields.work_limit_reached |= sequence_work_limit;
    // The fixed-layout path avoids length work when semantic fields cannot form a schema
    let length_fields = if pair_fields.supported.is_empty() {
        empty_length_fields()
    } else {
        length_candidates(
            training_messages,
            training_inputs,
            &fields.integer_shapes,
            fields.maximum_offset,
            limits.max_length_checks,
            &priority_data_offsets,
            work,
        )?
    };
    finish_candidate_generation(
        &fields,
        pair_fields,
        length_fields,
        limits,
        priority_data_offsets,
        work,
    )
}

fn normalized_training_data_offsets(
    offsets: &[usize],
    maximum_offset: usize,
) -> Result<Vec<usize>, RecordDiscoveryError> {
    let mut normalized = Vec::new();
    normalized
        .try_reserve_exact(offsets.len())
        .map_err(|_| allocation_error())?;
    normalized.extend(
        offsets
            .iter()
            .copied()
            .filter(|offset| *offset <= maximum_offset),
    );
    normalized.sort_unstable();
    normalized.dedup();
    Ok(normalized)
}

fn candidate_field_domains(
    training_messages: &[&[u8]],
    limits: RecordSchemaProposalLimits,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<FieldDomains, RecordDiscoveryError> {
    let shortest_message = training_messages
        .iter()
        .map(|message| message.len())
        .min()
        .unwrap_or(0);
    let maximum_offset = limits
        .max_field_offset
        .min(shortest_message.saturating_sub(1));
    let (identifier_fields, byte_checks, omitted_byte_checks, byte_work_limit) =
        byte_field_candidates(
            training_messages,
            maximum_offset,
            shortest_message,
            limits.discovery.record_limits.max_identifier_bytes,
            limits.max_field_checks_per_domain,
            work,
        )?;
    let (integer_shapes, integer_checks, omitted_integer_checks, integer_work_limit) =
        integer_field_shapes(
            maximum_offset,
            shortest_message,
            limits.max_field_checks_per_domain,
            work,
        )?;
    Ok(FieldDomains {
        maximum_offset,
        identifiers: identifier_fields,
        integer_shapes,
        examined_byte_checks: byte_checks,
        omitted_byte_checks,
        examined_integer_checks: integer_checks,
        omitted_integer_checks,
        work_limit_reached: byte_work_limit || integer_work_limit,
    })
}

const fn empty_length_fields() -> LengthFields {
    LengthFields {
        fields: Vec::new(),
        data_offsets: Vec::new(),
        meanings: Vec::new(),
        supported: Vec::new(),
        record_ranges: Vec::new(),
        view_groups: Vec::new(),
        group_view_count: 0,
        has_repeated_boundaries: false,
        omitted_record_views: 0,
        examined_checks: 0,
        omitted_checks: 0,
        work_limit_reached: false,
    }
}

fn finish_candidate_generation(
    fields: &FieldDomains,
    mut pair_fields: PairFields,
    mut length_fields: LengthFields,
    limits: RecordSchemaProposalLimits,
    priority_data_offsets: Vec<usize>,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<CandidateGeneration, RecordDiscoveryError> {
    let omitted_pair_checks = pair_fields.omitted_checks;
    let omitted_length_checks = length_fields.omitted_checks;
    let omitted_record_views = length_fields.omitted_record_views;
    let examined_pair_checks = pair_fields.examined_checks;
    let examined_length_checks = length_fields.examined_checks;
    let mut work_limit_reached = fields.work_limit_reached
        || pair_fields.work_limit_reached
        || length_fields.work_limit_reached;
    let record_ranges = std::mem::take(&mut length_fields.record_ranges);
    // Source framing lets training evidence rank before compactness without changing default search
    let prioritize_evidence = !priority_data_offsets.is_empty();
    pair_fields
        .supported
        .sort_unstable_by_key(|pair| supported_pair_order(pair, prioritize_evidence));
    let compatible_pairs =
        compatible_pair_counts(&pair_fields.supported, &length_fields.supported, work)?;
    if compatible_pairs.is_none() {
        work_limit_reached = true;
    }
    let (compatible_pair_summaries, candidate_combinations) = compatible_pairs.map_or_else(
        || (Vec::new(), None),
        |(summaries, total)| (summaries, Some(total)),
    );
    let supported_pairs = std::mem::take(&mut pair_fields.supported);
    let supported_lengths = std::mem::take(&mut length_fields.supported);
    let candidate_space = if work_limit_reached && candidate_combinations.is_none() {
        None
    } else {
        candidate_space(pair_fields, length_fields)
    };
    let omitted_schema_combinations =
        candidate_combinations.map(|count| count.saturating_sub(limits.discovery.max_candidates));
    let omitted_field_checks = fields
        .omitted_byte_checks
        .checked_add(fields.omitted_integer_checks)
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    let search_exhaustive_within_plan = !work_limit_reached
        && omitted_field_checks == 0
        && omitted_pair_checks == 0
        && omitted_length_checks == 0
        && omitted_record_views == 0
        && omitted_schema_combinations == Some(0);
    Ok(CandidateGeneration {
        candidate_space,
        priority_data_offsets,
        supported_pairs,
        supported_lengths,
        compatible_pair_summaries,
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
        work_limit_reached,
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
    validate_message_count(training_messages.len(), held_out_messages.len(), limits)?;

    validate_message_lengths(
        training_messages
            .iter()
            .chain(held_out_messages)
            .map(|message| message.len()),
        limits,
    )
}

fn validate_input_messages(
    training_inputs: &[&RecordInput<'_>],
    held_out_inputs: &[&RecordInput<'_>],
    limits: RecordSchemaProposalLimits,
) -> Result<(), RecordDiscoveryError> {
    validate_message_count(training_inputs.len(), held_out_inputs.len(), limits)?;
    validate_message_lengths(
        training_inputs
            .iter()
            .chain(held_out_inputs)
            .map(|input| input.bytes().len()),
        limits,
    )
}

fn validate_message_count(
    training_count: usize,
    held_out_count: usize,
    limits: RecordSchemaProposalLimits,
) -> Result<(), RecordDiscoveryError> {
    if training_count == 0 {
        return Err(RecordDiscoveryError::NoTrainingMessages {
            held_out: held_out_count,
        });
    }
    let message_count = training_count.checked_add(held_out_count).ok_or(
        RecordDiscoveryError::TooManyMessages {
            count: usize::MAX,
            maximum: limits.discovery.max_messages,
        },
    )?;
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
    Ok(())
}

fn validate_message_lengths(
    message_lengths: impl Iterator<Item = usize>,
    limits: RecordSchemaProposalLimits,
) -> Result<(), RecordDiscoveryError> {
    let mut total_bytes = 0_usize;
    for message_length in message_lengths {
        if message_length > limits.discovery.record_limits.max_input_bytes {
            return Err(RecordDiscoveryError::RecordOperation(
                RecordError::InputTooLarge {
                    length: message_length,
                    maximum: limits.discovery.record_limits.max_input_bytes,
                },
            ));
        }
        total_bytes = total_bytes.checked_add(message_length).ok_or(
            RecordDiscoveryError::RecordOperation(RecordError::InputTooLarge {
                length: usize::MAX,
                maximum: limits.discovery.record_limits.max_input_bytes,
            }),
        )?;
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

const fn validate_training_offsets(
    offsets: &[usize],
    limits: RecordSchemaProposalLimits,
) -> Result<(), RecordDiscoveryError> {
    if offsets.len() > limits.discovery.max_messages {
        return Err(RecordDiscoveryError::InvalidLimits);
    }
    Ok(())
}

fn charge_input_view_storage(
    training_count: usize,
    held_out_count: usize,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<usize, RecordDiscoveryError> {
    let input_count = training_count
        .checked_add(held_out_count)
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    let view_storage = input_count
        .checked_mul(std::mem::size_of::<&[u8]>())
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    if let Some(work) = work.as_deref_mut() {
        work.charge(view_storage)
            .map_err(RecordDiscoveryError::RecordOperation)?;
    }
    Ok(view_storage)
}

fn own_inputs<'bytes>(
    messages: &[&'bytes [u8]],
) -> Result<Vec<RecordInput<'bytes>>, RecordDiscoveryError> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(messages.len())
        .map_err(|_| allocation_error())?;
    inputs.extend(messages.iter().map(|message| RecordInput::new(message)));
    Ok(inputs)
}

fn input_refs<'inputs, 'bytes>(
    inputs: &'inputs [RecordInput<'bytes>],
) -> Result<Vec<&'inputs RecordInput<'bytes>>, RecordDiscoveryError> {
    let mut references = Vec::new();
    references
        .try_reserve_exact(inputs.len())
        .map_err(|_| allocation_error())?;
    references.extend(inputs.iter());
    Ok(references)
}

fn input_views<'bytes>(
    inputs: &[&RecordInput<'bytes>],
) -> Result<Vec<&'bytes [u8]>, RecordDiscoveryError> {
    let mut views = Vec::new();
    views
        .try_reserve_exact(inputs.len())
        .map_err(|_| allocation_error())?;
    views.extend(inputs.iter().map(|input| input.bytes()));
    Ok(views)
}

fn byte_field_candidates(
    messages: &[&[u8]],
    maximum_offset: usize,
    shortest_message: usize,
    maximum_width: usize,
    maximum_checks: usize,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<(Vec<ByteField>, usize, usize, bool), RecordDiscoveryError> {
    let total_checks = byte_shape_count(maximum_offset, shortest_message, maximum_width)?;
    let mut fields = Vec::new();
    let mut checks = 0_usize;
    let mut work_limit_reached = false;
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
            let field = ByteField { offset, width };
            let Some(repeats) = field_repeats(messages, field, work)? else {
                work_limit_reached = true;
                break 'diagonals;
            };
            checks = checks
                .checked_add(1)
                .ok_or(RecordDiscoveryError::InvalidLimits)?;
            if repeats {
                if !try_charge_work(work, std::mem::size_of::<ByteField>()) {
                    work_limit_reached = true;
                    break 'diagonals;
                }
                push(&mut fields, field)?;
            }
        }
    }
    Ok((
        fields,
        checks,
        total_checks.saturating_sub(checks),
        work_limit_reached,
    ))
}

fn integer_field_shapes(
    maximum_offset: usize,
    shortest_message: usize,
    maximum_checks: usize,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<(Vec<IntegerField>, usize, usize, bool), RecordDiscoveryError> {
    let total_checks = integer_shape_count(maximum_offset, shortest_message)?;
    let mut fields = Vec::new();
    let mut checks = 0_usize;
    let mut work_limit_reached = false;
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
                let field_work = std::mem::size_of::<IntegerField>()
                    .checked_add(std::mem::size_of::<usize>())
                    .ok_or(RecordDiscoveryError::InvalidLimits)?;
                if !try_charge_work(work, field_work) {
                    work_limit_reached = true;
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
    Ok((
        fields,
        checks,
        total_checks.saturating_sub(checks),
        work_limit_reached,
    ))
}

fn varying_sequence_fields(
    messages: &[&[u8]],
    fields: &[IntegerField],
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<(Vec<IntegerField>, bool), RecordDiscoveryError> {
    let mut candidates = Vec::new();
    let mut work_limit_reached = false;
    for field in fields {
        let mut first = None;
        let mut varies = false;
        for message in messages {
            if !try_charge_work(work, field.width) {
                work_limit_reached = true;
                break;
            }
            let value = decode_field(message, *field).ok_or(RecordDiscoveryError::InvalidLimits)?;
            if first.is_some_and(|initial| initial != value) {
                varies = true;
                break;
            }
            first = Some(value);
        }
        if work_limit_reached {
            break;
        }
        if varies {
            if !try_charge_work(work, std::mem::size_of::<IntegerField>()) {
                work_limit_reached = true;
                break;
            }
            candidates.try_reserve(1).map_err(|_| allocation_error())?;
            candidates.push(*field);
        }
    }
    Ok((candidates, work_limit_reached))
}

fn sequence_group_candidates(
    messages: &[&[u8]],
    identifiers: &[ByteField],
    sequences: &[IntegerField],
    maximum_checks: usize,
    layout_group: Option<usize>,
    supported: &mut SupportedPairCollection,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<PairCheckProgress, RecordDiscoveryError> {
    let total_checks = identifiers
        .len()
        .checked_mul(sequences.len())
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    if identifiers.is_empty() || sequences.is_empty() {
        return Ok(PairCheckProgress {
            examined_checks: 0,
            omitted_checks: total_checks,
            work_limit_reached: false,
        });
    }

    let mut checks = 0_usize;
    let mut work_limit_reached = false;
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
            let evidence = match sequence_pair_evidence(messages, *identifier, *sequence, work)? {
                SequenceEvidenceCheck::Supported(evidence) => {
                    checks = checks
                        .checked_add(1)
                        .ok_or(RecordDiscoveryError::InvalidLimits)?;
                    evidence
                }
                SequenceEvidenceCheck::Unsupported => {
                    checks = checks
                        .checked_add(1)
                        .ok_or(RecordDiscoveryError::InvalidLimits)?;
                    continue;
                }
                SequenceEvidenceCheck::WorkLimit => {
                    work_limit_reached = true;
                    break 'diagonals;
                }
            };
            supported.retain(*identifier, *sequence, evidence, layout_group)?;
        }
    }
    Ok(PairCheckProgress {
        examined_checks: checks,
        omitted_checks: total_checks.saturating_sub(checks),
        work_limit_reached,
    })
}

const fn empty_pair_fields(total_checks: usize) -> PairFields {
    PairFields {
        identifiers: Vec::new(),
        sequences: Vec::new(),
        supported: Vec::new(),
        examined_checks: 0,
        omitted_checks: total_checks,
        work_limit_reached: false,
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

enum SequenceEvidenceCheck {
    Supported(SequenceEvidence),
    Unsupported,
    WorkLimit,
}

fn sequence_pair_evidence(
    messages: &[&[u8]],
    identifier: ByteField,
    sequence: IntegerField,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<SequenceEvidenceCheck, RecordDiscoveryError> {
    if !try_charge_work(work, std::mem::size_of::<SupportedPair>()) {
        return Ok(SequenceEvidenceCheck::WorkLimit);
    }
    if fields_overlap(
        identifier,
        ByteField {
            offset: sequence.offset,
            width: sequence.width,
        },
    ) {
        return Ok(SequenceEvidenceCheck::Unsupported);
    }
    sequence_evidence(messages, identifier, sequence, work)
}

fn sequence_evidence(
    messages: &[&[u8]],
    identifier: ByteField,
    sequence: IntegerField,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<SequenceEvidenceCheck, RecordDiscoveryError> {
    let mut tracks = HashMap::<&[u8], SequenceTrack>::new();
    if !try_charge_work(
        work,
        std::mem::size_of::<SequenceTrack>().saturating_mul(messages.len()),
    ) {
        return Ok(SequenceEvidenceCheck::WorkLimit);
    }
    tracks
        .try_reserve(messages.len())
        .map_err(|_| allocation_error())?;
    for message in messages {
        if !try_charge_work(work, identifier.width.saturating_add(sequence.width)) {
            return Ok(SequenceEvidenceCheck::WorkLimit);
        }
        let id_end = identifier
            .offset
            .checked_add(identifier.width)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        let Some(id) = message.get(identifier.offset..id_end) else {
            return Ok(SequenceEvidenceCheck::Unsupported);
        };
        let Some(value) = decode_field(message, sequence) else {
            return Ok(SequenceEvidenceCheck::Unsupported);
        };
        if !update_sequence_track(&mut tracks, id, value, work)? {
            return Ok(SequenceEvidenceCheck::WorkLimit);
        }
    }
    Ok(summarize_sequence_tracks(&tracks))
}

fn update_sequence_track<'bytes>(
    tracks: &mut HashMap<&'bytes [u8], SequenceTrack>,
    identifier: &'bytes [u8],
    value: u64,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<bool, RecordDiscoveryError> {
    if let Some(track) = tracks.get_mut(identifier) {
        if value < track.last {
            track.capture_order_violations = track.capture_order_violations.saturating_add(1);
        }
        track.varies |= value != track.first;
        track.last = value;
        track.minimum = track.minimum.min(value);
        track.maximum = track.maximum.max(value);
        if !try_charge_work(work, std::mem::size_of::<u64>()) {
            return Ok(false);
        }
        track
            .distinct_values
            .try_reserve(1)
            .map_err(|_| allocation_error())?;
        track.distinct_values.insert(value);
        return Ok(true);
    }
    if !try_charge_work(
        work,
        std::mem::size_of::<SequenceTrack>()
            .saturating_add(identifier.len())
            .saturating_add(std::mem::size_of::<u64>()),
    ) {
        return Ok(false);
    }
    let mut distinct_values = HashSet::new();
    distinct_values
        .try_reserve(1)
        .map_err(|_| allocation_error())?;
    distinct_values.insert(value);
    tracks.insert(
        identifier,
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
    Ok(true)
}

fn summarize_sequence_tracks(tracks: &HashMap<&[u8], SequenceTrack>) -> SequenceEvidenceCheck {
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
    if has_varying_group {
        SequenceEvidenceCheck::Supported(evidence)
    } else {
        SequenceEvidenceCheck::Unsupported
    }
}

fn length_candidates(
    messages: &[&[u8]],
    _inputs: &[&RecordInput<'_>],
    fields: &[IntegerField],
    maximum_data_offset: usize,
    maximum_checks: usize,
    prioritized_offsets: &[usize],
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<LengthFields, RecordDiscoveryError> {
    let mut result = empty_length_fields();
    let mut seen = LengthFieldMembership::default();
    let (checks, total_checks, stopped) = visit_length_layouts(
        fields,
        maximum_data_offset,
        maximum_checks,
        prioritized_offsets,
        LengthLayoutOrder::GapFirst,
        &mut |field, data_offset, meaning| {
            match matches_length(messages, field, meaning, data_offset, work) {
                None => {
                    result.work_limit_reached = true;
                    return Ok(ControlFlow::Break(()));
                }
                Some(false) => return Ok(ControlFlow::Continue(())),
                Some(true) => {}
            }
            let retained_layout_bytes = std::mem::size_of::<SupportedLength>()
                .saturating_add(std::mem::size_of::<IntegerField>())
                .saturating_add(std::mem::size_of::<usize>())
                .saturating_add(std::mem::size_of::<super::super::RecordLengthMeaning>());
            if !try_charge_work(work, retained_layout_bytes) {
                result.work_limit_reached = true;
                return Ok(ControlFlow::Break(()));
            }
            result.retain_layout(
                &mut seen,
                SupportedLength {
                    field,
                    data_offset,
                    meaning,
                    layout_group: None,
                },
            )?;
            Ok(ControlFlow::Continue(()))
        },
    )?;
    result.examined_checks = checks;
    result.omitted_checks = total_checks
        .checked_sub(checks)
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    result.work_limit_reached |= stopped;
    Ok(result)
}

fn matches_length(
    messages: &[&[u8]],
    field: IntegerField,
    meaning: super::super::RecordLengthMeaning,
    data_offset: usize,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Option<bool> {
    let Some(field_end) = field.offset.checked_add(field.width) else {
        return Some(false);
    };
    for message in messages {
        if !try_charge_work(work, field.width) {
            return None;
        }
        let Some(value) = decode_field(message, field) else {
            return Some(false);
        };
        let expected = match meaning {
            super::super::RecordLengthMeaning::PayloadBytes => {
                let Some(payload_length) = message.len().checked_sub(data_offset) else {
                    return Some(false);
                };
                payload_length
            }
            super::super::RecordLengthMeaning::WholeRecord => message.len(),
            super::super::RecordLengthMeaning::BytesAfterLengthField => {
                let Some(remaining) = message.len().checked_sub(field_end) else {
                    return Some(false);
                };
                remaining
            }
        };
        if usize::try_from(value).ok() != Some(expected) {
            return Some(false);
        }
    }
    Some(true)
}

fn field_repeats(
    messages: &[&[u8]],
    field: ByteField,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<Option<bool>, RecordDiscoveryError> {
    let mut seen = HashSet::<&[u8]>::new();
    if !try_charge_work(
        work,
        std::mem::size_of::<&[u8]>().saturating_mul(messages.len()),
    ) {
        return Ok(None);
    }
    seen.try_reserve(messages.len())
        .map_err(|_| allocation_error())?;
    for message in messages {
        if !try_charge_work(work, field.width) {
            return Ok(None);
        }
        let end = field
            .offset
            .checked_add(field.width)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        let Some(value) = message.get(field.offset..end) else {
            return Ok(Some(false));
        };
        if !seen.insert(value) {
            return Ok(Some(true));
        }
    }
    Ok(Some(false))
}

fn try_charge_work(work: &mut Option<&mut RecordWorkBudget>, amount: usize) -> bool {
    work.as_deref_mut()
        .is_none_or(|budget| budget.try_charge(amount))
}

fn charge_proposal_work(
    work: &mut Option<&mut RecordWorkBudget>,
    amount: usize,
) -> Result<(), RecordDiscoveryError> {
    if let Some(work) = work.as_deref_mut() {
        work.charge(amount)
            .map_err(RecordDiscoveryError::RecordOperation)?;
    }
    Ok(())
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
