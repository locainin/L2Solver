//! Learn bounded message selectors before reusing strict record discovery

use super::super::super::message_family::{
    MAX_SELECTORS, MAX_VALUES, MAX_WORK_UNITS as FAMILY_WORK_LIMIT, limits as family_limits,
};
use super::super::input::learning_sample;
use super::{
    Executor, RecordAnalysis, RecordDiscoveryContext, RecordReportOutput, STATUS_HYPOTHESES_FOUND,
    SessionPartition, build_compact_report, cohort_work_bound, operational,
};
use crate::workbench::recovery_executor::RecoveryExecutionError;
use l2_workbench::{
    evidence::Case,
    job::{MemoryClass, MemoryError},
    protocol::{
        ByteRange, DEFAULT_MAX_FAMILY_RANGES, DEFAULT_MAX_FAMILY_SAMPLES, MAX_PROTOCOL_BYTES,
        MessageContext, MessageFamilySelector, MessageRole, MessageSample,
        RecordSchemaProposalLimits, discover_message_families, observation::ObservationCoverage,
    },
    recovery::RecoveryError,
};
use std::sync::Arc;

const MAX_GROUPS: usize = 8;
const MAX_APPLICATION_FRAMES: usize = 4096;
const MAX_FAMILY_MEMORY_BYTES: usize = 128 * 1024 * 1024;
const MAX_GROUP_EXAMPLES: usize = 8;

#[derive(serde::Serialize)]
pub(super) struct FamilySelection {
    selector_range: ByteRange,
    selector_value: Vec<u8>,
    selected_frame_count: usize,
    excluded_frame_count: usize,
    unassigned_frame_count: usize,
    application_complete: bool,
    learning_sample_count: usize,
    learning_sample_omitted_count: usize,
    selector_search_complete: bool,
}

#[derive(Default, serde::Serialize)]
pub(super) struct FamilySearchSummary {
    limits: RecordSchemaProposalLimits,
    discovery: FamilyDiscoveryEvidence,
    reason: Option<&'static str>,
    selectors_retained: usize,
    groups_proposed: usize,
    group_limit_reached: bool,
    groups_examined: usize,
    groups_with_schemas: usize,
    groups_without_candidate_space: usize,
    groups_without_surviving_schemas: usize,
    schema_candidate_evaluations: usize,
    schema_survivor_group_pairs: usize,
    complete_within_limits: bool,
    groups: Vec<FamilyGroupSummary>,
}

#[derive(Default, serde::Serialize)]
struct FamilyDiscoveryEvidence {
    range_pair_limit: usize,
    training_count: usize,
    heldout_count: usize,
    training_examples: Vec<FamilyFrameExample>,
    heldout_examples: Vec<FamilyFrameExample>,
    omitted_training_examples: usize,
    omitted_heldout_examples: usize,
    omitted_learning_inputs: usize,
    omitted_candidate_ranges: usize,
    omitted_report_budget_ranges: usize,
    omitted_selectors: usize,
    observation_coverage: Option<ObservationCoverage>,
}

#[derive(serde::Serialize)]
struct FamilyGroupSummary {
    selector_range: ByteRange,
    selector_value: Vec<u8>,
    training_count: usize,
    heldout_count: usize,
    training_examples: Vec<FamilyFrameExample>,
    heldout_examples: Vec<FamilyFrameExample>,
    omitted_training_examples: usize,
    omitted_heldout_examples: usize,
    application_count: usize,
    result: &'static str,
    reason: Option<&'static str>,
    schema_candidate_evaluations: usize,
    schema_survivors_retained: usize,
}

#[derive(serde::Serialize)]
struct FamilyFrameExample {
    node_id: u64,
    blob_id: String,
}

struct FamilyGroup {
    context: RecordDiscoveryContext,
    partition: SessionPartition,
    selection: FamilySelection,
}

struct FamilyGroups {
    groups: Vec<FamilyGroup>,
    incomplete: bool,
    selectors_retained: usize,
    discovery: FamilyDiscoveryEvidence,
    group_limit_reached: bool,
}

impl Executor<'_> {
    pub(super) fn analyze_message_families(
        &mut self,
        context: &RecordDiscoveryContext,
        uniform: &mut RecordAnalysis,
        limits: RecordSchemaProposalLimits,
    ) -> Result<Vec<RecordReportOutput>, RecoveryExecutionError> {
        if uniform.partition.training_session_nodes.len() < 2 {
            skipped_family(uniform, limits, "insufficient_training_sessions");
            return Ok(Vec::new());
        }
        if context.application_inputs.len() > MAX_APPLICATION_FRAMES {
            mark_incomplete(uniform, "message_family_input_limit");
            skipped_family(uniform, limits, "message_family_input_limit");
            return Ok(Vec::new());
        }
        let memory_bytes = memory_bound(context, limits)?;
        if memory_bytes > MAX_FAMILY_MEMORY_BYTES {
            mark_incomplete(uniform, "message_family_memory_limit");
            skipped_family(uniform, limits, "message_family_memory_limit");
            return Ok(Vec::new());
        }
        // Reserve temporary and queued data before learning any selectors
        let memory = if let Some(budget) = &self.memory {
            let requested =
                u64::try_from(memory_bytes).map_err(|_| RecoveryError::InvariantFailure)?;
            match budget.try_reserve(MemoryClass::Executor, requested) {
                Ok(lease) => Some(lease),
                Err(MemoryError::Limit { .. } | MemoryError::Pressure { .. }) => {
                    mark_incomplete(uniform, "message_family_memory_limit");
                    skipped_family(uniform, limits, "message_family_memory_limit");
                    return Ok(Vec::new());
                }
                Err(source) => return Err(operational("family memory admission failed", source)),
            }
        } else {
            None
        };
        let work = family_work_bound(context)?;
        if !self.charge_record_case_work(work)? {
            mark_incomplete(uniform, "message_family_work_limit");
            skipped_family(uniform, limits, "message_family_work_limit");
            return Ok(Vec::new());
        }
        // Keep the uniform report even when a separate family search is incomplete
        let proposal = propose_groups(self.case, context, &uniform.partition, limits)?;
        let mut summary = FamilySearchSummary {
            limits,
            discovery: proposal.discovery,
            selectors_retained: proposal.selectors_retained,
            groups_proposed: proposal.groups.len(),
            group_limit_reached: proposal.group_limit_reached,
            complete_within_limits: !proposal.incomplete,
            reason: if proposal.group_limit_reached {
                Some("message_family_group_limit")
            } else {
                proposal.incomplete.then_some("message_family_search_limit")
            },
            ..FamilySearchSummary::default()
        };
        summary
            .groups
            .try_reserve_exact(proposal.groups.len())
            .map_err(|source| operational("family group summary allocation failed", source))?;
        if proposal.incomplete {
            mark_incomplete(uniform, "message_family_search_limit");
        }
        let mut reports = Vec::new();
        reports
            .try_reserve_exact(proposal.groups.len())
            .map_err(|source| operational("family report allocation failed", source))?;
        for group in proposal.groups {
            if let Some(progress) = &self.job {
                progress.job.check_cancelled()?;
            }
            let bound = cohort_work_bound(&group.context.key, &group.context.inputs, limits)
                .ok_or(RecoveryError::InvariantFailure)?;
            let mut group_summary = group_summary(&group)?;
            if !self.charge_record_case_work(bound)? {
                mark_incomplete(uniform, "message_family_work_limit");
                summary.complete_within_limits = false;
                summary.reason = Some("message_family_work_limit");
                group_summary.result = "not_examined";
                group_summary.reason = Some("message_family_work_limit");
                summary.groups.push(group_summary);
                break;
            }
            let mut analysis = self.analyze_record_cohort(
                &group.context.inputs,
                group.partition,
                limits,
                group.context.omitted_frames > 0,
                false,
            )?;
            summary.groups_examined += 1;
            group_summary.result = analysis.result;
            group_summary.reason = analysis.no_candidate_reason;
            summary.complete_within_limits &=
                analysis.search_exhaustive_within_plan && analysis.report_details_complete;
            // Count work per selected group without retaining more schema arrays
            if let Some(strategies) = &analysis.strategies {
                for strategy in super::strategy_reports(strategies) {
                    if let Some(discovery) = &strategy.discovery {
                        summary.schema_candidate_evaluations += discovery.examined_combinations;
                        summary.schema_survivor_group_pairs += discovery.surviving.len();
                        group_summary.schema_candidate_evaluations +=
                            discovery.examined_combinations;
                        group_summary.schema_survivors_retained += discovery.surviving.len();
                    }
                }
            }
            summary.groups.push(group_summary);
            if analysis.result != STATUS_HYPOTHESES_FOUND {
                match analysis.no_candidate_reason {
                    Some("no_structural_candidate_space") => {
                        summary.groups_without_candidate_space += 1
                    }
                    Some("no_schema_survived_strict_parsing") => {
                        summary.groups_without_surviving_schemas += 1
                    }
                    _ => {}
                }
                continue;
            }
            summary.groups_with_schemas += 1;
            // Compact reports avoid materializing large speculative schema arrays
            analysis.report_details_complete = false;
            analysis.family_selection = Some(group.selection);
            let report = build_compact_report(&group.context, &analysis, bound)?;
            let bytes = serde_json::to_vec(&report)
                .map_err(|source| operational("family report serialization failed", source))?;
            reports.push(RecordReportOutput {
                context: group.context,
                analysis,
                bytes,
                work_bound_bytes: bound,
            });
        }
        if !reports.is_empty() {
            if let Some(lease) = memory {
                self.family_memory.try_reserve(1).map_err(|source| {
                    operational("family memory lease allocation failed", source)
                })?;
                self.family_memory.push(lease);
            }
        }
        uniform.family_search = Some(summary);
        Ok(reports)
    }
}

fn group_summary(group: &FamilyGroup) -> Result<FamilyGroupSummary, RecoveryExecutionError> {
    let training_count = group.partition.training_count;
    let heldout_count = group
        .context
        .inputs
        .len()
        .checked_sub(training_count)
        .ok_or(RecoveryError::InvariantFailure)?;
    let training = group
        .context
        .inputs
        .get(..training_count)
        .ok_or(RecoveryError::InvariantFailure)?;
    let heldout = group
        .context
        .inputs
        .get(training_count..)
        .ok_or(RecoveryError::InvariantFailure)?;
    Ok(FamilyGroupSummary {
        selector_range: group.selection.selector_range,
        selector_value: group.selection.selector_value.clone(),
        training_count,
        heldout_count,
        training_examples: frame_examples(training.iter())?,
        heldout_examples: frame_examples(heldout.iter())?,
        omitted_training_examples: training_count.saturating_sub(MAX_GROUP_EXAMPLES),
        omitted_heldout_examples: heldout_count.saturating_sub(MAX_GROUP_EXAMPLES),
        application_count: group.context.application_inputs.len(),
        result: "not_examined",
        reason: None,
        schema_candidate_evaluations: 0,
        schema_survivors_retained: 0,
    })
}

fn frame_examples<'a>(
    inputs: impl Iterator<Item = &'a super::RecordFrameInput>,
) -> Result<Vec<FamilyFrameExample>, RecoveryExecutionError> {
    let mut examples = Vec::new();
    examples
        .try_reserve_exact(MAX_GROUP_EXAMPLES)
        .map_err(|source| operational("family frame example allocation failed", source))?;
    examples.extend(
        inputs
            .take(MAX_GROUP_EXAMPLES)
            .map(|input| FamilyFrameExample {
                node_id: input.node_id,
                blob_id: input.blob_id.clone(),
            }),
    );
    Ok(examples)
}

fn mark_incomplete(analysis: &mut RecordAnalysis, reason: &'static str) {
    analysis.search_exhaustive_within_plan = false;
    analysis.strategy_omission = Some(reason);
}

fn skipped_family(
    analysis: &mut RecordAnalysis,
    limits: RecordSchemaProposalLimits,
    reason: &'static str,
) {
    analysis.family_search = Some(FamilySearchSummary {
        limits,
        discovery: FamilyDiscoveryEvidence {
            range_pair_limit: DEFAULT_MAX_FAMILY_RANGES,
            ..FamilyDiscoveryEvidence::default()
        },
        reason: Some(reason),
        ..FamilySearchSummary::default()
    });
}

fn family_work_bound(context: &RecordDiscoveryContext) -> Result<usize, RecoveryExecutionError> {
    // Cover the bounded observation pass and each selector's full-input comparisons
    let comparisons = context
        .application_inputs
        .len()
        .checked_mul(MAX_SELECTORS)
        .and_then(|value| value.checked_mul(MAX_VALUES))
        .and_then(|value| value.checked_mul(256))
        .ok_or(RecoveryError::InvariantFailure)?;
    FAMILY_WORK_LIMIT
        .checked_add(64 * 64 * 64)
        .and_then(|value| value.checked_add(comparisons))
        .ok_or_else(|| RecoveryError::InvariantFailure.into())
}

fn memory_bound(
    context: &RecordDiscoveryContext,
    limits: RecordSchemaProposalLimits,
) -> Result<usize, RecoveryExecutionError> {
    let frame_bytes = context
        .application_inputs
        .iter()
        .try_fold(0_usize, |sum, input| {
            sum.checked_add(std::mem::size_of_val(input))?
                .checked_add(input.blob_id.len())
        })
        .ok_or(RecoveryError::InvariantFailure)?;
    let schema_entries = limits
        .discovery
        .max_survivors
        .checked_add(limits.discovery.max_falsifications)
        .and_then(|value| value.checked_mul(1024))
        .ok_or(RecoveryError::InvariantFailure)?;
    let proposal_entries = limits
        .max_field_checks_per_domain
        .checked_mul(2)
        .and_then(|value| value.checked_add(limits.max_pair_checks))
        .and_then(|value| value.checked_add(limits.max_length_checks))
        .and_then(|value| value.checked_mul(512))
        .ok_or(RecoveryError::InvariantFailure)?;
    let survivors = limits
        .discovery
        .max_survivors
        .min(limits.discovery.max_candidates);
    let session_count = super::application_session_count(&context.application_inputs);
    let input_ids = context
        .application_inputs
        .len()
        .checked_mul(survivors)
        .and_then(|value| value.checked_mul(std::mem::size_of::<u64>()))
        .ok_or(RecoveryError::InvariantFailure)?;
    let queued_requests = session_count
        .checked_mul(survivors)
        .and_then(|value| {
            value.checked_mul(
                std::mem::size_of::<(Vec<u64>, l2_workbench::protocol::RecordSchema, u64)>()
                    + std::mem::size_of::<super::super::super::scheduler::PendingRecordAssembly>(),
            )
        })
        .ok_or(RecoveryError::InvariantFailure)?;
    // Include selected descriptors, schema models, report buffers, and pending assembly requests
    frame_bytes
        .checked_mul(4)
        .and_then(|value| value.checked_add(schema_entries))
        .and_then(|value| value.checked_add(proposal_entries))
        .and_then(|value| value.checked_add(input_ids.checked_mul(2)?))
        .and_then(|value| value.checked_add(queued_requests.checked_mul(2)?))
        .and_then(|value| value.checked_add(1024 * 1024))
        .and_then(|value| value.checked_mul(MAX_GROUPS))
        .and_then(|value| value.checked_add(2 * 1024 * 1024))
        .ok_or_else(|| RecoveryError::InvariantFailure.into())
}

fn propose_groups(
    case: &Case,
    context: &RecordDiscoveryContext,
    partition: &SessionPartition,
    limits: RecordSchemaProposalLimits,
) -> Result<FamilyGroups, RecoveryExecutionError> {
    // Keep the original session split while limiting the learning prefix
    let sample = learning_sample(
        &context.inputs,
        DEFAULT_MAX_FAMILY_SAMPLES,
        limits
            .discovery
            .record_limits
            .max_input_bytes
            .min(MAX_PROTOCOL_BYTES),
    )?;
    let mut messages = Vec::new();
    let mut training = Vec::new();
    messages
        .try_reserve_exact(sample.len())
        .map_err(|source| operational("family message allocation failed", source))?;
    training
        .try_reserve_exact(sample.len())
        .map_err(|source| operational("family training allocation failed", source))?;
    for input in &sample {
        if partition
            .training_session_nodes
            .contains(&input.session_node_id)
        {
            training.push(input.node_id);
        }
        messages.push(MessageSample {
            sample: input.node_id,
            role: MessageRole::Unclassified,
            bytes: frame_bytes(case, input)?,
            context: Some(MessageContext {
                source: context.key.source_id.clone(),
                scope: context.key.scope_json.clone(),
                session: input.session_node_id,
                direction: context.key.direction,
            }),
        });
    }
    let heldout_count = sample.len() - training.len();
    let mut discovery = FamilyDiscoveryEvidence {
        range_pair_limit: DEFAULT_MAX_FAMILY_RANGES,
        training_count: training.len(),
        heldout_count,
        training_examples: frame_examples(
            sample
                .iter()
                .copied()
                .filter(|input| training.contains(&input.node_id)),
        )?,
        heldout_examples: frame_examples(
            sample
                .iter()
                .copied()
                .filter(|input| !training.contains(&input.node_id)),
        )?,
        omitted_training_examples: training.len().saturating_sub(MAX_GROUP_EXAMPLES),
        omitted_heldout_examples: heldout_count.saturating_sub(MAX_GROUP_EXAMPLES),
        omitted_learning_inputs: context.inputs.len() - sample.len(),
        ..FamilyDiscoveryEvidence::default()
    };
    let mut training_sessions = sample
        .iter()
        .filter(|input| {
            partition
                .training_session_nodes
                .contains(&input.session_node_id)
        })
        .map(|input| input.session_node_id);
    let first_session = training_sessions.next();
    if first_session.is_none() || !training_sessions.any(|session| Some(session) != first_session) {
        // A bounded sample cannot support a multi-session selector without two sessions
        return Ok(FamilyGroups {
            groups: Vec::new(),
            incomplete: true,
            selectors_retained: 0,
            discovery,
            group_limit_reached: false,
        });
    }
    let family_limits = family_limits(limits, FAMILY_WORK_LIMIT);
    let report = discover_message_families(&messages, &training, family_limits)
        .map_err(|source| operational("message-family discovery failed", source))?;
    discovery.omitted_candidate_ranges = report.omitted_candidate_ranges;
    discovery.omitted_report_budget_ranges = report.omitted_report_budget_ranges;
    discovery.omitted_selectors = report.omitted_selectors;
    discovery.observation_coverage = Some(report.observation_coverage);
    let mut groups = Vec::new();
    let mut incomplete = !report.complete || discovery.omitted_learning_inputs > 0;
    let mut group_limit_reached = false;
    for selector in &report.selectors {
        // One supported value can still separate data from varied control messages
        let has_other_training_values = selector
            .unassigned
            .iter()
            .any(|observation| training.contains(&observation.sample));
        if !selector.training_coverage_complete
            || (selector.families.len() < 2 && !has_other_training_values)
        {
            continue;
        }
        let unassigned = unassigned_count(case, &context.application_inputs, selector)?;
        for family in &selector.families {
            let Some(group) = make_group(
                case,
                context,
                partition,
                selector,
                family,
                unassigned,
                sample.len(),
                report.complete && discovery.omitted_learning_inputs == 0,
            )?
            else {
                continue;
            };
            // Identical full input sets do not need another schema search
            if groups.iter().any(|existing: &FamilyGroup| {
                existing.context.application_inputs.len() == group.context.application_inputs.len()
                    && existing
                        .context
                        .application_inputs
                        .iter()
                        .zip(group.context.application_inputs.iter())
                        .all(|(left, right)| left.node_id == right.node_id)
            }) {
                continue;
            }
            if groups.len() == MAX_GROUPS {
                // Only a new cohort can be omitted by the group limit
                incomplete = true;
                group_limit_reached = true;
                break;
            }
            groups
                .try_reserve(1)
                .map_err(|source| operational("family group allocation failed", source))?;
            groups.push(group);
        }
        if group_limit_reached {
            break;
        }
    }
    Ok(FamilyGroups {
        groups,
        incomplete,
        selectors_retained: report.selectors.len(),
        discovery,
        group_limit_reached,
    })
}

fn frame_bytes<'a>(
    case: &'a Case,
    input: &super::RecordFrameInput,
) -> Result<&'a [u8], RecoveryExecutionError> {
    let blob = case
        .blob(&input.blob_id)
        .filter(|blob| blob.id == input.blob_id && blob.bytes.len() == input.byte_length)
        .ok_or(RecoveryError::InvariantFailure)?;
    Ok(&blob.bytes)
}

fn unassigned_count(
    case: &Case,
    inputs: &[super::RecordFrameInput],
    selector: &MessageFamilySelector,
) -> Result<usize, RecoveryExecutionError> {
    let mut unassigned = 0_usize;
    for input in inputs {
        let value = frame_bytes(case, input)?.get(selector.range.start..selector.range.end);
        // A value absent from training stays outside every supported family
        if !value.is_some_and(|bytes| selector.families.iter().any(|family| family.value == bytes))
        {
            unassigned += 1;
        }
    }
    Ok(unassigned)
}

fn make_group(
    case: &Case,
    context: &RecordDiscoveryContext,
    partition: &SessionPartition,
    selector: &MessageFamilySelector,
    family: &l2_workbench::protocol::MessageFamily,
    unassigned: usize,
    sample_count: usize,
    selector_search_complete: bool,
) -> Result<Option<FamilyGroup>, RecoveryExecutionError> {
    let select = |input: &super::RecordFrameInput| -> Result<bool, RecoveryExecutionError> {
        Ok(frame_bytes(case, input)?
            .get(selector.range.start..selector.range.end)
            .is_some_and(|value| value == family.value))
    };
    let mut selected = Vec::new();
    selected
        .try_reserve_exact(context.inputs.len())
        .map_err(|source| operational("family learning input allocation failed", source))?;
    for input in &context.inputs {
        if select(input)? {
            selected.push(input.clone());
        }
    }
    // Apply the frozen selector to all eligible frames, not just learning samples
    let mut application = Vec::new();
    application
        .try_reserve_exact(context.application_inputs.len())
        .map_err(|source| operational("family application input allocation failed", source))?;
    for input in context.application_inputs.iter() {
        if select(input)? {
            application.push(input.clone());
        }
    }
    if selected.is_empty() || application.len() == context.application_inputs.len() {
        return Ok(None);
    }
    let mut selected_partition = partition.clone();
    selected_partition.training_count = selected
        .iter()
        .filter(|input| {
            partition
                .training_session_nodes
                .contains(&input.session_node_id)
        })
        .count();
    if selected_partition.training_count == 0
        || selected
            .iter()
            .skip(selected_partition.training_count)
            .any(|input| {
                partition
                    .training_session_nodes
                    .contains(&input.session_node_id)
            })
    {
        return Err(RecoveryError::InvariantFailure.into());
    }
    let selected_count = application.len();
    let omitted_frames = selected_count.saturating_sub(selected.len());
    let selection = FamilySelection {
        selector_range: selector.range,
        selector_value: family.value.clone(),
        selected_frame_count: selected_count,
        excluded_frame_count: context.application_inputs.len() - selected_count,
        unassigned_frame_count: unassigned,
        application_complete: unassigned == 0 && selector.omitted_families == 0,
        learning_sample_count: sample_count,
        learning_sample_omitted_count: context.inputs.len() - sample_count,
        selector_search_complete,
    };
    Ok(Some(FamilyGroup {
        context: RecordDiscoveryContext {
            key: context.key.clone(),
            inputs: selected,
            application_inputs: Arc::from(application),
            sampling: context.sampling,
            omitted_frames,
            eligibility_omissions: context.eligibility_omissions.clone(),
        },
        partition: selected_partition,
        selection,
    }))
}
