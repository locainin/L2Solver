//! Learn bounded message selectors before reusing strict record discovery

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
        ByteRange, DEFAULT_MAX_FAMILY_SAMPLES, MAX_MESSAGE_BYTES, MAX_PROTOCOL_BYTES,
        MessageContext, MessageFamilyLimits, MessageFamilySelector, MessageRole, MessageSample,
        RecordSchemaProposalLimits, discover_message_families,
    },
    recovery::RecoveryError,
};
use std::sync::Arc;

const MAX_SELECTORS: usize = 8;
const MAX_VALUES: usize = 4;
const MAX_GROUPS: usize = 8;
const MAX_APPLICATION_FRAMES: usize = 4096;
const FAMILY_WORK_LIMIT: usize = 1_000_000;

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

struct FamilyGroup {
    context: RecordDiscoveryContext,
    partition: SessionPartition,
    selection: FamilySelection,
}

struct FamilyGroups {
    groups: Vec<FamilyGroup>,
    incomplete: bool,
}

impl Executor<'_> {
    pub(super) fn analyze_message_families(
        &mut self,
        context: &RecordDiscoveryContext,
        uniform: &mut RecordAnalysis,
        limits: RecordSchemaProposalLimits,
    ) -> Result<Vec<RecordReportOutput>, RecoveryExecutionError> {
        if uniform.partition.training_session_nodes.len() < 2 {
            return Ok(Vec::new());
        }
        if context.application_inputs.len() > MAX_APPLICATION_FRAMES {
            mark_incomplete(uniform, "message_family_input_limit");
            return Ok(Vec::new());
        }
        let memory_bytes = memory_bound(context, limits)?;
        let memory = if let Some(budget) = &self.memory {
            let requested =
                u64::try_from(memory_bytes).map_err(|_| RecoveryError::InvariantFailure)?;
            match budget.try_reserve(MemoryClass::Executor, requested) {
                Ok(lease) => Some(lease),
                Err(MemoryError::Limit { .. } | MemoryError::Pressure { .. }) => {
                    mark_incomplete(uniform, "message_family_memory_limit");
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
            return Ok(Vec::new());
        }
        let proposal = propose_groups(self.case, context, &uniform.partition, limits)?;
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
            if !self.charge_record_case_work(bound)? {
                mark_incomplete(uniform, "message_family_work_limit");
                break;
            }
            let mut analysis = self.analyze_record_cohort(
                &group.context.inputs,
                group.partition,
                limits,
                group.context.omitted_frames > 0,
                false,
            )?;
            if analysis.result != STATUS_HYPOTHESES_FOUND {
                continue;
            }
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
        Ok(reports)
    }
}

fn mark_incomplete(analysis: &mut RecordAnalysis, reason: &'static str) {
    analysis.search_exhaustive_within_plan = false;
    analysis.strategy_omission = Some(reason);
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
    // Include selected descriptors, bounded schema models, and compact report buffers
    frame_bytes
        .checked_mul(2)
        .and_then(|value| value.checked_add(schema_entries))
        .and_then(|value| value.checked_add(proposal_entries))
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
        });
    }
    let family_limits = MessageFamilyLimits {
        max_message_bytes: limits
            .discovery
            .record_limits
            .max_input_bytes
            .min(MAX_MESSAGE_BYTES),
        max_total_bytes: limits
            .discovery
            .record_limits
            .max_input_bytes
            .min(MAX_PROTOCOL_BYTES),
        max_selector_offset: limits.max_field_offset.min(15),
        max_selector_width: 4,
        max_candidate_ranges: 64,
        max_selectors: MAX_SELECTORS,
        max_families_per_selector: MAX_VALUES,
        max_work_units: FAMILY_WORK_LIMIT,
        max_report_bytes: 512 * 1024,
        ..MessageFamilyLimits::default()
    };
    let report = discover_message_families(&messages, &training, family_limits)
        .map_err(|source| operational("message-family discovery failed", source))?;
    let mut groups = Vec::new();
    let mut incomplete = !report.complete;
    for selector in &report.selectors {
        if !selector.training_coverage_complete || selector.families.len() < 2 {
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
                report.complete,
            )?
            else {
                continue;
            };
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
                incomplete = true;
                break;
            }
            groups
                .try_reserve(1)
                .map_err(|source| operational("family group allocation failed", source))?;
            groups.push(group);
        }
        if groups.len() == MAX_GROUPS {
            incomplete = true;
            break;
        }
    }
    Ok(FamilyGroups { groups, incomplete })
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
