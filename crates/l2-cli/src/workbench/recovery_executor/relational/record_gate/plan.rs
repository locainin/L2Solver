mod analysis;
mod family;

use super::super::super::RecoveryExecutionError;
use super::super::{DecodedFrameOutput, invalid_policy, operational};
use super::screen::SchemaObserverOptions;
use super::selection::{LearningSelection, select_learning_frames};
use super::{SchemaPlan, total_input_bytes};
use analysis::{AnalysisRequest, analyze_group};
use family::build_family_analysis;
use l2_workbench::{
    job::Job,
    protocol::{RecordSchemaProposalLimits, RelationalSessionId, RelationalTransformReport},
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const MAX_GATE_SCHEMA_CHECKS: usize = 512;
const MAX_RETAINED_SCHEMA_HYPOTHESES: usize = 128;

pub(super) struct LearningMessages<'a> {
    training: Vec<&'a [u8]>,
    heldout: Vec<&'a [u8]>,
    training_indices: Vec<usize>,
    heldout_indices: Vec<usize>,
    all_training_indices: Vec<usize>,
    all_heldout_indices: Vec<usize>,
    training_data_offsets: Vec<usize>,
    learning_bytes: usize,
    analysis_input_bytes: usize,
    eligible_input_bytes: usize,
    full_input_bytes: usize,
    training_session_count: usize,
}

struct PlanAnalysisRequest<'frames, 'messages> {
    frames: &'frames [DecodedFrameOutput],
    selection: &'frames LearningSelection,
    discovery: &'frames BTreeSet<u64>,
    messages: &'frames LearningMessages<'messages>,
    limits: RecordSchemaProposalLimits,
    work_limit: usize,
    parser_format: l2_workbench::artifact::ArtifactValidationFormat,
    artifact_policy: l2_workbench::artifact::ArtifactValidationPolicy,
    job: Option<&'frames Job>,
}

struct LearningMessageContents<'a> {
    training: Vec<&'a [u8]>,
    heldout: Vec<&'a [u8]>,
    training_indices: Vec<usize>,
    heldout_indices: Vec<usize>,
    all_training_indices: Vec<usize>,
    all_heldout_indices: Vec<usize>,
    training_data_offsets: Vec<usize>,
    learning_bytes: usize,
    analysis_input_bytes: usize,
    eligible_input_bytes: usize,
}

impl LearningMessageContents<'_> {
    fn reserve<'a>(
        selected_count: usize,
        frame_count: usize,
    ) -> Result<LearningMessageContents<'a>, RecoveryExecutionError> {
        let mut contents = LearningMessageContents {
            training: Vec::new(),
            heldout: Vec::new(),
            training_indices: Vec::new(),
            heldout_indices: Vec::new(),
            all_training_indices: Vec::new(),
            all_heldout_indices: Vec::new(),
            training_data_offsets: Vec::new(),
            learning_bytes: 0,
            analysis_input_bytes: 0,
            eligible_input_bytes: 0,
        };
        contents.reserve_selected(selected_count)?;
        contents.reserve_eligible(frame_count)?;
        Ok(contents)
    }

    fn reserve_selected(&mut self, selected_count: usize) -> Result<(), RecoveryExecutionError> {
        self.training
            .try_reserve_exact(selected_count)
            .map_err(|source| operational("record gate training allocation failed", source))?;
        self.heldout
            .try_reserve_exact(selected_count)
            .map_err(|source| operational("record gate held-out allocation failed", source))?;
        self.training_data_offsets
            .try_reserve_exact(selected_count)
            .map_err(|source| operational("record gate offset allocation failed", source))?;
        self.training_indices
            .try_reserve_exact(selected_count)
            .map_err(|source| {
                operational("record gate training index allocation failed", source)
            })?;
        self.heldout_indices
            .try_reserve_exact(selected_count)
            .map_err(|source| {
                operational("record gate held-out index allocation failed", source)
            })?;
        Ok(())
    }

    fn reserve_eligible(&mut self, frame_count: usize) -> Result<(), RecoveryExecutionError> {
        self.all_training_indices
            .try_reserve_exact(frame_count)
            .map_err(|source| {
                operational("record gate full training index allocation failed", source)
            })?;
        self.all_heldout_indices
            .try_reserve_exact(frame_count)
            .map_err(|source| {
                operational("record gate full held-out index allocation failed", source)
            })?;
        Ok(())
    }
}

pub(super) fn build_schema_plan(
    frames: &[DecodedFrameOutput],
    report: &RelationalTransformReport,
    schema_limits: RecordSchemaProposalLimits,
    work_limit: usize,
    parser_format: l2_workbench::artifact::ArtifactValidationFormat,
    artifact_policy: l2_workbench::artifact::ArtifactValidationPolicy,
    job: Option<&Job>,
) -> Result<SchemaPlan, RecoveryExecutionError> {
    let discovery = session_ids(&report.discovery_sessions);
    let heldout = session_ids(&report.heldout_sessions);
    if discovery.is_empty() || frames.is_empty() {
        return Ok(pending_plan(
            "no_decoded_discovery_frames",
            &json!({"schema_candidates_examined":0}),
        ));
    }

    let selection = select_learning_frames(
        frames,
        schema_limits.discovery.max_messages,
        &discovery,
        &heldout,
    )?;
    let messages = collect_learning_messages(frames, &selection, &discovery, &heldout)?;
    if messages.training.is_empty()
        || messages.learning_bytes == 0
        || messages.full_input_bytes > work_limit
    {
        return Ok(work_limited_plan(
            messages.learning_bytes,
            messages.full_input_bytes,
            work_limit,
        ));
    }

    let uniform_analysis_budget = work_limit.checked_div(2).unwrap_or(0);
    let Some(limits) = prepare_schema_limits(
        schema_limits,
        frames,
        messages.training_indices.as_slice(),
        &messages,
        uniform_analysis_budget,
    )?
    else {
        return Ok(work_limited_plan(
            messages.learning_bytes,
            messages.full_input_bytes,
            work_limit,
        ));
    };
    analyze_plan(&PlanAnalysisRequest {
        frames,
        selection: &selection,
        discovery: &discovery,
        messages: &messages,
        limits,
        work_limit,
        parser_format,
        artifact_policy,
        job,
    })
}

fn analyze_plan(
    request: &PlanAnalysisRequest<'_, '_>,
) -> Result<SchemaPlan, RecoveryExecutionError> {
    if let Some(job) = request.job {
        job.check_cancelled()?;
    }
    let observer = Some(SchemaObserverOptions {
        frames: request.frames,
        parser_format: request.parser_format,
        artifact_policy: request.artifact_policy,
        job: request.job,
    });
    let uniform_analysis_budget = request.work_limit.checked_div(2).unwrap_or(0);
    let uniform_request = AnalysisRequest {
        label: "uniform",
        family_details: None,
        frame_indices: None,
        messages: request.messages,
        limits: request.limits,
        work_limit: request.work_limit,
        analysis_work_limit: uniform_analysis_budget,
        observer_work_limit: request.work_limit.saturating_sub(uniform_analysis_budget),
        observer,
        omitted_learning_messages: request.selection.omitted_messages,
        job: request.job,
    };
    let uniform = analyze_group(&uniform_request)?;
    let family_budget = request.work_limit.saturating_sub(uniform.work_bytes);
    let family = build_family_analysis(
        request.frames,
        request.selection,
        request.discovery,
        request.limits,
        family_budget,
        observer,
        request.job,
    )?;
    let mut alternatives = uniform.alternatives;
    alternatives
        .try_reserve(family.alternatives.len())
        .map_err(|source| operational("record gate alternative allocation failed", source))?;
    alternatives.extend(family.alternatives);
    Ok(SchemaPlan {
        alternatives,
        details: json!({
            "uniform":uniform.details,
            "family":family.details,
            "family_work_bytes":family.work_bytes,
            "family_search_complete":family.complete,
        }),
        has_unassigned_family_messages: family.has_unassigned_messages,
        family_search_complete: family.complete,
    })
}

fn collect_learning_messages<'a>(
    frames: &'a [DecodedFrameOutput],
    selection: &LearningSelection,
    discovery: &BTreeSet<u64>,
    heldout: &BTreeSet<u64>,
) -> Result<LearningMessages<'a>, RecoveryExecutionError> {
    let mut contents = LearningMessageContents::reserve(selection.indices.len(), frames.len())?;
    let mut training_sessions = BTreeSet::new();
    collect_eligible_frames(frames, discovery, heldout, &mut contents)?;
    collect_selected_frames(
        frames,
        selection,
        discovery,
        heldout,
        &mut contents,
        &mut training_sessions,
    )?;
    let training_session_count = training_sessions.len();
    let full_input_bytes = total_input_bytes(frames)?;
    Ok(LearningMessages {
        training: contents.training,
        heldout: contents.heldout,
        training_indices: contents.training_indices,
        heldout_indices: contents.heldout_indices,
        all_training_indices: contents.all_training_indices,
        all_heldout_indices: contents.all_heldout_indices,
        training_data_offsets: contents.training_data_offsets,
        learning_bytes: contents.learning_bytes,
        analysis_input_bytes: contents.analysis_input_bytes,
        eligible_input_bytes: contents.eligible_input_bytes,
        full_input_bytes,
        training_session_count,
    })
}

fn collect_eligible_frames(
    frames: &[DecodedFrameOutput],
    discovery: &BTreeSet<u64>,
    heldout: &BTreeSet<u64>,
    contents: &mut LearningMessageContents<'_>,
) -> Result<(), RecoveryExecutionError> {
    for (frame_index, frame) in frames.iter().enumerate() {
        if discovery.contains(&frame.context.session) {
            contents.all_training_indices.push(frame_index);
            contents.eligible_input_bytes = contents
                .eligible_input_bytes
                .checked_add(frame.bytes.len())
                .ok_or_else(|| invalid_policy("record gate eligible input count overflowed"))?;
        } else if heldout.contains(&frame.context.session) {
            contents.all_heldout_indices.push(frame_index);
            contents.eligible_input_bytes = contents
                .eligible_input_bytes
                .checked_add(frame.bytes.len())
                .ok_or_else(|| invalid_policy("record gate eligible input count overflowed"))?;
        }
    }
    Ok(())
}

fn collect_selected_frames<'a>(
    frames: &'a [DecodedFrameOutput],
    selection: &LearningSelection,
    discovery: &BTreeSet<u64>,
    heldout: &BTreeSet<u64>,
    contents: &mut LearningMessageContents<'a>,
    training_sessions: &mut BTreeSet<u64>,
) -> Result<(), RecoveryExecutionError> {
    for frame_index in &selection.indices {
        let frame = frames
            .get(*frame_index)
            .ok_or_else(|| invalid_policy("record gate selected a missing frame"))?;
        contents.learning_bytes = contents
            .learning_bytes
            .checked_add(frame.bytes.len())
            .ok_or_else(|| invalid_policy("record gate learning byte count overflowed"))?;
        if discovery.contains(&frame.context.session) {
            contents.training.push(frame.bytes.as_slice());
            contents.training_indices.push(*frame_index);
            contents.analysis_input_bytes = contents
                .analysis_input_bytes
                .checked_add(frame.bytes.len())
                .ok_or_else(|| invalid_policy("record gate analysis input count overflowed"))?;
            training_sessions.insert(frame.context.session);
            if let Some(offset) = frame.preserved_header_end {
                contents.training_data_offsets.push(offset);
            }
        } else if heldout.contains(&frame.context.session) {
            contents.heldout.push(frame.bytes.as_slice());
            contents.heldout_indices.push(*frame_index);
            contents.analysis_input_bytes = contents
                .analysis_input_bytes
                .checked_add(frame.bytes.len())
                .ok_or_else(|| invalid_policy("record gate analysis input count overflowed"))?;
        }
    }
    Ok(())
}

fn work_limited_plan(
    learning_bytes: usize,
    full_input_bytes: usize,
    work_limit: usize,
) -> SchemaPlan {
    pending_plan(
        "record_schema_work_limit",
        &json!({
            "learning_bytes":learning_bytes,
            "full_input_bytes":full_input_bytes,
            "work_limit":work_limit,
        }),
    )
}

pub(super) fn prepare_schema_limits(
    initial: RecordSchemaProposalLimits,
    frames: &[DecodedFrameOutput],
    frame_indices: &[usize],
    messages: &LearningMessages<'_>,
    work_limit: usize,
) -> Result<Option<RecordSchemaProposalLimits>, RecoveryExecutionError> {
    let Some(mut limits) =
        bounded_schema_limits(initial, messages.analysis_input_bytes, work_limit)
    else {
        return Ok(None);
    };
    // Keep clear-header candidates bounded by bytes that the transform cannot change
    limits = restrict_header_offsets(limits, frames, frame_indices)?;
    limits.discovery.max_survivors = limits
        .discovery
        .max_survivors
        .min(MAX_RETAINED_SCHEMA_HYPOTHESES);
    limit_record_input(&mut limits, messages.eligible_input_bytes);
    Ok(Some(limits))
}

fn bounded_schema_limits(
    mut limits: RecordSchemaProposalLimits,
    input_bytes: usize,
    work_limit: usize,
) -> Option<RecordSchemaProposalLimits> {
    let steps = work_limit.checked_div(input_bytes)?;
    if steps < 6 {
        return None;
    }
    // Divide the caller budget across the six independent proposal checks
    let per_domain_limit = steps.checked_div(6)?.clamp(1, MAX_GATE_SCHEMA_CHECKS);
    limits.max_field_checks_per_domain = limits.max_field_checks_per_domain.min(per_domain_limit);
    limits.max_pair_checks = limits.max_pair_checks.min(per_domain_limit);
    limits.max_length_checks = limits.max_length_checks.min(per_domain_limit);
    limits.discovery.max_candidates = limits.discovery.max_candidates.min(per_domain_limit);
    Some(limits)
}

fn restrict_header_offsets(
    mut limits: RecordSchemaProposalLimits,
    frames: &[DecodedFrameOutput],
    frame_indices: &[usize],
) -> Result<RecordSchemaProposalLimits, RecoveryExecutionError> {
    let selected_frames = frame_indices
        .iter()
        .map(|index| {
            frames
                .get(*index)
                .ok_or_else(|| invalid_policy("record gate selected a missing frame"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !selected_frames.is_empty()
        && selected_frames
            .iter()
            .all(|frame| frame.preserved_header_end.is_some())
    {
        let prefix_end = selected_frames
            .iter()
            .filter_map(|frame| frame.preserved_header_end)
            .min()
            .ok_or_else(|| invalid_policy("record gate schema plan has no preserved headers"))?;
        if prefix_end > 0 {
            // Include a source-derived boundary one byte beyond the generic prefix-search cap
            let source_boundary_limit = limits.max_field_offset.saturating_add(1);
            limits.max_field_offset = prefix_end.min(source_boundary_limit);
        }
    }
    Ok(limits)
}

fn limit_record_input(limits: &mut RecordSchemaProposalLimits, full_input_bytes: usize) {
    limits.discovery.record_limits.max_input_bytes = limits
        .discovery
        .record_limits
        .max_input_bytes
        .min(full_input_bytes);
    limits.discovery.record_limits.max_output_bytes = limits
        .discovery
        .record_limits
        .max_output_bytes
        .min(full_input_bytes);
}

fn pending_plan(reason: &'static str, details: &Value) -> SchemaPlan {
    SchemaPlan {
        alternatives: Vec::new(),
        details: json!({"reason":reason,"details":details}),
        has_unassigned_family_messages: false,
        family_search_complete: false,
    }
}

fn session_ids(sessions: &[RelationalSessionId]) -> BTreeSet<u64> {
    sessions.iter().map(|session| session.session).collect()
}
