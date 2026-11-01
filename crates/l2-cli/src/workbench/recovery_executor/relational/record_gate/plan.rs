mod analysis;
mod family;

use super::super::super::RecoveryExecutionError;
use super::super::{DecodedFrameOutput, invalid_policy, operational};
use super::screen::SchemaObserverOptions;
use super::selection::{LearningSelection, select_learning_frames};
use super::{SchemaCandidateOptions, SchemaPlan, record_inputs, total_input_bytes};
use analysis::{AnalysisRequest, analyze_group};
use family::{FamilyAnalysisRequest, build_family_analysis};
use l2_workbench::{
    job::Job,
    protocol::{RecordSchemaProposalLimits, RelationalSessionId, RelationalTransformReport},
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const MAX_RETAINED_SCHEMA_HYPOTHESES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::workbench::recovery_executor::relational) enum SchemaOffsetScope {
    PreservedHeader,
    CompleteInput,
}

impl SchemaOffsetScope {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::PreservedHeader => "preserved_header",
            Self::CompleteInput => "complete_input",
        }
    }
}

pub(super) struct LearningMessages<'a> {
    training: Vec<&'a [u8]>,
    heldout: Vec<&'a [u8]>,
    training_indices: Vec<usize>,
    heldout_indices: Vec<usize>,
    all_training_indices: Vec<usize>,
    all_heldout_indices: Vec<usize>,
    training_data_offsets: Vec<usize>,
    learning_bytes: usize,
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
    structural_admission: Option<super::StructuralAdmission<'frames>>,
    inputs: &'frames [l2_workbench::protocol::RecordInput<'frames>],
    offset_scope: SchemaOffsetScope,
    assessment_scope: SchemaOffsetScope,
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

#[cfg(test)]
pub(super) fn build_schema_plan(
    frames: &[DecodedFrameOutput],
    report: &RelationalTransformReport,
    schema_limits: RecordSchemaProposalLimits,
    work_limit: usize,
    parser_format: l2_workbench::artifact::ArtifactValidationFormat,
    artifact_policy: l2_workbench::artifact::ArtifactValidationPolicy,
    job: Option<&Job>,
) -> Result<SchemaPlan, RecoveryExecutionError> {
    build_schema_plan_with_scope(
        frames,
        report,
        SchemaCandidateOptions {
            parser_format,
            schema_limits,
            artifact_policy,
            work_limit,
            job,
            producer_rule: None,
            structural_admission: None,
        },
        None,
        SchemaOffsetScope::PreservedHeader,
    )
}

pub(super) fn build_full_schema_plan(
    frames: &[DecodedFrameOutput],
    report: &RelationalTransformReport,
    options: SchemaCandidateOptions<'_>,
) -> Result<SchemaPlan, RecoveryExecutionError> {
    build_schema_plan_with_scope(
        frames,
        report,
        options,
        None,
        SchemaOffsetScope::CompleteInput,
    )
}

pub(super) fn build_schema_plan_with_inputs<'frames>(
    frames: &'frames [DecodedFrameOutput],
    report: &RelationalTransformReport,
    options: SchemaCandidateOptions<'_>,
    header_inputs: Option<&'frames [l2_workbench::protocol::RecordInput<'frames>]>,
) -> Result<SchemaPlan, RecoveryExecutionError> {
    build_schema_plan_with_scope(
        frames,
        report,
        options,
        header_inputs,
        SchemaOffsetScope::PreservedHeader,
    )
}

fn build_schema_plan_with_scope<'frames>(
    frames: &'frames [DecodedFrameOutput],
    report: &RelationalTransformReport,
    options: SchemaCandidateOptions<'_>,
    header_inputs: Option<&'frames [l2_workbench::protocol::RecordInput<'frames>]>,
    offset_scope: SchemaOffsetScope,
) -> Result<SchemaPlan, RecoveryExecutionError> {
    let SchemaCandidateOptions {
        parser_format,
        schema_limits,
        artifact_policy,
        work_limit,
        job,
        structural_admission,
        ..
    } = options;
    let discovery = session_ids(&report.discovery_sessions);
    let heldout = session_ids(&report.heldout_sessions);
    if discovery.is_empty() || frames.is_empty() {
        return Ok(pending_plan(
            "no_decoded_discovery_frames",
            &json!({"schema_candidates_examined":0}),
            SchemaOffsetScope::CompleteInput,
        ));
    }

    let selection = select_learning_frames(
        frames,
        schema_limits.discovery.max_messages,
        &discovery,
        &heldout,
    )?;
    let messages = collect_learning_messages(frames, &selection, &discovery, &heldout)?;
    let owned_inputs = header_inputs
        .is_none()
        .then(|| record_inputs(frames))
        .transpose()?;
    let inputs = header_inputs
        .or(owned_inputs.as_deref())
        .ok_or_else(|| invalid_policy("record gate input identities are missing"))?;
    let assessment_scope = effective_offset_scope(
        frames,
        &messages.training_indices,
        schema_limits,
        offset_scope,
    )?;
    if messages.training.is_empty() || messages.learning_bytes == 0 {
        return Ok(work_limited_plan(
            messages.learning_bytes,
            messages.full_input_bytes,
            work_limit,
            assessment_scope,
        ));
    }

    let limits = prepare_schema_limits(
        schema_limits,
        frames,
        messages.training_indices.as_slice(),
        &messages,
        offset_scope,
    )?;
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
        structural_admission: structural_admission.copied(),
        inputs,
        offset_scope,
        assessment_scope,
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
        structural_admission: request.structural_admission,
    });
    let uniform_analysis_budget = request.work_limit.checked_div(2).unwrap_or(0);
    let uniform_request = AnalysisRequest {
        label: "uniform",
        family_details: None,
        frame_indices: None,
        messages: request.messages,
        inputs: request.inputs,
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
    let family_request = FamilyAnalysisRequest {
        frames: request.frames,
        inputs: request.inputs,
        selection: request.selection,
        discovery_sessions: request.discovery,
        base_limits: request.limits,
        work_limit: family_budget,
        observer,
        offset_scope: request.offset_scope,
        job: request.job,
    };
    let family = build_family_analysis(&family_request)?;
    let work_limited = uniform.work_limited || family.work_limited;
    let mut alternatives = uniform.alternatives;
    alternatives
        .try_reserve(family.alternatives.len())
        .map_err(|source| operational("record gate alternative allocation failed", source))?;
    alternatives.extend(family.alternatives);
    Ok(SchemaPlan {
        alternatives,
        observation_work_bytes: family.observation_work_bytes,
        details: json!({
            "uniform":uniform.details,
            "family":family.details,
            "family_work_bytes":family.work_bytes,
            "family_search_complete":family.complete,
        }),
        work_limited,
        has_unassigned_family_messages: family.has_unassigned_messages,
        family_search_complete: family.complete,
        assessment_scope: request.assessment_scope,
        producer_rule: None,
    })
}

fn effective_offset_scope(
    frames: &[DecodedFrameOutput],
    frame_indices: &[usize],
    limits: RecordSchemaProposalLimits,
    requested: SchemaOffsetScope,
) -> Result<SchemaOffsetScope, RecoveryExecutionError> {
    if requested == SchemaOffsetScope::CompleteInput || frame_indices.is_empty() {
        return Ok(SchemaOffsetScope::CompleteInput);
    }
    let selected_frames = frame_indices
        .iter()
        .map(|index| {
            frames
                .get(*index)
                .ok_or_else(|| invalid_policy("record gate scope frame is missing"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if selected_frames
        .iter()
        .any(|frame| frame.preserved_header_end.is_none())
    {
        return Ok(SchemaOffsetScope::CompleteInput);
    }
    let prefix_end = selected_frames
        .iter()
        .filter_map(|frame| frame.preserved_header_end)
        .min()
        .unwrap_or_default();
    if prefix_end > 0 && prefix_end < limits.max_field_offset {
        Ok(SchemaOffsetScope::PreservedHeader)
    } else {
        Ok(SchemaOffsetScope::CompleteInput)
    }
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
            training_sessions.insert(frame.context.session);
            if let Some(offset) = frame.preserved_header_end {
                contents.training_data_offsets.push(offset);
            }
        } else if heldout.contains(&frame.context.session) {
            contents.heldout.push(frame.bytes.as_slice());
            contents.heldout_indices.push(*frame_index);
        }
    }
    Ok(())
}

fn work_limited_plan(
    learning_bytes: usize,
    full_input_bytes: usize,
    work_limit: usize,
    assessment_scope: SchemaOffsetScope,
) -> SchemaPlan {
    pending_plan(
        "record_schema_work_limit",
        &json!({
            "learning_bytes":learning_bytes,
            "full_input_bytes":full_input_bytes,
            "work_limit":work_limit,
        }),
        assessment_scope,
    )
}

pub(super) fn prepare_schema_limits(
    initial: RecordSchemaProposalLimits,
    frames: &[DecodedFrameOutput],
    frame_indices: &[usize],
    messages: &LearningMessages<'_>,
    offset_scope: SchemaOffsetScope,
) -> Result<RecordSchemaProposalLimits, RecoveryExecutionError> {
    // Search caps come from the proposal policy; actual reads and parses use RecordWorkBudget
    let mut limits = initial;
    if offset_scope == SchemaOffsetScope::PreservedHeader {
        // Keep the primary probe within bytes that the transform cannot change
        limits = restrict_header_offsets(limits, frames, frame_indices)?;
    }
    limits.discovery.max_survivors = limits
        .discovery
        .max_survivors
        .min(MAX_RETAINED_SCHEMA_HYPOTHESES);
    limit_record_input(&mut limits, messages.eligible_input_bytes);
    Ok(limits)
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

fn pending_plan(
    reason: &'static str,
    details: &Value,
    assessment_scope: SchemaOffsetScope,
) -> SchemaPlan {
    SchemaPlan {
        alternatives: Vec::new(),
        observation_work_bytes: 0,
        details: json!({"reason":reason,"details":details}),
        work_limited: false,
        has_unassigned_family_messages: false,
        family_search_complete: false,
        assessment_scope,
        producer_rule: None,
    }
}

fn session_ids(sessions: &[RelationalSessionId]) -> BTreeSet<u64> {
    sessions.iter().map(|session| session.session).collect()
}
