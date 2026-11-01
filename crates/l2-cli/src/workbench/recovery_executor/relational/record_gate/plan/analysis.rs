use super::super::super::super::RecoveryExecutionError;
use super::super::screen::{
    ObservedSchemaEvaluations, SchemaAlternativeEvaluation, SchemaObserverOptions,
    SchemaScreenContext, SurvivingSchemaInputs, observe_surviving_schema,
};
use super::super::{GateStatus, SchemaAlternative};
use super::super::{invalid_policy, operational, record_job_work};
use super::LearningMessages;
use l2_workbench::{
    job::{Counter, Job, Phase},
    protocol::{
        RecordDiscoveryError, RecordError, RecordInput, RecordSchemaAnalysisReport,
        RecordSchemaDiscoveryReport, RecordSchemaMultiStrategyAnalysisReport,
        RecordSchemaProposalLimits, RecordSchemaProposalReport, RecordSchemaStrategy,
        RecordWorkBudget, analyze_record_inputs_with_repeated_boundaries_and_offsets,
        analyze_record_inputs_with_repeated_boundaries_and_offsets_observed,
    },
};
use serde_json::{Value, json};
use std::{ops::ControlFlow, sync::Arc};

#[cfg(test)]
#[path = "../../../../../../tests/workbench/record_gate_plan.rs"]
mod tests;

pub(super) struct AnalysisGroup {
    pub(super) alternatives: Vec<SchemaAlternative>,
    pub(super) work_bytes: usize,
    pub(super) work_limited: bool,
    pub(super) details: Value,
    pub(super) exhaustive: bool,
}

pub(super) struct AnalysisRequest<'a, 'b> {
    pub(super) label: &'a str,
    pub(super) family_details: Option<&'a Value>,
    pub(super) frame_indices: Option<Arc<[usize]>>,
    pub(super) messages: &'a LearningMessages<'b>,
    pub(super) inputs: &'a [RecordInput<'b>],
    pub(super) limits: RecordSchemaProposalLimits,
    pub(super) work_limit: usize,
    pub(super) analysis_work_limit: usize,
    pub(super) observer_work_limit: usize,
    pub(super) observer: Option<SchemaObserverOptions<'a>>,
    pub(super) omitted_learning_messages: usize,
    pub(super) job: Option<&'a Job>,
}

pub(super) fn analyze_group(
    request: &AnalysisRequest<'_, '_>,
) -> Result<AnalysisGroup, RecoveryExecutionError> {
    let mut observed = ObservedSchemaEvaluations::default();
    let mut observer_work = 0_usize;
    let mut observer_error = None;
    let observer_indices = observer_indices(request)?;
    let observer_context = observer_context(request, &observer_indices);
    let training_inputs = record_input_refs(request.inputs, &request.messages.training_indices)?;
    let heldout_inputs = record_input_refs(request.inputs, &request.messages.heldout_indices)?;
    let mut schema_work = RecordWorkBudget::new(request.analysis_work_limit);
    let analysis = if let Some(context) = observer_context.as_ref() {
        analyze_with_observer(
            request,
            context,
            &training_inputs,
            &heldout_inputs,
            ObserverAnalysisState {
                work: &mut schema_work,
                observed: &mut observed,
                observer_work: &mut observer_work,
                observer_error: &mut observer_error,
            },
        )
    } else {
        analyze_without_observer(request, &training_inputs, &heldout_inputs, &mut schema_work)
    };
    if let Some(error) = observer_error {
        return Err(error);
    }
    let analysis = match analysis {
        Ok(analysis) => analysis,
        Err(error) => {
            return Ok(unavailable_group(
                request,
                &error,
                schema_work.consumed(),
                observer_work,
                observed,
            ));
        }
    };
    build_analysis_group(
        request,
        analysis,
        observed,
        observer_work,
        schema_work.consumed(),
    )
}

fn record_input_refs<'inputs, 'bytes>(
    inputs: &'inputs [RecordInput<'bytes>],
    indices: &[usize],
) -> Result<Vec<&'inputs RecordInput<'bytes>>, RecoveryExecutionError> {
    let mut selected = Vec::new();
    selected
        .try_reserve_exact(indices.len())
        .map_err(|source| operational("record gate parser input allocation failed", source))?;
    for index in indices {
        selected.push(
            inputs
                .get(*index)
                .ok_or_else(|| invalid_policy("record gate parser input is missing"))?,
        );
    }
    Ok(selected)
}

fn observer_indices(
    request: &AnalysisRequest<'_, '_>,
) -> Result<Vec<usize>, RecoveryExecutionError> {
    let mut indices = Vec::new();
    if request.observer.is_none() {
        return Ok(indices);
    }
    let count = request
        .messages
        .all_training_indices
        .len()
        .saturating_add(request.messages.all_heldout_indices.len());
    indices
        .try_reserve_exact(count)
        .map_err(|source| operational("record gate observer index allocation failed", source))?;
    indices.extend_from_slice(&request.messages.all_training_indices);
    indices.extend_from_slice(&request.messages.all_heldout_indices);
    indices.sort_unstable();
    Ok(indices)
}

fn observer_context<'a>(
    request: &AnalysisRequest<'a, '_>,
    indices: &'a [usize],
) -> Option<SchemaScreenContext<'a>> {
    request.observer.map(|options| SchemaScreenContext {
        frames: options.frames,
        inputs: request.inputs,
        frame_indices: indices,
        limits: request.limits,
        parser_format: options.parser_format,
        artifact_policy: options.artifact_policy,
        work_limit: request.observer_work_limit,
        job: options.job,
        structural_admission: options.structural_admission,
        full_input_bytes: request.messages.eligible_input_bytes,
    })
}

fn analyze_without_observer(
    request: &AnalysisRequest<'_, '_>,
    training_inputs: &[&RecordInput<'_>],
    heldout_inputs: &[&RecordInput<'_>],
    work: &mut RecordWorkBudget,
) -> Result<RecordSchemaMultiStrategyAnalysisReport, RecordDiscoveryError> {
    analyze_record_inputs_with_repeated_boundaries_and_offsets(
        training_inputs,
        heldout_inputs,
        request.limits,
        &request.messages.training_data_offsets,
        work,
    )
}

struct ObserverAnalysisState<'work> {
    work: &'work mut RecordWorkBudget,
    observed: &'work mut ObservedSchemaEvaluations,
    observer_work: &'work mut usize,
    observer_error: &'work mut Option<RecoveryExecutionError>,
}

fn analyze_with_observer(
    request: &AnalysisRequest<'_, '_>,
    context: &SchemaScreenContext<'_>,
    training_inputs: &[&RecordInput<'_>],
    heldout_inputs: &[&RecordInput<'_>],
    state: ObserverAnalysisState<'_>,
) -> Result<RecordSchemaMultiStrategyAnalysisReport, RecordDiscoveryError> {
    let ObserverAnalysisState {
        work,
        observed,
        observer_work,
        observer_error,
    } = state;
    analyze_record_inputs_with_repeated_boundaries_and_offsets_observed(
        training_inputs,
        heldout_inputs,
        request.limits,
        &request.messages.training_data_offsets,
        work,
        |strategy, hypothesis, training_reports, heldout_reports| {
            let evaluation = strategy_evaluation_mut(observed, strategy);
            evaluation.strict_survivors_seen = evaluation.strict_survivors_seen.saturating_add(1);
            match observe_surviving_schema(
                context,
                strategy,
                hypothesis,
                &SurvivingSchemaInputs {
                    selected_training_indices: &request.messages.training_indices,
                    selected_heldout_indices: &request.messages.heldout_indices,
                    all_training_indices: &request.messages.all_training_indices,
                    all_heldout_indices: &request.messages.all_heldout_indices,
                    training_reports,
                    heldout_reports,
                },
                observer_work,
                evaluation,
            ) {
                Ok(control) => {
                    record_exact_survivor_ordinal(evaluation);
                    control
                }
                Err(error) => {
                    *observer_error = Some(error);
                    ControlFlow::Break(())
                }
            }
        },
    )
}

const fn strategy_evaluation_mut(
    observed: &mut ObservedSchemaEvaluations,
    strategy: RecordSchemaStrategy,
) -> &mut SchemaAlternativeEvaluation {
    match strategy {
        RecordSchemaStrategy::FixedLayout => &mut observed.fixed_layout,
        RecordSchemaStrategy::RepeatedBoundaries => &mut observed.repeated_boundaries,
    }
}

const fn record_exact_survivor_ordinal(evaluation: &mut SchemaAlternativeEvaluation) {
    if evaluation.exact_artifact_matches > 0 && evaluation.exact_artifact_survivor_ordinal.is_none()
    {
        evaluation.exact_artifact_survivor_ordinal = Some(evaluation.strict_survivors_seen);
    }
}

fn build_analysis_group(
    request: &AnalysisRequest<'_, '_>,
    analysis: l2_workbench::protocol::RecordSchemaMultiStrategyAnalysisReport,
    observed: ObservedSchemaEvaluations,
    observer_work: usize,
    schema_work: usize,
) -> Result<AnalysisGroup, RecoveryExecutionError> {
    let fixed = analysis.fixed_layout;
    let repeated = analysis.repeated_boundaries;
    let work_limited = analysis_work_limited(&fixed)
        || repeated.as_ref().is_some_and(analysis_work_limited)
        || observed.fixed_layout.work_limited
        || observed.repeated_boundaries.work_limited;
    let fixed_limits = analysis.fixed_layout_limits;
    let repeated_limits = analysis.repeated_boundary_limits;
    let work = analysis_work(
        request,
        &fixed,
        repeated.as_ref(),
        repeated_limits.is_some(),
        observer_work,
        schema_work,
    )?;
    let examined_candidates = fixed
        .discovery
        .as_ref()
        .map_or(0, |report| report.examined_combinations)
        .saturating_add(
            repeated
                .as_ref()
                .and_then(|report| report.discovery.as_ref())
                .map_or(0, |report| report.examined_combinations),
        );
    if let Some(job) = request.job {
        record_job_work(
            job,
            Phase::FramingRecordDiscovery,
            Counter::CandidatesExamined,
            u64::try_from(examined_candidates).unwrap_or(u64::MAX),
        )?;
    }
    let fixed_exhaustive = analysis_exhaustive(&fixed);
    let repeated_exhaustive = repeated.as_ref().is_none_or(analysis_exhaustive);
    let exhaustive = fixed_exhaustive && repeated_exhaustive;
    let mut alternatives = Vec::new();
    alternatives
        .try_reserve_exact(usize::from(repeated.is_some()).saturating_add(1))
        .map_err(|source| operational("record gate strategy allocation failed", source))?;
    alternatives.push(schema_alternative(
        format!("{}:fixed_layout", request.label),
        request,
        fixed,
        fixed_limits,
        work.fixed_cost,
        request.observer.map(|_| observed.fixed_layout),
    ));
    if let (Some(repeated), Some(repeated_limits)) = (repeated, repeated_limits) {
        alternatives.push(schema_alternative(
            format!("{}:repeated_boundaries", request.label),
            request,
            repeated,
            repeated_limits,
            work.repeated_cost,
            request.observer.map(|_| observed.repeated_boundaries),
        ));
    }
    let details = json!({
        "label":request.label,
        "family":request.family_details,
        "fixed_layout_work_bytes":work.fixed_cost,
        "repeated_boundary_work_bytes":work.repeated_cost,
        "observer_work_bytes":observer_work,
        "work_bytes":work.total_work,
        "work_limit":request.work_limit,
        "search_exhaustive":exhaustive,
        "repeated_boundary_strategy_available":work.repeated_available,
    });
    Ok(AnalysisGroup {
        alternatives,
        work_bytes: work.total_work,
        work_limited,
        details,
        exhaustive,
    })
}

struct AnalysisWork {
    fixed_cost: usize,
    repeated_cost: usize,
    total_work: usize,
    repeated_available: bool,
}

fn analysis_work(
    request: &AnalysisRequest<'_, '_>,
    fixed: &RecordSchemaAnalysisReport,
    repeated: Option<&RecordSchemaAnalysisReport>,
    repeated_limits_available: bool,
    observer_work: usize,
    schema_work: usize,
) -> Result<AnalysisWork, RecoveryExecutionError> {
    let fixed_cost = fixed.work_bytes.unwrap_or_default();
    let repeated_cost = repeated
        .and_then(|analysis| analysis.work_bytes)
        .unwrap_or_default();
    let reported_schema_work = fixed_cost
        .checked_add(repeated_cost)
        .ok_or_else(|| invalid_policy("record gate multi-strategy work overflowed"))?;
    if reported_schema_work != schema_work
        || schema_work > request.analysis_work_limit
        || observer_work > request.observer_work_limit
    {
        return Err(invalid_policy(
            "record gate exceeded its observer work reservation",
        ));
    }
    let total_work = schema_work
        .checked_add(observer_work)
        .ok_or_else(|| invalid_policy("record gate observer work overflowed"))?;
    Ok(AnalysisWork {
        fixed_cost,
        repeated_cost,
        total_work,
        repeated_available: repeated.is_some() && repeated_limits_available,
    })
}

fn schema_alternative(
    label: String,
    request: &AnalysisRequest<'_, '_>,
    analysis: RecordSchemaAnalysisReport,
    limits: RecordSchemaProposalLimits,
    work_bytes: usize,
    observed: Option<SchemaAlternativeEvaluation>,
) -> SchemaAlternative {
    let exhaustive = analysis_exhaustive(&analysis);
    let observer_work_bytes = observed
        .as_ref()
        .map_or(0, |evaluation| evaluation.work_bytes);
    let total_work_bytes = work_bytes.saturating_add(observer_work_bytes);
    let status = analysis_status(&analysis, total_work_bytes, request.work_limit);
    let details = analysis_details(&analysis, request, status, work_bytes, observer_work_bytes);
    SchemaAlternative {
        label,
        frame_indices: request.frame_indices.clone(),
        discovery_report: analysis.discovery.map(Into::into),
        limits,
        discovery_work_bytes: total_work_bytes,
        learning_message_count: analysis.proposal.training_message_count,
        heldout_message_count: analysis.proposal.held_out_message_count,
        omitted_learning_messages: request.omitted_learning_messages,
        learning_session_count: request.messages.training_session_count,
        proposal_search_exhaustive: exhaustive,
        status,
        observed,
        details,
    }
}

fn unavailable_group(
    request: &AnalysisRequest<'_, '_>,
    error: &RecordDiscoveryError,
    schema_work: usize,
    observer_work: usize,
    observed: ObservedSchemaEvaluations,
) -> AnalysisGroup {
    let work_limited = matches!(
        error,
        RecordDiscoveryError::RecordOperation(RecordError::WorkLimitExceeded { .. })
    );
    let total_work = schema_work.saturating_add(observer_work);
    let observed = request
        .observer
        .map(|_| combine_observed_evaluations(observed));
    let reason = if matches!(
        error,
        RecordDiscoveryError::RecordOperation(RecordError::WorkLimitExceeded { .. })
    ) {
        "record_schema_work_limit"
    } else {
        "record_schema_analysis_unavailable"
    };
    let details = json!({
        "label":request.label,
        "family":request.family_details,
        "reason":reason,
        "error":error.to_string(),
        "training_message_count":request.messages.training.len(),
        "held_out_message_count":request.messages.heldout.len(),
        "schema_work_bytes":schema_work,
        "observer_work_bytes":observer_work,
        "work_bytes":total_work,
        "work_limit":request.work_limit,
    });
    let alternative = SchemaAlternative {
        label: format!("{}:analysis_unavailable", request.label),
        frame_indices: request.frame_indices.clone(),
        discovery_report: None,
        limits: request.limits,
        discovery_work_bytes: total_work,
        learning_message_count: request.messages.training.len(),
        heldout_message_count: request.messages.heldout.len(),
        omitted_learning_messages: request.omitted_learning_messages,
        learning_session_count: request.messages.training_session_count,
        proposal_search_exhaustive: false,
        status: GateStatus::Pending,
        observed,
        details: details.clone(),
    };
    AnalysisGroup {
        alternatives: vec![alternative],
        work_bytes: total_work,
        work_limited,
        details,
        exhaustive: false,
    }
}

fn combine_observed_evaluations(
    observed: ObservedSchemaEvaluations,
) -> SchemaAlternativeEvaluation {
    let fixed = observed.fixed_layout;
    let repeated = observed.repeated_boundaries;
    let structural_witness = fixed
        .structural_witness
        .clone()
        .or_else(|| repeated.structural_witness.clone());
    let accepted_schema = fixed
        .accepted_schema
        .clone()
        .or_else(|| repeated.accepted_schema.clone());
    let exact_artifact_survivor_ordinal = accepted_schema.as_ref().map_or_else(
        || {
            fixed
                .exact_artifact_survivor_ordinal
                .or(repeated.exact_artifact_survivor_ordinal)
        },
        |accepted| match accepted.strategy {
            RecordSchemaStrategy::FixedLayout => fixed.exact_artifact_survivor_ordinal,
            RecordSchemaStrategy::RepeatedBoundaries => repeated.exact_artifact_survivor_ordinal,
        },
    );
    let dropped_header_models = fixed
        .header_models
        .len()
        .saturating_add(repeated.header_models.len());

    SchemaAlternativeEvaluation {
        exact_artifact_matches: fixed
            .exact_artifact_matches
            .saturating_add(repeated.exact_artifact_matches),
        parser_omissions: fixed
            .parser_omissions
            .saturating_add(repeated.parser_omissions),
        schemas_checked: fixed
            .schemas_checked
            .saturating_add(repeated.schemas_checked),
        underdetermined_schemas: fixed
            .underdetermined_schemas
            .saturating_add(repeated.underdetermined_schemas),
        variable_length_schemas: fixed
            .variable_length_schemas
            .saturating_add(repeated.variable_length_schemas),
        coherent_sequence_schemas: fixed
            .coherent_sequence_schemas
            .saturating_add(repeated.coherent_sequence_schemas),
        sequence_conflict_schemas: fixed
            .sequence_conflict_schemas
            .saturating_add(repeated.sequence_conflict_schemas),
        surviving_schemas: fixed
            .surviving_schemas
            .saturating_add(repeated.surviving_schemas),
        work_bytes: fixed.work_bytes.saturating_add(repeated.work_bytes),
        work_limited: fixed.work_limited || repeated.work_limited,
        strict_survivors_seen: fixed
            .strict_survivors_seen
            .saturating_add(repeated.strict_survivors_seen),
        exact_artifact_survivor_ordinal,
        accepted_schema,
        structural_witness,
        survives: fixed.survives || repeated.survives,
        pending: true,
        header_models: Vec::new(),
        header_model_bytes: 0,
        header_models_omitted: fixed
            .header_models_omitted
            .saturating_add(repeated.header_models_omitted)
            .saturating_add(dropped_header_models),
    }
}

fn analysis_exhaustive(analysis: &RecordSchemaAnalysisReport) -> bool {
    analysis.proposal.search_exhaustive_within_plan
        && analysis
            .discovery
            .as_ref()
            .is_none_or(|report| report.search_exhaustive_within_plan)
}

fn analysis_status(
    analysis: &RecordSchemaAnalysisReport,
    work_bytes: usize,
    work_limit: usize,
) -> GateStatus {
    if work_bytes > work_limit || analysis_work_limited(analysis) {
        return GateStatus::Pending;
    }
    match analysis.discovery.as_ref() {
        Some(report)
            if report.surviving.is_empty()
                && report.omitted_survivors == 0
                && analysis_exhaustive(analysis) =>
        {
            GateStatus::Contradicted
        }
        None if analysis.proposal.candidate_space.is_none() && analysis_exhaustive(analysis) => {
            GateStatus::Contradicted
        }
        _ => GateStatus::Pending,
    }
}

fn analysis_details(
    analysis: &RecordSchemaAnalysisReport,
    request: &AnalysisRequest<'_, '_>,
    status: GateStatus,
    analysis_work_bytes: usize,
    observer_work_bytes: usize,
) -> Value {
    let proposal = &analysis.proposal;
    let discovery = analysis.discovery.as_ref();
    let work_limited = proposal.work_limit_reached
        || discovery.is_some_and(|report| report.work_limit_reached)
        || analysis_work_bytes.saturating_add(observer_work_bytes) > request.work_limit;
    let resource_limited_candidates =
        discovery.map_or(0, |report| report.resource_limited_candidates);
    let reason = if work_limited {
        "record_schema_work_limit"
    } else if resource_limited_candidates > 0 {
        "record_schema_candidate_resource_limit"
    } else {
        status.as_str()
    };
    let repeated_boundary_cues = proposal
        .repeated_boundary_cues
        .iter()
        .map(|cue| {
            json!({
                "message_index":cue.message_index,
                "range":{"start":cue.range.start,"end":cue.range.end},
            })
        })
        .collect::<Vec<_>>();
    json!({
        "reason":reason,
        "family":request.family_details,
        "training_message_count":proposal.training_message_count,
        "held_out_message_count":proposal.held_out_message_count,
        "schema_learning_messages_omitted":request.omitted_learning_messages,
        "schema_learning_sessions":request.messages.training_session_count,
        "schema_candidates_examined":discovery.map_or(0, |report| report.examined_combinations),
        "schema_candidates_omitted":discovery.and_then(|report| report.unexamined_combinations),
        "schema_candidates_resource_limited":resource_limited_candidates,
        "schema_survivors":discovery.map_or(0, |report| report.surviving.len()),
        "omitted_schema_survivors":discovery.map_or(0, |report| report.omitted_survivors),
        "omitted_record_views":proposal.omitted_record_views,
        "repeated_boundary_cues":repeated_boundary_cues,
        "schema_search_exhaustive":analysis_exhaustive_from_parts(proposal, discovery),
        "schema_work_bytes":analysis_work_bytes,
        "schema_observer_work_bytes":observer_work_bytes,
        "work_limit":request.work_limit,
    })
}

fn analysis_exhaustive_from_parts(
    proposal: &RecordSchemaProposalReport,
    discovery: Option<&RecordSchemaDiscoveryReport>,
) -> bool {
    proposal.search_exhaustive_within_plan
        && discovery.is_none_or(|report| report.search_exhaustive_within_plan)
}

fn analysis_work_limited(analysis: &RecordSchemaAnalysisReport) -> bool {
    analysis.proposal.work_limit_reached
        || analysis
            .discovery
            .as_ref()
            .is_some_and(|report| report.work_limit_reached)
}
