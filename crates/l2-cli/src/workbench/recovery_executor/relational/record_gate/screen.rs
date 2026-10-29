use super::super::super::RecoveryExecutionError;
use super::super::{DecodedFrameOutput, aggregate_validator, invalid_policy, operational};
use super::header::{HeaderSchemaModel, HeaderSchemaPlan};
use super::{
    GateResult, GateStatus, SchemaAlternative, SchemaOffsetScope, SchemaPlan, record_inputs,
    record_job_work, result,
};
use l2_workbench::{
    artifact::{
        ArtifactValidationFormat, ArtifactValidationOutcome, ArtifactValidationPolicy,
        scan_file_signatures,
    },
    job::{Counter, Job, Phase},
    protocol::{
        BoundRecordAssemblyPlan, HeaderParseTemplate, MessageContext, RecordAssemblyInput,
        RecordAssemblyModelStatus, RecordAssemblyOutcome, RecordError, RecordGroupReceipt,
        RecordInput, RecordParseReport, RecordSchema, RecordSchemaDiscoveryReport,
        RecordSchemaHypothesis, RecordSchemaProposalLimits, RecordSchemaStrategy, RecordWorkBudget,
        assemble_record_groups_from_inputs,
    },
};
use serde_json::{Value, json};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
};

#[derive(Clone, Copy)]
struct WorkLimitHit;

#[derive(Default)]
struct SchemaEvaluation {
    used_work: usize,
    schemas_checked: usize,
    exact_artifact_matches: usize,
    parser_omissions: usize,
    underdetermined_schemas: usize,
    variable_length_schemas: usize,
    coherent_sequence_schemas: usize,
    sequence_conflict_schemas: usize,
    surviving_schemas: usize,
    work_limited: Option<WorkLimitHit>,
    pending: bool,
    uniform_structural_support: bool,
    family_structural_support: bool,
    accepted_schema: Option<AcceptedRecordSchema>,
    alternatives: Vec<Value>,
}

#[derive(Default)]
struct HypothesisEvaluation {
    exact_artifact_matches: usize,
    accepted_receipt: Option<RecordGroupReceipt>,
    parser_omissions: usize,
    evidence: HypothesisEvidence,
    work_limited: bool,
    pending: bool,
}

#[derive(Clone, Default)]
pub(in crate::workbench::recovery_executor::relational) struct SchemaAlternativeEvaluation {
    pub(super) exact_artifact_matches: usize,
    pub(super) parser_omissions: usize,
    pub(super) schemas_checked: usize,
    pub(super) underdetermined_schemas: usize,
    pub(super) variable_length_schemas: usize,
    pub(super) coherent_sequence_schemas: usize,
    pub(super) sequence_conflict_schemas: usize,
    pub(super) surviving_schemas: usize,
    pub(super) work_bytes: usize,
    pub(super) strict_survivors_seen: usize,
    pub(super) exact_artifact_survivor_ordinal: Option<usize>,
    pub(super) accepted_schema: Option<AcceptedRecordSchema>,
    pub(super) work_limited: bool,
    pub(super) survives: bool,
    pub(super) pending: bool,
    pub(super) header_models: Vec<HeaderSchemaModel>,
    pub(super) header_model_bytes: usize,
    pub(super) header_models_omitted: usize,
}

#[derive(Default)]
pub(super) struct ObservedSchemaEvaluations {
    pub(super) fixed_layout: SchemaAlternativeEvaluation,
    pub(super) repeated_boundaries: SchemaAlternativeEvaluation,
}

#[derive(Clone)]
pub(in crate::workbench::recovery_executor::relational) struct AcceptedRecordSchema {
    pub(in crate::workbench::recovery_executor::relational) schema: RecordSchema,
    pub(in crate::workbench::recovery_executor::relational) strategy: RecordSchemaStrategy,
    /// Positions in the candidate's ordered `DecodedFrameOutput` slice
    pub(in crate::workbench::recovery_executor::relational) frame_indices: Vec<usize>,
    pub(in crate::workbench::recovery_executor::relational) frame_identities:
        Vec<AcceptedFrameIdentity>,
    /// The exact assembled group accepted by the artifact parser
    pub(in crate::workbench::recovery_executor::relational) artifact_receipt: RecordGroupReceipt,
    pub(in crate::workbench::recovery_executor::relational) artifact_format:
        ArtifactValidationFormat,
}

#[derive(Clone)]
pub(in crate::workbench::recovery_executor::relational) struct AcceptedFrameIdentity {
    pub(in crate::workbench::recovery_executor::relational) frame_index: usize,
    pub(in crate::workbench::recovery_executor::relational) input_node_id: u64,
    pub(in crate::workbench::recovery_executor::relational) context: MessageContext,
    pub(in crate::workbench::recovery_executor::relational) session_order: u64,
    pub(in crate::workbench::recovery_executor::relational) stream_offset: usize,
    pub(in crate::workbench::recovery_executor::relational) frame_byte_length: usize,
    pub(in crate::workbench::recovery_executor::relational) frame_bytes_sha256: String,
}

#[derive(Clone, Copy)]
pub(super) struct SchemaObserverOptions<'a> {
    pub(super) frames: &'a [DecodedFrameOutput],
    pub(super) parser_format: ArtifactValidationFormat,
    pub(super) artifact_policy: ArtifactValidationPolicy,
    pub(super) job: Option<&'a Job>,
}

pub(super) struct SurvivingSchemaInputs<'a> {
    pub(super) selected_training_indices: &'a [usize],
    pub(super) selected_heldout_indices: &'a [usize],
    pub(super) all_training_indices: &'a [usize],
    pub(super) all_heldout_indices: &'a [usize],
    pub(super) training_reports: &'a [RecordParseReport],
    pub(super) heldout_reports: &'a [RecordParseReport],
}

#[derive(Default)]
enum HypothesisEvidence {
    #[default]
    NotParsed,
    ParserOnly,
    VariableLength,
    VariableLengthWithSequenceConflict,
    CoherentSequence,
    SequenceConflict,
    ArtifactValidated,
}

impl HypothesisEvidence {
    const fn was_parsed(&self) -> bool {
        !matches!(self, Self::NotParsed)
    }

    const fn is_supported(&self) -> bool {
        matches!(
            self,
            Self::VariableLength
                | Self::VariableLengthWithSequenceConflict
                | Self::CoherentSequence
                | Self::ArtifactValidated
        )
    }

    const fn is_underdetermined(&self) -> bool {
        matches!(self, Self::ParserOnly | Self::SequenceConflict)
    }

    const fn has_variable_length_relation(&self) -> bool {
        matches!(
            self,
            Self::VariableLength | Self::VariableLengthWithSequenceConflict
        )
    }

    const fn has_coherent_sequence_relation(&self) -> bool {
        matches!(self, Self::CoherentSequence)
    }

    const fn has_sequence_conflict(&self) -> bool {
        matches!(
            self,
            Self::SequenceConflict | Self::VariableLengthWithSequenceConflict
        )
    }
}

#[derive(Clone, Copy, Default)]
struct CandidateInspection {
    exact_artifact_match: bool,
    parser_omission: bool,
    work_limited: Option<WorkLimitHit>,
    pending: bool,
}

pub(super) fn screen_with_schema_plan(
    frames: &[DecodedFrameOutput],
    parser_format: ArtifactValidationFormat,
    artifact_policy: ArtifactValidationPolicy,
    work_limit: usize,
    job: Option<&Job>,
    plan: &SchemaPlan,
    cache_hit: bool,
) -> Result<GateResult, RecoveryExecutionError> {
    let unchanged_schema_only = all_frames_have_preserved_headers(frames);
    if let Some(job) = job {
        job.check_cancelled()?;
        record_job_work(
            job,
            Phase::TransformDiscovery,
            Counter::CandidatesExamined,
            1,
        )?;
    }
    let initial_work = if cache_hit { 0 } else { plan_work_bytes(plan) };
    if initial_work > work_limit {
        return Ok(pending_work_result(
            initial_work,
            work_limit,
            cache_hit,
            plan,
        ));
    }
    let (evaluation, all_alternatives_contradicted) = evaluate_plan_alternatives(
        frames,
        parser_format,
        artifact_policy,
        work_limit,
        job,
        plan,
        initial_work,
    )?;
    let status = classify_status(
        &evaluation,
        unchanged_schema_only,
        all_alternatives_contradicted,
        plan,
    );
    let mut gate_result = result(
        status,
        evaluation.used_work,
        evaluation_details(
            &evaluation,
            status,
            unchanged_schema_only,
            plan,
            cache_hit,
            parser_format,
        ),
    );
    gate_result.work_limited_at =
        (evaluation.work_limited.is_some() || plan.work_limited).then_some(work_limit);
    gate_result.accepted_schema = evaluation.accepted_schema;
    gate_result.assessment_scope = plan.assessment_scope;
    Ok(gate_result)
}

pub(super) fn screen_with_header_plan(
    frames: &[DecodedFrameOutput],
    parser_format: ArtifactValidationFormat,
    artifact_policy: ArtifactValidationPolicy,
    limits: RecordSchemaProposalLimits,
    work_limit: usize,
    job: Option<&Job>,
    plan: &HeaderSchemaPlan,
) -> Result<GateResult, RecoveryExecutionError> {
    if let Some(job) = job {
        job.check_cancelled()?;
        record_job_work(
            job,
            Phase::TransformDiscovery,
            Counter::CandidatesExamined,
            1,
        )?;
    }
    let full_input_bytes = super::total_input_bytes(frames)?;
    let inputs = record_inputs(frames)?;
    let frame_indices = all_frame_indices(frames.len())?;
    let context = SchemaScreenContext {
        frames,
        inputs: &inputs,
        frame_indices: &frame_indices,
        limits,
        parser_format,
        artifact_policy,
        work_limit,
        job,
        full_input_bytes,
    };
    let evaluation = evaluate_header_models(&context, plan)?;

    let status = if evaluation.exact_artifact_matches > 0 {
        GateStatus::ArtifactValidated
    } else {
        GateStatus::Pending
    };
    let mut gate_result = result(
        status,
        evaluation.used_work,
        json!({
            "reason":if evaluation.exact_artifact_matches == 0 { "cached_partial_models_require_fresh_inference" } else { status.as_str() },
            "assessment_scope":"cached_partial_models",
            "schema_plan_cache_hit":false,
            "header_schema_plan_cache_hit":true,
            "header_schema_models":plan.assembly_plan.model_count(),
            "header_schema_models_attempted":evaluation.models_attempted,
            "header_schema_models_checked":evaluation.schemas_checked,
            "header_schema_models_omitted":plan.omitted_models,
            "header_schema_rebind_rejections":evaluation.rebind_rejections,
            "header_schema_assembly_rejections":evaluation.assembly_rejections,
            "header_schema_models_deferred_for_work":evaluation.models_deferred_for_work,
            "header_schema_prefix_bytes_checked":evaluation.prefix_bytes_checked,
            "header_schema_shared_input_checks":evaluation.shared_input_checks,
            "header_schema_model_input_checks":evaluation.model_input_checks,
            "header_schema_layout_membership_checks":evaluation.layout_membership_checks,
            "header_schema_layouts_materialized":evaluation.layouts_materialized,
            "header_schema_layout_reuses":evaluation.layout_reuses,
            "schema_alternatives":evaluation.alternatives,
            "exact_artifact_matches":evaluation.exact_artifact_matches,
            "parser_omissions":evaluation.parser_omissions,
            "work_bytes":evaluation.used_work,
            "work_limit":work_limit,
            "pending":evaluation.pending,
        }),
    );
    gate_result.work_limited_at = evaluation.work_limited.then_some(work_limit);
    gate_result.assessment_scope = SchemaOffsetScope::PreservedHeader;
    gate_result.accepted_schema = evaluation.accepted_schema;
    let needs_full_inference = gate_result.needs_full_inference();
    if let Some(details) = gate_result.details.as_object_mut() {
        details.insert(
            "full_inference_deferred".to_owned(),
            Value::Bool(needs_full_inference),
        );
        details.insert(
            "assessment_scope".to_owned(),
            Value::String("cached_partial_models".to_owned()),
        );
        details.insert(
            "full_inference_fallback_work_bytes".to_owned(),
            Value::from(0),
        );
    }
    Ok(gate_result)
}

#[derive(Default)]
struct HeaderPlanEvaluation {
    used_work: usize,
    schemas_checked: usize,
    models_attempted: usize,
    rebind_rejections: usize,
    assembly_rejections: usize,
    models_deferred_for_work: usize,
    prefix_bytes_checked: usize,
    shared_input_checks: usize,
    model_input_checks: usize,
    layout_membership_checks: usize,
    layouts_materialized: usize,
    layout_reuses: usize,
    exact_artifact_matches: usize,
    parser_omissions: usize,
    work_limited: bool,
    pending: bool,
    accepted_schema: Option<AcceptedRecordSchema>,
    alternatives: Vec<Value>,
}

struct BoundHeaderEvaluation<'plan, 'input> {
    bound: BoundRecordAssemblyPlan<'plan, 'input>,
    layout_inspections: Vec<Option<CandidateInspection>>,
    result: HeaderPlanEvaluation,
}

fn evaluate_header_models(
    context: &SchemaScreenContext<'_>,
    plan: &HeaderSchemaPlan,
) -> Result<HeaderPlanEvaluation, RecoveryExecutionError> {
    let inputs = context.inputs;
    let assembly_plan = &plan.assembly_plan;
    let bound = assembly_plan
        .bind(inputs)
        .map_err(|source| operational("record gate header plan bind failed", source))?;
    let mut layout_inspections = Vec::new();
    layout_inspections
        .try_reserve_exact(assembly_plan.layout_count())
        .map_err(|source| operational("header layout inspection allocation failed", source))?;
    layout_inspections.resize(assembly_plan.layout_count(), None::<CandidateInspection>);
    let mut result = HeaderPlanEvaluation {
        prefix_bytes_checked: bound.stats().prefix_bytes_checked,
        shared_input_checks: bound.stats().shared_input_checks,
        model_input_checks: bound.stats().model_input_checks,
        layout_membership_checks: bound.stats().layout_membership_checks,
        ..HeaderPlanEvaluation::default()
    };
    let bind_work = result
        .prefix_bytes_checked
        .checked_add(result.shared_input_checks)
        .and_then(|work| work.checked_add(result.model_input_checks))
        .and_then(|work| work.checked_add(result.layout_membership_checks))
        .ok_or_else(|| invalid_policy("record gate header bind work overflowed"))?;
    if !reserve_schema_work(&mut result.used_work, bind_work, context.work_limit)? {
        result.pending = true;
        result.work_limited = true;
        result.models_deferred_for_work = assembly_plan.model_count();
        return Ok(result);
    }
    result
        .alternatives
        .try_reserve_exact(1)
        .map_err(|source| operational("header schema result allocation failed", source))?;
    let mut state = BoundHeaderEvaluation {
        bound,
        layout_inspections,
        result,
    };
    for model_index in 0..assembly_plan.model_count() {
        if evaluate_header_model(context, plan, &mut state, model_index)? {
            break;
        }
    }
    Ok(state.result)
}

fn evaluate_header_model(
    context: &SchemaScreenContext<'_>,
    plan: &HeaderSchemaPlan,
    state: &mut BoundHeaderEvaluation<'_, '_>,
    model_index: usize,
) -> Result<bool, RecoveryExecutionError> {
    if let Some(job) = context.job {
        job.check_cancelled()?;
    }
    state.result.models_attempted = state.result.models_attempted.saturating_add(1);
    match state.bound.model_status(model_index) {
        Some(RecordAssemblyModelStatus::Ready) => {}
        Some(_) => {
            state.result.rebind_rejections = state.result.rebind_rejections.saturating_add(1);
            state.result.pending = true;
            return Ok(false);
        }
        None => return Err(invalid_policy("record gate header model is missing")),
    }
    let Some(group_count) = state.bound.model_group_count(model_index) else {
        return Err(invalid_policy("ready record gate model has no group count"));
    };
    if group_count == 0 {
        state.result.assembly_rejections = state.result.assembly_rejections.saturating_add(1);
        state.result.pending = true;
        return Ok(false);
    }
    state.result.schemas_checked = state.result.schemas_checked.saturating_add(1);
    let model_work_start = state.result.used_work;
    let mut candidate_matches = 0_usize;
    let mut model_pending = false;
    for group_index in 0..group_count {
        let Some(inspection) =
            evaluate_header_group(context, plan, state, model_index, group_index)?
        else {
            return Ok(true);
        };
        state.result.pending |= inspection.pending;
        candidate_matches =
            candidate_matches.saturating_add(usize::from(inspection.exact_artifact_match));
        if inspection.pending {
            model_pending = true;
            break;
        }
    }
    state.result.exact_artifact_matches = state
        .result
        .exact_artifact_matches
        .saturating_add(candidate_matches);
    if candidate_matches > 0 {
        state.result.alternatives.push(json!({
            "label":"header_only:fixed_layout",
            "status":GateStatus::ArtifactValidated.as_str(),
            "schema_model_ordinal":model_index.saturating_add(1),
            "exact_artifact_matches":candidate_matches,
            "header_model_bytes":plan.assembly_plan.retained_bytes(),
            "work_bytes":state.result.used_work.saturating_sub(model_work_start),
        }));
        return Ok(true);
    }
    Ok(model_pending)
}

fn evaluate_header_group(
    context: &SchemaScreenContext<'_>,
    plan: &HeaderSchemaPlan,
    state: &mut BoundHeaderEvaluation<'_, '_>,
    model_index: usize,
    group_index: usize,
) -> Result<Option<CandidateInspection>, RecoveryExecutionError> {
    let layout_id = state
        .bound
        .layout_id(model_index, group_index)
        .ok_or_else(|| invalid_policy("record gate model layout is missing"))?;
    let Some(inspection) = inspect_header_layout(context, plan, state, model_index, layout_id)?
    else {
        return Ok(None);
    };

    if inspection.exact_artifact_match && state.result.accepted_schema.is_none() {
        if !reserve_schema_work(
            &mut state.result.used_work,
            context.full_input_bytes,
            context.work_limit,
        )? {
            state.result.pending = true;
            state.result.work_limited = true;
            state.result.models_deferred_for_work =
                plan.assembly_plan.model_count().saturating_sub(model_index);
            return Ok(Some(CandidateInspection {
                pending: true,
                ..inspection
            }));
        }
        let receipt = state
            .bound
            .group_receipt(model_index, group_index)
            .map_err(|source| operational("record gate group receipt failed", source))?;
        let schema = plan
            .assembly_plan
            .model_schema(model_index)
            .cloned()
            .ok_or_else(|| invalid_policy("accepted record gate schema is missing"))?;
        state.result.accepted_schema = Some(accepted_record_schema(
            context,
            schema,
            RecordSchemaStrategy::FixedLayout,
            receipt,
            None,
        )?);
    }
    Ok(Some(inspection))
}

fn inspect_header_layout(
    context: &SchemaScreenContext<'_>,
    plan: &HeaderSchemaPlan,
    state: &mut BoundHeaderEvaluation<'_, '_>,
    model_index: usize,
    layout_id: usize,
) -> Result<Option<CandidateInspection>, RecoveryExecutionError> {
    if let Some(inspection) = state.layout_inspections.get(layout_id).copied().flatten() {
        state.result.layout_reuses = state.result.layout_reuses.saturating_add(1);
        return Ok(Some(inspection));
    }
    let output_length = state
        .bound
        .layout_output_length(layout_id)
        .ok_or_else(|| invalid_policy("record gate layout length is missing"))?;
    let copy_and_hash_work = output_length
        .checked_mul(2)
        .ok_or_else(|| invalid_policy("record gate layout work overflowed"))?;
    if !reserve_schema_work(
        &mut state.result.used_work,
        copy_and_hash_work,
        context.work_limit,
    )? {
        state.result.pending = true;
        state.result.work_limited = true;
        state.result.models_deferred_for_work =
            plan.assembly_plan.model_count().saturating_sub(model_index);
        return Ok(None);
    }
    let materialized = state
        .bound
        .materialize(layout_id)
        .map_err(|source| operational("record gate layout materialization failed", source))?;
    state.result.layouts_materialized = state.result.layouts_materialized.saturating_add(1);
    let candidate_bytes = materialized.bytes();
    if !reserve_schema_work(
        &mut state.result.used_work,
        candidate_bytes.len(),
        context.work_limit,
    )? {
        state.result.pending = true;
        state.result.work_limited = true;
        state.result.parser_omissions = state.result.parser_omissions.saturating_add(1);
        state.result.models_deferred_for_work =
            plan.assembly_plan.model_count().saturating_sub(model_index);
        return Ok(None);
    }
    let inspection =
        inspect_candidate_bytes(candidate_bytes, context, &mut state.result.used_work)?;
    state.result.work_limited |= inspection.work_limited.is_some();
    state.result.parser_omissions = state
        .result
        .parser_omissions
        .saturating_add(usize::from(inspection.parser_omission));
    if let Some(slot) = state.layout_inspections.get_mut(layout_id) {
        *slot = Some(inspection);
    }
    Ok(Some(inspection))
}

fn all_frame_indices(frame_count: usize) -> Result<Vec<usize>, RecoveryExecutionError> {
    let mut indices = Vec::new();
    indices.try_reserve_exact(frame_count).map_err(|source| {
        operational("record gate header frame index allocation failed", source)
    })?;
    indices.extend(0..frame_count);
    Ok(indices)
}

fn evaluate_plan_alternatives(
    frames: &[DecodedFrameOutput],
    parser_format: ArtifactValidationFormat,
    artifact_policy: ArtifactValidationPolicy,
    work_limit: usize,
    job: Option<&Job>,
    plan: &SchemaPlan,
    initial_work: usize,
) -> Result<(SchemaEvaluation, bool), RecoveryExecutionError> {
    let inputs = record_inputs(frames)?;
    let mut evaluation = SchemaEvaluation {
        used_work: initial_work,
        work_limited: plan.work_limited.then_some(WorkLimitHit),
        ..SchemaEvaluation::default()
    };
    if plan.alternatives.is_empty() {
        evaluation.pending = true;
    }
    let options = PlanScreenOptions {
        inputs: &inputs,
        parser_format,
        artifact_policy,
        work_limit,
        job,
    };
    let mut all_alternatives_contradicted = true;
    for alternative in &plan.alternatives {
        if alternative.status != GateStatus::Contradicted {
            all_alternatives_contradicted = false;
        }
        if evaluate_alternative(frames, alternative, &options, &mut evaluation)? {
            break;
        }
    }
    Ok((evaluation, all_alternatives_contradicted))
}

struct PlanScreenOptions<'a> {
    inputs: &'a [RecordInput<'a>],
    parser_format: ArtifactValidationFormat,
    artifact_policy: ArtifactValidationPolicy,
    work_limit: usize,
    job: Option<&'a Job>,
}

fn evaluate_alternative(
    frames: &[DecodedFrameOutput],
    alternative: &SchemaAlternative,
    options: &PlanScreenOptions<'_>,
    evaluation: &mut SchemaEvaluation,
) -> Result<bool, RecoveryExecutionError> {
    if let Some(job) = options.job {
        job.check_cancelled()?;
    }
    let before = EvaluationSnapshot::capture(evaluation);
    let Some(report) = alternative.discovery_report.as_ref() else {
        return Ok(evaluate_unreported_alternative(
            alternative,
            before,
            evaluation,
        ));
    };
    if alternative.omitted_learning_messages > 0 && alternative.observed.is_none() {
        record_incomplete_application(alternative, evaluation);
        return Ok(false);
    }
    let frame_indices = alternative_frame_indices(frames, alternative)?;
    let full_input_bytes = total_indexed_bytes(frames, &frame_indices)?;
    let context = SchemaScreenContext {
        frames,
        inputs: options.inputs,
        frame_indices: frame_indices.as_slice(),
        limits: alternative.limits,
        parser_format: options.parser_format,
        artifact_policy: options.artifact_policy,
        work_limit: options.work_limit,
        job: options.job,
        full_input_bytes,
    };
    let alt_result = if let Some(observed) = alternative.observed.as_ref() {
        accumulate_observed_evaluation(evaluation, observed);
        SchemaAlternativeEvaluation {
            exact_artifact_matches: observed.exact_artifact_matches,
            parser_omissions: observed.parser_omissions,
            schemas_checked: observed.schemas_checked,
            underdetermined_schemas: observed.underdetermined_schemas,
            variable_length_schemas: observed.variable_length_schemas,
            coherent_sequence_schemas: observed.coherent_sequence_schemas,
            sequence_conflict_schemas: observed.sequence_conflict_schemas,
            surviving_schemas: observed.surviving_schemas,
            work_bytes: observed.work_bytes,
            strict_survivors_seen: observed.strict_survivors_seen,
            exact_artifact_survivor_ordinal: observed.exact_artifact_survivor_ordinal,
            accepted_schema: observed.accepted_schema.clone(),
            work_limited: observed.work_limited,
            survives: observed.survives,
            pending: observed.pending,
            ..SchemaAlternativeEvaluation::default()
        }
    } else {
        evaluate_surviving_schemas(&context, report, evaluation)?
    };
    if evaluation.accepted_schema.is_none() {
        evaluation
            .accepted_schema
            .clone_from(&alt_result.accepted_schema);
    }
    let alternative_pending = alt_result.pending
        || report.omitted_survivors > 0
        || report
            .unexamined_combinations
            .is_some_and(|count| count > 0)
        || !alternative.proposal_search_exhaustive;
    evaluation.pending |= alternative_pending;
    if alt_result.work_limited {
        evaluation.work_limited = Some(WorkLimitHit);
    }
    // One corroborated schema is positive structural evidence even when other schemas remain unexamined
    record_structural_support(alternative, &alt_result, evaluation);
    let alternative_status = alternative_status(alternative, &alt_result, alternative_pending);
    evaluation.alternatives.push(alternative_details(
        alternative,
        report,
        &alt_result,
        before,
        evaluation,
        alternative_status,
    ));
    Ok(evaluation.exact_artifact_matches > before.matches)
}

fn evaluate_unreported_alternative(
    alternative: &SchemaAlternative,
    before: EvaluationSnapshot,
    evaluation: &mut SchemaEvaluation,
) -> bool {
    let Some(observed) = alternative.observed.as_ref() else {
        record_missing_report(alternative, evaluation);
        return false;
    };
    accumulate_observed_evaluation(evaluation, observed);
    if evaluation.accepted_schema.is_none() {
        evaluation
            .accepted_schema
            .clone_from(&observed.accepted_schema);
    }
    evaluation.pending = true;
    record_structural_support(alternative, observed, evaluation);
    let status = alternative_status(alternative, observed, true);
    evaluation.alternatives.push(json!({
        "label":alternative.label,
        "status":status.as_str(),
        "reason":"record_schema_analysis_incomplete",
        "schemas_checked":evaluation.schemas_checked.saturating_sub(before.checked),
        "schemas_structurally_supported":evaluation.surviving_schemas.saturating_sub(before.survivors),
        "exact_artifact_matches":evaluation.exact_artifact_matches.saturating_sub(before.matches),
        "parser_omissions":evaluation.parser_omissions.saturating_sub(before.omissions),
        "strict_survivors_observed":observed.strict_survivors_seen,
        "artifact_validating_survivor_ordinal":observed.exact_artifact_survivor_ordinal,
        "work_bytes":alternative.discovery_work_bytes,
        "analysis":alternative.details,
    }));
    evaluation.exact_artifact_matches > before.matches
}

fn record_missing_report(alternative: &SchemaAlternative, evaluation: &mut SchemaEvaluation) {
    evaluation.pending |= alternative.status == GateStatus::Pending;
    evaluation.alternatives.push(json!({
        "label":alternative.label,
        "training_message_count":alternative.learning_message_count,
        "held_out_message_count":alternative.heldout_message_count,
        "omitted_training_messages":alternative.omitted_learning_messages,
        "training_sessions":alternative.learning_session_count,
        "details":alternative.details,
    }));
}

fn record_incomplete_application(
    alternative: &SchemaAlternative,
    evaluation: &mut SchemaEvaluation,
) {
    evaluation.pending = true;
    evaluation.alternatives.push(json!({
        "label":alternative.label,
        "status":GateStatus::Pending.as_str(),
        "reason":"schema_full_application_incomplete",
        "omitted_training_messages":alternative.omitted_learning_messages,
        "training_message_count":alternative.learning_message_count,
        "held_out_message_count":alternative.heldout_message_count,
        "training_sessions":alternative.learning_session_count,
    }));
}

#[derive(Clone, Copy)]
struct EvaluationSnapshot {
    checked: usize,
    survivors: usize,
    matches: usize,
    omissions: usize,
    underdetermined: usize,
    variable_lengths: usize,
    coherent_sequences: usize,
    sequence_conflicts: usize,
    work: usize,
}

impl EvaluationSnapshot {
    const fn capture(evaluation: &SchemaEvaluation) -> Self {
        Self {
            checked: evaluation.schemas_checked,
            survivors: evaluation.surviving_schemas,
            matches: evaluation.exact_artifact_matches,
            omissions: evaluation.parser_omissions,
            underdetermined: evaluation.underdetermined_schemas,
            variable_lengths: evaluation.variable_length_schemas,
            coherent_sequences: evaluation.coherent_sequence_schemas,
            sequence_conflicts: evaluation.sequence_conflict_schemas,
            work: evaluation.used_work,
        }
    }
}

const fn record_structural_support(
    alternative: &SchemaAlternative,
    result: &SchemaAlternativeEvaluation,
    evaluation: &mut SchemaEvaluation,
) {
    if result.survives {
        if alternative.frame_indices.is_none() {
            evaluation.uniform_structural_support = true;
        } else {
            evaluation.family_structural_support = true;
        }
    }
}

fn alternative_details(
    alternative: &SchemaAlternative,
    report: &RecordSchemaDiscoveryReport,
    result: &SchemaAlternativeEvaluation,
    before: EvaluationSnapshot,
    evaluation: &SchemaEvaluation,
    status: GateStatus,
) -> Value {
    json!({
        "label":alternative.label,
        "status":status.as_str(),
        "schemas_checked":evaluation.schemas_checked.saturating_sub(before.checked),
        "schemas_structurally_supported":evaluation.surviving_schemas.saturating_sub(before.survivors),
        "underdetermined_schemas":evaluation.underdetermined_schemas.saturating_sub(before.underdetermined),
        "variable_length_schemas":evaluation.variable_length_schemas.saturating_sub(before.variable_lengths),
        "coherent_sequence_schemas":evaluation.coherent_sequence_schemas.saturating_sub(before.coherent_sequences),
        "sequence_conflict_schemas":evaluation.sequence_conflict_schemas.saturating_sub(before.sequence_conflicts),
        "exact_artifact_matches":evaluation.exact_artifact_matches.saturating_sub(before.matches),
        "parser_omissions":evaluation.parser_omissions.saturating_sub(before.omissions),
        "omitted_schema_survivors":report.omitted_survivors,
        "strict_survivors_observed":result.strict_survivors_seen,
        "artifact_validating_survivor_ordinal":result.exact_artifact_survivor_ordinal,
        "work_bytes":alternative.observed.as_ref().map_or_else(
            || evaluation.used_work.saturating_sub(before.work),
            |observed| observed.work_bytes,
        ),
        "training_message_count":alternative.learning_message_count,
        "held_out_message_count":alternative.heldout_message_count,
        "omitted_training_messages":alternative.omitted_learning_messages,
        "training_sessions":alternative.learning_session_count,
    })
}

const fn accumulate_observed_evaluation(
    evaluation: &mut SchemaEvaluation,
    observed: &SchemaAlternativeEvaluation,
) {
    evaluation.exact_artifact_matches = evaluation
        .exact_artifact_matches
        .saturating_add(observed.exact_artifact_matches);
    evaluation.parser_omissions = evaluation
        .parser_omissions
        .saturating_add(observed.parser_omissions);
    evaluation.schemas_checked = evaluation
        .schemas_checked
        .saturating_add(observed.schemas_checked);
    evaluation.underdetermined_schemas = evaluation
        .underdetermined_schemas
        .saturating_add(observed.underdetermined_schemas);
    evaluation.variable_length_schemas = evaluation
        .variable_length_schemas
        .saturating_add(observed.variable_length_schemas);
    evaluation.coherent_sequence_schemas = evaluation
        .coherent_sequence_schemas
        .saturating_add(observed.coherent_sequence_schemas);
    evaluation.sequence_conflict_schemas = evaluation
        .sequence_conflict_schemas
        .saturating_add(observed.sequence_conflict_schemas);
    evaluation.surviving_schemas = evaluation
        .surviving_schemas
        .saturating_add(observed.surviving_schemas);
    if observed.work_limited {
        evaluation.work_limited = Some(WorkLimitHit);
    }
    evaluation.pending |= observed.pending;
}

const fn alternative_status(
    alternative: &SchemaAlternative,
    evaluation: &SchemaAlternativeEvaluation,
    pending: bool,
) -> GateStatus {
    if evaluation.exact_artifact_matches > 0 {
        GateStatus::ArtifactValidated
    } else if evaluation.survives {
        GateStatus::StructurallySupported
    } else if pending {
        GateStatus::Pending
    } else {
        alternative.status
    }
}

fn plan_work_bytes(plan: &SchemaPlan) -> usize {
    plan.alternatives
        .iter()
        .map(|alternative| alternative.discovery_work_bytes)
        .fold(plan.observation_work_bytes, usize::saturating_add)
}

fn pending_work_result(
    requested_work: usize,
    work_limit: usize,
    cache_hit: bool,
    plan: &SchemaPlan,
) -> GateResult {
    let mut result = result(
        GateStatus::Pending,
        work_limit,
        json!({
            "reason":"record_schema_work_limit",
            "schema_plan_cache_hit":cache_hit,
            "schema_work_bytes":requested_work,
            "work_limit":work_limit,
            "schema_plan":plan.details,
        }),
    );
    result.work_limited_at = Some(work_limit);
    result.assessment_scope = plan.assessment_scope;
    result
}

fn all_frames_have_preserved_headers(frames: &[DecodedFrameOutput]) -> bool {
    !frames.is_empty()
        && frames.iter().all(|frame| {
            frame
                .preserved_header_end
                .is_some_and(|prefix_end| prefix_end > 0)
        })
}

fn alternative_frame_indices(
    frames: &[DecodedFrameOutput],
    alternative: &SchemaAlternative,
) -> Result<Vec<usize>, RecoveryExecutionError> {
    if let Some(indices) = &alternative.frame_indices {
        for index in indices.iter() {
            if frames.get(*index).is_none() {
                return Err(invalid_policy(
                    "record gate alternative references a missing frame",
                ));
            }
        }
        return Ok(indices.to_vec());
    }
    let mut indices = Vec::new();
    indices
        .try_reserve_exact(frames.len())
        .map_err(|source| operational("record gate frame index allocation failed", source))?;
    indices.extend(0..frames.len());
    Ok(indices)
}

fn total_indexed_bytes(
    frames: &[DecodedFrameOutput],
    indices: &[usize],
) -> Result<usize, RecoveryExecutionError> {
    indices.iter().try_fold(0_usize, |total, index| {
        let frame = frames
            .get(*index)
            .ok_or_else(|| invalid_policy("record gate alternative references a missing frame"))?;
        total
            .checked_add(frame.bytes.len())
            .ok_or_else(|| invalid_policy("record gate input byte count overflowed"))
    })
}

pub(super) struct SchemaScreenContext<'a> {
    pub(super) frames: &'a [DecodedFrameOutput],
    pub(super) inputs: &'a [RecordInput<'a>],
    pub(super) frame_indices: &'a [usize],
    pub(super) limits: RecordSchemaProposalLimits,
    pub(super) parser_format: ArtifactValidationFormat,
    pub(super) artifact_policy: ArtifactValidationPolicy,
    pub(super) work_limit: usize,
    pub(super) job: Option<&'a Job>,
    pub(super) full_input_bytes: usize,
}

fn evaluate_surviving_schemas(
    context: &SchemaScreenContext<'_>,
    report: &RecordSchemaDiscoveryReport,
    evaluation: &mut SchemaEvaluation,
) -> Result<SchemaAlternativeEvaluation, RecoveryExecutionError> {
    let mut alternative = SchemaAlternativeEvaluation::default();
    for (index, hypothesis) in report.surviving.iter().enumerate() {
        if let Some(job) = context.job {
            job.check_cancelled()?;
        }
        let result = evaluate_hypothesis(context, hypothesis, &mut evaluation.used_work)?;
        evaluation.exact_artifact_matches = evaluation
            .exact_artifact_matches
            .saturating_add(result.exact_artifact_matches);
        alternative.exact_artifact_matches = alternative
            .exact_artifact_matches
            .saturating_add(result.exact_artifact_matches);
        evaluation.parser_omissions = evaluation
            .parser_omissions
            .saturating_add(result.parser_omissions);
        alternative.parser_omissions = alternative
            .parser_omissions
            .saturating_add(result.parser_omissions);
        evaluation.schemas_checked = evaluation
            .schemas_checked
            .saturating_add(usize::from(result.evidence.was_parsed()));
        evaluation.underdetermined_schemas = evaluation
            .underdetermined_schemas
            .saturating_add(usize::from(result.evidence.is_underdetermined()));
        evaluation.variable_length_schemas = evaluation
            .variable_length_schemas
            .saturating_add(usize::from(result.evidence.has_variable_length_relation()));
        evaluation.coherent_sequence_schemas =
            evaluation
                .coherent_sequence_schemas
                .saturating_add(usize::from(
                    result.evidence.has_coherent_sequence_relation(),
                ));
        evaluation.sequence_conflict_schemas = evaluation
            .sequence_conflict_schemas
            .saturating_add(usize::from(result.evidence.has_sequence_conflict()));
        evaluation.surviving_schemas = evaluation
            .surviving_schemas
            .saturating_add(usize::from(result.evidence.is_supported()));
        alternative.survives |= result.evidence.is_supported();
        if result.work_limited {
            evaluation.work_limited = Some(WorkLimitHit);
        }
        alternative.work_limited |= result.work_limited;
        evaluation.pending |= result.pending;
        alternative.pending |= result.pending;
        if result.exact_artifact_matches > 0 {
            break;
        }
        if evaluation.used_work >= context.work_limit && index + 1 < report.surviving.len() {
            evaluation.pending = true;
            evaluation.work_limited = Some(WorkLimitHit);
            alternative.pending = true;
            alternative.work_limited = true;
            break;
        }
    }
    Ok(alternative)
}

pub(super) fn observe_surviving_schema(
    context: &SchemaScreenContext<'_>,
    strategy: RecordSchemaStrategy,
    hypothesis: &RecordSchemaHypothesis,
    inputs: &SurvivingSchemaInputs<'_>,
    observer_work: &mut usize,
    evaluation: &mut SchemaAlternativeEvaluation,
) -> Result<std::ops::ControlFlow<()>, RecoveryExecutionError> {
    if let Some(job) = context.job {
        job.check_cancelled()?;
    }
    let before_work = *observer_work;
    let mut parser_work = RecordWorkBudget::new(context.work_limit.saturating_sub(before_work));
    let completed = complete_application_reports(context, hypothesis, inputs, &mut parser_work);
    reserve_schema_work(observer_work, parser_work.consumed(), context.work_limit)?;
    let completed_reports = match completed? {
        FullApplicationReports::Complete(reports) => reports,
        FullApplicationReports::Contradicted => {
            finish_observer_work(evaluation, *observer_work, before_work);
            return Ok(std::ops::ControlFlow::Continue(()));
        }
        FullApplicationReports::WorkLimit => {
            evaluation.pending = true;
            evaluation.work_limited = true;
            finish_observer_work(evaluation, *observer_work, before_work);
            return Ok(std::ops::ControlFlow::Break(()));
        }
        FullApplicationReports::Omitted => {
            evaluation.pending = true;
            finish_observer_work(evaluation, *observer_work, before_work);
            return Ok(std::ops::ControlFlow::Continue(()));
        }
    };
    if strategy == RecordSchemaStrategy::FixedLayout
        && let Some(model) = capture_header_model(
            context,
            hypothesis,
            &completed_reports,
            observer_work,
            &mut evaluation.work_limited,
        )?
    {
        let next_bytes = evaluation
            .header_model_bytes
            .checked_add(model.retained_bytes)
            .ok_or_else(|| invalid_policy("record gate header model size overflowed"))?;
        if next_bytes <= context.limits.discovery.record_limits.max_report_bytes {
            evaluation
                .header_models
                .try_reserve_exact(1)
                .map_err(|source| {
                    operational("record gate header model allocation failed", source)
                })?;
            evaluation.header_models.push(model);
            evaluation.header_model_bytes = next_bytes;
        } else {
            evaluation.header_models_omitted = evaluation.header_models_omitted.saturating_add(1);
        }
    }
    let mut report_references = Vec::new();
    report_references
        .try_reserve_exact(completed_reports.len())
        .map_err(|source| operational("record gate parse reference allocation failed", source))?;
    report_references.extend(completed_reports.iter().map(Cow::as_ref));
    let result = evaluate_hypothesis_reports(context, &report_references, observer_work)?;
    let artifact_validated = result.exact_artifact_matches > 0;
    finish_observer_work(evaluation, *observer_work, before_work);
    accumulate_hypothesis_result(
        context,
        strategy,
        hypothesis,
        result,
        &report_references,
        evaluation,
    )?;
    Ok(if artifact_validated {
        std::ops::ControlFlow::Break(())
    } else {
        std::ops::ControlFlow::Continue(())
    })
}

fn capture_header_model(
    context: &SchemaScreenContext<'_>,
    hypothesis: &RecordSchemaHypothesis,
    reports: &[Cow<'_, RecordParseReport>],
    observer_work: &mut usize,
    work_limited: &mut bool,
) -> Result<Option<HeaderSchemaModel>, RecoveryExecutionError> {
    let inputs = context.inputs;
    if inputs.len() != context.frames.len()
        || context.frame_indices.len() != context.frames.len()
        || context
            .frame_indices
            .iter()
            .copied()
            .ne(0..context.frames.len())
        || reports.len() != context.frame_indices.len()
    {
        return Ok(None);
    }

    let mut estimated_bytes = std::mem::size_of::<HeaderSchemaModel>()
        .saturating_add(context.frames.len() * std::mem::size_of::<(usize, HeaderParseTemplate)>());
    for (frame_index, report) in context.frame_indices.iter().zip(reports) {
        let frame = context
            .frames
            .get(*frame_index)
            .ok_or_else(|| invalid_policy("record gate header model frame is missing"))?;
        let Some(prefix_end) = frame.preserved_header_end else {
            return Ok(None);
        };
        if prefix_end == 0 || report.schema() != &hypothesis.schema {
            return Ok(None);
        }
        estimated_bytes = estimated_bytes
            .saturating_add(std::mem::size_of::<HeaderParseTemplate>())
            .saturating_add(prefix_end)
            .saturating_add(report.metadata_bytes());
    }
    if estimated_bytes > context.limits.discovery.record_limits.max_report_bytes {
        return Ok(None);
    }
    // Header templates copy exact prefixes and parser metadata only after the shared gate reserves the cost
    if !reserve_schema_work(observer_work, estimated_bytes, context.work_limit)? {
        *work_limited = true;
        return Ok(None);
    }

    let mut templates = Vec::new();
    if templates.try_reserve_exact(context.frames.len()).is_err() {
        return Ok(None);
    }
    for (frame_index, report) in context.frame_indices.iter().zip(reports) {
        let frame = context
            .frames
            .get(*frame_index)
            .ok_or_else(|| invalid_policy("record gate header template frame is missing"))?;
        let prefix_end = frame
            .preserved_header_end
            .ok_or_else(|| invalid_policy("record gate header template lost its prefix"))?;
        let input = inputs
            .get(*frame_index)
            .ok_or_else(|| invalid_policy("record gate header template input is missing"))?;
        let Ok(Some(template)) =
            report.header_only_template(input, prefix_end, context.limits.discovery.record_limits)
        else {
            return Ok(None);
        };
        templates.push((*frame_index, template));
    }
    Ok(Some(HeaderSchemaModel::with_templates(
        hypothesis.schema.clone(),
        context.limits.discovery.record_limits,
        templates,
    )?))
}

enum FullApplicationReports<'a> {
    Complete(Vec<Cow<'a, RecordParseReport>>),
    Contradicted,
    WorkLimit,
    Omitted,
}

fn complete_application_reports<'reports>(
    context: &SchemaScreenContext<'_>,
    hypothesis: &RecordSchemaHypothesis,
    inputs: &SurvivingSchemaInputs<'reports>,
    work: &mut RecordWorkBudget,
) -> Result<FullApplicationReports<'reports>, RecoveryExecutionError> {
    let mut totals = RecordReportTotals::default();
    let training = match complete_reports(
        context,
        inputs.selected_training_indices,
        inputs.training_reports,
        inputs.all_training_indices,
        hypothesis,
        &mut totals,
        work,
    )? {
        CompleteReports::Complete(reports) => reports,
        CompleteReports::Contradicted => return Ok(FullApplicationReports::Contradicted),
        CompleteReports::WorkLimit => return Ok(FullApplicationReports::WorkLimit),
        CompleteReports::Omitted => return Ok(FullApplicationReports::Omitted),
    };
    let heldout = match complete_reports(
        context,
        inputs.selected_heldout_indices,
        inputs.heldout_reports,
        inputs.all_heldout_indices,
        hypothesis,
        &mut totals,
        work,
    )? {
        CompleteReports::Complete(reports) => reports,
        CompleteReports::Contradicted => return Ok(FullApplicationReports::Contradicted),
        CompleteReports::WorkLimit => return Ok(FullApplicationReports::WorkLimit),
        CompleteReports::Omitted => return Ok(FullApplicationReports::Omitted),
    };
    let report_count = training
        .len()
        .checked_add(heldout.len())
        .ok_or_else(|| invalid_policy("record gate full parse report count overflowed"))?;
    let mut indexed_reports = Vec::new();
    indexed_reports
        .try_reserve_exact(report_count)
        .map_err(|source| operational("record gate ordered report allocation failed", source))?;
    indexed_reports.extend(inputs.all_training_indices.iter().copied().zip(training));
    indexed_reports.extend(inputs.all_heldout_indices.iter().copied().zip(heldout));
    indexed_reports.sort_unstable_by_key(|(index, _)| *index);
    if indexed_reports
        .iter()
        .map(|(index, _)| *index)
        .ne(context.frame_indices.iter().copied())
    {
        return Err(invalid_policy(
            "record gate full application frame order differs from parse reports",
        ));
    }
    Ok(FullApplicationReports::Complete(
        indexed_reports
            .into_iter()
            .map(|(_, report)| report)
            .collect(),
    ))
}

fn accumulate_hypothesis_result(
    context: &SchemaScreenContext<'_>,
    strategy: RecordSchemaStrategy,
    hypothesis: &RecordSchemaHypothesis,
    result: HypothesisEvaluation,
    parse_reports: &[&RecordParseReport],
    evaluation: &mut SchemaAlternativeEvaluation,
) -> Result<(), RecoveryExecutionError> {
    evaluation.exact_artifact_matches = evaluation
        .exact_artifact_matches
        .saturating_add(result.exact_artifact_matches);
    evaluation.parser_omissions = evaluation
        .parser_omissions
        .saturating_add(result.parser_omissions);
    evaluation.schemas_checked = evaluation
        .schemas_checked
        .saturating_add(usize::from(result.evidence.was_parsed()));
    evaluation.underdetermined_schemas = evaluation
        .underdetermined_schemas
        .saturating_add(usize::from(result.evidence.is_underdetermined()));
    evaluation.variable_length_schemas = evaluation
        .variable_length_schemas
        .saturating_add(usize::from(result.evidence.has_variable_length_relation()));
    evaluation.coherent_sequence_schemas =
        evaluation
            .coherent_sequence_schemas
            .saturating_add(usize::from(
                result.evidence.has_coherent_sequence_relation(),
            ));
    evaluation.sequence_conflict_schemas = evaluation
        .sequence_conflict_schemas
        .saturating_add(usize::from(result.evidence.has_sequence_conflict()));
    evaluation.surviving_schemas = evaluation
        .surviving_schemas
        .saturating_add(usize::from(result.evidence.is_supported()));
    evaluation.work_limited |= result.work_limited;
    if result.exact_artifact_matches > 0 {
        let receipt = result
            .accepted_receipt
            .ok_or_else(|| invalid_policy("validated artifact has no record assembly receipt"))?;
        evaluation.accepted_schema = Some(accepted_record_schema(
            context,
            hypothesis.schema.clone(),
            strategy,
            receipt,
            Some(parse_reports),
        )?);
    }
    evaluation.survives |= result.evidence.is_supported();
    evaluation.pending |= result.pending;
    Ok(())
}

const fn finish_observer_work(
    evaluation: &mut SchemaAlternativeEvaluation,
    observer_work: usize,
    before_work: usize,
) {
    evaluation.work_bytes = evaluation
        .work_bytes
        .saturating_add(observer_work.saturating_sub(before_work));
}

fn accepted_record_schema(
    context: &SchemaScreenContext<'_>,
    schema: RecordSchema,
    strategy: RecordSchemaStrategy,
    artifact_receipt: RecordGroupReceipt,
    parse_reports: Option<&[&RecordParseReport]>,
) -> Result<AcceptedRecordSchema, RecoveryExecutionError> {
    if artifact_receipt.output_length.is_none() || artifact_receipt.output_sha256.is_none() {
        return Err(invalid_policy(
            "validated artifact record receipt is incomplete",
        ));
    }
    let mut frame_indices = Vec::new();
    frame_indices
        .try_reserve_exact(context.frame_indices.len())
        .map_err(|source| operational("accepted schema frame index allocation failed", source))?;
    let mut frame_identities = Vec::new();
    frame_identities
        .try_reserve_exact(context.frame_indices.len())
        .map_err(|source| {
            operational("accepted schema frame identity allocation failed", source)
        })?;
    if parse_reports.is_some_and(|reports| reports.len() != context.frame_indices.len()) {
        return Err(invalid_policy(
            "accepted schema parse report count differs from its frames",
        ));
    }
    for frame_index in context.frame_indices {
        let frame_position = frame_indices.len();
        let frame = context
            .frames
            .get(*frame_index)
            .ok_or_else(|| invalid_policy("accepted schema frame identity is missing"))?;
        frame_indices.push(*frame_index);
        frame_identities.push(AcceptedFrameIdentity {
            frame_index: *frame_index,
            input_node_id: frame.input_node_id,
            context: frame.context.clone(),
            session_order: frame.session_order,
            stream_offset: frame.stream_offset,
            frame_byte_length: frame.bytes.len(),
            frame_bytes_sha256: if let Some(reports) = parse_reports {
                let report = reports
                    .get(frame_position)
                    .ok_or_else(|| invalid_policy("accepted schema parse report is missing"))?;
                if report.input_length() != frame.bytes.len() || report.schema() != &schema {
                    return Err(invalid_policy(
                        "accepted schema parse report changed before receipt creation",
                    ));
                }
                report.input_sha256().to_owned()
            } else {
                l2_workbench::sha256(&frame.bytes)
            },
        });
    }
    Ok(AcceptedRecordSchema {
        schema,
        strategy,
        frame_indices,
        frame_identities,
        artifact_receipt,
        artifact_format: context.parser_format,
    })
}

#[derive(Default)]
struct RecordReportTotals {
    records: usize,
    metadata_bytes: usize,
}

impl RecordReportTotals {
    fn include(
        &mut self,
        report: &RecordParseReport,
        limits: l2_workbench::protocol::RecordLimits,
    ) -> bool {
        let Some(records) = self.records.checked_add(report.records().len()) else {
            return false;
        };
        let Some(metadata_bytes) = self.metadata_bytes.checked_add(report.metadata_bytes()) else {
            return false;
        };
        if records > limits.max_records || metadata_bytes > limits.max_report_bytes {
            return false;
        }
        self.records = records;
        self.metadata_bytes = metadata_bytes;
        true
    }
}

enum CompleteReports<'a> {
    Complete(Vec<Cow<'a, RecordParseReport>>),
    Contradicted,
    WorkLimit,
    Omitted,
}

enum HypothesisParseReports {
    Complete(Vec<RecordParseReport>),
    Contradicted,
    WorkLimit,
    Omitted,
}

fn complete_reports<'reports>(
    context: &SchemaScreenContext<'_>,
    selected_indices: &[usize],
    selected_reports: &'reports [RecordParseReport],
    all_indices: &[usize],
    hypothesis: &RecordSchemaHypothesis,
    totals: &mut RecordReportTotals,
    work: &mut RecordWorkBudget,
) -> Result<CompleteReports<'reports>, RecoveryExecutionError> {
    if context.full_input_bytes > context.limits.discovery.record_limits.max_input_bytes {
        return Ok(CompleteReports::Omitted);
    }
    if selected_indices.len() != selected_reports.len() {
        return Err(invalid_policy(
            "record gate selected frame and parser report counts differ",
        ));
    }
    let mut selected_by_index = HashMap::new();
    selected_by_index
        .try_reserve(selected_indices.len())
        .map_err(|source| operational("record gate selected report allocation failed", source))?;
    for (index, report) in selected_indices.iter().copied().zip(selected_reports) {
        if selected_by_index.insert(index, report).is_some() {
            return Err(invalid_policy("record gate selected frame is repeated"));
        }
    }
    let mut reports = Vec::new();
    reports
        .try_reserve_exact(all_indices.len())
        .map_err(|source| operational("record gate full parse report allocation failed", source))?;
    for index in all_indices {
        let report = if let Some(report) = selected_by_index.remove(index) {
            Cow::Borrowed(report)
        } else {
            if let Some(job) = context.job {
                job.check_cancelled()?;
            }
            let input = context
                .inputs
                .get(*index)
                .ok_or_else(|| invalid_policy("record gate full application input is missing"))?;
            match input.parse_with_work(
                &hypothesis.schema,
                context.limits.discovery.record_limits,
                work,
            ) {
                Ok(report) => Cow::Owned(report),
                Err(
                    RecordError::InputTooLarge { .. }
                    | RecordError::TooManyRecords { .. }
                    | RecordError::ReportTooLarge { .. }
                    | RecordError::AllocationFailed,
                ) => return Ok(CompleteReports::Omitted),
                Err(RecordError::WorkLimitExceeded { .. }) => {
                    return Ok(CompleteReports::WorkLimit);
                }
                Err(_) => {
                    if let Some(job) = context.job {
                        job.increment(Counter::CandidatesRejected, 1)?;
                    }
                    return Ok(CompleteReports::Contradicted);
                }
            }
        };
        if !totals.include(&report, context.limits.discovery.record_limits) {
            return Ok(CompleteReports::Omitted);
        }
        reports.push(report);
    }
    if !selected_by_index.is_empty() {
        return Err(invalid_policy(
            "record gate selected parser report is outside full application frames",
        ));
    }
    Ok(CompleteReports::Complete(reports))
}

fn reserve_schema_work(
    used_work: &mut usize,
    requested_work: usize,
    work_limit: usize,
) -> Result<bool, RecoveryExecutionError> {
    if requested_work > work_limit.saturating_sub(*used_work) {
        return Ok(false);
    }
    *used_work = used_work
        .checked_add(requested_work)
        .ok_or_else(|| invalid_policy("record gate work count overflowed"))?;
    Ok(true)
}

fn evaluate_hypothesis(
    context: &SchemaScreenContext<'_>,
    hypothesis: &RecordSchemaHypothesis,
    used_work: &mut usize,
) -> Result<HypothesisEvaluation, RecoveryExecutionError> {
    let mut parser_work = RecordWorkBudget::new(context.work_limit.saturating_sub(*used_work));
    let parsed = parse_hypothesis_frames(context, hypothesis, &mut parser_work);
    reserve_schema_work(used_work, parser_work.consumed(), context.work_limit)?;
    let parse_reports = match parsed? {
        HypothesisParseReports::Complete(reports) => reports,
        HypothesisParseReports::Contradicted => return Ok(HypothesisEvaluation::default()),
        HypothesisParseReports::WorkLimit => {
            return Ok(HypothesisEvaluation {
                pending: true,
                parser_omissions: 1,
                work_limited: true,
                ..HypothesisEvaluation::default()
            });
        }
        HypothesisParseReports::Omitted => {
            return Ok(HypothesisEvaluation {
                pending: true,
                parser_omissions: 1,
                ..HypothesisEvaluation::default()
            });
        }
    };
    let mut report_references = Vec::new();
    report_references
        .try_reserve_exact(parse_reports.len())
        .map_err(|source| operational("record gate parse reference allocation failed", source))?;
    report_references.extend(&parse_reports);
    evaluate_hypothesis_reports(context, &report_references, used_work)
}

fn evaluate_hypothesis_reports(
    context: &SchemaScreenContext<'_>,
    parse_reports: &[&RecordParseReport],
    used_work: &mut usize,
) -> Result<HypothesisEvaluation, RecoveryExecutionError> {
    let assembly_work = assembly_work_bytes(parse_reports)?;
    if !reserve_schema_work(used_work, assembly_work, context.work_limit)? {
        return Ok(HypothesisEvaluation {
            pending: true,
            parser_omissions: 1,
            work_limited: true,
            ..HypothesisEvaluation::default()
        });
    }
    let Some(assembly) = assemble_hypothesis(context, parse_reports)? else {
        return Ok(HypothesisEvaluation {
            pending: true,
            ..HypothesisEvaluation::default()
        });
    };
    let mut result = inspect_assembly(context, &assembly, used_work)?;
    if result.exact_artifact_matches > 0 {
        result.evidence = HypothesisEvidence::ArtifactValidated;
        return Ok(result);
    }

    let variable_length_relation = has_variable_record_lengths(context, parse_reports)?;
    let sequence_conflict = has_sequence_conflicts(context, parse_reports, &assembly)?;
    let coherent_sequence_relation =
        !sequence_conflict && has_coherent_sequence_relation(context, &assembly)?;
    result.evidence = if variable_length_relation && sequence_conflict {
        HypothesisEvidence::VariableLengthWithSequenceConflict
    } else if variable_length_relation {
        HypothesisEvidence::VariableLength
    } else if sequence_conflict {
        HypothesisEvidence::SequenceConflict
    } else if coherent_sequence_relation {
        HypothesisEvidence::CoherentSequence
    } else {
        HypothesisEvidence::ParserOnly
    };
    result.pending |= result.evidence.is_underdetermined();
    Ok(result)
}

fn parse_hypothesis_frames(
    context: &SchemaScreenContext<'_>,
    hypothesis: &RecordSchemaHypothesis,
    work: &mut RecordWorkBudget,
) -> Result<HypothesisParseReports, RecoveryExecutionError> {
    let mut reports = Vec::new();
    reports
        .try_reserve_exact(context.frame_indices.len())
        .map_err(|source| operational("record gate parse report allocation failed", source))?;
    for frame_index in context.frame_indices {
        let input = context
            .inputs
            .get(*frame_index)
            .ok_or_else(|| invalid_policy("record gate alternative input is missing"))?;
        let parsed = match input.parse_with_work(
            &hypothesis.schema,
            context.limits.discovery.record_limits,
            work,
        ) {
            Ok(parsed) => parsed,
            Err(RecordError::WorkLimitExceeded { .. }) => {
                return Ok(HypothesisParseReports::WorkLimit);
            }
            Err(
                RecordError::InputTooLarge { .. }
                | RecordError::TooManyRecords { .. }
                | RecordError::ReportTooLarge { .. }
                | RecordError::AllocationFailed,
            ) => return Ok(HypothesisParseReports::Omitted),
            Err(_) => {
                if let Some(job) = context.job {
                    job.increment(Counter::CandidatesRejected, 1)?;
                }
                return Ok(HypothesisParseReports::Contradicted);
            }
        };
        reports.push(parsed);
    }
    Ok(HypothesisParseReports::Complete(reports))
}

fn assembly_work_bytes(
    parse_reports: &[&RecordParseReport],
) -> Result<usize, RecoveryExecutionError> {
    let mut metadata_bytes = 0_usize;
    let mut output_bytes = 0_usize;
    for report in parse_reports {
        metadata_bytes = metadata_bytes
            .checked_add(report.metadata_bytes())
            .ok_or_else(|| invalid_policy("record gate assembly metadata work overflowed"))?;
        for record in report.records() {
            output_bytes = output_bytes
                .checked_add(record.payload.end.saturating_sub(record.payload.start))
                .ok_or_else(|| invalid_policy("record gate assembly output work overflowed"))?;
        }
    }
    metadata_bytes
        .checked_add(
            output_bytes
                .checked_mul(2)
                .ok_or_else(|| invalid_policy("record gate assembly output work overflowed"))?,
        )
        .ok_or_else(|| invalid_policy("record gate assembly work overflowed"))
}

fn assemble_hypothesis(
    context: &SchemaScreenContext<'_>,
    parse_reports: &[&RecordParseReport],
) -> Result<Option<RecordAssemblyOutcome>, RecoveryExecutionError> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(context.frame_indices.len())
        .map_err(|source| operational("record gate assembly input allocation failed", source))?;
    if parse_reports.len() != context.frame_indices.len() {
        return Err(invalid_policy(
            "record gate parser report count differs from inputs",
        ));
    }
    for (frame_index, parsed) in context.frame_indices.iter().zip(parse_reports) {
        let input = context
            .inputs
            .get(*frame_index)
            .ok_or_else(|| invalid_policy("record gate assembly input is missing"))?;
        inputs.push(
            RecordAssemblyInput::from_input(input, parsed)
                .map_err(|source| operational("record gate input identity changed", source))?,
        );
    }
    Ok(assemble_record_groups_from_inputs(&inputs, context.limits.discovery.record_limits).ok())
}

fn inspect_assembly(
    context: &SchemaScreenContext<'_>,
    assembly: &RecordAssemblyOutcome,
    used_work: &mut usize,
) -> Result<HypothesisEvaluation, RecoveryExecutionError> {
    let mut result = HypothesisEvaluation::default();
    for group in assembly.report().groups {
        let inspection = inspect_candidate_bytes(group.candidate_bytes(), context, used_work)?;
        if inspection.exact_artifact_match && result.accepted_receipt.is_none() {
            let receipt = group.receipt();
            if receipt.output_length != Some(group.candidate_bytes().len())
                || receipt.output_sha256.is_none()
            {
                return Err(invalid_policy(
                    "validated artifact record receipt does not match its output",
                ));
            }
            result.accepted_receipt = Some(receipt.clone());
        }
        result.exact_artifact_matches = result
            .exact_artifact_matches
            .saturating_add(usize::from(inspection.exact_artifact_match));
        result.parser_omissions = result
            .parser_omissions
            .saturating_add(usize::from(inspection.parser_omission));
        result.work_limited |= inspection.work_limited.is_some();
        result.pending |= inspection.pending;
        if inspection.pending {
            break;
        }
    }
    Ok(result)
}

fn has_variable_record_lengths(
    context: &SchemaScreenContext<'_>,
    parse_reports: &[&RecordParseReport],
) -> Result<bool, RecoveryExecutionError> {
    let mut session_lengths = BTreeMap::<u64, (usize, usize)>::new();
    for (frame_index, parsed) in context.frame_indices.iter().zip(parse_reports) {
        let frame = context
            .frames
            .get(*frame_index)
            .ok_or_else(|| invalid_policy("record gate alternative references a missing frame"))?;
        for record in parsed.records() {
            let record_length = record
                .record
                .end
                .checked_sub(record.record.start)
                .ok_or_else(|| invalid_policy("parsed record range is inverted"))?;
            let lengths = session_lengths
                .entry(frame.context.session)
                .or_insert((record_length, record_length));
            lengths.0 = lengths.0.min(record_length);
            lengths.1 = lengths.1.max(record_length);
        }
    }
    if session_lengths.len() < 2 {
        return Ok(false);
    }

    let mut common_length = None;
    for (minimum, maximum) in session_lengths.values() {
        if minimum != maximum || common_length.is_some_and(|length| length != *minimum) {
            return Ok(true);
        }
        common_length = Some(*minimum);
    }
    Ok(false)
}

fn has_coherent_sequence_relation(
    context: &SchemaScreenContext<'_>,
    assembly: &RecordAssemblyOutcome,
) -> Result<bool, RecoveryExecutionError> {
    for group in assembly.report().groups {
        let receipt = group.receipt();
        if receipt.record_count < 2
            || receipt.minimum_sequence == receipt.maximum_sequence
            || receipt.parts.len() != receipt.record_count
        {
            continue;
        }

        let mut first_session = None;
        let mut spans_sessions = false;
        for part in &receipt.parts {
            let frame_index = context
                .frame_indices
                .get(part.input_index)
                .ok_or_else(|| invalid_policy("record gate assembly references a missing input"))?;
            let frame = context
                .frames
                .get(*frame_index)
                .ok_or_else(|| invalid_policy("record gate assembly references a missing frame"))?;
            if let Some(session) = first_session {
                spans_sessions |= session != frame.context.session;
            } else {
                first_session = Some(frame.context.session);
            }
        }
        if spans_sessions {
            return Ok(true);
        }
    }
    Ok(false)
}

fn has_sequence_conflicts(
    context: &SchemaScreenContext<'_>,
    parse_reports: &[&RecordParseReport],
    assembly: &RecordAssemblyOutcome,
) -> Result<bool, RecoveryExecutionError> {
    for group in assembly.report().groups {
        let receipt = group.receipt();
        if receipt.missing_sequence_count > 0
            || !receipt.sequences_before_base.is_empty()
            || receipt.omitted_sequences_before_base > 0
            || !receipt.sequences_after_terminal.is_empty()
            || receipt.omitted_sequences_after_terminal > 0
            || receipt.parts.len() != receipt.record_count
        {
            return Ok(true);
        }

        let mut records_by_sequence = HashMap::<u64, &[u8]>::new();
        records_by_sequence
            .try_reserve(receipt.record_count)
            .map_err(|source| operational("record gate sequence map allocation failed", source))?;
        for part in &receipt.parts {
            let frame_index = context
                .frame_indices
                .get(part.input_index)
                .ok_or_else(|| invalid_policy("record gate assembly references a missing input"))?;
            let frame = context
                .frames
                .get(*frame_index)
                .ok_or_else(|| invalid_policy("record gate assembly references a missing frame"))?;
            let parsed = parse_reports
                .get(part.input_index)
                .ok_or_else(|| invalid_policy("record gate parse report is missing"))?;
            let record = parsed.records().get(part.record_index).ok_or_else(|| {
                invalid_policy("record gate assembly references a missing record")
            })?;
            if record.sequence != part.sequence {
                return Err(invalid_policy(
                    "record gate assembly sequence differs from its parse report",
                ));
            }
            let record_bytes = frame
                .bytes
                .get(record.record.start..record.record.end)
                .ok_or_else(|| invalid_policy("parsed record range is outside its frame"))?;
            if let Some(previous) = records_by_sequence.get(&part.sequence) {
                if *previous != record_bytes {
                    return Ok(true);
                }
            } else {
                records_by_sequence.insert(part.sequence, record_bytes);
            }
        }
    }
    Ok(false)
}

fn inspect_candidate_bytes(
    candidate_bytes: &[u8],
    context: &SchemaScreenContext<'_>,
    used_work: &mut usize,
) -> Result<CandidateInspection, RecoveryExecutionError> {
    if candidate_bytes.is_empty() {
        return Ok(CandidateInspection::default());
    }
    let signature_scan_work = candidate_bytes.len();
    if !reserve_schema_work(used_work, signature_scan_work, context.work_limit)? {
        return Ok(CandidateInspection {
            parser_omission: true,
            work_limited: Some(WorkLimitHit),
            pending: true,
            ..CandidateInspection::default()
        });
    }
    if scan_file_signatures(candidate_bytes).matches.is_empty() {
        return Ok(CandidateInspection::default());
    }
    if !reserve_schema_work(used_work, candidate_bytes.len(), context.work_limit)? {
        return Ok(CandidateInspection {
            parser_omission: true,
            work_limited: Some(WorkLimitHit),
            pending: true,
            ..CandidateInspection::default()
        });
    }
    let remaining_after_input = context.work_limit.saturating_sub(*used_work);
    let Ok(validator) = aggregate_validator(
        context.artifact_policy,
        candidate_bytes.len(),
        remaining_after_input,
    ) else {
        return Ok(CandidateInspection {
            parser_omission: true,
            work_limited: (remaining_after_input == 0).then_some(WorkLimitHit),
            pending: true,
            ..CandidateInspection::default()
        });
    };
    let mut expansion_remaining = remaining_after_input;
    let validation =
        if context.parser_format == l2_workbench::artifact::ArtifactValidationFormat::Zip {
            validator.validate_as_with_zip_budget(
                context.parser_format,
                candidate_bytes,
                &mut expansion_remaining,
            )
        } else {
            validator.validate_as(context.parser_format, candidate_bytes)
        };
    let expansion_work = remaining_after_input.saturating_sub(expansion_remaining);
    if !reserve_schema_work(used_work, expansion_work, context.work_limit)? {
        return Ok(CandidateInspection {
            parser_omission: true,
            work_limited: Some(WorkLimitHit),
            pending: true,
            ..CandidateInspection::default()
        });
    }
    let exact_artifact_match = matches!(
        validation,
        ArtifactValidationOutcome::Validated { ref range, .. }
            if range.offset == 0 && range.length == candidate_bytes.len()
    );
    Ok(CandidateInspection {
        exact_artifact_match,
        ..CandidateInspection::default()
    })
}

const fn classify_status(
    evaluation: &SchemaEvaluation,
    unchanged_schema_only: bool,
    all_alternatives_contradicted: bool,
    plan: &SchemaPlan,
) -> GateStatus {
    // Exact parser evidence wins; unchanged headers alone can never falsify a transform
    if evaluation.exact_artifact_matches > 0 {
        GateStatus::ArtifactValidated
    } else if unchanged_schema_only {
        GateStatus::Pending
    } else if evaluation.uniform_structural_support
        || (evaluation.family_structural_support
            && !plan.has_unassigned_family_messages
            && plan.family_search_complete)
    {
        GateStatus::StructurallySupported
    } else if evaluation.parser_omissions > 0
        || evaluation.pending
        || plan.has_unassigned_family_messages
        || !plan.family_search_complete
        || !all_alternatives_contradicted
    {
        GateStatus::Pending
    } else {
        GateStatus::Contradicted
    }
}

fn evaluation_details(
    evaluation: &SchemaEvaluation,
    status: GateStatus,
    unchanged_schema_only: bool,
    plan: &SchemaPlan,
    cache_hit: bool,
    parser_format: ArtifactValidationFormat,
) -> Value {
    let family_unassigned_sample_details = plan
        .details
        .get("family")
        .and_then(|family| family.get("family_analysis"))
        .and_then(|analysis| analysis.get("unassigned_samples"))
        .cloned()
        .unwrap_or(Value::Null);
    let reason = if unchanged_schema_only && evaluation.exact_artifact_matches == 0 {
        "clear_header_schema_only"
    } else if status == GateStatus::Pending
        && evaluation.underdetermined_schemas > 0
        && evaluation.exact_artifact_matches == 0
    {
        "record_corroboration_missing"
    } else {
        status.as_str()
    };
    json!({
        "reason":reason,
        "assessment_scope":plan.assessment_scope.as_str(),
        "schema_only_constraints":unchanged_schema_only,
        "schema_alternatives":evaluation.alternatives,
        "schemas_checked":evaluation.schemas_checked,
        "underdetermined_schemas":evaluation.underdetermined_schemas,
        "schema_survivors":evaluation.surviving_schemas,
        "schema_search_exhaustive":plan.family_search_complete,
        "family_unassigned_messages":plan.has_unassigned_family_messages,
        "schema_plan_cache_hit":cache_hit,
        "exact_artifact_matches":evaluation.exact_artifact_matches,
        "parser_omissions":evaluation.parser_omissions,
        "work_bytes":evaluation.used_work,
        "parser_format":format!("{parser_format:?}"),
        "family_unassigned_sample_details":family_unassigned_sample_details,
    })
}
