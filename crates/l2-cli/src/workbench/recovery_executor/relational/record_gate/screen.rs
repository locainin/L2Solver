use super::super::super::RecoveryExecutionError;
use super::super::{DecodedFrameOutput, aggregate_validator, invalid_policy, operational};
use super::header::{HeaderSchemaModel, HeaderSchemaPlan};
use super::{
    GateResult, GateStatus, SchemaAlternative, SchemaPlan, record_inputs, record_job_work, result,
};
use l2_workbench::{
    artifact::{
        ArtifactStructure, ArtifactValidationFormat, ArtifactValidationOutcome,
        ArtifactValidationPolicy, scan_file_signatures,
    },
    job::{Counter, Job, Phase},
    protocol::{
        HeaderParseTemplate, MessageContext, RecordAssemblyInput, RecordAssemblyOutcome,
        RecordError, RecordGroupReceipt, RecordInput, RecordParseReport, RecordSchema,
        RecordSchemaDiscoveryReport, RecordSchemaHypothesis, RecordSchemaProposalLimits,
        RecordSchemaStrategy, assemble_record_groups_from_inputs, parse_records_with_limits,
    },
};
use serde_json::{Value, json};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
};

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
    pub(super) inputs: Option<&'a [RecordInput<'a>]>,
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

#[derive(Default)]
struct CandidateInspection {
    exact_artifact_match: bool,
    parser_omission: bool,
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
    gate_result.accepted_schema = evaluation.accepted_schema;
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
    if full_input_bytes > work_limit {
        return Ok(result(
            GateStatus::Pending,
            work_limit,
            json!({
                "reason":"record_schema_work_limit",
                "schema_plan_cache_hit":false,
                "header_schema_plan_cache_hit":true,
                "header_schema_models":plan.models.len(),
                "header_schema_models_omitted":plan.omitted_models,
                "work_bytes":work_limit,
                "work_limit":work_limit,
            }),
        ));
    }

    let inputs = record_inputs(frames)?;
    let frame_indices = all_frame_indices(frames.len())?;
    let context = SchemaScreenContext {
        frames,
        inputs: Some(&inputs),
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
            "reason":if evaluation.exact_artifact_matches == 0 { "header_schema_requires_fresh_inference" } else { status.as_str() },
            "schema_plan_cache_hit":false,
            "header_schema_plan_cache_hit":true,
            "header_schema_models":plan.models.len(),
            "header_schema_models_attempted":evaluation.models_attempted,
            "header_schema_models_checked":evaluation.schemas_checked,
            "header_schema_models_omitted":plan.omitted_models,
            "header_schema_rebind_rejections":evaluation.rebind_rejections,
            "header_schema_assembly_rejections":evaluation.assembly_rejections,
            "header_schema_models_deferred_for_work":evaluation.models_deferred_for_work,
            "schema_alternatives":evaluation.alternatives,
            "exact_artifact_matches":evaluation.exact_artifact_matches,
            "parser_omissions":evaluation.parser_omissions,
            "work_bytes":evaluation.used_work,
            "work_limit":work_limit,
            "pending":evaluation.pending,
        }),
    );
    gate_result.accepted_schema = evaluation.accepted_schema;
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
    exact_artifact_matches: usize,
    parser_omissions: usize,
    pending: bool,
    accepted_schema: Option<AcceptedRecordSchema>,
    alternatives: Vec<Value>,
}

fn evaluate_header_models(
    context: &SchemaScreenContext<'_>,
    plan: &HeaderSchemaPlan,
) -> Result<HeaderPlanEvaluation, RecoveryExecutionError> {
    let mut evaluation = HeaderPlanEvaluation::default();
    evaluation
        .alternatives
        .try_reserve_exact(1)
        .map_err(|source| operational("header schema result allocation failed", source))?;
    let mut identity_charged = false;
    for (model_index, model) in plan.models.iter().enumerate() {
        if let Some(job) = context.job {
            job.check_cancelled()?;
        }
        if !identity_charged {
            if !reserve_schema_work(
                &mut evaluation.used_work,
                context.full_input_bytes,
                context.work_limit,
            )? {
                evaluation.pending = true;
                evaluation.models_deferred_for_work = plan.models.len().saturating_sub(model_index);
                break;
            }
            identity_charged = true;
        }
        if evaluate_header_model(context, plan, model, model_index, &mut evaluation)? {
            break;
        }
    }
    Ok(evaluation)
}

fn evaluate_header_model(
    context: &SchemaScreenContext<'_>,
    plan: &HeaderSchemaPlan,
    model: &HeaderSchemaModel,
    model_index: usize,
    evaluation: &mut HeaderPlanEvaluation,
) -> Result<bool, RecoveryExecutionError> {
    let inputs = context
        .inputs
        .ok_or_else(|| invalid_policy("record gate header inputs are missing"))?;
    let model_work_start = evaluation.used_work;
    let header_work = header_rebind_work(context.frames, model)?;
    if !reserve_schema_work(&mut evaluation.used_work, header_work, context.work_limit)? {
        evaluation.pending = true;
        evaluation.models_deferred_for_work = plan.models.len().saturating_sub(model_index);
        return Ok(true);
    }
    evaluation.models_attempted = evaluation.models_attempted.saturating_add(1);
    let Some(parse_reports) = rebind_header_model(inputs, context.frames, model)? else {
        evaluation.parser_omissions = evaluation.parser_omissions.saturating_add(1);
        evaluation.rebind_rejections = evaluation.rebind_rejections.saturating_add(1);
        evaluation.pending = true;
        return Ok(false);
    };
    let assembly_work = parse_reports.iter().try_fold(0_usize, |total, report| {
        report
            .records()
            .iter()
            .try_fold(total, |records_total, record| {
                records_total.checked_add(record.payload.end.saturating_sub(record.payload.start))
            })
    });
    let Some(assembly_work) = assembly_work.and_then(|bytes| bytes.checked_mul(2)) else {
        return Err(invalid_policy(
            "record gate header assembly work overflowed",
        ));
    };
    // Materialization copies each payload and computes the assembly receipt digest
    if !reserve_schema_work(&mut evaluation.used_work, assembly_work, context.work_limit)? {
        evaluation.pending = true;
        evaluation.models_deferred_for_work = plan.models.len().saturating_sub(model_index);
        return Ok(true);
    }
    let Some(assembly) = assemble_header_model(
        inputs,
        context.frames,
        context.frame_indices,
        &parse_reports,
        model,
    )?
    else {
        evaluation.pending = true;
        evaluation.parser_omissions = evaluation.parser_omissions.saturating_add(1);
        evaluation.assembly_rejections = evaluation.assembly_rejections.saturating_add(1);
        return Ok(false);
    };
    evaluation.schemas_checked = evaluation.schemas_checked.saturating_add(1);
    inspect_header_assembly(
        context,
        model,
        model_index,
        model_work_start,
        plan.models.len(),
        &assembly,
        evaluation,
    )
}

fn inspect_header_assembly(
    context: &SchemaScreenContext<'_>,
    model: &HeaderSchemaModel,
    model_index: usize,
    model_work_start: usize,
    model_count: usize,
    assembly: &RecordAssemblyOutcome,
    evaluation: &mut HeaderPlanEvaluation,
) -> Result<bool, RecoveryExecutionError> {
    let mut candidate_matches = 0_usize;
    for group in assembly.report().groups {
        let candidate_bytes = group.candidate_bytes();
        if !reserve_schema_work(
            &mut evaluation.used_work,
            candidate_bytes.len(),
            context.work_limit,
        )? {
            evaluation.pending = true;
            evaluation.parser_omissions = evaluation.parser_omissions.saturating_add(1);
            evaluation.models_deferred_for_work = model_count.saturating_sub(model_index);
            break;
        }
        let inspection =
            inspect_candidate_bytes(candidate_bytes, context, &mut evaluation.used_work)?;
        evaluation.parser_omissions = evaluation
            .parser_omissions
            .saturating_add(usize::from(inspection.parser_omission));
        evaluation.pending |= inspection.pending;
        candidate_matches =
            candidate_matches.saturating_add(usize::from(inspection.exact_artifact_match));
        if inspection.exact_artifact_match && evaluation.accepted_schema.is_none() {
            evaluation.accepted_schema = Some(accepted_record_schema(
                context,
                model.schema.clone(),
                RecordSchemaStrategy::FixedLayout,
                group.receipt().clone(),
            )?);
        }
        if inspection.pending {
            break;
        }
    }
    evaluation.exact_artifact_matches = evaluation
        .exact_artifact_matches
        .saturating_add(candidate_matches);
    if candidate_matches > 0 {
        evaluation.alternatives.push(json!({
            "label":"header_only:fixed_layout",
            "status":GateStatus::ArtifactValidated.as_str(),
            "schema_model_ordinal":model_index.saturating_add(1),
            "exact_artifact_matches":candidate_matches,
            "header_model_bytes":model.retained_bytes,
            "work_bytes":evaluation.used_work.saturating_sub(model_work_start),
        }));
    }
    Ok(candidate_matches > 0 || evaluation.pending)
}

fn all_frame_indices(frame_count: usize) -> Result<Vec<usize>, RecoveryExecutionError> {
    let mut indices = Vec::new();
    indices.try_reserve_exact(frame_count).map_err(|source| {
        operational("record gate header frame index allocation failed", source)
    })?;
    indices.extend(0..frame_count);
    Ok(indices)
}

fn header_rebind_work(
    frames: &[DecodedFrameOutput],
    model: &HeaderSchemaModel,
) -> Result<usize, RecoveryExecutionError> {
    frames.iter().try_fold(0_usize, |total, frame| {
        let Some(prefix_end) = frame.preserved_header_end else {
            return Err(invalid_policy("header schema plan lost a preserved prefix"));
        };
        if frame.bytes.get(..prefix_end).is_none() {
            return Err(invalid_policy(
                "header schema plan prefix exceeds its frame",
            ));
        }
        total
            .checked_add(prefix_end)
            .and_then(|amount| amount.checked_add(model.schema.identifier.width))
            .ok_or_else(|| invalid_policy("record gate header rebind work overflowed"))
    })
}

fn rebind_header_model(
    inputs: &[RecordInput<'_>],
    frames: &[DecodedFrameOutput],
    model: &HeaderSchemaModel,
) -> Result<Option<Vec<RecordParseReport>>, RecoveryExecutionError> {
    if model.templates.len() != frames.len() {
        return Ok(None);
    }
    let mut reports = Vec::new();
    reports
        .try_reserve_exact(frames.len())
        .map_err(|source| operational("record gate rebound report allocation failed", source))?;
    for (frame_index, (template_index, template)) in model.templates.iter().enumerate() {
        if frame_index != *template_index {
            return Ok(None);
        }
        let input = inputs
            .get(frame_index)
            .ok_or_else(|| invalid_policy("record gate rebound input is missing"))?;
        let Ok(report) = template.rebind(input, model.limits) else {
            return Ok(None);
        };
        reports.push(report);
    }
    Ok(Some(reports))
}

fn assemble_header_model(
    inputs: &[RecordInput<'_>],
    frames: &[DecodedFrameOutput],
    frame_indices: &[usize],
    reports: &[RecordParseReport],
    model: &HeaderSchemaModel,
) -> Result<Option<RecordAssemblyOutcome>, RecoveryExecutionError> {
    if inputs.len() != frame_indices.len() || reports.len() != frame_indices.len() {
        return Ok(None);
    }
    let mut assembly_inputs = Vec::new();
    assembly_inputs
        .try_reserve_exact(frame_indices.len())
        .map_err(|source| operational("record gate rebound assembly allocation failed", source))?;
    for (position, frame_index) in frame_indices.iter().enumerate() {
        let Some(input) = inputs.get(*frame_index) else {
            return Err(invalid_policy(
                "record gate rebound assembly input is missing",
            ));
        };
        let Some(report) = reports.get(position) else {
            return Err(invalid_policy(
                "record gate rebound parse report is missing",
            ));
        };
        let _frame = frames
            .get(*frame_index)
            .ok_or_else(|| invalid_policy("record gate rebound frame is missing"))?;
        let Ok(assembly_input) = RecordAssemblyInput::from_input(input, report) else {
            return Ok(None);
        };
        assembly_inputs.push(assembly_input);
    }
    Ok(assemble_record_groups_from_inputs(&assembly_inputs, model.limits).ok())
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
    let mut evaluation = SchemaEvaluation {
        used_work: initial_work,
        ..SchemaEvaluation::default()
    };
    if plan.alternatives.is_empty() {
        evaluation.pending = true;
    }
    let options = PlanScreenOptions {
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
    let Some(report) = alternative.discovery_report.as_ref() else {
        record_missing_report(alternative, evaluation);
        return Ok(false);
    };
    if let Some(job) = options.job {
        job.check_cancelled()?;
    }
    if alternative.omitted_learning_messages > 0 && alternative.observed.is_none() {
        record_incomplete_application(alternative, evaluation);
        return Ok(false);
    }
    let frame_indices = alternative_frame_indices(frames, alternative)?;
    let full_input_bytes = total_indexed_bytes(frames, &frame_indices)?;
    if full_input_bytes > options.work_limit.saturating_sub(evaluation.used_work) {
        evaluation.pending = true;
        return Ok(true);
    }
    let context = SchemaScreenContext {
        frames,
        inputs: None,
        frame_indices: frame_indices.as_slice(),
        limits: alternative.limits,
        parser_format: options.parser_format,
        artifact_policy: options.artifact_policy,
        work_limit: options.work_limit,
        job: options.job,
        full_input_bytes,
    };
    let before = EvaluationSnapshot::capture(evaluation);
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
        .fold(0_usize, usize::saturating_add)
}

fn pending_work_result(
    requested_work: usize,
    work_limit: usize,
    cache_hit: bool,
    plan: &SchemaPlan,
) -> GateResult {
    result(
        GateStatus::Pending,
        work_limit,
        json!({
            "reason":"record_schema_work_limit",
            "schema_plan_cache_hit":cache_hit,
            "schema_work_bytes":requested_work,
            "work_limit":work_limit,
            "schema_plan":plan.details,
        }),
    )
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
    pub(super) inputs: Option<&'a [RecordInput<'a>]>,
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
    for hypothesis in &report.surviving {
        if let Some(job) = context.job {
            job.check_cancelled()?;
        }
        // Charge the full schema parse before starting work on any frame
        if !reserve_schema_work(
            &mut evaluation.used_work,
            context.full_input_bytes,
            context.work_limit,
        )? {
            evaluation.pending = true;
            alternative.pending = true;
            break;
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
        evaluation.pending |= result.pending;
        alternative.pending |= result.pending;
        if result.exact_artifact_matches > 0 {
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
    let Some(next_work) = context
        .full_input_bytes
        .checked_mul(3)
        .and_then(|amount| before_work.checked_add(amount))
        .filter(|work| *work <= context.work_limit)
    else {
        evaluation.pending = true;
        return Ok(std::ops::ControlFlow::Break(()));
    };
    *observer_work = next_work;

    let completed_reports = match complete_application_reports(context, hypothesis, inputs)? {
        FullApplicationReports::Complete(reports) => reports,
        FullApplicationReports::Contradicted => {
            finish_observer_work(evaluation, *observer_work, before_work);
            return Ok(std::ops::ControlFlow::Continue(()));
        }
        FullApplicationReports::Omitted => {
            evaluation.pending = true;
            finish_observer_work(evaluation, *observer_work, before_work);
            return Ok(std::ops::ControlFlow::Continue(()));
        }
    };
    if strategy == RecordSchemaStrategy::FixedLayout
        && let Some(model) = capture_header_model(context, hypothesis, &completed_reports)?
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
    accumulate_hypothesis_result(context, strategy, hypothesis, result, evaluation)?;
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
) -> Result<Option<HeaderSchemaModel>, RecoveryExecutionError> {
    let Some(inputs) = context.inputs else {
        return Ok(None);
    };
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

    let mut templates = Vec::new();
    templates
        .try_reserve_exact(context.frames.len())
        .map_err(|source| operational("record gate header template allocation failed", source))?;
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
    Omitted,
}

fn complete_application_reports<'reports>(
    context: &SchemaScreenContext<'_>,
    hypothesis: &RecordSchemaHypothesis,
    inputs: &SurvivingSchemaInputs<'reports>,
) -> Result<FullApplicationReports<'reports>, RecoveryExecutionError> {
    let mut totals = RecordReportTotals::default();
    let training = match complete_reports(
        context,
        inputs.selected_training_indices,
        inputs.training_reports,
        inputs.all_training_indices,
        hypothesis,
        &mut totals,
    )? {
        CompleteReports::Complete(reports) => reports,
        CompleteReports::Contradicted => return Ok(FullApplicationReports::Contradicted),
        CompleteReports::Omitted => return Ok(FullApplicationReports::Omitted),
    };
    let heldout = match complete_reports(
        context,
        inputs.selected_heldout_indices,
        inputs.heldout_reports,
        inputs.all_heldout_indices,
        hypothesis,
        &mut totals,
    )? {
        CompleteReports::Complete(reports) => reports,
        CompleteReports::Contradicted => return Ok(FullApplicationReports::Contradicted),
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
    if result.exact_artifact_matches > 0 {
        let receipt = result
            .accepted_receipt
            .ok_or_else(|| invalid_policy("validated artifact has no record assembly receipt"))?;
        evaluation.accepted_schema = Some(accepted_record_schema(
            context,
            hypothesis.schema.clone(),
            strategy,
            receipt,
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
    for frame_index in context.frame_indices {
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
            frame_bytes_sha256: l2_workbench::sha256(&frame.bytes),
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
    Omitted,
}

fn complete_reports<'reports>(
    context: &SchemaScreenContext<'_>,
    selected_indices: &[usize],
    selected_reports: &'reports [RecordParseReport],
    all_indices: &[usize],
    hypothesis: &RecordSchemaHypothesis,
    totals: &mut RecordReportTotals,
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
        let frame = context
            .frames
            .get(*index)
            .ok_or_else(|| invalid_policy("record gate full application frame is missing"))?;
        let report = if let Some(report) = selected_by_index.remove(index) {
            Cow::Borrowed(report)
        } else {
            if let Some(job) = context.job {
                job.check_cancelled()?;
            }
            match parse_records_with_limits(
                &frame.bytes,
                &hypothesis.schema,
                context.limits.discovery.record_limits,
            ) {
                Ok(report) => Cow::Owned(report),
                Err(
                    RecordError::InputTooLarge { .. }
                    | RecordError::TooManyRecords { .. }
                    | RecordError::ReportTooLarge { .. }
                    | RecordError::AllocationFailed,
                ) => return Ok(CompleteReports::Omitted),
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
    full_input_bytes: usize,
    work_limit: usize,
) -> Result<bool, RecoveryExecutionError> {
    let schema_work = full_input_bytes
        .checked_mul(3)
        .ok_or_else(|| invalid_policy("record gate schema work overflowed"))?;
    if schema_work > work_limit.saturating_sub(*used_work) {
        return Ok(false);
    }
    *used_work = used_work
        .checked_add(schema_work)
        .ok_or_else(|| invalid_policy("record gate work count overflowed"))?;
    Ok(true)
}

fn evaluate_hypothesis(
    context: &SchemaScreenContext<'_>,
    hypothesis: &RecordSchemaHypothesis,
    used_work: &mut usize,
) -> Result<HypothesisEvaluation, RecoveryExecutionError> {
    let Some(parse_reports) = parse_hypothesis_frames(context, hypothesis)? else {
        return Ok(HypothesisEvaluation::default());
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
) -> Result<Option<Vec<RecordParseReport>>, RecoveryExecutionError> {
    let mut reports = Vec::new();
    reports
        .try_reserve_exact(context.frame_indices.len())
        .map_err(|source| operational("record gate parse report allocation failed", source))?;
    for frame_index in context.frame_indices {
        let frame = context
            .frames
            .get(*frame_index)
            .ok_or_else(|| invalid_policy("record gate alternative references a missing frame"))?;
        let Ok(parsed) = parse_records_with_limits(
            &frame.bytes,
            &hypothesis.schema,
            context.limits.discovery.record_limits,
        ) else {
            if let Some(job) = context.job {
                job.increment(Counter::CandidatesRejected, 1)?;
            }
            return Ok(None);
        };
        reports.push(parsed);
    }
    Ok(Some(reports))
}

fn assemble_hypothesis(
    context: &SchemaScreenContext<'_>,
    parse_reports: &[&RecordParseReport],
) -> Result<Option<RecordAssemblyOutcome>, RecoveryExecutionError> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(context.frame_indices.len())
        .map_err(|source| operational("record gate assembly input allocation failed", source))?;
    inputs.extend(context.frame_indices.iter().zip(parse_reports).filter_map(
        |(frame_index, parsed)| {
            context
                .frames
                .get(*frame_index)
                .map(|frame| RecordAssemblyInput::new(&frame.bytes, parsed))
        },
    ));
    if inputs.len() != context.frame_indices.len() {
        return Err(invalid_policy(
            "record gate alternative references a missing frame",
        ));
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
    if candidate_bytes.is_empty() || scan_file_signatures(candidate_bytes).matches.is_empty() {
        return Ok(CandidateInspection::default());
    }
    let remaining = context.work_limit.saturating_sub(*used_work);
    if candidate_bytes.len() > remaining {
        return Ok(CandidateInspection {
            parser_omission: true,
            pending: true,
            ..CandidateInspection::default()
        });
    }
    let Ok(validator) = aggregate_validator(
        context.artifact_policy,
        candidate_bytes.len(),
        remaining.saturating_sub(candidate_bytes.len()),
    ) else {
        return Ok(CandidateInspection {
            parser_omission: true,
            pending: true,
            ..CandidateInspection::default()
        });
    };
    let validation = validator.validate_as(context.parser_format, candidate_bytes);
    let expansion_work = match &validation {
        ArtifactValidationOutcome::Validated {
            structure: ArtifactStructure::Zip(report),
            ..
        } => report.expanded_work_byte_count,
        _ => 0,
    };
    let parser_work = candidate_bytes
        .len()
        .checked_add(expansion_work)
        .ok_or_else(|| invalid_policy("record gate parser work overflowed"))?;
    if parser_work > remaining {
        return Ok(CandidateInspection {
            parser_omission: true,
            pending: true,
            ..CandidateInspection::default()
        });
    }
    *used_work = used_work
        .checked_add(parser_work)
        .ok_or_else(|| invalid_policy("record gate work count overflowed"))?;
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
