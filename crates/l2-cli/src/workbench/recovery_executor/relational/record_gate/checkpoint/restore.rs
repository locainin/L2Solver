//! Rebuild cached models only after replaying and checking their exact producers

use super::super::{
    AcceptedRecordSchema, GateStatus, HeaderSchemaPlan, MAX_CACHED_HEADER_PLAN_BYTES,
    MAX_CACHED_SCHEMA_PLANS, SchemaAlternative, SchemaGateReport, SchemaOffsetScope, SchemaPlan,
    SchemaPlanCache,
    key::{SchemaHeaderKey, SchemaLayoutKey},
    operational,
    screen::SchemaAlternativeEvaluation,
};
use super::{Observed, VERSION, replay};
use crate::workbench::recovery_executor::{
    RecoveryExecutionError,
    relational::{DecodedFrameOutput, StoredSample},
};
use l2_workbench::{
    artifact::ArtifactValidationPolicy,
    job::{Job, MemoryBudget, MemoryClass, MemoryLease, admit_json},
    protocol::{
        RecordAssemblyPlan, RecordAssemblyPlanDescription, RecordLimits,
        RecordSchemaProposalLimits, RelationalRecordSample, RelationalRestoreBudget,
        RelationalTransformLimits, RelationalTransformReport, RelationalTransformRule,
    },
    recovery::RecoveryError,
};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::HashSet, sync::Arc};

pub(in crate::workbench::recovery_executor::relational) struct SchemaCacheRestoreContext<
    'ctx,
    'bytes,
> {
    pub(in crate::workbench::recovery_executor::relational) raw_directional_run: bool,
    pub(in crate::workbench::recovery_executor::relational) samples:
        &'ctx [RelationalRecordSample<'bytes>],
    pub(in crate::workbench::recovery_executor::relational) stored_samples: &'ctx [StoredSample],
    pub(in crate::workbench::recovery_executor::relational) report: &'ctx RelationalTransformReport,
    pub(in crate::workbench::recovery_executor::relational) relational_limits:
        RelationalTransformLimits,
    pub(in crate::workbench::recovery_executor::relational) schema_limits:
        RecordSchemaProposalLimits,
    pub(in crate::workbench::recovery_executor::relational) artifact_policy:
        ArtifactValidationPolicy,
    pub(in crate::workbench::recovery_executor::relational) maximum_checkpoint_bytes: usize,
    pub(in crate::workbench::recovery_executor::relational) maximum_workspace_bytes: usize,
    pub(in crate::workbench::recovery_executor::relational) memory: &'ctx MemoryBudget,
    pub(in crate::workbench::recovery_executor::relational) work: &'ctx mut RelationalRestoreBudget,
    pub(in crate::workbench::recovery_executor::relational) job: Option<&'ctx Job>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Description {
    version: u32,
    producers: Vec<RelationalTransformRule>,
    plans: Vec<PlanDescription>,
    headers: Vec<HeaderDescription>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanDescription {
    key: SchemaLayoutKey,
    producer: usize,
    plan: PlanBody,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanBody {
    alternatives: Vec<AlternativeDescription>,
    observation_work_bytes: usize,
    details: Value,
    work_limited: bool,
    has_unassigned_family_messages: bool,
    family_search_complete: bool,
    assessment_scope: SchemaOffsetScope,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AlternativeDescription {
    label: String,
    frame_indices: Option<Vec<usize>>,
    discovery_report: Option<SchemaGateReport>,
    limits: RecordSchemaProposalLimits,
    discovery_work_bytes: usize,
    learning_message_count: usize,
    heldout_message_count: usize,
    omitted_learning_messages: usize,
    learning_session_count: usize,
    proposal_search_exhaustive: bool,
    status: GateStatus,
    observed: Option<Observed<AcceptedRecordSchema, super::structural::StructuralWitness>>,
    details: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderDescription {
    key: SchemaHeaderKey,
    producer: usize,
    description: RecordAssemblyPlanDescription,
    omitted_models: usize,
}

impl SchemaPlanCache {
    pub(in crate::workbench::recovery_executor::relational) fn restore_checkpoint(
        bytes: &[u8],
        mut context: SchemaCacheRestoreContext<'_, '_>,
    ) -> Result<Self, RecoveryExecutionError> {
        if bytes.len() > context.maximum_checkpoint_bytes {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        if let Some(job) = context.job {
            job.check_cancelled()?;
        }
        let decoding_work = bytes
            .len()
            .checked_mul(2)
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        replay::charge(&mut context, decoding_work)?;
        // Admission precedes deserialization, including strings and nested JSON details
        let admission = admit_json(bytes, context.memory, MemoryClass::Executor)
            .map_err(|error| operational("schema checkpoint decoding admission failed", error))?;
        let saved: Description =
            serde_json::from_slice(bytes).map_err(|_| RecoveryError::InvalidCheckpoint)?;
        let count = saved
            .plans
            .len()
            .checked_add(saved.headers.len())
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        if saved.version != VERSION
            || count > MAX_CACHED_SCHEMA_PLANS
            || saved.producers.len() > MAX_CACHED_SCHEMA_PLANS
        {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        let mut result = Self::default();
        result
            .plans
            .try_reserve(saved.plans.len())
            .map_err(|error| operational("schema checkpoint map allocation failed", error))?;
        result
            .compiled_memory
            .try_reserve_exact(saved.headers.len())
            .map_err(|error| operational("schema checkpoint charge allocation failed", error))?;
        let mut plans = saved.plans;
        let mut headers = saved.headers;
        for (index, rule) in saved.producers.iter().enumerate() {
            if saved
                .producers
                .iter()
                .take(index)
                .any(|prior| prior == rule)
            {
                return Err(RecoveryError::InvalidCheckpoint.into());
            }
            let frames = replay::replay(rule, &mut context)?;
            let producer = Arc::new(rule.clone());
            let before = plans.len() + headers.len();
            plans = result.restore_producer_plans(
                plans,
                index,
                &frames.frames,
                &producer,
                &mut context,
            )?;
            headers = result.restore_producer_headers(
                headers,
                index,
                &frames.frames,
                &producer,
                &mut context,
            )?;
            if plans.len() + headers.len() == before {
                return Err(RecoveryError::InvalidCheckpoint.into());
            }
        }
        if !plans.is_empty() || !headers.is_empty() {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        result.checkpoint_memory = Some(admission.into_retained());
        Ok(result)
    }

    fn restore_producer_plans(
        &mut self,
        plans: Vec<PlanDescription>,
        index: usize,
        frames: &[DecodedFrameOutput],
        producer: &Arc<RelationalTransformRule>,
        context: &mut SchemaCacheRestoreContext<'_, '_>,
    ) -> Result<Vec<PlanDescription>, RecoveryExecutionError> {
        let mut remaining = Vec::new();
        remaining
            .try_reserve_exact(plans.len())
            .map_err(|error| operational("schema checkpoint plan allocation failed", error))?;
        for description in plans {
            if description.producer != index {
                remaining.push(description);
                continue;
            }
            description.key.verify_replay(
                frames,
                context.report,
                producer.parser_format,
                context.artifact_policy,
                context.schema_limits,
            )?;
            let body = description
                .plan
                .restore(frames, Arc::clone(producer), context)?;
            if self.plans.insert(description.key, Arc::new(body)).is_some() {
                return Err(RecoveryError::InvalidCheckpoint.into());
            }
        }
        Ok(remaining)
    }

    fn restore_producer_headers(
        &mut self,
        headers: Vec<HeaderDescription>,
        index: usize,
        frames: &[DecodedFrameOutput],
        producer: &Arc<RelationalTransformRule>,
        context: &mut SchemaCacheRestoreContext<'_, '_>,
    ) -> Result<Vec<HeaderDescription>, RecoveryExecutionError> {
        let mut remaining = Vec::new();
        remaining
            .try_reserve_exact(headers.len())
            .map_err(|error| operational("schema checkpoint header allocation failed", error))?;
        for description in headers {
            if description.producer != index {
                remaining.push(description);
                continue;
            }
            self.restore_header(description, frames, Arc::clone(producer), context)?;
        }
        Ok(remaining)
    }

    fn restore_header(
        &mut self,
        saved: HeaderDescription,
        frames: &[DecodedFrameOutput],
        producer: Arc<RelationalTransformRule>,
        context: &mut SchemaCacheRestoreContext<'_, '_>,
    ) -> Result<(), RecoveryExecutionError> {
        charge_header_key_replay(frames, context)?;
        saved.key.verify_replay(
            frames,
            context.report,
            producer.parser_format,
            context.artifact_policy,
            context.schema_limits,
            context.job,
        )?;
        if self.header_plans.contains_key(&saved.key) {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        let (plan, retained_bytes, memory) =
            rebuild_header_plan(&saved.description, frames, context)?;
        let previous_count = self.header_plans.len();
        self.cache_header_plan(
            saved.key,
            HeaderSchemaPlan {
                assembly_plan: plan,
                retained_bytes,
                omitted_models: saved.omitted_models,
                producer_rule: Some(producer),
            },
            context
                .schema_limits
                .discovery
                .record_limits
                .max_report_bytes
                .min(MAX_CACHED_HEADER_PLAN_BYTES),
        )?;
        // A saved entry must survive the same admission rule that originally retained it
        if self.header_plans.len() == previous_count {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        self.compiled_memory.push(memory);
        Ok(())
    }
}

fn rebuild_header_plan(
    description: &RecordAssemblyPlanDescription,
    frames: &[DecodedFrameOutput],
    context: &mut SchemaCacheRestoreContext<'_, '_>,
) -> Result<(RecordAssemblyPlan, usize, MemoryLease), RecoveryExecutionError> {
    let job = context.job;
    let work = &mut *context.work;
    // Verification consumes its own allowance without changing frozen search work
    let limit = work.remaining_verification_work_bytes();
    let mut control = |bytes| {
        if job.is_some_and(Job::is_cancelled) {
            return Err(l2_workbench::protocol::RecordError::Cancelled);
        }
        if !work.try_charge_verification(bytes) {
            return Err(l2_workbench::protocol::RecordError::WorkLimitExceeded {
                limit,
                consumed: limit - work.remaining_verification_work_bytes(),
                requested: bytes,
            });
        }
        Ok(())
    };
    let input_work = frames
        .len()
        .checked_mul(size_of::<&[u8]>())
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    control(input_work).map_err(|error| checkpoint_record_error(&error))?;
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(frames.len())
        .map_err(|error| operational("schema checkpoint header allocation failed", error))?;
    for frame in frames {
        control(0).map_err(|error| checkpoint_record_error(&error))?;
        inputs.push(frame.bytes.as_slice());
    }
    description
        .validate_inputs(&inputs, &mut control)
        .map_err(|error| checkpoint_record_error(&error))?;
    // Cover compiler capacity and allocator slack within the admitted workspace
    let mut memory = context
        .memory
        .try_reserve(
            MemoryClass::Executor,
            u64::try_from(context.maximum_workspace_bytes)
                .map_err(|_| RecoveryError::InvalidCheckpoint)?,
        )
        .map_err(|error| operational("schema checkpoint compilation admission failed", error))?;
    let logical_workspace = (context.maximum_workspace_bytes / 4)
        .checked_sub(size_of::<HeaderSchemaPlan>())
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let plan = description
        .restore(
            context.schema_limits.discovery.record_limits,
            context.maximum_checkpoint_bytes,
            logical_workspace,
            &mut control,
        )
        .map_err(|error| checkpoint_record_error(&error))?;
    let retained_bytes = size_of::<HeaderSchemaPlan>()
        .checked_add(plan.retained_bytes())
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let admitted_bytes = retained_bytes
        .checked_mul(4)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    memory
        .try_resize(admitted_bytes)
        .map_err(|error| operational("schema checkpoint plan admission failed", error))?;
    Ok((plan, retained_bytes, memory))
}

fn charge_header_key_replay(
    frames: &[DecodedFrameOutput],
    context: &mut SchemaCacheRestoreContext<'_, '_>,
) -> Result<(), RecoveryExecutionError> {
    let sessions = context
        .report
        .discovery_sessions
        .len()
        .checked_add(context.report.heldout_sessions.len())
        .and_then(|count| count.checked_mul(4 * size_of::<u64>()))
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    replay::charge(context, sessions)?;
    for frame in frames {
        if let Some(job) = context.job {
            job.check_cancelled()?;
        }
        let bytes = frame
            .context
            .source
            .len()
            .checked_add(frame.context.scope.len())
            .and_then(|total| {
                frame
                    .expected_session_orders
                    .len()
                    .checked_mul(size_of::<u64>())
                    .and_then(|orders| total.checked_add(orders))
            })
            .and_then(|total| total.checked_add(size_of::<DecodedFrameOutput>()))
            .and_then(|total| total.checked_mul(4))
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        replay::charge(context, bytes)?;
    }
    Ok(())
}

fn checkpoint_record_error(error: &l2_workbench::protocol::RecordError) -> RecoveryExecutionError {
    match error {
        l2_workbench::protocol::RecordError::Cancelled => l2_workbench::job::JobError::Cancelled.into(),
        l2_workbench::protocol::RecordError::WorkLimitExceeded { .. } => operational(
            "schema checkpoint verification work limit reached",
            l2_workbench::protocol::RelationalCursorError::<std::convert::Infallible>::RestoreWorkLimit,
        ),
        l2_workbench::protocol::RecordError::AllocationFailed => RecoveryError::AllocationFailed.into(),
        _ => RecoveryError::InvalidCheckpoint.into(),
    }
}

impl PlanBody {
    fn restore(
        self,
        frames: &[DecodedFrameOutput],
        producer: Arc<RelationalTransformRule>,
        context: &mut SchemaCacheRestoreContext<'_, '_>,
    ) -> Result<SchemaPlan, RecoveryExecutionError> {
        let mut alternatives = Vec::new();
        alternatives
            .try_reserve_exact(self.alternatives.len())
            .map_err(|error| {
                operational("schema checkpoint alternative allocation failed", error)
            })?;
        for alternative in self.alternatives {
            if let Some(indices) = &alternative.frame_indices {
                if indices.len() > frames.len() {
                    return Err(RecoveryError::InvalidCheckpoint.into());
                }
                let mut seen = HashSet::new();
                seen.try_reserve(indices.len()).map_err(|error| {
                    operational("schema checkpoint membership allocation failed", error)
                })?;
                for index in indices {
                    if *index >= frames.len() || !seen.insert(*index) {
                        return Err(RecoveryError::InvalidCheckpoint.into());
                    }
                }
            }
            let observed = alternative
                .observed
                .map(|observed| {
                    observed.restore(frames, alternative.limits.discovery.record_limits, context)
                })
                .transpose()?;
            alternatives.push(SchemaAlternative {
                label: alternative.label,
                frame_indices: alternative.frame_indices.map(Arc::from),
                discovery_report: alternative.discovery_report,
                limits: alternative.limits,
                discovery_work_bytes: alternative.discovery_work_bytes,
                learning_message_count: alternative.learning_message_count,
                heldout_message_count: alternative.heldout_message_count,
                omitted_learning_messages: alternative.omitted_learning_messages,
                learning_session_count: alternative.learning_session_count,
                proposal_search_exhaustive: alternative.proposal_search_exhaustive,
                status: alternative.status,
                observed,
                details: alternative.details,
            });
        }
        Ok(SchemaPlan {
            alternatives,
            observation_work_bytes: self.observation_work_bytes,
            details: self.details,
            work_limited: self.work_limited,
            has_unassigned_family_messages: self.has_unassigned_family_messages,
            family_search_complete: self.family_search_complete,
            assessment_scope: self.assessment_scope,
            producer_rule: Some(producer),
        })
    }
}

impl Observed<AcceptedRecordSchema, super::structural::StructuralWitness> {
    fn restore(
        self,
        frames: &[DecodedFrameOutput],
        limits: RecordLimits,
        context: &mut SchemaCacheRestoreContext<'_, '_>,
    ) -> Result<SchemaAlternativeEvaluation, RecoveryExecutionError> {
        if (self.exact_artifact_matches > 0) != self.accepted_schema.is_some() {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        if self.survives && self.exact_artifact_matches == 0 && self.structural_witness.is_none() {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        if let Some(witness) = &self.structural_witness {
            super::structural::verify_witness(witness, frames, context)?;
        }
        if let Some(accepted) = &self.accepted_schema {
            super::accepted::verify(accepted, frames, limits, context)?;
        }
        Ok(SchemaAlternativeEvaluation {
            accepted_schema: self.accepted_schema,
            structural_witness: self.structural_witness,
            exact_artifact_matches: self.exact_artifact_matches,
            parser_omissions: self.parser_omissions,
            schemas_checked: self.schemas_checked,
            underdetermined_schemas: self.underdetermined_schemas,
            variable_length_schemas: self.variable_length_schemas,
            coherent_sequence_schemas: self.coherent_sequence_schemas,
            sequence_conflict_schemas: self.sequence_conflict_schemas,
            surviving_schemas: self.surviving_schemas,
            work_bytes: self.work_bytes,
            strict_survivors_seen: self.strict_survivors_seen,
            exact_artifact_survivor_ordinal: self.exact_artifact_survivor_ordinal,
            work_limited: self.work_limited,
            survives: self.survives,
            pending: self.pending,
            header_models_omitted: self.header_models_omitted,
            ..SchemaAlternativeEvaluation::default()
        })
    }
}
