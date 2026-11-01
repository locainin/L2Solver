//! In-memory record and artifact checks used before relational output retention

pub(super) mod checkpoint;
mod header;
mod key;
mod plan;
mod screen;
mod selection;

pub(in crate::workbench::recovery_executor::relational) use checkpoint::structural::StructuralEvidence;
pub(in crate::workbench::recovery_executor::relational) use checkpoint::{
    SchemaCacheRestoreContext, verify_assessment, verify_structural_assessment,
};
pub(super) use plan::SchemaOffsetScope;
pub(super) use screen::{AcceptedFrameIdentity, AcceptedRecordSchema};

#[cfg(test)]
#[path = "../../../../tests/workbench/record_gate.rs"]
mod tests;

#[cfg(test)]
#[path = "../../../../tests/workbench/record_gate_family.rs"]
mod family_tests;

#[cfg(test)]
#[path = "../../../../tests/workbench/record_gate_screening.rs"]
mod screening_tests;

#[cfg(test)]
use self::screen::screen_with_schema_plan;
use self::{
    header::HeaderSchemaPlan,
    key::{SchemaHeaderKey, SchemaLayoutKey, schema_header_key, schema_layout_key},
    plan::{build_full_schema_plan, build_schema_plan_with_inputs},
    screen::{screen_with_header_plan, screen_with_schema_plan_with_memory},
};
use super::super::RecoveryExecutionError;
use super::{DecodedFrameOutput, invalid_policy, operational};
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationPolicy},
    job::{Counter, Job, MemoryBudget, Phase},
    protocol::{
        RecordAssemblyHeaderModel, RecordAssemblyPlan, RecordInput, RecordSchemaDiscoveryReport,
        RecordSchemaHypothesis, RecordSchemaProposalLimits, RelationalTransformReport,
        RelationalTransformRule,
    },
};
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};

const MAX_CACHED_SCHEMA_PLANS: usize = 32;
const MAX_CACHED_HEADER_PLAN_BYTES: usize = l2_workbench::protocol::DEFAULT_MAX_RECORD_REPORT_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum GateStatus {
    ArtifactValidated,
    StructurallySupported,
    Pending,
    Contradicted,
}

impl GateStatus {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactValidated => "artifact_validated",
            Self::StructurallySupported => "structurally_supported",
            Self::Pending => "pending",
            Self::Contradicted => "contradicted",
        }
    }

    pub(super) const fn priority(self) -> u8 {
        match self {
            Self::ArtifactValidated => 3,
            Self::StructurallySupported => 2,
            Self::Pending => 1,
            Self::Contradicted => 0,
        }
    }
}

pub(super) struct GateResult {
    pub(super) status: GateStatus,
    pub(super) work_bytes: usize,
    pub(super) work_limited_at: Option<usize>,
    pub(super) details: Value,
    pub(super) accepted_schema: Option<screen::AcceptedRecordSchema>,
    pub(super) structural_evidence: Option<checkpoint::structural::StructuralEvidence>,
    pub(super) assessment_scope: SchemaOffsetScope,
}

impl GateResult {
    pub(super) const fn needs_full_inference(&self) -> bool {
        matches!(self.assessment_scope, SchemaOffsetScope::PreservedHeader)
            && !matches!(self.status, GateStatus::ArtifactValidated)
    }
}

#[derive(Default)]
pub(super) struct SchemaPlanCache {
    plans: HashMap<SchemaLayoutKey, Arc<SchemaPlan>>,
    header_plans: HashMap<SchemaHeaderKey, Arc<HeaderSchemaPlan>>,
    header_plan_bytes: usize,
    // Restored maps and compiled plans retain their charges until their data is dropped
    checkpoint_memory: Option<l2_workbench::job::MemoryLease>,
    compiled_memory: Vec<l2_workbench::job::MemoryLease>,
}

impl SchemaPlanCache {
    #[cfg(test)]
    pub(super) fn checkpoint_plan_count(&self) -> usize {
        self.plans.len() + self.header_plans.len()
    }
}

pub(super) struct SchemaPlan {
    pub(super) alternatives: Vec<SchemaAlternative>,
    // Observation work remains when no schema alternative survives
    pub(super) observation_work_bytes: usize,
    pub(super) details: Value,
    pub(super) work_limited: bool,
    pub(super) has_unassigned_family_messages: bool,
    pub(super) family_search_complete: bool,
    pub(super) assessment_scope: SchemaOffsetScope,
    // A checkpoint can reuse a plan only after proving its producing output
    producer_rule: Option<Arc<RelationalTransformRule>>,
}

#[derive(Clone, Copy)]
pub(super) struct SchemaCandidateOptions<'a> {
    pub(super) parser_format: ArtifactValidationFormat,
    pub(super) schema_limits: RecordSchemaProposalLimits,
    pub(super) artifact_policy: ArtifactValidationPolicy,
    pub(super) work_limit: usize,
    pub(super) job: Option<&'a Job>,
    pub(super) producer_rule: Option<&'a RelationalTransformRule>,
    pub(super) structural_admission: Option<&'a StructuralAdmission<'a>>,
}

#[derive(Clone, Copy)]
pub(super) struct StructuralAdmission<'a> {
    pub(super) memory: &'a MemoryBudget,
    pub(super) maximum: usize,
}

#[derive(Clone)]
pub(super) struct SchemaAlternative {
    pub(super) label: String,
    pub(super) frame_indices: Option<Arc<[usize]>>,
    discovery_report: Option<SchemaGateReport>,
    pub(super) limits: RecordSchemaProposalLimits,
    pub(super) discovery_work_bytes: usize,
    pub(super) learning_message_count: usize,
    pub(super) heldout_message_count: usize,
    pub(super) omitted_learning_messages: usize,
    pub(super) learning_session_count: usize,
    pub(super) proposal_search_exhaustive: bool,
    pub(super) status: GateStatus,
    pub(super) observed: Option<screen::SchemaAlternativeEvaluation>,
    pub(super) details: Value,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaGateReport {
    surviving: Vec<RecordSchemaHypothesis>,
    omitted_survivors: usize,
    unexamined_combinations: Option<usize>,
}

impl From<RecordSchemaDiscoveryReport> for SchemaGateReport {
    fn from(report: RecordSchemaDiscoveryReport) -> Self {
        Self {
            surviving: report.surviving,
            omitted_survivors: report.omitted_survivors,
            unexamined_combinations: report.unexamined_combinations,
        }
    }
}

impl SchemaPlanCache {
    /// Check a candidate against the cached cross-session schema plan
    pub(super) fn screen_candidate(
        &mut self,
        frames: &[DecodedFrameOutput],
        report: &RelationalTransformReport,
        options: SchemaCandidateOptions<'_>,
    ) -> Result<GateResult, RecoveryExecutionError> {
        let header_key = schema_header_key(
            frames,
            report,
            options.parser_format,
            options.artifact_policy,
            options.schema_limits,
            options
                .schema_limits
                .discovery
                .record_limits
                .max_report_bytes
                .min(MAX_CACHED_HEADER_PLAN_BYTES),
        )?;
        let key = schema_layout_key(
            frames,
            report,
            options.parser_format,
            options.artifact_policy,
            options.schema_limits,
            options.work_limit,
        )?;
        // Reuse plans only when their complete cache keys match
        if let Some(plan) = self.plans.get(&key) {
            let primary = screen_plan(frames, options, plan, true)?;
            return self.finish_primary_plan(frames, report, options, primary, header_key.as_ref());
        }
        if let Some(header_key) = header_key.as_ref()
            && let Some(plan) = self.header_plans.get(header_key)
        {
            return screen_header_cache_hit(frames, options, plan);
        }

        let plan = self.build_and_cache_plan(frames, report, options, key, header_key.as_ref())?;
        let mut result = screen_plan(frames, options, &plan, false)?;
        if let Some(details) = result.details.as_object_mut() {
            add_header_cache_miss_details(details, header_key.as_ref(), self);
        }
        self.finish_primary_plan(frames, report, options, result, header_key.as_ref())
    }

    fn build_and_cache_plan(
        &mut self,
        frames: &[DecodedFrameOutput],
        report: &RelationalTransformReport,
        options: SchemaCandidateOptions<'_>,
        key: SchemaLayoutKey,
        header_key: Option<&SchemaHeaderKey>,
    ) -> Result<Arc<SchemaPlan>, RecoveryExecutionError> {
        let header_inputs = header_key.map(|_| record_inputs(frames)).transpose()?;
        let mut built_plan =
            build_schema_plan_with_inputs(frames, report, options, header_inputs.as_deref())?;
        let producer_rule = options.producer_rule.map(|rule| Arc::new(rule.clone()));
        built_plan.producer_rule.clone_from(&producer_rule);
        let header_cache_has_slot = header_key.is_some()
            && self.plans.len().saturating_add(self.header_plans.len()) < MAX_CACHED_SCHEMA_PLANS;
        let header_plan_maximum = if header_cache_has_slot {
            header_plan_model_budget(
                options
                    .schema_limits
                    .discovery
                    .record_limits
                    .max_report_bytes
                    .min(MAX_CACHED_HEADER_PLAN_BYTES),
                self.header_plan_bytes,
                header_key.map_or(0, SchemaHeaderKey::retained_bytes),
            )
        } else {
            0
        };
        let mut header_plan = take_header_plan(&mut built_plan, header_plan_maximum)?;
        if let Some(header_plan) = &mut header_plan {
            header_plan.producer_rule = producer_rule;
        }
        for alternative in &mut built_plan.alternatives {
            if let Some(observed) = &mut alternative.observed {
                // Templates are only needed while constructing the reusable header plan
                drop(std::mem::take(&mut observed.header_models));
                observed.header_model_bytes = 0;
            }
        }
        if let Some(header_key) = header_key
            && let Some(header_plan) = header_plan
        {
            self.cache_header_plan(
                header_key.clone(),
                header_plan,
                options
                    .schema_limits
                    .discovery
                    .record_limits
                    .max_report_bytes
                    .min(MAX_CACHED_HEADER_PLAN_BYTES),
            )?;
        }
        let plan = Arc::new(built_plan);
        if self.plans.len().saturating_add(self.header_plans.len()) < MAX_CACHED_SCHEMA_PLANS {
            self.plans.try_reserve(1).map_err(|source| {
                operational("record gate schema cache allocation failed", source)
            })?;
            self.plans.insert(key, Arc::clone(&plan));
        }
        Ok(plan)
    }

    fn finish_primary_plan(
        &self,
        frames: &[DecodedFrameOutput],
        report: &RelationalTransformReport,
        options: SchemaCandidateOptions<'_>,
        primary: GateResult,
        header_key: Option<&SchemaHeaderKey>,
    ) -> Result<GateResult, RecoveryExecutionError> {
        if !primary.needs_full_inference() {
            return Ok(primary);
        }
        let reusable_header_plan =
            header_key.is_some_and(|key| self.header_plans.contains_key(key));
        if reusable_header_plan {
            return Ok(deferred_header_result(
                primary,
                "reusable_header_plan",
                "cached_partial_models",
            ));
        }

        let remaining_work = options.work_limit.saturating_sub(primary.work_bytes);
        if remaining_work == 0 {
            return Ok(deferred_header_result(
                primary,
                "application_work_reserve",
                SchemaOffsetScope::PreservedHeader.as_str(),
            ));
        }

        let primary_work = primary.work_bytes;
        let mut fallback_options = options;
        fallback_options.work_limit = remaining_work;
        let fallback = Self::screen_full_inference(frames, report, fallback_options)?;
        if fallback.work_bytes > remaining_work {
            return Err(invalid_policy(
                "cold complete-input inference exceeded its admitted work",
            ));
        }
        let total_work = primary_work
            .checked_add(fallback.work_bytes)
            .ok_or_else(|| invalid_policy("cold complete-input work count overflowed"))?;
        if total_work > options.work_limit {
            return Err(invalid_policy(
                "cold complete-input inference exceeded its work limit",
            ));
        }
        Ok(GateResult {
            status: fallback.status,
            work_bytes: total_work,
            work_limited_at: fallback.work_limited_at,
            details: serde_json::json!({
                "assessment_scope":SchemaOffsetScope::CompleteInput.as_str(),
                "schema_plan_cache_hit":false,
                "header_schema_plan_cache_hit":false,
                "primary_header_assessment":primary.details,
                "full_inference_deferred":false,
                "full_inference_fallback":{
                    "attempted":true,
                    "work_bytes":fallback.work_bytes,
                    "assessment":fallback.details,
                },
                "work_bytes":total_work,
                "work_limit":options.work_limit,
            }),
            accepted_schema: fallback.accepted_schema,
            structural_evidence: fallback.structural_evidence,
            assessment_scope: SchemaOffsetScope::CompleteInput,
        })
    }

    fn cache_header_plan(
        &mut self,
        key: SchemaHeaderKey,
        plan: HeaderSchemaPlan,
        maximum_bytes: usize,
    ) -> Result<(), RecoveryExecutionError> {
        if plan.assembly_plan.model_count() == 0
            || self.plans.len().saturating_add(self.header_plans.len()) >= MAX_CACHED_SCHEMA_PLANS
            || self.header_plans.contains_key(&key)
        {
            return Ok(());
        }
        let entry_bytes = key
            .retained_bytes()
            .checked_add(plan.retained_bytes)
            .ok_or_else(|| invalid_policy("header schema cache size overflowed"))?;
        let Some(total_bytes) = self.header_plan_bytes.checked_add(entry_bytes) else {
            return Ok(());
        };
        if total_bytes > maximum_bytes {
            return Ok(());
        }
        self.header_plans
            .try_reserve(1)
            .map_err(|source| operational("header schema cache allocation failed", source))?;
        self.header_plans.insert(key, Arc::new(plan));
        self.header_plan_bytes = total_bytes;
        Ok(())
    }

    /// Run complete schema inference after a cached header-only probe found no artifact
    pub(super) fn screen_full_inference(
        frames: &[DecodedFrameOutput],
        report: &RelationalTransformReport,
        options: SchemaCandidateOptions<'_>,
    ) -> Result<GateResult, RecoveryExecutionError> {
        let plan = build_full_schema_plan(frames, report, options)?;
        let mut result = screen_with_schema_plan_with_memory(frames, options, &plan, false)?;
        result.assessment_scope = SchemaOffsetScope::CompleteInput;
        if let Some(details) = result.details.as_object_mut() {
            details.insert("full_inference_fallback".to_owned(), Value::Bool(true));
            details.insert(
                "full_inference_fallback_work_bytes".to_owned(),
                Value::from(result.work_bytes),
            );
        }
        Ok(result)
    }
}

const fn header_plan_model_budget(
    maximum_bytes: usize,
    cached_bytes: usize,
    key_bytes: usize,
) -> usize {
    maximum_bytes
        .saturating_sub(cached_bytes)
        .saturating_sub(key_bytes)
        .saturating_sub(std::mem::size_of::<HeaderSchemaPlan>())
}

fn screen_plan(
    frames: &[DecodedFrameOutput],
    options: SchemaCandidateOptions<'_>,
    plan: &SchemaPlan,
    cache_hit: bool,
) -> Result<GateResult, RecoveryExecutionError> {
    screen_with_schema_plan_with_memory(frames, options, plan, cache_hit)
}

fn add_header_cache_miss_details(
    details: &mut serde_json::Map<String, Value>,
    header_key: Option<&SchemaHeaderKey>,
    cache: &SchemaPlanCache,
) {
    let retained_plan = header_key.and_then(|key| cache.header_plans.get(key));
    details.insert(
        "header_schema_plan_cache_hit".to_owned(),
        Value::Bool(false),
    );
    details.insert(
        "header_schema_models_retained".to_owned(),
        Value::from(retained_plan.map_or(0, |plan| plan.assembly_plan.model_count())),
    );
    details.insert(
        "header_schema_plan_retained_bytes".to_owned(),
        Value::from(retained_plan.map_or(0, |plan| plan.retained_bytes)),
    );
}

fn deferred_header_result(
    mut primary: GateResult,
    reason: &'static str,
    assessment_scope: &'static str,
) -> GateResult {
    let work_bytes = primary.work_bytes;
    let schema_plan_cache_hit = primary
        .details
        .get("schema_plan_cache_hit")
        .and_then(Value::as_bool);
    let header_schema_plan_cache_hit = primary
        .details
        .get("header_schema_plan_cache_hit")
        .and_then(Value::as_bool);
    let header_schema_models_retained = primary
        .details
        .get("header_schema_models_retained")
        .and_then(Value::as_u64);
    let header_schema_plan_retained_bytes = primary
        .details
        .get("header_schema_plan_retained_bytes")
        .and_then(Value::as_u64);
    let mut details = serde_json::json!({
        "assessment_scope":assessment_scope,
        "primary_header_assessment":primary.details,
        "full_inference_deferred":true,
        "full_inference_fallback":{
            "attempted":false,
            "reason":reason,
            "work_bytes":0,
        },
        "full_inference_fallback_work_bytes":0,
        "work_bytes":work_bytes,
    });
    if let Some(details) = details.as_object_mut() {
        if let Some(cache_hit) = schema_plan_cache_hit {
            details.insert("schema_plan_cache_hit".to_owned(), Value::Bool(cache_hit));
        }
        if let Some(cache_hit) = header_schema_plan_cache_hit {
            details.insert(
                "header_schema_plan_cache_hit".to_owned(),
                Value::Bool(cache_hit),
            );
        }
        if let Some(models) = header_schema_models_retained {
            details.insert(
                "header_schema_models_retained".to_owned(),
                Value::from(models),
            );
        }
        if let Some(bytes) = header_schema_plan_retained_bytes {
            details.insert(
                "header_schema_plan_retained_bytes".to_owned(),
                Value::from(bytes),
            );
        }
    }
    primary.details = details;
    primary.assessment_scope = SchemaOffsetScope::PreservedHeader;
    primary
}

fn record_inputs(
    frames: &[DecodedFrameOutput],
) -> Result<Vec<RecordInput<'_>>, RecoveryExecutionError> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(frames.len())
        .map_err(|source| operational("record gate input identity allocation failed", source))?;
    inputs.extend(frames.iter().map(|frame| RecordInput::new(&frame.bytes)));
    Ok(inputs)
}

fn screen_header_cache_hit(
    frames: &[DecodedFrameOutput],
    options: SchemaCandidateOptions<'_>,
    header_plan: &HeaderSchemaPlan,
) -> Result<GateResult, RecoveryExecutionError> {
    screen_with_header_plan(
        frames,
        options.parser_format,
        options.artifact_policy,
        options.schema_limits,
        options.work_limit,
        options.job,
        header_plan,
    )
}

fn take_header_plan(
    plan: &mut SchemaPlan,
    maximum_retained_bytes: usize,
) -> Result<Option<HeaderSchemaPlan>, RecoveryExecutionError> {
    let Some(alternative) = plan.alternatives.iter_mut().find(|alternative| {
        alternative.label.ends_with(":fixed_layout") && alternative.frame_indices.is_none()
    }) else {
        return Ok(None);
    };
    let Some(observed) = alternative.observed.as_mut() else {
        return Ok(None);
    };
    if maximum_retained_bytes == 0 {
        drop(std::mem::take(&mut observed.header_models));
        return Ok(None);
    }
    if observed.header_models.is_empty() {
        return Ok(None);
    }
    let models = std::mem::take(&mut observed.header_models);
    let mut compiled_models = Vec::new();
    compiled_models
        .try_reserve_exact(models.len())
        .map_err(|source| operational("record gate compiled model allocation failed", source))?;
    for model in models {
        compiled_models.push(RecordAssemblyHeaderModel::new(
            model.schema,
            model.limits,
            model.templates,
        ));
    }
    let assembly_plan =
        match RecordAssemblyPlan::compile_header_models(compiled_models, maximum_retained_bytes) {
            Ok(plan) => plan,
            Err(l2_workbench::protocol::RecordError::PlanTooLarge { .. }) => return Ok(None),
            Err(source) => {
                return Err(operational(
                    "record gate header plan compilation failed",
                    source,
                ));
            }
        };
    let retained_bytes =
        std::mem::size_of::<HeaderSchemaPlan>().saturating_add(assembly_plan.retained_bytes());
    Ok(Some(HeaderSchemaPlan {
        assembly_plan,
        retained_bytes,
        omitted_models: observed.header_models_omitted,
        producer_rule: None,
    }))
}

pub(super) fn record_job_work(
    job: &Job,
    phase: Phase,
    counter: Counter,
    amount: u64,
) -> Result<(), RecoveryExecutionError> {
    job.record_work(phase, counter, amount).map_err(Into::into)
}

pub(super) fn total_input_bytes(
    frames: &[DecodedFrameOutput],
) -> Result<usize, RecoveryExecutionError> {
    frames
        .iter()
        .try_fold(0_usize, |total, frame| total.checked_add(frame.bytes.len()))
        .ok_or_else(|| invalid_policy("record gate full input byte count overflowed"))
}

const fn result(status: GateStatus, work_bytes: usize, details: Value) -> GateResult {
    GateResult {
        status,
        work_bytes,
        work_limited_at: None,
        details,
        accepted_schema: None,
        structural_evidence: None,
        assessment_scope: SchemaOffsetScope::CompleteInput,
    }
}
