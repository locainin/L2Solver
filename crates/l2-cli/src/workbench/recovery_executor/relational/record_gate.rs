//! In-memory record and artifact checks used before relational output retention

mod header;
mod key;
mod plan;
mod screen;
mod selection;

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

use self::{
    header::HeaderSchemaPlan,
    key::{SchemaHeaderKey, SchemaLayoutKey, schema_header_key, schema_layout_key},
    plan::{build_schema_plan, build_schema_plan_with_inputs},
    screen::{screen_with_header_plan, screen_with_schema_plan},
};
use super::super::RecoveryExecutionError;
use super::{DecodedFrameOutput, invalid_policy, operational};
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationPolicy},
    job::{Counter, Job, Phase},
    protocol::{
        RecordInput, RecordSchemaDiscoveryReport, RecordSchemaProposalLimits,
        RelationalTransformReport,
    },
};
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};

const MAX_CACHED_SCHEMA_PLANS: usize = 32;
const MAX_CACHED_HEADER_PLAN_BYTES: usize = l2_workbench::protocol::DEFAULT_MAX_RECORD_REPORT_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    pub(super) details: Value,
    pub(super) accepted_schema: Option<screen::AcceptedRecordSchema>,
}

#[derive(Default)]
pub(super) struct SchemaPlanCache {
    plans: HashMap<SchemaLayoutKey, Arc<SchemaPlan>>,
    header_plans: HashMap<SchemaHeaderKey, Arc<HeaderSchemaPlan>>,
    header_plan_bytes: usize,
}

pub(super) struct SchemaPlan {
    pub(super) alternatives: Vec<SchemaAlternative>,
    pub(super) details: Value,
    pub(super) has_unassigned_family_messages: bool,
    pub(super) family_search_complete: bool,
}

#[derive(Clone, Copy)]
pub(super) struct SchemaCandidateOptions<'a> {
    pub(super) parser_format: ArtifactValidationFormat,
    pub(super) schema_limits: RecordSchemaProposalLimits,
    pub(super) artifact_policy: ArtifactValidationPolicy,
    pub(super) work_limit: usize,
    pub(super) job: Option<&'a Job>,
}

#[derive(Clone)]
pub(super) struct SchemaAlternative {
    pub(super) label: String,
    pub(super) frame_indices: Option<Arc<[usize]>>,
    discovery_report: Option<RecordSchemaDiscoveryReport>,
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

impl SchemaPlanCache {
    /// Check a candidate against the cached cross-session schema plan
    pub(super) fn screen_candidate(
        &mut self,
        frames: &[DecodedFrameOutput],
        report: &RelationalTransformReport,
        options: SchemaCandidateOptions<'_>,
    ) -> Result<GateResult, RecoveryExecutionError> {
        let key = schema_layout_key(
            frames,
            report,
            options.parser_format,
            options.artifact_policy,
            options.schema_limits,
            options.work_limit,
        )?;
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
        // Reuse plans only when their complete cache keys match
        if let Some(plan) = self.plans.get(&key) {
            return screen_plan(frames, options, plan, true);
        }
        if let Some(header_key) = header_key.as_ref()
            && let Some(plan) = self.header_plans.get(header_key)
        {
            return screen_header_cache_hit(frames, report, options, plan);
        }

        let plan = self.build_and_cache_plan(frames, report, options, key, header_key.as_ref())?;
        let mut result = screen_plan(frames, options, &plan, false)?;
        if let Some(details) = result.details.as_object_mut() {
            add_header_cache_miss_details(details, header_key.as_ref(), self);
        }
        Ok(result)
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
        let mut built_plan = if let Some(inputs) = header_inputs.as_deref() {
            build_schema_plan_with_inputs(frames, report, options, Some(inputs))?
        } else {
            build_schema_plan(
                frames,
                report,
                options.schema_limits,
                options.work_limit,
                options.parser_format,
                options.artifact_policy,
                options.job,
            )?
        };
        if let Some(header_key) = header_key
            && let Some(header_plan) = take_header_plan(&mut built_plan)
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

    fn cache_header_plan(
        &mut self,
        key: SchemaHeaderKey,
        plan: HeaderSchemaPlan,
        maximum_bytes: usize,
    ) -> Result<(), RecoveryExecutionError> {
        if plan.models.is_empty()
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
}

fn screen_plan(
    frames: &[DecodedFrameOutput],
    options: SchemaCandidateOptions<'_>,
    plan: &SchemaPlan,
    cache_hit: bool,
) -> Result<GateResult, RecoveryExecutionError> {
    screen_with_schema_plan(
        frames,
        options.parser_format,
        options.artifact_policy,
        options.work_limit,
        options.job,
        plan,
        cache_hit,
    )
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
        Value::from(retained_plan.map_or(0, |plan| plan.models.len())),
    );
    details.insert(
        "header_schema_plan_retained_bytes".to_owned(),
        Value::from(retained_plan.map_or(0, |plan| plan.retained_bytes)),
    );
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
    report: &RelationalTransformReport,
    options: SchemaCandidateOptions<'_>,
    header_plan: &HeaderSchemaPlan,
) -> Result<GateResult, RecoveryExecutionError> {
    let header_result = screen_with_header_plan(
        frames,
        options.parser_format,
        options.artifact_policy,
        options.schema_limits,
        options.work_limit,
        options.job,
        header_plan,
    )?;
    if header_result.status == GateStatus::ArtifactValidated
        || header_result.work_bytes >= options.work_limit
    {
        return Ok(header_result);
    }

    let remaining_work = options.work_limit.saturating_sub(header_result.work_bytes);
    let fallback_plan = Arc::new(build_schema_plan(
        frames,
        report,
        options.schema_limits,
        remaining_work,
        options.parser_format,
        options.artifact_policy,
        options.job,
    )?);
    let mut result = screen_with_schema_plan(
        frames,
        options.parser_format,
        options.artifact_policy,
        remaining_work,
        options.job,
        &fallback_plan,
        false,
    )?;
    result.work_bytes = result.work_bytes.saturating_add(header_result.work_bytes);
    if let Value::Object(details) = &mut result.details {
        let checked_models = header_result
            .details
            .get("header_schema_models_checked")
            .and_then(Value::as_u64)
            .map_or_else(|| Value::from(0), Value::from);
        let replay_details = header_result.details;
        details.insert("header_schema_plan_cache_hit".to_owned(), Value::Bool(true));
        details.insert(
            "header_schema_models".to_owned(),
            Value::from(header_plan.models.len()),
        );
        details.insert(
            "header_schema_models_omitted".to_owned(),
            Value::from(header_plan.omitted_models),
        );
        details.insert("header_schema_models_checked".to_owned(), checked_models);
        details.insert(
            "header_schema_work_bytes".to_owned(),
            Value::from(header_result.work_bytes),
        );
        details.insert("header_schema_replay".to_owned(), replay_details);
        details.insert("work_bytes".to_owned(), Value::from(result.work_bytes));
    }
    Ok(result)
}

fn take_header_plan(plan: &mut SchemaPlan) -> Option<HeaderSchemaPlan> {
    let alternative = plan.alternatives.iter_mut().find(|alternative| {
        alternative.label.ends_with(":fixed_layout") && alternative.frame_indices.is_none()
    })?;
    let observed = alternative.observed.as_mut()?;
    if observed.header_models.is_empty() {
        return None;
    }
    let models = std::mem::take(&mut observed.header_models);
    let retained_bytes = models.iter().fold(
        std::mem::size_of::<HeaderSchemaPlan>()
            .saturating_add(std::mem::size_of_val(models.as_slice())),
        |total, model| total.saturating_add(model.retained_bytes),
    );
    Some(HeaderSchemaPlan {
        models,
        retained_bytes,
        omitted_models: observed.header_models_omitted,
    })
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
        details,
        accepted_schema: None,
    }
}
