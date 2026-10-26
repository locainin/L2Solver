//! In-memory record and artifact checks used before relational output retention

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
    key::{SchemaLayoutKey, schema_layout_key},
    plan::build_schema_plan,
    screen::screen_with_schema_plan,
};
use super::super::RecoveryExecutionError;
use super::{DecodedFrameOutput, invalid_policy, operational};
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationPolicy},
    job::{Counter, Job, Phase},
    protocol::{
        RecordSchemaDiscoveryReport, RecordSchemaProposalLimits, RelationalTransformReport,
    },
};
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};

const MAX_CACHED_SCHEMA_PLANS: usize = 32;

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
        // Reuse only bounded plans with the same sessions and frame layout
        let (plan, cache_hit) = if let Some(plan) = self.plans.get(&key) {
            (Arc::clone(plan), true)
        } else {
            let plan = Arc::new(build_schema_plan(
                frames,
                report,
                options.schema_limits,
                options.work_limit,
                options.parser_format,
                options.artifact_policy,
                options.job,
            )?);
            if self.plans.len() < MAX_CACHED_SCHEMA_PLANS {
                self.plans.try_reserve(1).map_err(|source| {
                    operational("record gate schema cache allocation failed", source)
                })?;
                self.plans.insert(key, Arc::clone(&plan));
            }
            (plan, false)
        };

        screen_with_schema_plan(
            frames,
            options.parser_format,
            options.artifact_policy,
            options.work_limit,
            options.job,
            &plan,
            cache_hit,
        )
    }
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
