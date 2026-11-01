//! Bounded relational transform discovery over strict per-session record candidates

mod application;
pub(super) mod checkpoint;
mod history;
mod input;
mod publication;
mod record_gate;
mod report;
mod search;

pub(super) use application::aggregate_validator;

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_relational/materialization.rs"]
mod materialization_tests;

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_relational/gate_checkpoint.rs"]
mod gate_checkpoint_tests;

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_relational/prepared_checkpoint.rs"]
mod prepared_checkpoint_tests;

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_relational/application_fallback.rs"]
mod application_fallback_tests;

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_relational/search_budget.rs"]
mod search_budget_tests;

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_relational/producer_admission.rs"]
mod producer_admission_tests;

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_relational/scheduler.rs"]
mod scheduler_tests;

use super::record_discovery::{RecordCohortKey, RecordCohortOrigin, RecordFrameInput};
use super::{
    Executor, RecoveryCandidateId, RecoveryExecutionError, RecoveryOmission, RecoveryStage,
    RecoveryTask,
};
use l2_workbench::{
    protocol::{MessageContext, RecordSchema, RelationalAppliedOutput},
    recovery::{EnqueueOutcome, RecoveryError, RecoveryResult},
};
use record_gate::{AcceptedRecordSchema, GateStatus, SchemaOffsetScope};
use serde_json::Value;
use std::collections::{BTreeSet, HashSet};

const REPORT_KIND: &str = "recovery_relational_transform_report";
const REPORT_VERSION: u16 = 2;
const OUTPUT_KIND: &str = "relational_transform_output";
pub(super) const MAX_RETAINED_RELATIONAL_APPLICATIONS: usize = 8;
pub(super) const DECODED_FRAME_KIND: &str = "relational_decoded_frame";
const OUTPUT_REASON: &str = "This exact output was produced by a frozen session-relative rule that passed its parser checks";
const DECODED_FRAME_REASON: &str = "This frame preserves its observed header while replacing only the range transformed by the frozen relational rule";
const INPUT_REASON: &str =
    "This assembled record candidate was included in a bounded cross-session relational analysis";
const RAW_RUN_FRAMING_RULE: &str = "{\"kind\":\"raw_directional_run\"}";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize)]
struct RelationalCohortKey {
    source_id: String,
    scope_json: String,
    endpoints_json: String,
    direction: l2_workbench::protocol::Direction,
    framing_rule_json: String,
    schema_json: String,
}

#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct StoredSample {
    node_id: u64,
    context: MessageContext,
    session_order: u64,
    direction_node_id: u64,
    episode_node_id: u64,
    stream_offset: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct HistorySampleIdentity {
    node_id: u64,
    session: u64,
    session_order: u64,
    direction_node_id: u64,
    episode_node_id: u64,
    stream_offset: usize,
}

fn history_input_signature(
    key: &RelationalCohortKey,
    samples: &[StoredSample],
    maximum_bytes: usize,
) -> Option<Vec<HistorySampleIdentity>> {
    let bytes = samples
        .len()
        .checked_mul(std::mem::size_of::<HistorySampleIdentity>())?;
    if bytes > maximum_bytes {
        return None;
    }
    let mut identities = Vec::new();
    identities.try_reserve_exact(samples.len()).ok()?;
    if identities
        .capacity()
        .checked_mul(std::mem::size_of::<HistorySampleIdentity>())?
        > maximum_bytes
    {
        return None;
    }
    for sample in samples {
        identities.push(history_sample_identity(key, sample)?);
    }
    Some(identities)
}

fn history_sample_identity(
    key: &RelationalCohortKey,
    sample: &StoredSample,
) -> Option<HistorySampleIdentity> {
    if sample.context.source != key.source_id
        || sample.context.scope != key.scope_json
        || sample.context.direction != key.direction
    {
        return None;
    }
    Some(HistorySampleIdentity {
        node_id: sample.node_id,
        session: sample.context.session,
        session_order: sample.session_order,
        direction_node_id: sample.direction_node_id,
        episode_node_id: sample.episode_node_id,
        stream_offset: sample.stream_offset,
    })
}

fn history_input_matches(
    key: &RelationalCohortKey,
    samples: &[StoredSample],
    expected: &[HistorySampleIdentity],
) -> bool {
    samples.len() == expected.len()
        && samples
            .iter()
            .zip(expected)
            .all(|(sample, identity)| history_sample_identity(key, sample) == Some(*identity))
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct SampleCohort {
    key: Option<RelationalCohortKey>,
    samples: Vec<StoredSample>,
    #[serde(with = "crate::workbench::recovery_executor::checkpoint::collections::hash_set")]
    incomplete_sessions: HashSet<u64>,
    #[serde(with = "crate::workbench::recovery_executor::checkpoint::collections::hash_set")]
    omitted_sample_ids: HashSet<u64>,
    scheduled_sample_count: usize,
    completed_sample_count: usize,
    evidence_limit_reported: bool,
    omitted_sessions: usize,
    omitted_samples: usize,
    source_eligibility_omissions: usize,
    input_coverage_complete: bool,
}

impl SampleCohort {
    fn new(key: RelationalCohortKey) -> Self {
        Self {
            key: Some(key),
            input_coverage_complete: true,
            ..Self::default()
        }
    }

    fn active_samples(&self) -> impl Iterator<Item = &StoredSample> {
        self.samples
            .iter()
            .filter(|sample| !self.incomplete_sessions.contains(&sample.context.session))
    }

    fn active_session_ids(&self) -> Result<HashSet<u64>, RecoveryExecutionError> {
        let mut sessions = HashSet::new();
        for sample in self.active_samples() {
            if !sessions.contains(&sample.context.session) {
                sessions.try_reserve(1).map_err(|source| {
                    operational("relational session index allocation failed", source)
                })?;
                sessions.insert(sample.context.session);
            }
        }
        Ok(sessions)
    }
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub(super) struct RelationalSampleCollections {
    cohorts: Vec<SampleCohort>,
    incremental_cohorts: Vec<SampleCohort>,
    histories: history::RelationalReplayHistories,
    incremental_metadata_used: usize,
    incremental_metadata_stop: Option<std::borrow::Cow<'static, str>>,
    incremental_metadata_reported: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(super) enum RelationalLane {
    Normal,
    Incremental,
}

impl RelationalSampleCollections {
    fn cohorts(&self, lane: RelationalLane) -> &[SampleCohort] {
        match lane {
            RelationalLane::Normal => &self.cohorts,
            RelationalLane::Incremental => &self.incremental_cohorts,
        }
    }

    const fn cohorts_mut(&mut self, lane: RelationalLane) -> &mut Vec<SampleCohort> {
        match lane {
            RelationalLane::Normal => &mut self.cohorts,
            RelationalLane::Incremental => &mut self.incremental_cohorts,
        }
    }
}

pub(in crate::workbench::recovery_executor) struct RawRelationalRunInput {
    pub(in crate::workbench::recovery_executor) node_id: u64,
    pub(in crate::workbench::recovery_executor) episode_node_id: u64,
    pub(in crate::workbench::recovery_executor) direction_node_id: u64,
    pub(in crate::workbench::recovery_executor) session_order: u64,
    pub(in crate::workbench::recovery_executor) stream_offset: usize,
    pub(in crate::workbench::recovery_executor) start_known: bool,
}

#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(super) struct RelationalDiscoveryContext {
    lane: RelationalLane,
    key: RelationalCohortKey,
    sample_node_ids: Vec<u64>,
    samples: Vec<StoredSample>,
    sessions_available: usize,
    omitted_sessions: usize,
    omitted_samples: usize,
    source_eligibility_omissions: usize,
    input_coverage_complete: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AppliedOutput {
    candidate_index: usize,
    #[serde(with = "l2_workbench::job::checkpoint_relational_output")]
    value: RelationalAppliedOutput,
    sha256: String,
    parser_format: l2_workbench::artifact::ArtifactValidationFormat,
    session_ids: Vec<u64>,
    session_orders: Vec<u64>,
    seed_samples: Vec<u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreparedRelationalCohort {
    context: RelationalDiscoveryContext,
    #[serde(with = "l2_workbench::job::checkpoint_bytes")]
    report_bytes: Vec<u8>,
    outputs: Vec<AppliedOutput>,
    decoded_frames: Vec<DecodedFrameOutput>,
    accepted_schemas: Vec<(usize, AcceptedRecordSchema)>,
    structural_evidence: Vec<(usize, record_gate::StructuralEvidence)>,
    // Retained data can be checked against its exact producing rule after restoration
    producer_rules: Vec<(usize, l2_workbench::protocol::RelationalTransformRule)>,
    // The cohort admission replaces this temporary charge before the next checkpoint
    #[serde(skip)]
    producer_memory: Option<l2_workbench::job::MemoryLease>,
    published_rules: Vec<l2_workbench::protocol::RelationalTransformRule>,
    history_used: bool,
    report_details_complete: bool,
    search_exhaustive_within_plan: bool,
    candidate_limit_remaining: usize,
    locator_candidate_limit_remaining: usize,
    work_bytes_remaining: usize,
    reason: Option<std::borrow::Cow<'static, str>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodedFrameOutput {
    context: MessageContext,
    input_node_id: u64,
    seed_sample: u64,
    session_order: u64,
    transformed_output_sha256: String,
    direction_node_id: u64,
    episode_node_id: u64,
    stream_offset: usize,
    candidate_index: usize,
    parser_format: l2_workbench::artifact::ArtifactValidationFormat,
    expected_session_orders: Vec<u64>,
    payload_range: l2_workbench::protocol::ByteRange,
    preserved_header_end: Option<usize>,
    #[serde(with = "l2_workbench::job::checkpoint_bytes")]
    bytes: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GateAssessment {
    status: GateStatus,
    details: Value,
    accepted_schema: Option<AcceptedRecordSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    structural_evidence: Option<record_gate::StructuralEvidence>,
    assessment_scope: Option<SchemaOffsetScope>,
    work_limited_at: Option<usize>,
}

impl GateAssessment {
    fn needs_full_inference(&self, available_work: usize) -> bool {
        if self.status == GateStatus::ArtifactValidated {
            return false;
        }
        // A larger application allowance can finish work cut short during ranking
        matches!(
            self.assessment_scope,
            Some(SchemaOffsetScope::PreservedHeader)
        ) || self
            .work_limited_at
            .is_some_and(|previous_limit| available_work > previous_limit)
    }
}

struct RetainedRelationalRule {
    candidate_index: usize,
    evidence_priority: u8,
    outputs: Vec<AppliedOutput>,
    decoded_frames: Vec<DecodedFrameOutput>,
    accepted_schema: Option<AcceptedRecordSchema>,
}

struct CommittedRelationalOutputs {
    output_node_ids: Vec<u64>,
    decoded_record_inputs: Vec<(RecordCohortKey, Vec<RecordFrameInput>)>,
    accepted_record_schemas: Vec<(Vec<u64>, RecordSchema, u64)>,
}

impl Executor<'_> {
    pub(super) fn report_incremental_metadata_omission(
        &mut self,
    ) -> Result<(), RecoveryExecutionError> {
        let Some(reason) = self.relational_samples.incremental_metadata_stop.clone() else {
            return Ok(());
        };
        if self.relational_samples.incremental_metadata_reported {
            return Ok(());
        }
        let limit = self
            .policy
            .relational_incremental_plan
            .as_ref()
            .ok_or(RecoveryError::InvariantFailure)?
            .limits
            .max_total_bytes;
        self.omissions.try_reserve(1).map_err(|source| {
            operational("relational metadata omission allocation failed", source)
        })?;
        self.omissions
            .push(RecoveryOmission::RelationalIncrementalMetadata { limit, reason });
        self.relational_samples.incremental_metadata_reported = true;
        Ok(())
    }

    pub(super) fn omit_unsearched_incremental_cohorts(
        &mut self,
    ) -> Result<(), RecoveryExecutionError> {
        let Some(plan) = &self.policy.relational_incremental_plan else {
            return Ok(());
        };
        self.omissions
            .try_reserve(self.relational_samples.incremental_cohorts.len())
            .map_err(|source| operational("relational omission allocation failed", source))?;
        for cohort in &mut self.relational_samples.incremental_cohorts {
            let sample_count = cohort.active_samples().count();
            if sample_count <= cohort.completed_sample_count || cohort.evidence_limit_reported {
                continue;
            }
            let source_id = cohort
                .key
                .as_ref()
                .ok_or(RecoveryError::InvariantFailure)?
                .source_id
                .clone();
            let sessions_available = cohort.active_session_ids()?.len();
            self.omissions
                .push(RecoveryOmission::RelationalTransformAnalysis {
                    source_id,
                    sessions_available,
                    omitted_sessions: cohort.omitted_sessions,
                    omitted_samples: cohort.omitted_samples,
                    omitted_rules: 0,
                    candidate_limit_remaining: plan.limits.max_candidates,
                    locator_candidate_limit_remaining: plan
                        .limits
                        .max_locator_candidates
                        .saturating_mul(2),
                    work_bytes_remaining: plan
                        .limits
                        .max_work_bytes
                        .min(self.coordinator.remaining_work_bytes()),
                    input_coverage_complete: cohort.input_coverage_complete,
                    search_exhaustive_within_plan: false,
                    report_details_complete: false,
                    reason: Some("incremental_evidence_limit".into()),
                });
            cohort.evidence_limit_reported = true;
        }
        Ok(())
    }

    fn relational_session_omission(
        &mut self,
        source_id: &str,
        omitted_sessions: usize,
        omitted_samples: usize,
        input_coverage_complete: bool,
        reason: &'static str,
        limits: l2_workbench::protocol::RelationalTransformLimits,
    ) -> Result<(), RecoveryExecutionError> {
        self.omissions
            .try_reserve(1)
            .map_err(|source| operational("relational omission allocation failed", source))?;
        self.omissions
            .push(RecoveryOmission::RelationalTransformAnalysis {
                source_id: try_clone_string(source_id).map_err(|source| {
                    operational("relational omission source allocation failed", source)
                })?,
                sessions_available: 0,
                omitted_sessions,
                omitted_samples,
                omitted_rules: 0,
                candidate_limit_remaining: limits.max_candidates,
                locator_candidate_limit_remaining: limits.max_locator_candidates.saturating_mul(2),
                work_bytes_remaining: limits.max_work_bytes,
                input_coverage_complete,
                search_exhaustive_within_plan: false,
                report_details_complete: true,
                reason: Some(reason.into()),
            });
        Ok(())
    }

    pub(super) fn flush_relational_cohorts(
        &mut self,
        lane: RelationalLane,
    ) -> Result<bool, RecoveryExecutionError> {
        let mut scheduled_any = false;
        let task = match lane {
            RelationalLane::Normal => RecoveryTask::RelationalTransformDiscovery,
            RelationalLane::Incremental => RecoveryTask::RelationalTransformDiscoveryIncremental,
        };
        for cohort_index in 0..self.relational_samples.cohorts(lane).len() {
            let (sample_node_ids, context) = {
                let cohort = self
                    .relational_samples
                    .cohorts_mut(lane)
                    .get_mut(cohort_index)
                    .ok_or(RecoveryError::InvariantFailure)?;
                let key = cohort.key.clone().ok_or(RecoveryError::InvariantFailure)?;
                let mut active = cohort.active_samples().cloned().collect::<Vec<_>>();
                active.sort_by_key(|sample| {
                    (
                        sample.context.session,
                        sample.stream_offset,
                        sample.context.direction,
                        sample.node_id,
                    )
                });
                if active.len() <= cohort.scheduled_sample_count {
                    continue;
                }
                let mut node_ids = Vec::new();
                node_ids
                    .try_reserve_exact(active.len())
                    .map_err(|source| operational("relational input allocation failed", source))?;
                node_ids.extend(active.iter().map(|sample| sample.node_id));
                let sessions_available = active
                    .iter()
                    .map(|sample| sample.context.session)
                    .collect::<BTreeSet<_>>()
                    .len();
                cohort.scheduled_sample_count = active.len();
                (
                    node_ids.clone(),
                    RelationalDiscoveryContext {
                        lane,
                        key,
                        sample_node_ids: node_ids,
                        samples: active,
                        sessions_available,
                        omitted_sessions: cohort.omitted_sessions,
                        omitted_samples: cohort.omitted_samples,
                        source_eligibility_omissions: cohort.source_eligibility_omissions,
                        input_coverage_complete: cohort.input_coverage_complete,
                    },
                )
            };
            let result =
                self.coordinator
                    .enqueue_nodes(self.case, &sample_node_ids, task.clone())?;
            let candidate_id = match &result {
                EnqueueOutcome::Queued(id)
                | EnqueueOutcome::Merged(id)
                | EnqueueOutcome::MergedNeedsContext(id)
                | EnqueueOutcome::CycleSkipped { candidate_id: id } => Some(*id),
                EnqueueOutcome::ResourceExhausted { .. } => None,
            };
            self.record_enqueue(result, &task, &sample_node_ids)?;
            if let Some(candidate_id) = candidate_id {
                let contexts = self.relational_discoveries.entry(candidate_id).or_default();
                if !contexts.iter().any(|existing| {
                    existing.key == context.key
                        && existing.sample_node_ids == context.sample_node_ids
                }) {
                    contexts.try_reserve(1).map_err(|source| {
                        operational("relational discovery context allocation failed", source)
                    })?;
                    contexts.push(context);
                }
            }
            scheduled_any = true;
        }
        Ok(scheduled_any)
    }

    pub(super) fn run_relational_transform_discovery(
        &mut self,
        candidate_id: RecoveryCandidateId,
    ) -> Result<(), RecoveryExecutionError> {
        let contexts = self
            .relational_discoveries
            .get(&candidate_id)
            .cloned()
            .ok_or(RecoveryError::InvariantFailure)?;
        if contexts.is_empty() {
            return Err(RecoveryError::InvariantFailure.into());
        }
        let mut work_remaining = self.coordinator.remaining_work_bytes();
        let (_, base_plan) = self.relational_task_plan(candidate_id)?;
        let mut histories = std::mem::take(&mut self.relational_samples.histories);
        let prepared = {
            let job = self.job.as_ref().map(|progress| &progress.job);
            search::prepare_contexts(
                self,
                contexts,
                &base_plan,
                &mut work_remaining,
                &mut histories,
                job,
            )
        };
        self.relational_samples.histories = histories;
        self.publish_prepared_relational(candidate_id, &prepared?, work_remaining)
    }

    pub(super) fn publish_prepared_relational(
        &mut self,
        candidate_id: RecoveryCandidateId,
        prepared: &[PreparedRelationalCohort],
        work_remaining: usize,
    ) -> Result<(), RecoveryExecutionError> {
        let contexts = self
            .relational_discoveries
            .get(&candidate_id)
            .ok_or(RecoveryError::InvariantFailure)?;
        let origins = contexts
            .iter()
            .flat_map(|context| context.sample_node_ids.iter().copied())
            .collect::<Vec<_>>();
        let (task, _) = self.relational_task_plan(candidate_id)?;
        let total_work = self
            .coordinator
            .remaining_work_bytes()
            .checked_sub(work_remaining)
            .ok_or(RecoveryError::InvariantFailure)?;
        if !self.charge_work(candidate_id, &task, &origins, total_work)? {
            self.discard_unpublished_histories(prepared);
            return Ok(());
        }
        if !self.check_output(
            candidate_id,
            &task,
            &origins,
            prepared_output_bytes(prepared)?,
        )? {
            self.discard_unpublished_histories(prepared);
            return Ok(());
        }
        self.omissions
            .try_reserve(prepared.len())
            .map_err(|source| operational("relational omission allocation failed", source))?;
        let committed = self.case_transaction_and_finish(candidate_id, |case| {
            publication::publish_prepared_cohorts(case, prepared)
        })?;
        self.record_committed_cohorts(prepared);
        self.record_relational_omissions(prepared);
        for output_node in committed.output_node_ids {
            self.enqueue_root(output_node, OUTPUT_KIND)?;
        }
        if self.plan.discover_records {
            self.defer_record_schema_group(committed.accepted_record_schemas)?;
        }
        for (key, frames) in committed.decoded_record_inputs {
            self.enqueue_relational_record_discovery(key, frames)?;
        }
        Ok(())
    }

    pub(super) fn relational_task_plan(
        &self,
        candidate_id: RecoveryCandidateId,
    ) -> Result<
        (
            RecoveryTask,
            l2_workbench::protocol::RelationalTransformPlan,
        ),
        RecoveryExecutionError,
    > {
        let task = self
            .coordinator
            .candidate(candidate_id)
            .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?
            .task()
            .clone();
        let base_plan = match task {
            RecoveryTask::RelationalTransformDiscovery => {
                self.policy.relational_transform_plan.clone()
            }
            RecoveryTask::RelationalTransformDiscoveryIncremental => self
                .policy
                .relational_incremental_plan
                .clone()
                .ok_or_else(|| invalid_policy("incremental relational plan is unavailable"))?,
            _ => return Err(RecoveryError::InvariantFailure.into()),
        };
        Ok((task, base_plan))
    }

    fn discard_unpublished_histories(&mut self, prepared: &[PreparedRelationalCohort]) {
        for cohort in prepared {
            self.relational_samples
                .histories
                .discard_context(&cohort.context);
        }
    }

    fn record_committed_cohorts(&mut self, prepared: &[PreparedRelationalCohort]) {
        // Only graph-committed rules can suppress their later exact replay
        for cohort in prepared {
            if let Some(stored) = self
                .relational_samples
                .cohorts_mut(cohort.context.lane)
                .iter_mut()
                .find(|stored| stored.key.as_ref() == Some(&cohort.context.key))
            {
                stored.completed_sample_count = stored
                    .completed_sample_count
                    .max(cohort.context.samples.len());
            }
            if let Some(history) = self.relational_samples.histories.published_history(
                &cohort.context,
                self.policy.relational_transform_plan.limits.max_total_bytes,
            ) {
                for rule in &cohort.published_rules {
                    history.register_published_rule(rule);
                }
            }
        }
    }

    fn record_relational_omissions(&mut self, prepared: &[PreparedRelationalCohort]) {
        for cohort in prepared {
            if cohort.reason.as_deref() == Some("insufficient_independent_sessions")
                && cohort.context.input_coverage_complete
                && cohort.context.omitted_sessions == 0
                && cohort.context.omitted_samples == 0
                && cohort.context.source_eligibility_omissions == 0
            {
                continue;
            }
            if cohort.search_exhaustive_within_plan
                && cohort.report_details_complete
                && cohort.context.input_coverage_complete
                && cohort.context.omitted_sessions == 0
                && cohort.context.omitted_samples == 0
                && cohort.reason.is_none()
            {
                continue;
            }
            self.omissions
                .push(RecoveryOmission::RelationalTransformAnalysis {
                    source_id: cohort.context.key.source_id.clone(),
                    sessions_available: cohort.context.sessions_available,
                    omitted_sessions: cohort.context.omitted_sessions,
                    omitted_samples: cohort.context.omitted_samples,
                    omitted_rules: usize::from(
                        cohort.reason.as_deref() == Some("supported_rule_application_limit"),
                    ),
                    candidate_limit_remaining: cohort.candidate_limit_remaining,
                    locator_candidate_limit_remaining: cohort.locator_candidate_limit_remaining,
                    work_bytes_remaining: cohort.work_bytes_remaining,
                    input_coverage_complete: cohort.context.input_coverage_complete,
                    search_exhaustive_within_plan: cohort.search_exhaustive_within_plan,
                    report_details_complete: cohort.report_details_complete,
                    reason: cohort.reason.clone(),
                });
        }
    }
}

fn prepared_output_bytes(
    prepared: &[PreparedRelationalCohort],
) -> Result<usize, RecoveryExecutionError> {
    let report_bytes = prepared
        .iter()
        .try_fold(0_usize, |total, cohort| {
            total.checked_add(cohort.report_bytes.len())
        })
        .ok_or_else(|| invalid_policy("relational report byte count overflowed"))?;
    prepared
        .iter()
        .flat_map(|cohort| &cohort.outputs)
        .try_fold(report_bytes, |total, output| {
            total.checked_add(output.value.bytes.len())
        })
        .and_then(|total| {
            prepared
                .iter()
                .flat_map(|cohort| &cohort.decoded_frames)
                .try_fold(total, |total, frame| total.checked_add(frame.bytes.len()))
        })
        .ok_or_else(|| invalid_policy("relational output byte count overflowed"))
}

fn admit_sample_views(
    case: &l2_workbench::evidence::Case,
    normal: Option<&mut SampleCohort>,
    incremental: Option<(
        &mut SampleCohort,
        l2_workbench::protocol::RelationalTransformLimits,
    )>,
    incoming: &[StoredSample],
    normal_limits: l2_workbench::protocol::RelationalTransformLimits,
) -> Result<(), RecoveryExecutionError> {
    if let Some(normal) = normal {
        append_framed_samples(
            case,
            normal,
            incoming,
            normal_limits,
            RelationalLane::Normal,
        )?;
    }
    if let Some((incremental, limits)) = incremental {
        append_framed_samples(
            case,
            incremental,
            incoming,
            limits,
            RelationalLane::Incremental,
        )?;
    }
    Ok(())
}

fn append_framed_samples(
    case: &l2_workbench::evidence::Case,
    cohort: &mut SampleCohort,
    incoming: &[StoredSample],
    limits: l2_workbench::protocol::RelationalTransformLimits,
    lane: RelationalLane,
) -> Result<(), RecoveryExecutionError> {
    let mut existing_ids = HashSet::new();
    existing_ids
        .try_reserve(
            cohort
                .samples
                .len()
                .saturating_add(cohort.omitted_sample_ids.len())
                .saturating_add(if matches!(lane, RelationalLane::Incremental) {
                    incoming.len()
                } else {
                    0
                }),
        )
        .map_err(|source| operational("relational sample index allocation failed", source))?;
    existing_ids.extend(cohort.samples.iter().map(|sample| sample.node_id));
    existing_ids.extend(cohort.omitted_sample_ids.iter().copied());

    // Keep session groups intact so partial input cannot enter a searchable cohort
    let mut cursor = 0_usize;
    while cursor < incoming.len() {
        let session_id = incoming
            .get(cursor)
            .ok_or(RecoveryError::InvariantFailure)?
            .context
            .session;
        let mut end = cursor + 1;
        while incoming
            .get(end)
            .is_some_and(|sample| sample.context.session == session_id)
        {
            end += 1;
        }
        let session_samples = incoming
            .get(cursor..end)
            .ok_or(RecoveryError::InvariantFailure)?;
        append_framed_session(
            case,
            cohort,
            session_samples,
            &mut existing_ids,
            limits,
            lane,
        )?;
        cursor = end;
    }
    Ok(())
}

fn append_framed_session(
    case: &l2_workbench::evidence::Case,
    cohort: &mut SampleCohort,
    incoming: &[StoredSample],
    existing_ids: &mut HashSet<u64>,
    limits: l2_workbench::protocol::RelationalTransformLimits,
    lane: RelationalLane,
) -> Result<(), RecoveryExecutionError> {
    let session_id = incoming
        .first()
        .ok_or(RecoveryError::InvariantFailure)?
        .context
        .session;
    let mut new_samples = Vec::new();
    new_samples
        .try_reserve_exact(incoming.len())
        .map_err(|source| operational("relational session sample allocation failed", source))?;
    for sample in incoming {
        if existing_ids.insert(sample.node_id) {
            let copied = match lane {
                RelationalLane::Normal => sample.clone(),
                RelationalLane::Incremental => {
                    try_clone_stored_sample(sample).map_err(|source| {
                        operational("incremental sample allocation failed", source)
                    })?
                }
            };
            new_samples.push(copied);
        }
    }
    if new_samples.is_empty() {
        return Ok(());
    }

    let (exceeds_limits, existing_session_samples) =
        session_exceeds_limits(case, cohort, session_id, &new_samples, limits)?;
    if exceeds_limits {
        record_omitted_session(cohort, session_id, &new_samples, existing_session_samples)?;
        return Ok(());
    }
    cohort
        .samples
        .try_reserve(new_samples.len())
        .map_err(|source| operational("relational cohort sample allocation failed", source))?;
    cohort.samples.extend(new_samples);
    Ok(())
}

fn try_clone_string(value: &str) -> Result<String, std::collections::TryReserveError> {
    let mut copy = String::new();
    copy.try_reserve_exact(value.len())?;
    copy.push_str(value);
    Ok(copy)
}

fn try_clone_stored_sample(
    sample: &StoredSample,
) -> Result<StoredSample, std::collections::TryReserveError> {
    Ok(StoredSample {
        node_id: sample.node_id,
        context: MessageContext {
            source: try_clone_string(&sample.context.source)?,
            scope: try_clone_string(&sample.context.scope)?,
            session: sample.context.session,
            direction: sample.context.direction,
        },
        session_order: sample.session_order,
        direction_node_id: sample.direction_node_id,
        episode_node_id: sample.episode_node_id,
        stream_offset: sample.stream_offset,
    })
}

fn session_exceeds_limits(
    case: &l2_workbench::evidence::Case,
    cohort: &SampleCohort,
    session_id: u64,
    new_samples: &[StoredSample],
    limits: l2_workbench::protocol::RelationalTransformLimits,
) -> Result<(bool, usize), RecoveryExecutionError> {
    let existing_session_samples = cohort
        .samples
        .iter()
        .filter(|sample| sample.context.session == session_id)
        .count();
    let existing_session_bytes = sample_bytes_for_session(case, &cohort.samples, session_id)?;
    let new_session_bytes = sample_bytes_for_session(case, new_samples, session_id)?;
    let next_sample_count = existing_session_samples
        .checked_add(new_samples.len())
        .ok_or_else(|| invalid_policy("relational session sample count overflowed"))?;
    let next_session_bytes = existing_session_bytes
        .checked_add(new_session_bytes)
        .ok_or_else(|| invalid_policy("relational session byte count overflowed"))?;
    let active_session_ids = cohort.active_session_ids()?;
    let new_session_count = active_session_ids
        .len()
        .checked_add(usize::from(!active_session_ids.contains(&session_id)))
        .ok_or_else(|| invalid_policy("relational session count overflowed"))?;
    let active_byte_count = cohort
        .active_samples()
        .try_fold(0_usize, |total, sample| {
            case.node(sample.node_id)
                .and_then(|node| node.blob.as_deref())
                .and_then(|blob_id| case.blob(blob_id))
                .and_then(|blob| total.checked_add(blob.bytes.len()))
        })
        .ok_or_else(|| invalid_policy("relational cohort byte count overflowed"))?;
    let next_total_bytes = active_byte_count
        .checked_add(new_session_bytes)
        .ok_or_else(|| invalid_policy("relational cohort byte count overflowed"))?;
    let exceeds_limits = cohort.incomplete_sessions.contains(&session_id)
        || next_sample_count > limits.max_records_per_session
        || next_session_bytes > limits.max_total_bytes
        || new_session_count > limits.max_sessions
        || next_total_bytes > limits.max_total_bytes
        || new_samples.iter().any(|sample| {
            case.node(sample.node_id)
                .and_then(|node| node.blob.as_deref())
                .and_then(|blob_id| case.blob(blob_id))
                .is_none_or(|blob| blob.bytes.len() > limits.max_record_bytes)
        });
    Ok((exceeds_limits, existing_session_samples))
}

fn record_omitted_session(
    cohort: &mut SampleCohort,
    session_id: u64,
    new_samples: &[StoredSample],
    existing_session_samples: usize,
) -> Result<(), RecoveryExecutionError> {
    cohort
        .incomplete_sessions
        .try_reserve(1)
        .map_err(|source| operational("relational session omission allocation failed", source))?;
    let first_omission = cohort.incomplete_sessions.insert(session_id);
    let mut prior_session_ids = Vec::new();
    prior_session_ids
        .try_reserve_exact(existing_session_samples)
        .map_err(|source| {
            operational("relational omitted sample index allocation failed", source)
        })?;
    prior_session_ids.extend(
        cohort
            .samples
            .iter()
            .filter(|sample| sample.context.session == session_id)
            .map(|sample| sample.node_id),
    );
    cohort
        .omitted_sample_ids
        .try_reserve(prior_session_ids.len().saturating_add(new_samples.len()))
        .map_err(|source| {
            operational("relational omitted sample index allocation failed", source)
        })?;
    cohort.omitted_sample_ids.extend(prior_session_ids);
    cohort
        .omitted_sample_ids
        .extend(new_samples.iter().map(|sample| sample.node_id));
    if first_omission {
        cohort.omitted_sessions = cohort
            .omitted_sessions
            .checked_add(1)
            .ok_or_else(|| invalid_policy("relational omitted-session count overflowed"))?;
        cohort.omitted_samples = cohort
            .omitted_samples
            .checked_add(existing_session_samples)
            .ok_or_else(|| invalid_policy("relational omitted-sample count overflowed"))?;
    }
    cohort.omitted_samples = cohort
        .omitted_samples
        .checked_add(new_samples.len())
        .ok_or_else(|| invalid_policy("relational omitted-sample count overflowed"))?;
    cohort.input_coverage_complete = false;
    Ok(())
}

fn sample_bytes_for_session(
    case: &l2_workbench::evidence::Case,
    samples: &[StoredSample],
    session_id: u64,
) -> Result<usize, RecoveryExecutionError> {
    samples
        .iter()
        .filter(|sample| sample.context.session == session_id)
        .try_fold(0_usize, |total, sample| {
            case.node(sample.node_id)
                .and_then(|node| node.blob.as_deref())
                .and_then(|blob_id| case.blob(blob_id))
                .and_then(|blob| total.checked_add(blob.bytes.len()))
        })
        .ok_or_else(|| invalid_policy("relational session byte count overflowed"))
}

fn checked_output_sha256<'a>(
    candidate: &'a l2_workbench::protocol::RelationalTransformCandidate,
    output: &RelationalAppliedOutput,
) -> Result<&'a str, RecoveryExecutionError> {
    let check = candidate
        .discovery
        .checks
        .iter()
        .chain(&candidate.heldout.checks)
        .find(|check| check.session == output.session)
        .ok_or_else(|| invalid_policy("relational output has no matching frozen session check"))?;
    if check.output_length != Some(output.bytes.len()) {
        return Err(invalid_policy(
            "relational output length differs from its frozen session check",
        ));
    }
    check
        .output_sha256
        .as_deref()
        .ok_or_else(|| invalid_policy("relational output has no frozen SHA-256 identity"))
}

fn invalid_policy(message: &'static str) -> RecoveryExecutionError {
    RecoveryExecutionError::InvalidPolicy(message.to_owned())
}

fn operational(
    message: &'static str,
    source: impl std::error::Error + 'static,
) -> RecoveryExecutionError {
    RecoveryExecutionError::Operational {
        stage: RecoveryStage::TransformDiscovery,
        source: Box::new(RelationalRecoveryError {
            message,
            source: Box::new(source),
        }),
    }
}

#[derive(Debug)]
struct RelationalRecoveryError {
    message: &'static str,
    source: Box<dyn std::error::Error>,
}

impl std::fmt::Display for RelationalRecoveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.message, self.source)
    }
}

impl std::error::Error for RelationalRecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}
