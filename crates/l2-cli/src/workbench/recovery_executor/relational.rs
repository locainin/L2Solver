//! Bounded relational transform discovery over strict per-session record candidates

mod application;
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
#[path = "../../../tests/workbench/recovery_relational/application_fallback.rs"]
mod application_fallback_tests;

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
const REPORT_VERSION: u16 = 1;
const OUTPUT_KIND: &str = "relational_transform_output";
pub(super) const DECODED_FRAME_KIND: &str = "relational_decoded_frame";
const OUTPUT_REASON: &str = "This exact output was produced by a frozen session-relative rule that passed its parser checks";
const DECODED_FRAME_REASON: &str = "This frame preserves its observed header while replacing only the range transformed by the frozen relational rule";
const INPUT_REASON: &str =
    "This assembled record candidate was included in a bounded cross-session relational analysis";
const RAW_RUN_FRAMING_RULE: &str = "{\"kind\":\"raw_directional_run\"}";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RelationalCohortKey {
    source_id: String,
    scope_json: String,
    endpoints_json: String,
    direction: l2_workbench::protocol::Direction,
    framing_rule_json: String,
    schema_json: String,
}

#[derive(Clone)]
struct StoredSample {
    node_id: u64,
    context: MessageContext,
    session_order: u64,
    direction_node_id: u64,
    episode_node_id: u64,
    stream_offset: usize,
}

#[derive(Default)]
struct SampleCohort {
    key: Option<RelationalCohortKey>,
    samples: Vec<StoredSample>,
    incomplete_sessions: BTreeSet<u64>,
    omitted_sample_ids: HashSet<u64>,
    scheduled_sample_count: usize,
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

    fn active_session_ids(&self) -> BTreeSet<u64> {
        self.active_samples()
            .map(|sample| sample.context.session)
            .collect()
    }
}

#[derive(Default)]
pub(super) struct RelationalSampleCollections {
    cohorts: Vec<SampleCohort>,
}

pub(in crate::workbench::recovery_executor) struct RawRelationalRunInput {
    pub(in crate::workbench::recovery_executor) node_id: u64,
    pub(in crate::workbench::recovery_executor) episode_node_id: u64,
    pub(in crate::workbench::recovery_executor) direction_node_id: u64,
    pub(in crate::workbench::recovery_executor) session_order: u64,
    pub(in crate::workbench::recovery_executor) stream_offset: usize,
    pub(in crate::workbench::recovery_executor) start_known: bool,
}

#[derive(Clone)]
pub(super) struct RelationalDiscoveryContext {
    key: RelationalCohortKey,
    sample_node_ids: Vec<u64>,
    samples: Vec<StoredSample>,
    sessions_available: usize,
    omitted_sessions: usize,
    omitted_samples: usize,
    source_eligibility_omissions: usize,
    input_coverage_complete: bool,
}

struct AppliedOutput {
    candidate_index: usize,
    value: RelationalAppliedOutput,
    sha256: String,
    parser_format: l2_workbench::artifact::ArtifactValidationFormat,
    session_ids: Vec<u64>,
    session_orders: Vec<u64>,
    seed_samples: Vec<u64>,
}

struct PreparedRelationalCohort {
    context: RelationalDiscoveryContext,
    report_bytes: Vec<u8>,
    outputs: Vec<AppliedOutput>,
    decoded_frames: Vec<DecodedFrameOutput>,
    accepted_schemas: Vec<(usize, AcceptedRecordSchema)>,
    report_details_complete: bool,
    search_exhaustive_within_plan: bool,
    candidate_limit_remaining: usize,
    locator_candidate_limit_remaining: usize,
    work_bytes_remaining: usize,
    reason: Option<&'static str>,
}

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
    bytes: Vec<u8>,
}

struct GateAssessment {
    status: GateStatus,
    details: Value,
    accepted_schema: Option<AcceptedRecordSchema>,
    assessment_scope: Option<SchemaOffsetScope>,
}

impl GateAssessment {
    const fn needs_full_inference(&self) -> bool {
        matches!(
            self.assessment_scope,
            Some(SchemaOffsetScope::PreservedHeader)
        ) && !matches!(self.status, GateStatus::ArtifactValidated)
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
    fn relational_session_omission(
        &mut self,
        source_id: &str,
        omitted_sessions: usize,
        omitted_samples: usize,
        input_coverage_complete: bool,
        reason: &'static str,
    ) -> Result<(), RecoveryExecutionError> {
        let limits = self.policy.relational_transform_plan.limits;
        self.omissions
            .try_reserve(1)
            .map_err(|source| operational("relational omission allocation failed", source))?;
        self.omissions
            .push(RecoveryOmission::RelationalTransformAnalysis {
                source_id: source_id.to_owned(),
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
                reason: Some(reason),
            });
        Ok(())
    }

    pub(super) fn flush_relational_cohorts(&mut self) -> Result<bool, RecoveryExecutionError> {
        let mut scheduled_any = false;
        let task = RecoveryTask::RelationalTransformDiscovery;
        for cohort_index in 0..self.relational_samples.cohorts.len() {
            let (sample_node_ids, context) = {
                let cohort = self
                    .relational_samples
                    .cohorts
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
        let origins = contexts
            .iter()
            .flat_map(|context| context.sample_node_ids.iter().copied())
            .collect::<Vec<_>>();
        let mut work_remaining = self.coordinator.remaining_work_bytes();
        let base_plan = self.policy.relational_transform_plan.clone();
        let job = self.job.as_ref().map(|progress| &progress.job);
        let prepared =
            search::prepare_contexts(self, contexts, &base_plan, &mut work_remaining, job)?;
        let total_work = self
            .coordinator
            .remaining_work_bytes()
            .checked_sub(work_remaining)
            .ok_or(RecoveryError::InvariantFailure)?;
        if !self.charge_work(
            candidate_id,
            &RecoveryTask::RelationalTransformDiscovery,
            &origins,
            total_work,
        )? {
            return Ok(());
        }
        let report_bytes = prepared.iter().try_fold(0_usize, |total, cohort| {
            total.checked_add(cohort.report_bytes.len())
        });
        let report_bytes = report_bytes
            .ok_or_else(|| invalid_policy("relational report byte count overflowed"))?;
        let output_bytes = prepared
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
            .ok_or_else(|| invalid_policy("relational output byte count overflowed"))?;
        if !self.check_output(
            candidate_id,
            &RecoveryTask::RelationalTransformDiscovery,
            &origins,
            output_bytes,
        )? {
            return Ok(());
        }
        self.omissions
            .try_reserve(prepared.len())
            .map_err(|source| operational("relational omission allocation failed", source))?;
        let committed = self.case_transaction_and_finish(candidate_id, |case, identities| {
            publication::publish_prepared_cohorts(case, identities, &prepared)
        })?;
        self.record_relational_omissions(&prepared);
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

    fn record_relational_omissions(&mut self, prepared: &[PreparedRelationalCohort]) {
        for cohort in prepared {
            if cohort.reason == Some("insufficient_independent_sessions")
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
                        cohort.reason == Some("supported_rule_application_limit"),
                    ),
                    candidate_limit_remaining: cohort.candidate_limit_remaining,
                    locator_candidate_limit_remaining: cohort.locator_candidate_limit_remaining,
                    work_bytes_remaining: cohort.work_bytes_remaining,
                    input_coverage_complete: cohort.context.input_coverage_complete,
                    search_exhaustive_within_plan: cohort.search_exhaustive_within_plan,
                    report_details_complete: cohort.report_details_complete,
                    reason: cohort.reason,
                });
        }
    }
}

fn append_framed_samples(
    case: &l2_workbench::evidence::Case,
    cohort: &mut SampleCohort,
    incoming: &[StoredSample],
    limits: l2_workbench::protocol::RelationalTransformLimits,
) -> Result<(), RecoveryExecutionError> {
    let mut existing_ids = HashSet::new();
    existing_ids
        .try_reserve(
            cohort
                .samples
                .len()
                .saturating_add(cohort.omitted_sample_ids.len()),
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
        append_framed_session(case, cohort, session_samples, &mut existing_ids, limits)?;
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
            new_samples.push(sample.clone());
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
    let active_session_ids = cohort.active_session_ids();
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
    let first_omission = cohort.incomplete_sessions.insert(session_id);
    let prior_session_ids = cohort
        .samples
        .iter()
        .filter(|sample| sample.context.session == session_id)
        .map(|sample| sample.node_id)
        .collect::<Vec<_>>();
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
