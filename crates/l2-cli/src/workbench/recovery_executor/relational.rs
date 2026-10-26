//! Bounded relational transform discovery over strict per-session record candidates

mod input;
mod record_gate;
mod report;

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_relational/materialization.rs"]
mod materialization_tests;

use super::evidence::{add_transaction_edge, add_transaction_links};
use super::record_discovery::{RecordCohortKey, RecordCohortOrigin, RecordFrameInput};
use super::{
    Executor, RecoveryCandidateId, RecoveryExecutionError, RecoveryOmission, RecoveryStage,
    RecoveryTask,
};
use l2_workbench::{
    artifact::{ArtifactValidationOutcome, ArtifactValidator},
    evidence::{Edge, EvidenceStatus},
    protocol::{
        HoldoutBasis, MessageContext, RecordSchema, RecordSchemaStrategy, RelationalAppliedOutput,
        RelationalCandidateEvaluation, RelationalFitStatus, RelationalParserScope,
        RelationalRecordSample, RelationalTransformEvaluationContext,
        RelationalTransformEvaluationOptions, RelationalTransformReport, RelationalTransformRule,
        RelationalTransformStatus, apply_relational_transform_rule,
        infer_relational_transform_candidates_with_evaluator,
    },
    recovery::{EnqueueOutcome, RecoveryError, RecoveryResult},
    sha256,
};
use record_gate::{AcceptedRecordSchema, GateStatus, SchemaCandidateOptions, SchemaPlanCache};
use report::{budget_report, insufficient_sessions_report, report_json};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashSet};

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
        let mut prepared = Vec::new();
        let job = self.job.as_ref().map(|progress| &progress.job);
        let base_plan = self.policy.relational_transform_plan.clone();
        for context in contexts {
            if let Some(job) = job {
                job.check_cancelled()?;
            }
            let samples = samples_for_context(self.case, &context)?;
            let sample_bytes = samples.iter().try_fold(0_usize, |total, sample| {
                total.checked_add(sample.bytes.len())
            });
            let sample_bytes = sample_bytes
                .ok_or_else(|| invalid_policy("relational input byte count overflowed"))?;
            let mut search_plan = base_plan.clone();
            if context.key.framing_rule_json == RAW_RUN_FRAMING_RULE {
                // Raw runs may place a stable payload marker after the seed prefix
                search_plan.limits.max_marker_offset = search_plan
                    .limits
                    .max_marker_offset
                    .max(search_plan.limits.max_locator_offset);
            }
            let shared_work_budget = work_remaining.saturating_sub(sample_bytes) / 2;
            let cohort_work_budget = search_plan.limits.max_work_bytes.min(shared_work_budget);
            // Keep half of the existing cohort allowance available for full application
            // and exact artifact parsing after candidate discovery
            search_plan.limits.max_work_bytes = cohort_work_budget / 2;
            let mut outputs = Vec::new();
            let mut decoded_frames = Vec::new();
            let mut accepted_schemas = Vec::new();
            let (
                report_value,
                report_complete,
                exhaustive,
                candidate_remaining,
                locator_remaining,
                used_work,
                reason,
            ) = if context.sessions_available < 2 {
                (
                    insufficient_sessions_report(&context, &search_plan),
                    true,
                    false,
                    search_plan.limits.max_candidates,
                    search_plan.limits.max_locator_candidates.saturating_mul(2),
                    0,
                    Some("insufficient_independent_sessions"),
                )
            } else if sample_bytes >= work_remaining {
                (
                    budget_report(&context, &search_plan, "coordinator_work_limit"),
                    true,
                    false,
                    search_plan.limits.max_candidates,
                    search_plan.limits.max_locator_candidates.saturating_mul(2),
                    0,
                    Some("coordinator_work_limit"),
                )
            } else {
                let mut schema_plan_cache = SchemaPlanCache::default();
                let evaluation = infer_relational_transform_candidates_with_evaluator(
                    &samples,
                    &search_plan,
                    job,
                    RelationalTransformEvaluationOptions {
                        max_retained_output_bytes: search_plan.limits.max_total_bytes,
                    },
                    |evaluation_context, candidate, discovery_outputs, heldout_outputs| {
                        evaluate_candidate_before_retention(
                            evaluation_context,
                            candidate,
                            discovery_outputs,
                            heldout_outputs,
                            &samples,
                            &context.samples,
                            context.key.framing_rule_json == RAW_RUN_FRAMING_RULE,
                            &mut schema_plan_cache,
                            self.policy.record_schema_proposal_limits,
                            self.policy.artifact_validation_policy,
                            job,
                        )
                    },
                );
                let evaluation = match evaluation {
                    Ok(evaluation) => evaluation,
                    Err(l2_workbench::protocol::RelationalEvaluationError::Search(error)) => {
                        return Err(error.into());
                    }
                    Err(l2_workbench::protocol::RelationalEvaluationError::Evaluator(error)) => {
                        return Err(error);
                    }
                    Err(
                        l2_workbench::protocol::RelationalEvaluationError::EvaluatorWorkLimit {
                            ..
                        },
                    ) => {
                        return Err(invalid_policy(
                            "relational record gate exceeded its shared work budget",
                        ));
                    }
                    Err(_) => {
                        return Err(invalid_policy(
                            "relational candidate evaluation failed unexpectedly",
                        ));
                    }
                };
                let l2_workbench::protocol::RelationalCandidateEvaluationReport {
                    report,
                    evaluations,
                    ..
                } = evaluation;
                let mut replay_work_remaining =
                    cohort_work_budget.saturating_sub(report.work_bytes);
                // Exact artifact evidence is local to the validated bytes, even when
                // unrelated eligible input was omitted from the wider search cohort
                let maximum_materialized_rules = search_plan.limits.max_retained_candidates.min(8);
                let supported_rules = report
                    .candidates
                    .iter()
                    .filter(|candidate| {
                        matches!(
                            candidate.status,
                            RelationalTransformStatus::HeldoutConstraintsSatisfied
                                | RelationalTransformStatus::AwaitingAcrossSessionValidation
                        )
                    })
                    .count();
                let mut attempted_rule_count = 0_usize;
                let mut qualified_rule_count = 0_usize;
                let mut aggregate_parser_checks = Vec::new();
                let mut application_evidence_checks = Vec::new();
                let mut application_unresolved = !context.input_coverage_complete;
                let mut retained_rules = Vec::new();
                retained_rules
                    .try_reserve_exact(maximum_materialized_rules)
                    .map_err(|source| {
                        operational("retained relational rule allocation failed", source)
                    })?;
                let mut retained_frame_bytes = 0_usize;
                let mut aliases = HashSet::<(Vec<u64>, String)>::new();
                let mut decoded_aliases = HashSet::<(Vec<u64>, Vec<String>, usize, String)>::new();
                if evaluations.len() != report.candidates.len() {
                    return Err(RecoveryError::InvariantFailure.into());
                }
                for (candidate_index, (candidate, evaluation)) in
                    report.candidates.iter().zip(evaluations).enumerate()
                {
                    if !matches!(
                        candidate.status,
                        RelationalTransformStatus::HeldoutConstraintsSatisfied
                            | RelationalTransformStatus::AwaitingAcrossSessionValidation
                    ) {
                        continue;
                    }
                    attempted_rule_count += 1;
                    if let Some(job) = job {
                        job.check_cancelled()?;
                    }
                    let expected_check_status = match candidate.rule.parser_scope {
                        RelationalParserScope::EachSession => {
                            RelationalFitStatus::ConstraintsSatisfied
                        }
                        RelationalParserScope::AcrossSessions => {
                            RelationalFitStatus::TransformConstraintsSatisfied
                        }
                    };
                    let all_checks = candidate
                        .discovery
                        .checks
                        .iter()
                        .chain(&candidate.heldout.checks);
                    let mut captured_outputs = evaluation.outputs.map(|outputs| {
                        let mut captured = outputs.discovery;
                        captured.extend(outputs.heldout);
                        captured.sort_unstable_by_key(|output| output.session_order);
                        captured
                    });
                    let mut candidate_outputs = Vec::new();
                    for check in all_checks {
                        if check.status != expected_check_status {
                            return Err(invalid_policy(
                                "supported relational candidate contains an unexpected session check",
                            ));
                        }
                        if let Some(job) = job {
                            job.check_cancelled()?;
                        }
                        if !samples
                            .iter()
                            .any(|sample| sample.context.session == check.session.session)
                        {
                            continue;
                        }
                        let applied = if let Some(captured) = &mut captured_outputs {
                            let Some(position) = captured
                                .iter()
                                .position(|output| output.session.session == check.session.session)
                            else {
                                return Err(RecoveryError::InvariantFailure.into());
                            };
                            captured.remove(position)
                        } else {
                            let session_samples = samples
                                .iter()
                                .filter(|sample| sample.context.session == check.session.session)
                                .cloned()
                                .collect::<Vec<_>>();
                            apply_relational_transform_rule(
                                &session_samples,
                                &candidate.rule,
                                search_plan.limits,
                                replay_work_remaining,
                            )?
                        };
                        if check.output_length != Some(applied.bytes.len())
                            || check.output_sha256.as_deref()
                                != Some(sha256(&applied.bytes).as_str())
                        {
                            return Err(invalid_policy(
                                "relational rule replay did not match its frozen check",
                            ));
                        }
                        if captured_outputs.is_none() {
                            replay_work_remaining = replay_work_remaining
                                .checked_sub(applied.work_bytes)
                                .ok_or_else(|| {
                                    invalid_policy("relational replay exceeded admitted work")
                                })?;
                        }
                        candidate_outputs.push(applied);
                    }
                    if captured_outputs
                        .as_ref()
                        .is_some_and(|captured| !captured.is_empty())
                    {
                        return Err(RecoveryError::InvariantFailure.into());
                    }
                    let GateAssessment {
                        status: gate_status,
                        details: gate_details,
                        accepted_schema,
                    } = evaluation.assessment;

                    match candidate.rule.parser_scope {
                        RelationalParserScope::EachSession => {
                            if accepted_schema.is_some() {
                                return Err(RecoveryError::InvariantFailure.into());
                            }
                            let mut candidate_applied = false;
                            let mut candidate_retained_outputs = Vec::new();
                            candidate_retained_outputs
                                .try_reserve_exact(candidate_outputs.len())
                                .map_err(|source| {
                                    operational("relational output allocation failed", source)
                                })?;
                            for applied in candidate_outputs {
                                let session_id = applied.session.session;
                                let session_order = applied.session_order;
                                let seed_sample = applied.seed_sample;
                                let digest = sha256(&applied.bytes);
                                if aliases.insert((vec![session_id], digest.clone())) {
                                    candidate_retained_outputs.push(AppliedOutput {
                                        candidate_index,
                                        value: applied,
                                        sha256: digest,
                                        parser_format: candidate.rule.parser_format,
                                        session_ids: vec![session_id],
                                        session_orders: vec![session_order],
                                        seed_samples: vec![seed_sample],
                                    });
                                }
                                candidate_applied = true;
                            }
                            if candidate_applied {
                                qualified_rule_count = qualified_rule_count.saturating_add(1);
                                application_evidence_checks.push(json!({
                                    "candidate_index":candidate_index,
                                    "status":GateStatus::ArtifactValidated.as_str(),
                                    "artifact_validated":true,
                                    "structurally_supported":true,
                                    "reason":"exact_each_session_parser_constraints_satisfied",
                                    "details":gate_details,
                                    "accepted_record_schema":Value::Null,
                                }));
                                let retained = RetainedRelationalRule {
                                    candidate_index,
                                    evidence_priority: GateStatus::ArtifactValidated.priority(),
                                    outputs: candidate_retained_outputs,
                                    decoded_frames: Vec::new(),
                                    accepted_schema: None,
                                };
                                let _ = retain_relational_rule(
                                    &mut retained_rules,
                                    &mut retained_frame_bytes,
                                    maximum_materialized_rules,
                                    search_plan.limits.max_total_bytes,
                                    retained,
                                )?;
                            }
                        }
                        RelationalParserScope::AcrossSessions => {
                            let raw_directional_run =
                                context.key.framing_rule_json == RAW_RUN_FRAMING_RULE;
                            candidate_outputs.sort_by_key(|output| output.session_order);
                            let expected_session_orders = candidate_outputs
                                .iter()
                                .map(|output| output.session_order)
                                .collect::<Vec<_>>();
                            let mut candidate_frames = Vec::new();
                            for applied in &candidate_outputs {
                                let output_sha256 = checked_output_sha256(&candidate, applied)?;
                                candidate_frames.extend(decoded_payload_frames(
                                    &samples,
                                    &context.samples,
                                    applied,
                                    &candidate.rule,
                                    candidate_index,
                                    output_sha256,
                                    &expected_session_orders,
                                    raw_directional_run,
                                )?);
                            }
                            if let Some(accepted) = &accepted_schema {
                                validate_accepted_record_schema(
                                    candidate_index,
                                    &candidate_frames,
                                    accepted,
                                )?;
                            }
                            let mut candidate_status = gate_status;
                            let mut candidate_priority = candidate_status.priority();
                            let mut candidate_retained_outputs = Vec::new();
                            let mut exact_aggregate_output = None;
                            if candidate_status == GateStatus::Pending {
                                application_unresolved = true;
                            } else if candidate_status == GateStatus::Contradicted
                                && let Some(job) = job
                            {
                                job.increment(l2_workbench::job::Counter::CandidatesRejected, 1)?;
                            }
                            let aggregate_length =
                                candidate_outputs.iter().try_fold(0_usize, |total, output| {
                                    total.checked_add(output.bytes.len())
                                });
                            let aggregate_length = aggregate_length.ok_or_else(|| {
                                invalid_policy("relational aggregate output length overflowed")
                            })?;
                            if aggregate_length > search_plan.limits.max_total_bytes {
                                application_unresolved = true;
                                aggregate_parser_checks.push(json!({
                                    "candidate_index":candidate_index,
                                    "parser_format":format!("{:?}", candidate.rule.parser_format),
                                    "parser_scope":"across_sessions",
                                    "sessions":candidate_outputs.iter().map(|output| output.session.session).collect::<Vec<_>>(),
                                    "length":aggregate_length,
                                    "status":"unresolved_on_aggregate_byte_limit",
                                    "maximum":search_plan.limits.max_total_bytes,
                                }));
                            } else if aggregate_length > replay_work_remaining {
                                application_unresolved = true;
                                aggregate_parser_checks.push(json!({
                                    "candidate_index":candidate_index,
                                    "parser_format":format!("{:?}", candidate.rule.parser_format),
                                    "parser_scope":"across_sessions",
                                    "sessions":candidate_outputs.iter().map(|output| output.session.session).collect::<Vec<_>>(),
                                    "length":aggregate_length,
                                    "status":"unresolved_on_aggregate_work_limit",
                                    "remaining_work_bytes":replay_work_remaining,
                                }));
                            } else {
                                let mut aggregate = Vec::new();
                                aggregate.try_reserve_exact(aggregate_length).map_err(
                                    |source| {
                                        operational(
                                            "relational aggregate output allocation failed",
                                            source,
                                        )
                                    },
                                )?;
                                let mut payload_samples = Vec::new();
                                let payload_range_count = candidate_outputs
                                    .iter()
                                    .try_fold(0_usize, |total, output| {
                                        total.checked_add(output.payload_ranges.len())
                                    })
                                    .ok_or_else(|| {
                                        invalid_policy("relational payload range count overflowed")
                                    })?;
                                let mut payload_ranges = Vec::new();
                                payload_ranges
                                    .try_reserve_exact(payload_range_count)
                                    .map_err(|source| {
                                        operational(
                                            "relational payload range allocation failed",
                                            source,
                                        )
                                    })?;
                                let mut seed_samples = Vec::new();
                                let mut session_ids = Vec::new();
                                let mut session_work = 0_usize;
                                for applied in &candidate_outputs {
                                    if applied.payload_ranges.len() != applied.payload_samples.len()
                                    {
                                        return Err(RecoveryError::InvariantFailure.into());
                                    }
                                    let aggregate_offset = aggregate.len();
                                    aggregate.extend_from_slice(&applied.bytes);
                                    payload_samples.extend_from_slice(&applied.payload_samples);
                                    for range in &applied.payload_ranges {
                                        if range.start > range.end
                                            || range.end > applied.bytes.len()
                                        {
                                            return Err(RecoveryError::InvariantFailure.into());
                                        }
                                        payload_ranges.push(l2_workbench::protocol::ByteRange {
                                            start: aggregate_offset
                                                .checked_add(range.start)
                                                .ok_or_else(|| {
                                                    invalid_policy(
                                                        "relational payload offset overflowed",
                                                    )
                                                })?,
                                            end: aggregate_offset
                                                .checked_add(range.end)
                                                .ok_or_else(|| {
                                                    invalid_policy(
                                                        "relational payload offset overflowed",
                                                    )
                                                })?,
                                        });
                                    }
                                    seed_samples.push(applied.seed_sample);
                                    session_ids.push(applied.session.session);
                                    session_work =
                                        session_work.checked_add(applied.work_bytes).ok_or_else(
                                            || invalid_policy("relational session work overflowed"),
                                        )?;
                                }
                                let parser_work_limit = replay_work_remaining
                                    .checked_sub(aggregate_length)
                                    .ok_or_else(|| {
                                        invalid_policy("relational parser work limit underflowed")
                                    })?;
                                let validator = aggregate_validator(
                                    self.policy.artifact_validation_policy,
                                    aggregate_length,
                                    parser_work_limit,
                                )?;
                                let validation =
                                    validator.validate_as(candidate.rule.parser_format, &aggregate);
                                let zip_expansion_work = match &validation {
                                    ArtifactValidationOutcome::Validated {
                                        structure:
                                            l2_workbench::artifact::ArtifactStructure::Zip(report),
                                        ..
                                    } => report.expanded_work_byte_count,
                                    _ => 0,
                                };
                                let parser_work = aggregate_length
                                    .checked_add(zip_expansion_work)
                                    .ok_or_else(|| {
                                        invalid_policy("relational parser work overflowed")
                                    })?;
                                replay_work_remaining = replay_work_remaining
                                    .checked_sub(parser_work)
                                    .ok_or_else(|| {
                                        invalid_policy("relational parser exceeded admitted work")
                                    })?;
                                let (accepted, validation_status) = match &validation {
                                    ArtifactValidationOutcome::Validated { range, .. }
                                        if range.offset == 0 && range.length == aggregate.len() =>
                                    {
                                        (true, "validated_exact_range")
                                    }
                                    ArtifactValidationOutcome::Validated { .. } => {
                                        (false, "validated_non_exact_range")
                                    }
                                    ArtifactValidationOutcome::BoundaryUnproven { .. } => {
                                        (false, "boundary_unproven")
                                    }
                                    ArtifactValidationOutcome::Rejected { .. } => {
                                        (false, "rejected")
                                    }
                                    ArtifactValidationOutcome::Unsupported { .. } => {
                                        (false, "unsupported")
                                    }
                                    ArtifactValidationOutcome::Omitted { .. } => {
                                        (false, "omitted_on_parser_budget")
                                    }
                                };
                                aggregate_parser_checks.push(json!({
                                    "candidate_index":candidate_index,
                                    "parser_format":format!("{:?}", candidate.rule.parser_format),
                                    "parser_scope":"across_sessions",
                                    "sessions":session_ids,
                                    "length":aggregate.len(),
                                    "sha256":sha256(&aggregate),
                                    "parser_work_bytes":parser_work,
                                    "status":validation_status,
                                    "accepted":accepted,
                                    "result":format!("{validation:?}"),
                                }));
                                if accepted {
                                    candidate_status = GateStatus::ArtifactValidated;
                                    candidate_priority = GateStatus::ArtifactValidated.priority();
                                    let Some(first) = candidate_outputs.first() else {
                                        return Err(invalid_policy(
                                            "supported relational rule produced no session outputs",
                                        ));
                                    };
                                    let digest = sha256(&aggregate);
                                    if aliases.insert((session_ids.clone(), digest.clone())) {
                                        exact_aggregate_output = Some(AppliedOutput {
                                            candidate_index,
                                            value: RelationalAppliedOutput {
                                                session: first.session.clone(),
                                                session_order: first.session_order,
                                                seed_sample: first.seed_sample,
                                                payload_samples,
                                                payload_ranges,
                                                bytes: aggregate,
                                                parser_validation_deferred: false,
                                                work_bytes: session_work
                                                    .checked_add(aggregate_length)
                                                    .ok_or_else(|| {
                                                        invalid_policy(
                                                            "relational aggregate work overflowed",
                                                        )
                                                    })?,
                                            },
                                            sha256: digest,
                                            parser_format: candidate.rule.parser_format,
                                            session_ids,
                                            session_orders: candidate_outputs
                                                .iter()
                                                .map(|output| output.session_order)
                                                .collect(),
                                            seed_samples,
                                        });
                                    }
                                } else {
                                    let parser_unresolved = matches!(
                                        validation,
                                        ArtifactValidationOutcome::Omitted { .. }
                                    );
                                    application_unresolved |= parser_unresolved;
                                    if let Some(job) = job
                                        && !parser_unresolved
                                    {
                                        job.increment(
                                            l2_workbench::job::Counter::CandidatesRejected,
                                            1,
                                        )?;
                                    }
                                }
                            }
                            let keep_decoded_frames = should_retain_rule(
                                candidate_status,
                                context.input_coverage_complete,
                            );
                            let decoded_alias = (
                                candidate_outputs
                                    .iter()
                                    .flat_map(|output| output.payload_samples.iter().copied())
                                    .collect::<Vec<_>>(),
                                candidate_outputs
                                    .iter()
                                    .map(|output| sha256(&output.bytes))
                                    .collect::<Vec<_>>(),
                                candidate.rule.payload_locator.value_offset,
                                format!("{:?}", candidate.rule.parser_format),
                            );
                            let has_unique_decoded_alias =
                                keep_decoded_frames && decoded_aliases.insert(decoded_alias);
                            let candidate_retained_frames =
                                if has_unique_decoded_alias || accepted_schema.is_some() {
                                    candidate_frames
                                } else {
                                    Vec::new()
                                };
                            if !candidate_retained_frames.is_empty()
                                || !candidate_retained_outputs.is_empty()
                            {
                                qualified_rule_count = qualified_rule_count.saturating_add(1);
                                if let Some(output) = exact_aggregate_output {
                                    candidate_retained_outputs.push(output);
                                }
                                application_evidence_checks.push(json!({
                                    "candidate_index":candidate_index,
                                    "status":candidate_status.as_str(),
                                    "artifact_validated":candidate_status == GateStatus::ArtifactValidated,
                                    "structurally_supported":candidate_status == GateStatus::StructurallySupported,
                                    "details":gate_details,
                                    "accepted_record_schema":accepted_schema.as_ref().map(accepted_record_schema_json),
                                }));
                                let retained = RetainedRelationalRule {
                                    candidate_index,
                                    evidence_priority: candidate_priority,
                                    outputs: candidate_retained_outputs,
                                    decoded_frames: candidate_retained_frames,
                                    accepted_schema,
                                };
                                let _ = retain_relational_rule(
                                    &mut retained_rules,
                                    &mut retained_frame_bytes,
                                    maximum_materialized_rules,
                                    search_plan.limits.max_total_bytes,
                                    retained,
                                )?;
                            } else {
                                application_evidence_checks.push(json!({
                                    "candidate_index":candidate_index,
                                    "status":candidate_status.as_str(),
                                    "artifact_validated":false,
                                    "structurally_supported":false,
                                    "details":gate_details,
                                    "accepted_record_schema":accepted_schema.as_ref().map(accepted_record_schema_json),
                                }));
                            }
                        }
                    }
                }
                retained_rules.sort_unstable_by_key(|rule| rule.candidate_index);
                let applied_rule_count = retained_rules.len();
                accepted_schemas
                    .try_reserve_exact(retained_rules.len())
                    .map_err(|source| {
                        operational("accepted relational schema allocation failed", source)
                    })?;
                for mut rule in retained_rules {
                    outputs.append(&mut rule.outputs);
                    decoded_frames.append(&mut rule.decoded_frames);
                    if let Some(accepted) = rule.accepted_schema.take() {
                        accepted_schemas.push((rule.candidate_index, accepted));
                    }
                }
                let replay_used = cohort_work_budget
                    .saturating_sub(report.work_bytes)
                    .saturating_sub(replay_work_remaining);
                let used_work = report
                    .work_bytes
                    .checked_add(replay_used)
                    .ok_or_else(|| invalid_policy("relational work count overflowed"))?;
                let report_value = report_json(
                    &context,
                    &report,
                    &search_plan,
                    supported_rules,
                    applied_rule_count,
                    &aggregate_parser_checks,
                    &application_evidence_checks,
                );
                (
                    report_value,
                    true,
                    report.search_exhaustive_within_plan,
                    report.candidate_limit_remaining,
                    report.locator_candidate_limit_remaining,
                    used_work,
                    if application_unresolved {
                        Some("aggregate_application_unresolved")
                    } else if qualified_rule_count > applied_rule_count
                        || attempted_rule_count < supported_rules
                    {
                        Some("supported_rule_application_limit")
                    } else {
                        None
                    },
                )
            };
            let bytes = serde_json::to_vec(&report_value)
                .map_err(|source| operational("relational report serialization failed", source))?;
            let spent = sample_bytes
                .checked_add(used_work)
                .ok_or_else(|| invalid_policy("relational work total overflowed"))?;
            if spent > work_remaining {
                return Err(invalid_policy("relational work admission was exceeded"));
            }
            work_remaining -= spent;
            prepared
                .try_reserve(1)
                .map_err(|source| operational("relational report allocation failed", source))?;
            prepared.push(PreparedRelationalCohort {
                context,
                report_bytes: bytes,
                outputs,
                decoded_frames,
                accepted_schemas,
                report_details_complete: report_complete,
                search_exhaustive_within_plan: exhaustive,
                candidate_limit_remaining: candidate_remaining,
                locator_candidate_limit_remaining: locator_remaining,
                work_bytes_remaining: work_remaining,
                reason,
            });
        }
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
            let mut report_nodes = Vec::new();
            let mut output_node_ids = Vec::new();
            let mut decoded_record_inputs = Vec::new();
            let mut accepted_record_schemas = Vec::new();
            report_nodes
                .try_reserve_exact(prepared.len())
                .map_err(|source| operational("relational report node allocation failed", source))?;
            decoded_record_inputs
                .try_reserve(prepared.len())
                .map_err(|source| operational("decoded record cohort allocation failed", source))?;
            let accepted_schema_count = prepared
                .iter()
                .try_fold(0_usize, |total, cohort| {
                    total.checked_add(cohort.accepted_schemas.len())
                })
                .ok_or_else(|| invalid_policy("accepted schema request count overflowed"))?;
            accepted_record_schemas
                .try_reserve_exact(accepted_schema_count)
                .map_err(|source| {
                    operational("accepted record schema allocation failed", source)
                })?;
            for cohort in &prepared {
                let details = json!({
                    "representation":"json_blob",
                    "report_schema_version":REPORT_VERSION,
                    "source_id":cohort.context.key.source_id,
                    "candidate_limit_remaining":cohort.candidate_limit_remaining,
                    "locator_candidate_limit_remaining":cohort.locator_candidate_limit_remaining,
                    "work_bytes_remaining":cohort.work_bytes_remaining,
                    "search_exhaustive_within_plan":cohort.search_exhaustive_within_plan,
                    "report_details_complete":cohort.report_details_complete,
                    "source_eligibility_omissions":cohort.context.source_eligibility_omissions,
                });
                let report_node = case.add_bytes_node(
                    REPORT_KIND,
                    &cohort.report_bytes,
                    Vec::new(),
                    details,
                )?;
                let mut cohort_origins = cohort.context.sample_node_ids.clone();
                cohort_origins.sort_unstable();
                cohort_origins.dedup();
                add_transaction_links(
                    case,
                    identities,
                    report_node,
                    &cohort_origins,
                    "relational_transform_input",
                    EvidenceStatus::Unresolved,
                    INPUT_REASON,
                )?;
                report_nodes.push(report_node);
                for output in &cohort.outputs {
                    let details = json!({
                        "representation":"raw_bytes",
                        "report_node_id":report_node,
                        "candidate_index":output.candidate_index,
                        "session":output.value.session,
                        "sessions":output.session_ids,
                        "session_order":output.value.session_order,
                        "session_orders":output.session_orders,
                        "seed_sample":output.value.seed_sample,
                        "seed_samples":output.seed_samples,
                        "payload_samples":output.value.payload_samples,
                        "parser_format":format!("{:?}", output.parser_format),
                        "parser_scope":if output.session_ids.len() > 1 { "across_sessions" } else { "each_session" },
                        "parser_validation_deferred":output.value.parser_validation_deferred,
                        "length":output.value.bytes.len(),
                        "sha256":output.sha256,
                        "terminal_sequence":"unknown",
                    });
                    let output_node = case.add_bytes_node(
                        OUTPUT_KIND,
                        &output.value.bytes,
                        Vec::new(),
                        details,
                    )?;
                    let mut parents = output.value.payload_samples.clone();
                    parents.extend_from_slice(&output.seed_samples);
                    parents.sort_unstable();
                    parents.dedup();
                    add_transaction_links(
                        case,
                        identities,
                        output_node,
                        &parents,
                        "derived_from",
                        EvidenceStatus::Hypothesis,
                        OUTPUT_REASON,
                    )?;
                    add_transaction_edge(
                        case,
                        identities,
                        Edge {
                            from: report_node,
                            to: output_node,
                            relation: "supports_relational_output".to_owned(),
                            status: EvidenceStatus::Hypothesis,
                            reason: OUTPUT_REASON.to_owned(),
                        },
                    )?;
                    output_node_ids.push(output_node);
                }
                let mut decoded_by_candidate = BTreeMap::<usize, Vec<RecordFrameInput>>::new();
                let mut accepted_by_candidate =
                    BTreeMap::<usize, AcceptedRecordSchema>::new();
                for (candidate_index, accepted) in &cohort.accepted_schemas {
                    if accepted_by_candidate
                        .insert(*candidate_index, accepted.clone())
                        .is_some()
                    {
                        return Err(RecoveryError::InvariantFailure.into());
                    }
                }
                let mut accepted_members_seen = BTreeMap::<usize, usize>::new();
                for frame in &cohort.decoded_frames {
                    let frame_details = json!({
                        "representation":"raw_bytes",
                        "relational_decoded_frame":true,
                        "logical_source_id":cohort.context.key.source_id,
                        "relational_report_node_id":report_node,
                        "relational_candidate_index":frame.candidate_index,
                        "relational_parser_format":format!("{:?}", frame.parser_format),
                        "expected_session_orders":frame.expected_session_orders,
                        "session_node_id":frame.context.session,
                        "session_order":frame.session_order,
                        "direction_node_id":frame.direction_node_id,
                        "episode_node_id":frame.episode_node_id,
                        "stream_offset":frame.stream_offset,
                        "input_frame_node_id":frame.input_node_id,
                        "seed_sample":frame.seed_sample,
                        "payload_range":frame.payload_range,
                        "length":frame.bytes.len(),
                        "sha256":sha256(&frame.bytes),
                    });
                    let decoded_node = case.add_bytes_node(
                        DECODED_FRAME_KIND,
                        &frame.bytes,
                        Vec::new(),
                        frame_details,
                    )?;
                    let mut parents = vec![frame.input_node_id, frame.seed_sample];
                    parents.sort_unstable();
                    parents.dedup();
                    add_transaction_links(
                        case,
                        identities,
                        decoded_node,
                        &parents,
                        "decoded_from",
                        EvidenceStatus::Hypothesis,
                        DECODED_FRAME_REASON,
                    )?;
                    add_transaction_edge(
                        case,
                        identities,
                        Edge {
                            from: report_node,
                            to: decoded_node,
                            relation: "supports_relational_frame".to_owned(),
                            status: EvidenceStatus::Hypothesis,
                            reason: DECODED_FRAME_REASON.to_owned(),
                        },
                    )?;
                    let blob_id = case
                        .node(decoded_node)
                        .and_then(|node| node.blob.clone())
                        .ok_or(RecoveryError::InvariantFailure)?;
                    let frame_inputs = decoded_by_candidate
                        .entry(frame.candidate_index)
                        .or_default();
                    frame_inputs.try_reserve(1).map_err(|source| {
                        operational("decoded record input allocation failed", source)
                    })?;
                    let frame_index = frame_inputs.len();
                    if let Some(accepted) = accepted_by_candidate.get(&frame.candidate_index)
                        && let Ok(identity_index) =
                            accepted.frame_indices.binary_search(&frame_index)
                    {
                        let identity = accepted
                            .frame_identities
                            .get(identity_index)
                            .ok_or(RecoveryError::InvariantFailure)?;
                        let frame_blob = case
                            .blob(&blob_id)
                            .ok_or(RecoveryError::InvariantFailure)?;
                        let frame_bytes_sha256 = blob_id
                            .strip_prefix("sha256:")
                            .ok_or(RecoveryError::InvariantFailure)?;
                        validate_accepted_frame_identity(
                            identity,
                            frame,
                            frame_index,
                            frame_blob.bytes.len(),
                            frame_bytes_sha256,
                        )?;
                        let seen = accepted_members_seen
                            .entry(frame.candidate_index)
                            .or_default();
                        *seen = seen
                            .checked_add(1)
                            .ok_or(RecoveryError::InvariantFailure)?;
                    }
                    frame_inputs.push(RecordFrameInput {
                        node_id: decoded_node,
                        blob_id,
                        receipt_node_id: report_node,
                        session_node_id: frame.context.session,
                        direction_node_id: frame.direction_node_id,
                        episode_node_id: frame.episode_node_id,
                        session_id: frame.session_order,
                        frame_index,
                        stream_range: l2_workbench::protocol::ByteRange {
                            start: 0,
                            end: frame.bytes.len(),
                        },
                        stream_offset: frame.stream_offset,
                        byte_length: frame.bytes.len(),
                    });
                }
                for (candidate_index, accepted) in accepted_by_candidate {
                    let frames = decoded_by_candidate
                        .remove(&candidate_index)
                        .ok_or(RecoveryError::InvariantFailure)?;
                    if accepted_members_seen.get(&candidate_index).copied()
                        != Some(accepted.frame_indices.len())
                    {
                        return Err(RecoveryError::InvariantFailure.into());
                    }
                    let mut accepted_input_node_ids = Vec::new();
                    accepted_input_node_ids
                        .try_reserve_exact(accepted.frame_indices.len())
                        .map_err(|source| {
                            operational("accepted schema input allocation failed", source)
                        })?;
                    let mut remaining_inputs = Vec::new();
                    remaining_inputs
                        .try_reserve_exact(frames.len().saturating_sub(accepted.frame_indices.len()))
                        .map_err(|source| {
                            operational("unassigned record input allocation failed", source)
                        })?;
                    for (frame_index, frame_input) in frames.into_iter().enumerate() {
                        if accepted.frame_indices.binary_search(&frame_index).is_ok() {
                            accepted_input_node_ids.push(frame_input.node_id);
                        } else {
                            remaining_inputs.push(frame_input);
                        }
                    }
                    if accepted_input_node_ids.len() != accepted.frame_indices.len() {
                        return Err(RecoveryError::InvariantFailure.into());
                    }
                    accepted_record_schemas.push((
                        accepted_input_node_ids,
                        accepted.schema,
                        report_node,
                    ));
                    if !remaining_inputs.is_empty() {
                        let key = relational_record_cohort_key(
                            &cohort.context,
                            report_node,
                            candidate_index,
                        );
                        decoded_record_inputs.push((key, remaining_inputs));
                    }
                }
                for (candidate_index, frames) in decoded_by_candidate {
                    let key = relational_record_cohort_key(
                        &cohort.context,
                        report_node,
                        candidate_index,
                    );
                    decoded_record_inputs.push((key, frames));
                }
            }
            let result_node = report_nodes
                .first()
                .copied()
                .ok_or(RecoveryError::InvariantFailure)?;
            let result = if output_node_ids.is_empty() {
                RecoveryResult::Hypothesis { node_id: result_node }
            } else {
                RecoveryResult::Derived {
                    evidence_node_id: result_node,
                }
            };
            Ok((
                CommittedRelationalOutputs {
                    output_node_ids,
                    decoded_record_inputs,
                    accepted_record_schemas,
                },
                result,
            ))
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

fn relational_record_cohort_key(
    context: &RelationalDiscoveryContext,
    report_node: u64,
    candidate_index: usize,
) -> RecordCohortKey {
    RecordCohortKey {
        source_id: context.key.source_id.clone(),
        scope_json: context.key.scope_json.clone(),
        endpoints_json: context.key.endpoints_json.clone(),
        direction: context.key.direction,
        origin: RecordCohortOrigin::Relational {
            report_node,
            candidate_index,
        },
        framing_rule_json: context.key.framing_rule_json.clone(),
    }
}

fn validate_accepted_record_schema(
    candidate_index: usize,
    frames: &[DecodedFrameOutput],
    accepted: &AcceptedRecordSchema,
) -> Result<(), RecoveryExecutionError> {
    if accepted.frame_indices.is_empty()
        || accepted.frame_indices.len() != accepted.frame_identities.len()
        || accepted.artifact_receipt.output_length.is_none()
        || accepted.artifact_receipt.output_sha256.is_none()
    {
        return Err(invalid_policy(
            "accepted record schema has incomplete frame or artifact evidence",
        ));
    }
    let mut previous_index = None;
    for (frame_index, identity) in accepted
        .frame_indices
        .iter()
        .copied()
        .zip(&accepted.frame_identities)
    {
        if previous_index.is_some_and(|previous| previous >= frame_index) {
            return Err(invalid_policy(
                "accepted record schema frame membership is not strictly ordered",
            ));
        }
        let frame = frames
            .get(frame_index)
            .ok_or_else(|| invalid_policy("accepted record schema references a missing frame"))?;
        let frame_bytes_sha256 = sha256(&frame.bytes);
        validate_accepted_frame_identity(
            identity,
            frame,
            frame_index,
            frame.bytes.len(),
            &frame_bytes_sha256,
        )?;
        if frame.candidate_index != candidate_index
            || frame.parser_format != accepted.artifact_format
        {
            return Err(invalid_policy(
                "accepted record schema does not match its frozen candidate",
            ));
        }
        previous_index = Some(frame_index);
    }
    if accepted
        .artifact_receipt
        .parts
        .iter()
        .any(|part| part.input_index >= accepted.frame_indices.len())
    {
        return Err(invalid_policy(
            "accepted artifact receipt references a missing frame",
        ));
    }
    Ok(())
}

fn validate_accepted_frame_identity(
    identity: &record_gate::AcceptedFrameIdentity,
    frame: &DecodedFrameOutput,
    frame_index: usize,
    frame_byte_length: usize,
    frame_bytes_sha256: &str,
) -> Result<(), RecoveryExecutionError> {
    if identity.frame_index != frame_index
        || identity.input_node_id != frame.input_node_id
        || identity.context != frame.context
        || identity.session_order != frame.session_order
        || identity.stream_offset != frame.stream_offset
        || identity.frame_byte_length != frame_byte_length
        || identity.frame_byte_length != frame.bytes.len()
        || identity.frame_bytes_sha256 != frame_bytes_sha256
    {
        return Err(invalid_policy(
            "accepted record schema frame identity changed before materialization",
        ));
    }
    Ok(())
}

fn accepted_record_schema_json(accepted: &AcceptedRecordSchema) -> Value {
    let strategy = match accepted.strategy {
        RecordSchemaStrategy::FixedLayout => "fixed_layout",
        RecordSchemaStrategy::RepeatedBoundaries => "repeated_boundaries",
    };
    let frame_identities = accepted.frame_identities.iter().map(|identity| {
        json!({
            "frame_index":identity.frame_index,
            "input_node_id":identity.input_node_id,
            "context":identity.context,
            "session_order":identity.session_order,
            "stream_offset":identity.stream_offset,
            "frame_byte_length":identity.frame_byte_length,
            "frame_bytes_sha256":identity.frame_bytes_sha256,
        })
    });
    json!({
        "schema":&accepted.schema,
        "strategy":strategy,
        "frame_indices":accepted.frame_indices,
        "frame_identities":frame_identities.collect::<Vec<_>>(),
        "artifact_receipt":&accepted.artifact_receipt,
        "artifact_format":format!("{:?}", accepted.artifact_format),
    })
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
        let mut new_samples = Vec::new();
        new_samples
            .try_reserve_exact(end - cursor)
            .map_err(|source| operational("relational session sample allocation failed", source))?;
        for sample in incoming
            .get(cursor..end)
            .ok_or(RecoveryError::InvariantFailure)?
        {
            if existing_ids.insert(sample.node_id) {
                new_samples.push(sample.clone());
            }
        }
        cursor = end;
        if new_samples.is_empty() {
            continue;
        }

        let existing_session_samples = cohort
            .samples
            .iter()
            .filter(|sample| sample.context.session == session_id)
            .count();
        let existing_session_bytes = sample_bytes_for_session(case, &cohort.samples, session_id)?;
        let new_session_bytes = sample_bytes_for_session(case, &new_samples, session_id)?;
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
        let session_exceeds_limits = cohort.incomplete_sessions.contains(&session_id)
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
        if session_exceeds_limits {
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
            continue;
        }
        cohort
            .samples
            .try_reserve(new_samples.len())
            .map_err(|source| operational("relational cohort sample allocation failed", source))?;
        cohort.samples.extend(new_samples);
    }
    Ok(())
}

fn retain_relational_rule(
    retained: &mut Vec<RetainedRelationalRule>,
    retained_frame_bytes: &mut usize,
    maximum_rules: usize,
    maximum_frame_bytes: usize,
    candidate: RetainedRelationalRule,
) -> Result<bool, RecoveryExecutionError> {
    if maximum_rules == 0 {
        return Ok(false);
    }
    let candidate_frame_bytes = candidate
        .decoded_frames
        .iter()
        .try_fold(0_usize, |total, frame| total.checked_add(frame.bytes.len()))
        .ok_or_else(|| invalid_policy("retained relational frame size overflowed"))?;
    let weakest_index = retained
        .iter()
        .enumerate()
        .min_by_key(|(_, existing)| {
            (
                existing.evidence_priority,
                usize::MAX - existing.candidate_index,
            )
        })
        .map(|(index, _)| index);
    let Some(weakest_index) = weakest_index.filter(|_| retained.len() >= maximum_rules) else {
        if candidate_frame_bytes > maximum_frame_bytes.saturating_sub(*retained_frame_bytes) {
            return Ok(false);
        }
        *retained_frame_bytes = retained_frame_bytes
            .checked_add(candidate_frame_bytes)
            .ok_or_else(|| invalid_policy("retained relational frame size overflowed"))?;
        retained
            .try_reserve(1)
            .map_err(|source| operational("retained relational rule allocation failed", source))?;
        retained.push(candidate);
        return Ok(true);
    };
    let weakest = retained
        .get(weakest_index)
        .ok_or(RecoveryError::InvariantFailure)?;
    let candidate_is_better = candidate.evidence_priority > weakest.evidence_priority
        || (candidate.evidence_priority == weakest.evidence_priority
            && candidate.candidate_index < weakest.candidate_index);
    if !candidate_is_better {
        return Ok(false);
    }
    let weakest_frame_bytes = weakest
        .decoded_frames
        .iter()
        .try_fold(0_usize, |total, frame| total.checked_add(frame.bytes.len()))
        .ok_or_else(|| invalid_policy("retained relational frame size overflowed"))?;
    let available_after_replacement = maximum_frame_bytes
        .saturating_sub(*retained_frame_bytes)
        .saturating_add(weakest_frame_bytes);
    if candidate_frame_bytes > available_after_replacement {
        return Ok(false);
    }
    *retained_frame_bytes = retained_frame_bytes
        .checked_sub(weakest_frame_bytes)
        .and_then(|total| total.checked_add(candidate_frame_bytes))
        .ok_or_else(|| invalid_policy("retained relational frame size overflowed"))?;
    *retained
        .get_mut(weakest_index)
        .ok_or(RecoveryError::InvariantFailure)? = candidate;
    Ok(true)
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

pub(super) fn aggregate_validator(
    mut policy: l2_workbench::artifact::ArtifactValidationPolicy,
    input_length: usize,
    zip_expansion_budget: usize,
) -> Result<ArtifactValidator, RecoveryExecutionError> {
    policy.max_input_bytes = policy.max_input_bytes.min(input_length);
    policy.png_limits.max_input_bytes = policy.png_limits.max_input_bytes.min(input_length);
    policy.zip_limits.max_archive_bytes = policy.zip_limits.max_archive_bytes.min(input_length);
    policy.zip_limits.max_entry_expanded_bytes = policy
        .zip_limits
        .max_entry_expanded_bytes
        .min(zip_expansion_budget.max(1));
    policy.zip_limits.max_total_expanded_bytes = policy
        .zip_limits
        .max_total_expanded_bytes
        .min(zip_expansion_budget);
    ArtifactValidator::new(policy)
        .map_err(|source| operational("relational artifact parser policy was rejected", source))
}

fn samples_for_context<'a>(
    case: &'a l2_workbench::evidence::Case,
    context: &RelationalDiscoveryContext,
) -> Result<Vec<RelationalRecordSample<'a>>, RecoveryExecutionError> {
    let mut samples = Vec::new();
    samples
        .try_reserve_exact(context.sample_node_ids.len())
        .map_err(|source| operational("relational sample allocation failed", source))?;
    for stored in &context.samples {
        let node = case
            .node(stored.node_id)
            .ok_or(RecoveryError::InvariantFailure)?;
        let blob_id = node
            .blob
            .as_deref()
            .ok_or(RecoveryError::InvariantFailure)?;
        let blob = case.blob(blob_id).ok_or(RecoveryError::InvariantFailure)?;
        samples.push(RelationalRecordSample {
            sample: stored.node_id,
            context: stored.context.clone(),
            session_order: stored.session_order,
            bytes: &blob.bytes,
        });
    }
    Ok(samples)
}

fn decoded_payload_frames(
    samples: &[RelationalRecordSample<'_>],
    stored_samples: &[StoredSample],
    applied: &RelationalAppliedOutput,
    rule: &RelationalTransformRule,
    candidate_index: usize,
    transformed_output_sha256: &str,
    expected_session_orders: &[u64],
    raw_directional_run: bool,
) -> Result<Vec<DecodedFrameOutput>, RecoveryExecutionError> {
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(applied.payload_samples.len())
        .map_err(|source| operational("decoded relational frame allocation failed", source))?;
    let payload_start = rule.payload_locator.value_offset;
    if applied.payload_samples.len() != applied.payload_ranges.len() {
        return Err(RecoveryError::InvariantFailure.into());
    }
    for (payload_sample, output_range) in
        applied.payload_samples.iter().zip(&applied.payload_ranges)
    {
        if output_range.start > output_range.end || output_range.end > applied.bytes.len() {
            return Err(RecoveryError::InvariantFailure.into());
        }
        let sample = samples
            .iter()
            .find(|sample| sample.sample == *payload_sample)
            .ok_or(RecoveryError::InvariantFailure)?;
        let stored = stored_samples
            .iter()
            .find(|stored| stored.node_id == *payload_sample)
            .ok_or(RecoveryError::InvariantFailure)?;
        if sample.context.session != applied.session.session {
            return Err(RecoveryError::InvariantFailure.into());
        }
        let transformed = applied
            .bytes
            .get(output_range.start..output_range.end)
            .filter(|payload| !payload.is_empty())
            .ok_or(RecoveryError::InvariantFailure)?;
        let payload_end = payload_start
            .checked_add(transformed.len())
            .ok_or_else(|| invalid_policy("decoded relational payload range overflowed"))?;
        let _payload = sample
            .bytes
            .get(payload_start..payload_end)
            .filter(|payload| !payload.is_empty())
            .ok_or(RecoveryError::InvariantFailure)?;
        let (bytes, payload_range, preserved_header_end, stream_offset) = if raw_directional_run {
            // A raw run has no observed message boundary, so only decrypted bytes are a frame
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(transformed.len())
                .map_err(|source| {
                    operational("decoded relational frame allocation failed", source)
                })?;
            bytes.extend_from_slice(transformed);
            let end = bytes.len();
            let stream_offset = stored
                .stream_offset
                .checked_add(payload_start)
                .ok_or_else(|| invalid_policy("decoded stream offset overflowed"))?;
            (
                bytes,
                l2_workbench::protocol::ByteRange { start: 0, end },
                None,
                stream_offset,
            )
        } else {
            // Source-framed messages keep their exact observed header and byte ancestry
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(sample.bytes.len())
                .map_err(|source| {
                    operational("decoded relational frame allocation failed", source)
                })?;
            bytes.extend_from_slice(sample.bytes);
            let destination = bytes
                .get_mut(payload_start..payload_end)
                .ok_or(RecoveryError::InvariantFailure)?;
            destination.copy_from_slice(transformed);
            (
                bytes,
                l2_workbench::protocol::ByteRange {
                    start: payload_start,
                    end: sample.bytes.len(),
                },
                Some(payload_start),
                stored.stream_offset,
            )
        };
        frames.push(DecodedFrameOutput {
            context: sample.context.clone(),
            input_node_id: sample.sample,
            seed_sample: applied.seed_sample,
            session_order: applied.session_order,
            transformed_output_sha256: transformed_output_sha256.to_owned(),
            direction_node_id: stored.direction_node_id,
            episode_node_id: stored.episode_node_id,
            stream_offset,
            candidate_index,
            parser_format: rule.parser_format,
            expected_session_orders: expected_session_orders.to_vec(),
            payload_range,
            preserved_header_end,
            bytes,
        });
    }
    Ok(frames)
}

fn evaluate_candidate_before_retention(
    evaluation_context: &RelationalTransformEvaluationContext<'_>,
    candidate: &l2_workbench::protocol::RelationalTransformCandidate,
    discovery_outputs: &[RelationalAppliedOutput],
    heldout_outputs: &[RelationalAppliedOutput],
    samples: &[RelationalRecordSample<'_>],
    stored_samples: &[StoredSample],
    raw_directional_run: bool,
    schema_plan_cache: &mut SchemaPlanCache,
    schema_limits: l2_workbench::protocol::RecordSchemaProposalLimits,
    artifact_policy: l2_workbench::artifact::ArtifactValidationPolicy,
    job: Option<&l2_workbench::job::Job>,
) -> Result<RelationalCandidateEvaluation<GateAssessment>, RecoveryExecutionError> {
    let status = match candidate.status {
        RelationalTransformStatus::HeldoutConstraintsSatisfied
            if candidate.rule.parser_scope == RelationalParserScope::EachSession =>
        {
            Some(GateStatus::ArtifactValidated)
        }
        RelationalTransformStatus::AwaitingAcrossSessionValidation => None,
        RelationalTransformStatus::DiscoveryOnlyHypothesis
        | RelationalTransformStatus::UnresolvedOnBudget
        | RelationalTransformStatus::HeldoutConstraintsSatisfied => Some(GateStatus::Pending),
        RelationalTransformStatus::ContradictedByHeldoutSession
        | RelationalTransformStatus::DiscoveryContradicted => Some(GateStatus::Contradicted),
    };
    if let Some(status) = status {
        return Ok(RelationalCandidateEvaluation {
            priority: status.priority(),
            work_bytes: 0,
            assessment: GateAssessment {
                status,
                details: json!({"reason":"candidate_did_not_require_across_session_gate"}),
                accepted_schema: None,
            },
        });
    }

    let output_count = discovery_outputs
        .len()
        .checked_add(heldout_outputs.len())
        .ok_or_else(|| invalid_policy("relational evaluated output count overflowed"))?;
    let mut ordered_outputs = Vec::new();
    ordered_outputs
        .try_reserve_exact(output_count)
        .map_err(|source| operational("relational evaluated output allocation failed", source))?;
    ordered_outputs.extend(discovery_outputs.iter().chain(heldout_outputs));
    ordered_outputs.sort_unstable_by_key(|output| output.session_order);
    let expected_session_orders = ordered_outputs
        .iter()
        .map(|output| output.session_order)
        .collect::<Vec<_>>();

    let mut frames = Vec::new();
    for output in ordered_outputs {
        let output_sha256 = checked_output_sha256(candidate, &output)?;
        frames.extend(decoded_payload_frames(
            samples,
            stored_samples,
            output,
            &candidate.rule,
            0,
            output_sha256,
            &expected_session_orders,
            raw_directional_run,
        )?);
    }
    let report = RelationalTransformReport {
        split_basis: HoldoutBasis::CompleteSessions,
        discovery_sessions: evaluation_context.discovery_sessions.to_vec(),
        heldout_sessions: evaluation_context.heldout_sessions.to_vec(),
        candidates: Vec::new(),
        equivalent_candidate_aliases: 0,
        candidates_examined: 0,
        omitted_candidates: 0,
        omitted_candidates_exact: true,
        candidate_limit_remaining: 0,
        locator_candidates_examined: 0,
        locator_candidate_limit_remaining: 0,
        work_bytes: 0,
        work_bytes_remaining: evaluation_context.work_bytes_remaining,
        search_exhaustive_within_plan: false,
        search_limits: Vec::new(),
        search_limit: None,
    };
    let gate = schema_plan_cache.screen_candidate(
        &frames,
        &report,
        SchemaCandidateOptions {
            parser_format: candidate.rule.parser_format,
            schema_limits,
            artifact_policy,
            work_limit: evaluation_context.work_bytes_remaining,
            job,
        },
    )?;
    Ok(RelationalCandidateEvaluation {
        priority: gate.status.priority(),
        work_bytes: gate.work_bytes,
        assessment: GateAssessment {
            status: gate.status,
            details: gate.details,
            accepted_schema: gate.accepted_schema,
        },
    })
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

const fn should_retain_rule(status: GateStatus, input_coverage_complete: bool) -> bool {
    match status {
        GateStatus::ArtifactValidated => true,
        GateStatus::StructurallySupported => input_coverage_complete,
        GateStatus::Pending | GateStatus::Contradicted => false,
    }
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
