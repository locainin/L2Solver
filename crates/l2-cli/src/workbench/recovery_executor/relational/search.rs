use super::super::{Executor, RecoveryExecutionError};
use super::application::{CandidateApplication, DecodedFrameContext, decoded_payload_frames};
use super::record_gate::SchemaPlanCache;
use super::record_gate::{GateResult, SchemaCandidateOptions};
use super::report::{budget_report, insufficient_sessions_report, report_json};
use super::{
    DecodedFrameOutput, GateAssessment, PreparedRelationalCohort, RelationalDiscoveryContext,
    StoredSample, invalid_policy, operational,
};
use l2_workbench::{
    artifact::ArtifactValidationPolicy,
    job::Job,
    protocol::{
        HoldoutBasis, RelationalAppliedOutput, RelationalCandidateEvaluation,
        RelationalCandidateEvaluationReport, RelationalParserScope, RelationalRecordSample,
        RelationalTransformEvaluationOptions, RelationalTransformReport, RelationalTransformStatus,
        infer_relational_transform_candidates_with_evaluator,
    },
    recovery::RecoveryError,
};
use serde_json::Value;

struct CohortSearchResult {
    report_value: Value,
    report_details_complete: bool,
    exhaustive: bool,
    candidate_remaining: usize,
    locator_remaining: usize,
    used_work: usize,
    reason: Option<&'static str>,
    outputs: Vec<super::AppliedOutput>,
    decoded_frames: Vec<DecodedFrameOutput>,
    accepted_schemas: Vec<(usize, super::record_gate::AcceptedRecordSchema)>,
}

#[derive(Clone, Copy)]
struct FinishEvaluationContext<'ctx, 'samples> {
    context: &'ctx RelationalDiscoveryContext,
    samples: &'ctx [RelationalRecordSample<'samples>],
    search_plan: &'ctx l2_workbench::protocol::RelationalTransformPlan,
    cohort_work_budget: usize,
    artifact_validation_policy: ArtifactValidationPolicy,
    job: Option<&'ctx Job>,
    gate: &'ctx CandidateGate<'samples>,
}

// Gate checks consume the same frozen outputs used by retained candidates
pub(super) struct CandidateGate<'a> {
    samples: &'a [RelationalRecordSample<'a>],
    stored_samples: &'a [StoredSample],
    raw_directional_run: bool,
    schema_plan_cache: SchemaPlanCache,
    schema_limits: l2_workbench::protocol::RecordSchemaProposalLimits,
    artifact_policy: ArtifactValidationPolicy,
    job: Option<&'a Job>,
}

pub(super) fn prepare_contexts(
    executor: &Executor<'_>,
    contexts: Vec<RelationalDiscoveryContext>,
    base_plan: &l2_workbench::protocol::RelationalTransformPlan,
    work_remaining: &mut usize,
    job: Option<&Job>,
) -> Result<Vec<PreparedRelationalCohort>, RecoveryExecutionError> {
    let mut prepared = Vec::new();
    for context in contexts {
        if let Some(job) = job {
            job.check_cancelled()?;
        }
        let cohort = prepare_cohort(executor, context, base_plan, work_remaining)?;
        prepared
            .try_reserve(1)
            .map_err(|source| operational("relational report allocation failed", source))?;
        prepared.push(cohort);
    }
    Ok(prepared)
}

impl<'a> CandidateGate<'a> {
    pub(super) fn new(
        samples: &'a [RelationalRecordSample<'a>],
        stored_samples: &'a [StoredSample],
        raw_directional_run: bool,
        schema_limits: l2_workbench::protocol::RecordSchemaProposalLimits,
        artifact_policy: ArtifactValidationPolicy,
        job: Option<&'a Job>,
    ) -> Self {
        Self {
            samples,
            stored_samples,
            raw_directional_run,
            schema_plan_cache: SchemaPlanCache::default(),
            schema_limits,
            artifact_policy,
            job,
        }
    }

    pub(super) fn evaluate(
        &mut self,
        evaluation_context: &l2_workbench::protocol::RelationalTransformEvaluationContext<'_>,
        candidate: &l2_workbench::protocol::RelationalTransformCandidate,
        discovery_outputs: &[RelationalAppliedOutput],
        heldout_outputs: &[RelationalAppliedOutput],
    ) -> Result<RelationalCandidateEvaluation<GateAssessment>, RecoveryExecutionError> {
        if let Some(status) = initial_gate_status(candidate) {
            return Ok(RelationalCandidateEvaluation {
                priority: status.priority(),
                work_bytes: 0,
                assessment: GateAssessment {
                    status,
                    details: serde_json::json!({"reason":"candidate_did_not_require_across_session_gate"}),
                    accepted_schema: None,
                    assessment_scope: None,
                    work_limited_at: None,
                },
            });
        }
        let frames = self.frames_for_candidate(candidate, discovery_outputs, heldout_outputs)?;
        let report = empty_gate_report(evaluation_context);
        let gate = self.schema_plan_cache.screen_candidate(
            &frames,
            &report,
            SchemaCandidateOptions {
                parser_format: candidate.rule.parser_format,
                schema_limits: self.schema_limits,
                artifact_policy: self.artifact_policy,
                work_limit: evaluation_context.work_bytes_remaining,
                job: self.job,
            },
        )?;
        Ok(RelationalCandidateEvaluation {
            priority: gate.status.priority(),
            work_bytes: gate.work_bytes,
            assessment: GateAssessment {
                status: gate.status,
                details: gate.details,
                accepted_schema: gate.accepted_schema,
                assessment_scope: Some(gate.assessment_scope),
                work_limited_at: gate.work_limited_at,
            },
        })
    }

    pub(super) fn screen_full_inference(
        &self,
        frames: &[DecodedFrameOutput],
        report: &l2_workbench::protocol::RelationalTransformReport,
        parser_format: l2_workbench::artifact::ArtifactValidationFormat,
        work_limit: usize,
    ) -> Result<GateResult, RecoveryExecutionError> {
        SchemaPlanCache::screen_full_inference(
            frames,
            report,
            SchemaCandidateOptions {
                parser_format,
                schema_limits: self.schema_limits,
                artifact_policy: self.artifact_policy,
                work_limit,
                job: self.job,
            },
        )
    }

    fn frames_for_candidate(
        &self,
        candidate: &l2_workbench::protocol::RelationalTransformCandidate,
        discovery_outputs: &[RelationalAppliedOutput],
        heldout_outputs: &[RelationalAppliedOutput],
    ) -> Result<Vec<DecodedFrameOutput>, RecoveryExecutionError> {
        let output_count = discovery_outputs
            .len()
            .checked_add(heldout_outputs.len())
            .ok_or_else(|| invalid_policy("relational evaluated output count overflowed"))?;
        let mut ordered_outputs = Vec::new();
        ordered_outputs
            .try_reserve_exact(output_count)
            .map_err(|source| {
                operational("relational evaluated output allocation failed", source)
            })?;
        ordered_outputs.extend(discovery_outputs.iter().chain(heldout_outputs));
        ordered_outputs.sort_unstable_by_key(|output| output.session_order);
        let expected_session_orders = ordered_outputs
            .iter()
            .map(|output| output.session_order)
            .collect::<Vec<_>>();
        let frame_context = DecodedFrameContext {
            samples: self.samples,
            stored_samples: self.stored_samples,
            candidate_index: 0,
            expected_session_orders: &expected_session_orders,
            raw_directional_run: self.raw_directional_run,
        };
        let mut frames = Vec::new();
        for output in ordered_outputs {
            let output_sha256 = super::checked_output_sha256(candidate, output)?;
            frames.extend(decoded_payload_frames(
                &frame_context,
                output,
                &candidate.rule,
                output_sha256,
            )?);
        }
        Ok(frames)
    }
}

fn initial_gate_status(
    candidate: &l2_workbench::protocol::RelationalTransformCandidate,
) -> Option<super::record_gate::GateStatus> {
    use super::record_gate::GateStatus;
    match candidate.status {
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
    }
}

fn empty_gate_report(
    evaluation_context: &l2_workbench::protocol::RelationalTransformEvaluationContext<'_>,
) -> RelationalTransformReport {
    RelationalTransformReport {
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
        prefix_probe_hypotheses_examined: 0,
        prefix_probes_examined: 0,
        prefix_probe_cache_reuses: 0,
        prefix_probe_candidates_with_novelty: 0,
        prefix_probe_work_bytes: 0,
        prefix_probe_complete: true,
        locator_candidate_limit_remaining: 0,
        work_bytes: 0,
        work_bytes_remaining: evaluation_context.work_bytes_remaining,
        search_exhaustive_within_plan: false,
        search_limits: Vec::new(),
        search_limit: None,
    }
}

pub(super) fn prepare_cohort(
    executor: &Executor<'_>,
    context: RelationalDiscoveryContext,
    base_plan: &l2_workbench::protocol::RelationalTransformPlan,
    work_remaining: &mut usize,
) -> Result<PreparedRelationalCohort, RecoveryExecutionError> {
    let samples = samples_for_context(executor.case, &context)?;
    let sample_bytes = samples.iter().try_fold(0_usize, |total, sample| {
        total.checked_add(sample.bytes.len())
    });
    let sample_bytes =
        sample_bytes.ok_or_else(|| invalid_policy("relational input byte count overflowed"))?;
    let mut search_plan = base_plan.clone();
    if context.key.framing_rule_json == super::RAW_RUN_FRAMING_RULE {
        // Raw runs may place a stable payload marker after the seed prefix
        search_plan.limits.max_marker_offset = search_plan
            .limits
            .max_marker_offset
            .max(search_plan.limits.max_locator_offset);
    }
    // Input scans reserve half of the remaining allowance for validation and replay
    let shared_work_budget = work_remaining.saturating_sub(sample_bytes) / 2;
    let cohort_work_budget = search_plan.limits.max_work_bytes.min(shared_work_budget);
    // Keep half of the existing cohort allowance available for replay and parser checks
    search_plan.limits.max_work_bytes = cohort_work_budget / 2;
    let job = executor.job.as_ref().map(|progress| &progress.job);
    let result = if context.sessions_available < 2 {
        preflight_result(
            insufficient_sessions_report(&context, &search_plan),
            search_plan.limits.max_candidates,
            search_plan.limits.max_locator_candidates.saturating_mul(2),
            "insufficient_independent_sessions",
        )
    } else if sample_bytes >= *work_remaining {
        preflight_result(
            budget_report(&context, &search_plan, "coordinator_work_limit"),
            search_plan.limits.max_candidates,
            search_plan.limits.max_locator_candidates.saturating_mul(2),
            "coordinator_work_limit",
        )
    } else {
        evaluate_cohort(
            executor,
            &context,
            &samples,
            &search_plan,
            cohort_work_budget,
            job,
        )?
    };
    let report_bytes = serde_json::to_vec(&result.report_value)
        .map_err(|source| operational("relational report serialization failed", source))?;
    let spent = sample_bytes
        .checked_add(result.used_work)
        .ok_or_else(|| invalid_policy("relational work total overflowed"))?;
    if spent > *work_remaining {
        return Err(invalid_policy("relational work admission was exceeded"));
    }
    *work_remaining -= spent;
    Ok(PreparedRelationalCohort {
        context,
        report_bytes,
        outputs: result.outputs,
        decoded_frames: result.decoded_frames,
        accepted_schemas: result.accepted_schemas,
        report_details_complete: result.report_details_complete,
        search_exhaustive_within_plan: result.exhaustive,
        candidate_limit_remaining: result.candidate_remaining,
        locator_candidate_limit_remaining: result.locator_remaining,
        work_bytes_remaining: *work_remaining,
        reason: result.reason,
    })
}

const fn preflight_result(
    report_value: Value,
    candidate_remaining: usize,
    locator_remaining: usize,
    reason: &'static str,
) -> CohortSearchResult {
    CohortSearchResult {
        report_value,
        report_details_complete: true,
        exhaustive: false,
        candidate_remaining,
        locator_remaining,
        used_work: 0,
        reason: Some(reason),
        outputs: Vec::new(),
        decoded_frames: Vec::new(),
        accepted_schemas: Vec::new(),
    }
}

fn evaluate_cohort(
    executor: &Executor<'_>,
    context: &RelationalDiscoveryContext,
    samples: &[RelationalRecordSample<'_>],
    search_plan: &l2_workbench::protocol::RelationalTransformPlan,
    cohort_work_budget: usize,
    job: Option<&Job>,
) -> Result<CohortSearchResult, RecoveryExecutionError> {
    let mut gate = CandidateGate::new(
        samples,
        &context.samples,
        context.key.framing_rule_json == super::RAW_RUN_FRAMING_RULE,
        executor.policy.record_schema_proposal_limits,
        executor.policy.artifact_validation_policy,
        job,
    );
    let evaluation = infer_relational_transform_candidates_with_evaluator(
        samples,
        search_plan,
        job,
        RelationalTransformEvaluationOptions {
            max_retained_output_bytes: search_plan.limits.max_total_bytes,
        },
        |evaluation_context, candidate, discovery_outputs, heldout_outputs| {
            gate.evaluate(
                evaluation_context,
                candidate,
                discovery_outputs,
                heldout_outputs,
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
        Err(l2_workbench::protocol::RelationalEvaluationError::EvaluatorWorkLimit { .. }) => {
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
    finish_evaluation(
        FinishEvaluationContext {
            context,
            samples,
            search_plan,
            cohort_work_budget,
            artifact_validation_policy: executor.policy.artifact_validation_policy,
            job,
            gate: &gate,
        },
        evaluation,
    )
}

fn finish_evaluation(
    context: FinishEvaluationContext<'_, '_>,
    evaluation: RelationalCandidateEvaluationReport<GateAssessment>,
) -> Result<CohortSearchResult, RecoveryExecutionError> {
    let FinishEvaluationContext {
        context,
        samples,
        search_plan,
        cohort_work_budget,
        artifact_validation_policy,
        job,
        gate,
    } = context;
    let RelationalCandidateEvaluationReport {
        report,
        evaluations,
        ..
    } = evaluation;
    let applications = CandidateApplication::new(
        context,
        samples,
        search_plan,
        artifact_validation_policy,
        cohort_work_budget,
        &report,
        job,
    )?
    .apply(&report, evaluations, gate)?;
    let report_value = report_json(
        context,
        &report,
        search_plan,
        applications.supported_rules,
        applications.applied_rules,
        &applications.aggregate_parser_checks,
        &applications.application_evidence_checks,
    );
    Ok(CohortSearchResult {
        report_value,
        report_details_complete: true,
        exhaustive: report.search_exhaustive_within_plan,
        candidate_remaining: report.candidate_limit_remaining,
        locator_remaining: report.locator_candidate_limit_remaining,
        used_work: applications.used_work,
        reason: applications.reason,
        outputs: applications.outputs,
        decoded_frames: applications.decoded_frames,
        accepted_schemas: applications.accepted_schemas,
    })
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
