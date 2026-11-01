use super::super::{Executor, RecoveryExecutionError};
use super::application::{CandidateApplication, DecodedFrameContext, decoded_payload_frames};
use super::history::RelationalReplayHistories;
use super::record_gate::SchemaPlanCache;
use super::record_gate::{GateResult, SchemaCandidateOptions, StructuralAdmission};
use super::report::{budget_report, insufficient_sessions_report, report_json};
use super::{
    DecodedFrameOutput, GateAssessment, MAX_RETAINED_RELATIONAL_APPLICATIONS,
    PreparedRelationalCohort, RelationalDiscoveryContext, StoredSample, invalid_policy,
    operational,
};
use l2_workbench::{
    artifact::ArtifactValidationPolicy,
    job::Job,
    protocol::{
        HoldoutBasis, RelationalAppliedOutput, RelationalCandidateEvaluation,
        RelationalCandidateEvaluationReport, RelationalParserScope, RelationalRecordSample,
        RelationalReplayHistory, RelationalTransformEvaluationOptions, RelationalTransformReport,
        RelationalTransformRule, RelationalTransformStatus,
        infer_relational_transform_candidates_with_evaluator_and_history,
    },
    recovery::RecoveryError,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

mod producers;
pub(super) use producers::collect_producer_rules;

pub(super) struct CohortSearchResult {
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
    structural_evidence: Vec<(usize, super::record_gate::StructuralEvidence)>,
    producer_rules: Vec<(usize, RelationalTransformRule)>,
    producer_memory: Option<l2_workbench::job::MemoryLease>,
    published_rules: Vec<RelationalTransformRule>,
    history_used: bool,
}

#[derive(Clone, Copy)]
pub(super) struct FinishEvaluationContext<'ctx, 'samples> {
    pub(super) context: &'ctx RelationalDiscoveryContext,
    pub(super) samples: &'ctx [RelationalRecordSample<'samples>],
    pub(super) search_plan: &'ctx l2_workbench::protocol::RelationalTransformPlan,
    pub(super) cohort_work_budget: usize,
    pub(super) artifact_validation_policy: ArtifactValidationPolicy,
    pub(super) job: Option<&'ctx Job>,
    pub(super) gate: &'ctx CandidateGate<'samples>,
    pub(super) history_complete: Option<bool>,
}

// Gate checks consume the same frozen outputs used by retained candidates
pub(super) struct CandidateGate<'a> {
    samples: &'a [RelationalRecordSample<'a>],
    stored_samples: &'a [StoredSample],
    raw_directional_run: bool,
    pub(super) schema_plan_cache: SchemaPlanCache,
    schema_limits: l2_workbench::protocol::RecordSchemaProposalLimits,
    artifact_policy: ArtifactValidationPolicy,
    job: Option<&'a Job>,
    structural_admission: Option<StructuralAdmission<'a>>,
}

pub(super) fn prepare_contexts(
    executor: &Executor<'_>,
    contexts: Vec<RelationalDiscoveryContext>,
    base_plan: &l2_workbench::protocol::RelationalTransformPlan,
    work_remaining: &mut usize,
    histories: &mut RelationalReplayHistories,
    job: Option<&Job>,
) -> Result<Vec<PreparedRelationalCohort>, RecoveryExecutionError> {
    let mut prepared = Vec::new();
    for context in contexts {
        if let Some(job) = job {
            job.check_cancelled()?;
        }
        let history = if executor.policy.relational_incremental_plan.is_some()
            && executor
                .relational_samples
                .incremental_metadata_stop
                .is_none()
        {
            let limits = executor.policy.relational_transform_plan.limits;
            histories.for_context(&context, limits.max_cohorts, limits.max_total_bytes)
        } else {
            None
        };
        let cohort = prepare_cohort(executor, context, base_plan, work_remaining, history)?;
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
            structural_admission: None,
        }
    }

    pub(super) const fn with_structural_admission(
        mut self,
        memory: &'a l2_workbench::job::MemoryBudget,
        maximum: usize,
    ) -> Self {
        self.structural_admission = Some(StructuralAdmission { memory, maximum });
        self
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
                    structural_evidence: None,
                    assessment_scope: None,
                    work_limited_at: None,
                },
            });
        }
        let frames = self.frames_for_candidate(candidate, discovery_outputs, heldout_outputs)?;
        let report = empty_gate_report(evaluation_context);
        // Framed-message screens share the cohort budget; raw directional runs keep their allocation
        let screen_work_limit = if self.raw_directional_run {
            evaluation_context.work_bytes_remaining
        } else {
            evaluation_context.work_bytes_remaining / MAX_RETAINED_RELATIONAL_APPLICATIONS
        };
        let gate = self.schema_plan_cache.screen_candidate(
            &frames,
            &report,
            SchemaCandidateOptions {
                parser_format: candidate.rule.parser_format,
                schema_limits: self.schema_limits,
                artifact_policy: self.artifact_policy,
                work_limit: screen_work_limit,
                job: self.job,
                producer_rule: Some(&candidate.rule),
                structural_admission: self.structural_admission.as_ref(),
            },
        )?;
        Ok(RelationalCandidateEvaluation {
            priority: gate.status.priority(),
            work_bytes: gate.work_bytes,
            assessment: GateAssessment {
                status: gate.status,
                details: gate.details,
                accepted_schema: gate.accepted_schema,
                structural_evidence: gate.structural_evidence,
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
                producer_rule: None,
                structural_admission: self.structural_admission.as_ref(),
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
            job: self.job,
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

pub(super) fn initial_gate_status(
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

pub(super) fn empty_gate_report(
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
    history: Option<&mut RelationalReplayHistory>,
) -> Result<PreparedRelationalCohort, RecoveryExecutionError> {
    let samples = samples_for_context(executor.case, &context)?;
    let (search_plan, cohort_work_budget, sample_bytes) =
        configure_cohort(&context, &samples, base_plan, *work_remaining)?;
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
            history,
        )?
    };
    finish_cohort(context, result, sample_bytes, work_remaining)
}

pub(super) fn configure_cohort(
    context: &RelationalDiscoveryContext,
    samples: &[RelationalRecordSample<'_>],
    base_plan: &l2_workbench::protocol::RelationalTransformPlan,
    work_remaining: usize,
) -> Result<
    (
        l2_workbench::protocol::RelationalTransformPlan,
        usize,
        usize,
    ),
    RecoveryExecutionError,
> {
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
    Ok((search_plan, cohort_work_budget, sample_bytes))
}

pub(super) fn finish_cohort(
    context: RelationalDiscoveryContext,
    result: CohortSearchResult,
    sample_bytes: usize,
    work_remaining: &mut usize,
) -> Result<PreparedRelationalCohort, RecoveryExecutionError> {
    let report_bytes = serde_json::to_vec(&result.report_value)
        .map_err(|source| operational("relational report serialization failed", source))?;
    // A denied cohort only inspects lengths; it never starts its input scan
    let admitted_input_bytes = if sample_bytes >= *work_remaining {
        0
    } else {
        sample_bytes
    };
    let spent = admitted_input_bytes
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
        structural_evidence: result.structural_evidence,
        producer_rules: result.producer_rules,
        producer_memory: result.producer_memory,
        published_rules: result.published_rules,
        history_used: result.history_used,
        report_details_complete: result.report_details_complete,
        search_exhaustive_within_plan: result.exhaustive,
        candidate_limit_remaining: result.candidate_remaining,
        locator_candidate_limit_remaining: result.locator_remaining,
        work_bytes_remaining: *work_remaining,
        reason: result.reason.map(std::borrow::Cow::Borrowed),
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
        structural_evidence: Vec::new(),
        producer_rules: Vec::new(),
        producer_memory: None,
        published_rules: Vec::new(),
        history_used: false,
    }
}

fn evaluate_cohort(
    executor: &Executor<'_>,
    context: &RelationalDiscoveryContext,
    samples: &[RelationalRecordSample<'_>],
    search_plan: &l2_workbench::protocol::RelationalTransformPlan,
    cohort_work_budget: usize,
    job: Option<&Job>,
    mut history: Option<&mut RelationalReplayHistory>,
) -> Result<CohortSearchResult, RecoveryExecutionError> {
    let mut gate = CandidateGate::new(
        samples,
        &context.samples,
        context.key.framing_rule_json == super::RAW_RUN_FRAMING_RULE,
        executor.policy.record_schema_proposal_limits,
        executor.policy.artifact_validation_policy,
        job,
    );
    let evaluation = infer_relational_transform_candidates_with_evaluator_and_history(
        samples,
        search_plan,
        job,
        RelationalTransformEvaluationOptions {
            max_retained_output_bytes: search_plan.limits.max_total_bytes,
        },
        history.as_deref_mut(),
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
    let history_complete = history.as_deref().map(RelationalReplayHistory::is_complete);
    finish_evaluation(
        FinishEvaluationContext {
            context,
            samples,
            search_plan,
            cohort_work_budget,
            artifact_validation_policy: executor.policy.artifact_validation_policy,
            job,
            gate: &gate,
            history_complete,
        },
        evaluation,
    )
}

pub(super) fn finish_evaluation(
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
        history_complete,
    } = context;
    let RelationalCandidateEvaluationReport {
        report,
        evaluations,
        history_reused_rejections,
        history_reused_published,
        history_recording_omissions,
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
    let (producer_rules, producer_memory) =
        collect_producer_rules(&report.candidates, &applications, gate.structural_admission)?;
    let published_rules = if history_complete.is_some() {
        fully_published_rules(&report, &applications.outputs)?
    } else {
        Vec::new()
    };
    let mut report_value = report_json(
        context,
        &report,
        search_plan,
        applications.supported_rules,
        applications.applied_rules,
        &applications.aggregate_parser_checks,
        &applications.application_evidence_checks,
    );
    if context.lane == super::RelationalLane::Incremental {
        let fields = report_value
            .as_object_mut()
            .ok_or_else(|| invalid_policy("relational report is not an object"))?;
        add_history_search_fields(
            fields,
            history_reused_rejections,
            history_reused_published,
            history_recording_omissions,
            history_complete,
        );
    }
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
        structural_evidence: applications.structural_evidence,
        producer_rules,
        producer_memory,
        published_rules,
        history_used: history_complete.is_some(),
    })
}

pub(super) fn add_history_search_fields(
    fields: &mut serde_json::Map<String, Value>,
    reused_rejections: usize,
    reused_published: usize,
    recording_omissions: usize,
    complete_before_publication: Option<bool>,
) {
    fields.insert(
        "history_reused_rejections".to_owned(),
        serde_json::json!(reused_rejections),
    );
    fields.insert(
        "history_reused_published".to_owned(),
        serde_json::json!(reused_published),
    );
    fields.insert(
        "history_search_recording_omissions".to_owned(),
        serde_json::json!(recording_omissions),
    );
    fields.insert(
        "history_complete_before_publication".to_owned(),
        serde_json::json!(complete_before_publication),
    );
}

fn fully_published_rules(
    report: &RelationalTransformReport,
    outputs: &[super::AppliedOutput],
) -> Result<Vec<RelationalTransformRule>, RecoveryExecutionError> {
    let sessions = report
        .discovery_sessions
        .iter()
        .chain(&report.heldout_sessions)
        .map(|session| session.session)
        .collect::<BTreeSet<_>>();
    let mut by_candidate = BTreeMap::<usize, BTreeSet<u64>>::new();
    for output in outputs {
        by_candidate
            .entry(output.candidate_index)
            .or_default()
            .extend(output.session_ids.iter().copied());
    }
    let mut rules = Vec::new();
    rules
        .try_reserve_exact(by_candidate.len())
        .map_err(|source| operational("published relational rule allocation failed", source))?;
    for (candidate_index, output_sessions) in by_candidate {
        if !sessions.is_empty() && output_sessions == sessions {
            let candidate = report
                .candidates
                .get(candidate_index)
                .ok_or(RecoveryError::InvariantFailure)?;
            rules.push(candidate.rule.clone());
        }
    }
    Ok(rules)
}

pub(super) fn samples_for_context<'a>(
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
