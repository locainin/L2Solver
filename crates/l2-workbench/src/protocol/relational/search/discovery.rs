use super::super::model::{
    RelationalAppliedOutput, RelationalCandidateEvaluation, RelationalCandidateEvaluationReport,
    RelationalCandidateOutputs, RelationalCounterReset, RelationalEvaluationError, RelationalFit,
    RelationalFitStatus, RelationalOperationTemplate, RelationalRecordSample,
    RelationalRetainedEvaluation, RelationalSearchLimit, RelationalSha256CounterXor,
    RelationalTransformCandidate, RelationalTransformError, RelationalTransformEvaluationContext,
    RelationalTransformEvaluationOptions, RelationalTransformLimits, RelationalTransformPlan,
    RelationalTransformReport, RelationalTransformRule, RelationalTransformStatus,
};
use super::{
    input::{
        SessionGroup, build_selector_indexes, group_sessions, shared_selectors, validate_plan,
    },
    locator::{LocatorCandidate, locator_ranges_overlap, payload_locators, seed_locators},
    replay::{EvaluatedSplit, candidate_status, empty_fit, evaluate_split},
};
use crate::{
    job::{Counter, Job, Phase},
    protocol::{HoldoutBasis, RelationalSessionId},
};
use std::convert::Infallible;

struct SearchState<T> {
    candidates: Vec<RetainedCandidate<T>>,
    candidates_examined: usize,
    equivalent_candidate_aliases: usize,
    omitted_candidates: usize,
    omitted_candidates_exact: bool,
    work_bytes: usize,
    search_exhaustive: bool,
    search_limit: Option<RelationalSearchLimit>,
    search_limits: Vec<RelationalSearchLimit>,
    locator_candidates_examined: usize,
    output_bytes_retained: usize,
    output_capture_omissions: usize,
}

struct RetainedCandidate<T> {
    candidate: RelationalTransformCandidate,
    priority: u8,
    assessment: T,
    outputs: Option<RelationalCandidateOutputs>,
    captured_output_bytes: usize,
    output_capture_omitted: bool,
    search_order: usize,
}

struct CandidateRetention<T> {
    candidate: RelationalTransformCandidate,
    evaluation: RelationalCandidateEvaluation<T>,
    discovery_outputs: Vec<RelationalAppliedOutput>,
    heldout_outputs: Vec<RelationalAppliedOutput>,
    search_order: usize,
}

#[derive(Clone, Copy)]
enum RetentionMode {
    PerLocatorPair,
    EvaluatorPriority,
}

#[derive(Clone, Copy)]
struct SearchSettings {
    retention_mode: RetentionMode,
    max_retained_output_bytes: usize,
    capture_outputs_for_evaluator: bool,
}

#[derive(Clone, Copy)]
struct CandidateParameters {
    operation: RelationalSha256CounterXor,
    counter_reset: RelationalCounterReset,
    parser_format: crate::artifact::ArtifactValidationFormat,
}

impl<T> SearchState<T> {
    const fn new() -> Self {
        Self {
            candidates: Vec::new(),
            candidates_examined: 0,
            equivalent_candidate_aliases: 0,
            omitted_candidates: 0,
            omitted_candidates_exact: true,
            work_bytes: 0,
            search_exhaustive: true,
            search_limit: None,
            search_limits: Vec::new(),
            locator_candidates_examined: 0,
            output_bytes_retained: 0,
            output_capture_omissions: 0,
        }
    }

    fn stop(&mut self, limit: RelationalSearchLimit) {
        self.search_exhaustive = false;
        self.record_limit(limit);
    }

    fn record_limit(&mut self, limit: RelationalSearchLimit) {
        if self.search_limit.is_none() {
            self.search_limit = Some(limit);
        }
        if !self.search_limits.contains(&limit) {
            self.search_limits.push(limit);
        }
    }
}

struct PreparedSearch {
    discovery_sessions: Vec<RelationalSessionId>,
    heldout_sessions: Vec<RelationalSessionId>,
    discovery_groups: Vec<SessionGroup>,
    heldout_groups: Vec<SessionGroup>,
    discovery_indexes: Vec<super::input::SelectorIndex>,
    seed_locators: Vec<LocatorCandidate>,
    payload_locators: Vec<LocatorCandidate>,
    locators_complete: bool,
}

const RETAINED_LOCATOR_PAIR_TARGET: usize = 8;

/// Learn session-relative seed and payload ranges, then apply frozen rules to whole held-out sessions
///
/// Marker bytes and offsets are proposed from discovery sessions only. Each discovered rule reads
/// a new seed from every session and must produce bytes accepted by an exact structural parser.
/// Failed locator and parser checks remain attached to any rule with discovery support
///
/// # Errors
/// Returns an error for invalid samples, unsupported search plans, or canonical derivation errors
pub fn infer_relational_transform_candidates(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
) -> Result<RelationalTransformReport, RelationalTransformError> {
    infer_relational_transform_candidates_with_job(samples, plan, None)
}

/// Discover bounded relational transform candidates while reporting progress and cancellation
///
/// The supplied job remains optional so callers can use deterministic offline analysis without
/// attaching it to a longer recovery run
///
/// # Errors
/// Returns an error for invalid samples, unsupported plans, derivation failures, or cancellation
pub fn infer_relational_transform_candidates_with_job(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
    job: Option<&Job>,
) -> Result<RelationalTransformReport, RelationalTransformError> {
    let mut evaluator =
        |_: &RelationalTransformEvaluationContext<'_>,
         _: &RelationalTransformCandidate,
         _: &[RelationalAppliedOutput],
         _: &[RelationalAppliedOutput]| { Ok::<_, Infallible>(no_candidate_evaluation()) };
    match infer_with_evaluator(
        samples,
        plan,
        job,
        RelationalTransformEvaluationOptions::default(),
        RetentionMode::PerLocatorPair,
        false,
        &mut evaluator,
    ) {
        Ok(evaluated) => Ok(evaluated.report),
        Err(RelationalEvaluationError::Search(error)) => Err(error),
        Err(RelationalEvaluationError::Evaluator(never)) => match never {},
        Err(RelationalEvaluationError::EvaluatorWorkLimit { .. }) => {
            Err(RelationalTransformError::InvalidPlan(
                "default candidate evaluator exceeded its work allowance",
            ))
        }
    }
}

const fn no_candidate_evaluation() -> RelationalCandidateEvaluation<()> {
    RelationalCandidateEvaluation {
        priority: 0,
        work_bytes: 0,
        assessment: (),
    }
}

/// Evaluate frozen candidates before a bounded priority-based retention step
///
/// The callback sees successful decoded outputs from the same discovery and held-out replay
/// passes. Candidate fit checks preserve each session's pass, contradiction, or unresolved state
/// Reported callback work is charged to the shared limit before retention. Its assessment is stored
/// only for retained candidates, while optional output capture stays within the explicit global
/// byte allowance. Higher priorities replace lower priorities; ties preserve earlier search results
/// Assessment size is caller controlled, so assessments should remain compact
///
/// # Errors
/// Returns search, callback, or evaluator-budget errors
pub fn infer_relational_transform_candidates_with_evaluator<T, E, F>(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
    job: Option<&Job>,
    options: RelationalTransformEvaluationOptions,
    mut evaluator: F,
) -> Result<RelationalCandidateEvaluationReport<T>, RelationalEvaluationError<E>>
where
    F: FnMut(
        &RelationalTransformEvaluationContext<'_>,
        &RelationalTransformCandidate,
        &[RelationalAppliedOutput],
        &[RelationalAppliedOutput],
    ) -> Result<RelationalCandidateEvaluation<T>, E>,
{
    infer_with_evaluator(
        samples,
        plan,
        job,
        options,
        RetentionMode::EvaluatorPriority,
        true,
        &mut evaluator,
    )
}

fn infer_with_evaluator<T, E, F>(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
    job: Option<&Job>,
    options: RelationalTransformEvaluationOptions,
    retention_mode: RetentionMode,
    capture_outputs_for_evaluator: bool,
    evaluator: &mut F,
) -> Result<RelationalCandidateEvaluationReport<T>, RelationalEvaluationError<E>>
where
    F: FnMut(
        &RelationalTransformEvaluationContext<'_>,
        &RelationalTransformCandidate,
        &[RelationalAppliedOutput],
        &[RelationalAppliedOutput],
    ) -> Result<RelationalCandidateEvaluation<T>, E>,
{
    if let Some(job) = job {
        job.check_cancelled()
            .map_err(RelationalTransformError::from)?;
    }
    validate_plan(plan)?;
    if options.max_retained_output_bytes > plan.limits.max_total_bytes {
        return Err(RelationalEvaluationError::Search(
            RelationalTransformError::InvalidPlan(
                "retained evaluator outputs exceed the aggregate byte limit",
            ),
        ));
    }
    let prepared = prepare_search(samples, plan)?;
    let search = search_candidates(
        samples,
        plan,
        job,
        &prepared,
        SearchSettings {
            retention_mode,
            max_retained_output_bytes: options.max_retained_output_bytes,
            capture_outputs_for_evaluator,
        },
        evaluator,
    )?;
    Ok(build_report(search, prepared, plan.limits)?)
}

fn prepare_search(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
) -> Result<PreparedSearch, RelationalTransformError> {
    let mut discovery_groups = group_sessions(samples, plan.limits)?;
    let discovery_count = discovery_groups.len().div_ceil(2);
    let heldout_groups = discovery_groups.split_off(discovery_count);
    let discovery_sessions = discovery_groups
        .iter()
        .map(|group| group.id.clone())
        .collect();
    let heldout_sessions = heldout_groups
        .iter()
        .map(|group| group.id.clone())
        .collect();
    let discovery_indexes = build_selector_indexes(samples, &discovery_groups, plan.limits)?;
    let common_selectors = shared_selectors(&discovery_indexes)?;
    let (seed_locators, seed_locators_complete) = seed_locators(
        samples,
        &discovery_groups,
        &discovery_indexes,
        &common_selectors,
        plan.limits,
    )?;
    let (payload_locators, payload_locators_complete) = payload_locators(
        samples,
        &discovery_groups,
        &discovery_indexes,
        &common_selectors,
        plan.limits,
    )?;
    Ok(PreparedSearch {
        discovery_sessions,
        heldout_sessions,
        discovery_groups,
        heldout_groups,
        discovery_indexes,
        seed_locators,
        payload_locators,
        locators_complete: seed_locators_complete && payload_locators_complete,
    })
}

fn search_candidates<T, E, F>(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
    job: Option<&Job>,
    prepared: &PreparedSearch,
    settings: SearchSettings,
    evaluator: &mut F,
) -> Result<SearchState<T>, RelationalEvaluationError<E>>
where
    F: FnMut(
        &RelationalTransformEvaluationContext<'_>,
        &RelationalTransformCandidate,
        &[RelationalAppliedOutput],
        &[RelationalAppliedOutput],
    ) -> Result<RelationalCandidateEvaluation<T>, E>,
{
    let mut search = SearchState::new();
    search.locator_candidates_examined =
        prepared.seed_locators.len() + prepared.payload_locators.len();
    SearchContext {
        samples,
        plan,
        job,
        prepared,
        settings,
    }
    .search_all(&mut search, evaluator)?;
    Ok(search)
}

struct SearchContext<'a, 'bytes> {
    samples: &'a [RelationalRecordSample<'bytes>],
    plan: &'a RelationalTransformPlan,
    job: Option<&'a Job>,
    prepared: &'a PreparedSearch,
    settings: SearchSettings,
}

impl SearchContext<'_, '_> {
    fn search_all<T, E, F>(
        &self,
        search: &mut SearchState<T>,
        evaluator: &mut F,
    ) -> Result<(), RelationalEvaluationError<E>>
    where
        F: FnMut(
            &RelationalTransformEvaluationContext<'_>,
            &RelationalTransformCandidate,
            &[RelationalAppliedOutput],
            &[RelationalAppliedOutput],
        ) -> Result<RelationalCandidateEvaluation<T>, E>,
    {
        if !self.prepared.locators_complete {
            search.stop(RelationalSearchLimit::LocatorCount);
            search.omitted_candidates_exact = false;
        }
        for seed_locator in &self.prepared.seed_locators {
            for payload_locator in &self.prepared.payload_locators {
                if locator_ranges_overlap(
                    self.samples,
                    &self.prepared.discovery_indexes,
                    &seed_locator.selector,
                    &payload_locator.selector,
                    &seed_locator.locator,
                    &payload_locator.locator,
                ) {
                    continue;
                }
                if !self.search_locator_pair(search, seed_locator, payload_locator, evaluator)? {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn search_locator_pair<T, E, F>(
        &self,
        search: &mut SearchState<T>,
        seed_locator: &LocatorCandidate,
        payload_locator: &LocatorCandidate,
        evaluator: &mut F,
    ) -> Result<bool, RelationalEvaluationError<E>>
    where
        F: FnMut(
            &RelationalTransformEvaluationContext<'_>,
            &RelationalTransformCandidate,
            &[RelationalAppliedOutput],
            &[RelationalAppliedOutput],
        ) -> Result<RelationalCandidateEvaluation<T>, E>,
    {
        for counter_width in &self.plan.counter_widths {
            for initial_counter in &self.plan.initial_counters {
                if *initial_counter > counter_width.maximum_counter() {
                    continue;
                }
                if !self.search_counter_options(
                    search,
                    seed_locator,
                    payload_locator,
                    *counter_width,
                    *initial_counter,
                    evaluator,
                )? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn search_counter_options<T, E, F>(
        &self,
        search: &mut SearchState<T>,
        seed_locator: &LocatorCandidate,
        payload_locator: &LocatorCandidate,
        counter_width: crate::derivation::CounterWidth,
        initial_counter: u64,
        evaluator: &mut F,
    ) -> Result<bool, RelationalEvaluationError<E>>
    where
        F: FnMut(
            &RelationalTransformEvaluationContext<'_>,
            &RelationalTransformCandidate,
            &[RelationalAppliedOutput],
            &[RelationalAppliedOutput],
        ) -> Result<RelationalCandidateEvaluation<T>, E>,
    {
        let mut first_byte_order = true;
        for counter_byte_order in &self.plan.counter_byte_orders {
            if counter_width == crate::derivation::CounterWidth::OneByte && !first_byte_order {
                self.count_equivalent_candidate_aliases(search)?;
                continue;
            }
            first_byte_order = false;
            for seed_order in &self.plan.seed_orders {
                for counter_reset in &self.plan.counter_resets {
                    for parser_format in &self.plan.parser_formats {
                        if !self.try_candidate(
                            search,
                            seed_locator,
                            payload_locator,
                            CandidateParameters {
                                operation: RelationalSha256CounterXor {
                                    initial_counter,
                                    counter_width,
                                    counter_byte_order: *counter_byte_order,
                                    seed_order: *seed_order,
                                },
                                counter_reset: *counter_reset,
                                parser_format: *parser_format,
                            },
                            evaluator,
                        )? {
                            return Ok(false);
                        }
                    }
                }
            }
        }
        Ok(true)
    }

    fn try_candidate<T, E, F>(
        &self,
        search: &mut SearchState<T>,
        seed_locator: &LocatorCandidate,
        payload_locator: &LocatorCandidate,
        parameters: CandidateParameters,
        evaluator: &mut F,
    ) -> Result<bool, RelationalEvaluationError<E>>
    where
        F: FnMut(
            &RelationalTransformEvaluationContext<'_>,
            &RelationalTransformCandidate,
            &[RelationalAppliedOutput],
            &[RelationalAppliedOutput],
        ) -> Result<RelationalCandidateEvaluation<T>, E>,
    {
        if search.candidates_examined == self.plan.limits.max_candidates {
            search.stop(RelationalSearchLimit::CandidateCount);
            search.omitted_candidates = search.omitted_candidates.checked_add(1).ok_or(
                RelationalTransformError::InvalidPlan(
                    "omitted relational candidate count overflowed",
                ),
            )?;
            search.omitted_candidates_exact = false;
            return Ok(false);
        }
        if let Some(job) = self.job {
            job.check_cancelled()
                .map_err(RelationalTransformError::from)?;
            job.record_work(Phase::TransformDiscovery, Counter::CandidatesExamined, 1)
                .map_err(RelationalTransformError::from)?;
        }
        search.candidates_examined += 1;
        let rule = make_rule(seed_locator, payload_locator, parameters, self.plan);
        self.evaluate_candidate(search, rule, evaluator)
    }
}

fn make_rule(
    seed_locator: &LocatorCandidate,
    payload_locator: &LocatorCandidate,
    parameters: CandidateParameters,
    plan: &RelationalTransformPlan,
) -> RelationalTransformRule {
    RelationalTransformRule {
        seed_locator: seed_locator.locator.clone(),
        payload_locator: payload_locator.locator.clone(),
        operation: RelationalOperationTemplate::Sha256CounterXor(parameters.operation),
        counter_reset: parameters.counter_reset,
        parser_format: parameters.parser_format,
        parser_scope: plan.parser_scope,
    }
}

impl SearchContext<'_, '_> {
    fn evaluate_candidate<T, E, F>(
        &self,
        search: &mut SearchState<T>,
        rule: RelationalTransformRule,
        evaluator: &mut F,
    ) -> Result<bool, RelationalEvaluationError<E>>
    where
        F: FnMut(
            &RelationalTransformEvaluationContext<'_>,
            &RelationalTransformCandidate,
            &[RelationalAppliedOutput],
            &[RelationalAppliedOutput],
        ) -> Result<RelationalCandidateEvaluation<T>, E>,
    {
        let discovery_evaluation = evaluate_split(
            self.samples,
            &self.prepared.discovery_groups,
            Some(&self.prepared.discovery_indexes),
            &rule,
            self.plan.limits,
            &mut search.work_bytes,
            self.settings.capture_outputs_for_evaluator,
        )?;
        if discovery_evaluation.fit.supported_sessions.is_empty() {
            if let Some(job) = self.job {
                job.increment(Counter::CandidatesRejected, 1)
                    .map_err(RelationalTransformError::from)?;
            }
            if search.work_bytes == self.plan.limits.max_work_bytes {
                stop_for_work_limit(search, true)?;
                return Ok(false);
            }
            return Ok(true);
        }
        self.evaluate_supported_candidate(search, rule, discovery_evaluation, evaluator)
    }

    fn evaluate_supported_candidate<T, E, F>(
        &self,
        search: &mut SearchState<T>,
        rule: RelationalTransformRule,
        discovery_evaluation: EvaluatedSplit,
        evaluator: &mut F,
    ) -> Result<bool, RelationalEvaluationError<E>>
    where
        F: FnMut(
            &RelationalTransformEvaluationContext<'_>,
            &RelationalTransformCandidate,
            &[RelationalAppliedOutput],
            &[RelationalAppliedOutput],
        ) -> Result<RelationalCandidateEvaluation<T>, E>,
    {
        let EvaluatedSplit {
            fit: discovery,
            outputs: discovery_outputs,
        } = discovery_evaluation;
        let heldout_evaluation = evaluate_heldout(
            self.samples,
            self.plan,
            self.prepared,
            search,
            &rule,
            &discovery,
            self.settings.capture_outputs_for_evaluator,
        )?;
        let heldout = heldout_evaluation.fit;
        let status = candidate_status(&discovery, &heldout, self.plan.parser_scope);
        count_rejected_candidate(self.job, status)?;
        let candidate = RelationalTransformCandidate {
            rule,
            discovery,
            heldout,
            status,
        };
        let evaluation_context = RelationalTransformEvaluationContext {
            discovery_sessions: &self.prepared.discovery_sessions,
            heldout_sessions: &self.prepared.heldout_sessions,
            work_bytes_remaining: self
                .plan
                .limits
                .max_work_bytes
                .saturating_sub(search.work_bytes),
        };
        // The callback inspects outputs already produced by this frozen replay
        let evaluation = evaluator(
            &evaluation_context,
            &candidate,
            &discovery_outputs,
            &heldout_evaluation.outputs,
        )
        .map_err(RelationalEvaluationError::Evaluator)?;
        if evaluation.work_bytes > evaluation_context.work_bytes_remaining {
            return Err(RelationalEvaluationError::EvaluatorWorkLimit {
                requested: evaluation.work_bytes,
                remaining: evaluation_context.work_bytes_remaining,
            });
        }
        // Charge caller-reported screening work before the retention decision
        search.work_bytes = search.work_bytes.checked_add(evaluation.work_bytes).ok_or(
            RelationalTransformError::InvalidPlan(
                "relational evaluator work accounting overflowed",
            ),
        )?;
        retain_candidate(
            search,
            CandidateRetention {
                candidate,
                evaluation,
                discovery_outputs,
                heldout_outputs: heldout_evaluation.outputs,
                search_order: search.candidates_examined,
            },
            self.plan.limits,
            self.settings,
        )?;
        if search.work_bytes >= self.plan.limits.max_work_bytes {
            stop_for_work_limit(search, false)?;
            return Ok(false);
        }
        Ok(true)
    }

    fn count_equivalent_candidate_aliases<T>(
        &self,
        search: &mut SearchState<T>,
    ) -> Result<(), RelationalTransformError> {
        for _ in &self.plan.seed_orders {
            for _ in &self.plan.counter_resets {
                for _ in &self.plan.parser_formats {
                    search.equivalent_candidate_aliases = search
                        .equivalent_candidate_aliases
                        .checked_add(1)
                        .ok_or(RelationalTransformError::InvalidPlan(
                            "equivalent relational candidate alias count overflowed",
                        ))?;
                }
            }
        }
        Ok(())
    }
}

fn evaluate_heldout<T>(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
    prepared: &PreparedSearch,
    search: &mut SearchState<T>,
    rule: &RelationalTransformRule,
    discovery: &RelationalFit,
    capture_outputs: bool,
) -> Result<EvaluatedSplit, RelationalTransformError> {
    if prepared.heldout_groups.is_empty() {
        return Ok(EvaluatedSplit {
            fit: empty_fit(RelationalFitStatus::NotEvaluated),
            outputs: Vec::new(),
        });
    }
    if !matches!(
        discovery.status,
        RelationalFitStatus::ConstraintsSatisfied
            | RelationalFitStatus::TransformConstraintsSatisfied
    ) {
        return Ok(EvaluatedSplit {
            fit: empty_fit(RelationalFitStatus::NotEvaluated),
            outputs: Vec::new(),
        });
    }
    evaluate_split(
        samples,
        &prepared.heldout_groups,
        None,
        rule,
        plan.limits,
        &mut search.work_bytes,
        capture_outputs,
    )
}

fn count_rejected_candidate(
    job: Option<&Job>,
    status: RelationalTransformStatus,
) -> Result<(), RelationalTransformError> {
    if !matches!(
        status,
        RelationalTransformStatus::HeldoutConstraintsSatisfied
            | RelationalTransformStatus::AwaitingAcrossSessionValidation
    ) && let Some(job) = job
    {
        job.increment(Counter::CandidatesRejected, 1)?;
    }
    Ok(())
}

fn retain_candidate<T>(
    search: &mut SearchState<T>,
    retained: CandidateRetention<T>,
    limits: RelationalTransformLimits,
    settings: SearchSettings,
) -> Result<(), RelationalTransformError> {
    let decision = retention_decision(
        search,
        &retained.candidate,
        retained.evaluation.priority,
        limits,
        settings.retention_mode,
    )?;
    match decision {
        RetentionDecision::Omit => {
            omit_retained_candidate(search)?;
            return Ok(());
        }
        RetentionDecision::Append => search
            .candidates
            .try_reserve(1)
            .map_err(|_| RelationalTransformError::AllocationFailed)?,
        RetentionDecision::Replace(index) => {
            evict_retained_candidate(search, index)?;
            omit_retained_candidate(search)?;
        }
    }
    let output_capture = capture_candidate_outputs(
        search,
        retained.discovery_outputs,
        retained.heldout_outputs,
        settings.max_retained_output_bytes,
    )?;
    search.candidates.push(RetainedCandidate {
        candidate: retained.candidate,
        priority: retained.evaluation.priority,
        assessment: retained.evaluation.assessment,
        outputs: output_capture.outputs,
        captured_output_bytes: output_capture.captured_bytes,
        output_capture_omitted: output_capture.omitted,
        search_order: retained.search_order,
    });
    if output_capture.omitted {
        search.output_capture_omissions = search.output_capture_omissions.checked_add(1).ok_or(
            RelationalTransformError::InvalidPlan("retained evaluator omission count overflowed"),
        )?;
    }
    Ok(())
}

enum RetentionDecision {
    Append,
    Replace(usize),
    Omit,
}

fn retention_decision<T>(
    search: &SearchState<T>,
    candidate: &RelationalTransformCandidate,
    priority: u8,
    limits: RelationalTransformLimits,
    retention_mode: RetentionMode,
) -> Result<RetentionDecision, RelationalTransformError> {
    match retention_mode {
        RetentionMode::PerLocatorPair => {
            let per_pair_limit = limits
                .max_retained_candidates
                .div_ceil(RETAINED_LOCATOR_PAIR_TARGET);
            let retained_for_pair = search
                .candidates
                .iter()
                .filter(|retained| {
                    retained.candidate.rule.seed_locator == candidate.rule.seed_locator
                        && retained.candidate.rule.payload_locator == candidate.rule.payload_locator
                })
                .count();
            if search.candidates.len() < limits.max_retained_candidates
                && retained_for_pair < per_pair_limit
            {
                Ok(RetentionDecision::Append)
            } else {
                Ok(RetentionDecision::Omit)
            }
        }
        RetentionMode::EvaluatorPriority => {
            if search.candidates.len() < limits.max_retained_candidates {
                Ok(RetentionDecision::Append)
            } else {
                // Equal-priority ties choose the newest entry so earlier candidates remain stable
                let Some((lowest_index, lowest_priority)) = search
                    .candidates
                    .iter()
                    .enumerate()
                    .fold(None, |lowest, (index, retained)| match lowest {
                        Some((_, priority)) if priority < retained.priority => lowest,
                        Some((_, priority)) if priority > retained.priority => {
                            Some((index, retained.priority))
                        }
                        _ => Some((index, retained.priority)),
                    })
                else {
                    return Err(RelationalTransformError::InvalidPlan(
                        "retained candidate cap is full without retained candidates",
                    ));
                };
                if priority <= lowest_priority {
                    Ok(RetentionDecision::Omit)
                } else {
                    Ok(RetentionDecision::Replace(lowest_index))
                }
            }
        }
    }
}

fn evict_retained_candidate<T>(
    search: &mut SearchState<T>,
    index: usize,
) -> Result<(), RelationalTransformError> {
    let removed = search
        .candidates
        .get(index)
        .ok_or(RelationalTransformError::InvalidPlan(
            "retained replacement index is unavailable",
        ))?;
    let captured_output_bytes = removed.captured_output_bytes;
    let output_capture_omitted = removed.output_capture_omitted;
    search.candidates.remove(index);
    search.output_bytes_retained = search
        .output_bytes_retained
        .checked_sub(captured_output_bytes)
        .ok_or(RelationalTransformError::InvalidPlan(
            "retained evaluator output accounting underflowed",
        ))?;
    if output_capture_omitted {
        search.output_capture_omissions = search.output_capture_omissions.checked_sub(1).ok_or(
            RelationalTransformError::InvalidPlan(
                "retained evaluator omission accounting underflowed",
            ),
        )?;
    }
    Ok(())
}

struct OutputCapture {
    outputs: Option<RelationalCandidateOutputs>,
    captured_bytes: usize,
    omitted: bool,
}

fn capture_candidate_outputs<T>(
    search: &mut SearchState<T>,
    discovery_outputs: Vec<RelationalAppliedOutput>,
    heldout_outputs: Vec<RelationalAppliedOutput>,
    max_retained_output_bytes: usize,
) -> Result<OutputCapture, RelationalTransformError> {
    let output_bytes = discovery_outputs
        .iter()
        .chain(&heldout_outputs)
        .try_fold(0_usize, |total, output| {
            total.checked_add(output.bytes.len())
        })
        .ok_or(RelationalTransformError::InvalidPlan(
            "retained evaluator output length overflowed",
        ))?;
    let remaining_output_bytes =
        max_retained_output_bytes.saturating_sub(search.output_bytes_retained);
    if max_retained_output_bytes == 0 || output_bytes > remaining_output_bytes {
        return Ok(OutputCapture {
            outputs: None,
            captured_bytes: 0,
            omitted: max_retained_output_bytes > 0,
        });
    }
    // Only selected candidates own captured bytes after this point
    search.output_bytes_retained = search
        .output_bytes_retained
        .checked_add(output_bytes)
        .ok_or(RelationalTransformError::InvalidPlan(
            "retained evaluator output accounting overflowed",
        ))?;
    Ok(OutputCapture {
        outputs: Some(RelationalCandidateOutputs {
            discovery: discovery_outputs,
            heldout: heldout_outputs,
        }),
        captured_bytes: output_bytes,
        omitted: false,
    })
}

fn omit_retained_candidate<T>(search: &mut SearchState<T>) -> Result<(), RelationalTransformError> {
    search.omitted_candidates =
        search
            .omitted_candidates
            .checked_add(1)
            .ok_or(RelationalTransformError::InvalidPlan(
                "omitted relational candidate count overflowed",
            ))?;
    search.record_limit(RelationalSearchLimit::RetainedCandidates);
    Ok(())
}

fn stop_for_work_limit<T>(
    search: &mut SearchState<T>,
    one_candidate_omitted: bool,
) -> Result<(), RelationalTransformError> {
    search.stop(RelationalSearchLimit::WorkBytes);
    if one_candidate_omitted {
        search.omitted_candidates = search.omitted_candidates.checked_add(1).ok_or(
            RelationalTransformError::InvalidPlan("omitted relational candidate count overflowed"),
        )?;
    }
    search.omitted_candidates_exact = false;
    Ok(())
}

fn build_report<T>(
    mut search: SearchState<T>,
    prepared: PreparedSearch,
    limits: RelationalTransformLimits,
) -> Result<RelationalCandidateEvaluationReport<T>, RelationalTransformError> {
    // Replacement appends newer candidates, so restore search order once for the final report
    search
        .candidates
        .sort_unstable_by_key(|retained| retained.search_order);
    let mut candidates = Vec::new();
    candidates
        .try_reserve_exact(search.candidates.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let mut evaluations = Vec::new();
    evaluations
        .try_reserve_exact(search.candidates.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    for retained in search.candidates {
        candidates.push(retained.candidate);
        evaluations.push(RelationalRetainedEvaluation {
            assessment: retained.assessment,
            outputs: retained.outputs,
        });
    }
    Ok(RelationalCandidateEvaluationReport {
        report: RelationalTransformReport {
            split_basis: HoldoutBasis::CompleteSessions,
            discovery_sessions: prepared.discovery_sessions,
            heldout_sessions: prepared.heldout_sessions,
            candidates,
            candidates_examined: search.candidates_examined,
            equivalent_candidate_aliases: search.equivalent_candidate_aliases,
            omitted_candidates: search.omitted_candidates,
            omitted_candidates_exact: search.omitted_candidates_exact,
            candidate_limit_remaining: limits
                .max_candidates
                .saturating_sub(search.candidates_examined),
            locator_candidates_examined: search.locator_candidates_examined,
            locator_candidate_limit_remaining: limits
                .max_locator_candidates
                .saturating_mul(2)
                .saturating_sub(search.locator_candidates_examined),
            work_bytes: search.work_bytes,
            work_bytes_remaining: limits.max_work_bytes.saturating_sub(search.work_bytes),
            search_exhaustive_within_plan: search.search_exhaustive,
            search_limits: search.search_limits,
            search_limit: search.search_limit,
        },
        evaluations,
        output_bytes_retained: search.output_bytes_retained,
        output_capture_omissions: search.output_capture_omissions,
        output_capture_complete: search.output_capture_omissions == 0,
    })
}
