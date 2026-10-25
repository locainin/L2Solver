use super::super::model::{
    RelationalCounterReset, RelationalFit, RelationalFitStatus, RelationalOperationTemplate,
    RelationalRecordSample, RelationalSearchLimit, RelationalSha256CounterXor,
    RelationalTransformCandidate, RelationalTransformError, RelationalTransformLimits,
    RelationalTransformPlan, RelationalTransformReport, RelationalTransformRule,
    RelationalTransformStatus,
};
use super::{
    input::{
        SessionGroup, build_selector_indexes, group_sessions, shared_selectors, validate_plan,
    },
    locator::{LocatorCandidate, locator_selectors_overlap, payload_locators, seed_locators},
    replay::{candidate_status, empty_fit, evaluate_split},
};
use crate::{
    job::{Counter, Job},
    protocol::{HoldoutBasis, RelationalSessionId},
};

struct SearchState {
    candidates: Vec<RelationalTransformCandidate>,
    candidates_examined: usize,
    omitted_candidates: usize,
    omitted_candidates_exact: bool,
    work_bytes: usize,
    search_exhaustive: bool,
    search_limit: Option<RelationalSearchLimit>,
    search_limits: Vec<RelationalSearchLimit>,
    locator_candidates_examined: usize,
}

impl SearchState {
    const fn new() -> Self {
        Self {
            candidates: Vec::new(),
            candidates_examined: 0,
            omitted_candidates: 0,
            omitted_candidates_exact: true,
            work_bytes: 0,
            search_exhaustive: true,
            search_limit: None,
            search_limits: Vec::new(),
            locator_candidates_examined: 0,
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
    if let Some(job) = job {
        job.check_cancelled()?;
    }
    validate_plan(plan)?;
    let prepared = prepare_search(samples, plan)?;
    let search = search_candidates(samples, plan, job, &prepared)?;
    Ok(build_report(search, prepared, plan.limits))
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

fn search_candidates(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
    job: Option<&Job>,
    prepared: &PreparedSearch,
) -> Result<SearchState, RelationalTransformError> {
    let mut search = SearchState::new();
    search.locator_candidates_examined =
        prepared.seed_locators.len() + prepared.payload_locators.len();
    SearchContext {
        samples,
        plan,
        job,
        prepared,
    }
    .search_all(&mut search)?;
    Ok(search)
}

struct SearchContext<'a, 'bytes> {
    samples: &'a [RelationalRecordSample<'bytes>],
    plan: &'a RelationalTransformPlan,
    job: Option<&'a Job>,
    prepared: &'a PreparedSearch,
}

impl SearchContext<'_, '_> {
    fn search_all(&self, search: &mut SearchState) -> Result<(), RelationalTransformError> {
        if !self.prepared.locators_complete {
            search.stop(RelationalSearchLimit::LocatorCount);
            search.omitted_candidates_exact = false;
        }
        for seed_locator in &self.prepared.seed_locators {
            for payload_locator in &self.prepared.payload_locators {
                if locator_selectors_overlap(
                    &seed_locator.selector,
                    &payload_locator.selector,
                    &self.prepared.discovery_indexes,
                ) {
                    continue;
                }
                if !self.search_locator_pair(search, seed_locator, payload_locator)? {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn search_locator_pair(
        &self,
        search: &mut SearchState,
        seed_locator: &LocatorCandidate,
        payload_locator: &LocatorCandidate,
    ) -> Result<bool, RelationalTransformError> {
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
                )? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn search_counter_options(
        &self,
        search: &mut SearchState,
        seed_locator: &LocatorCandidate,
        payload_locator: &LocatorCandidate,
        counter_width: crate::derivation::CounterWidth,
        initial_counter: u64,
    ) -> Result<bool, RelationalTransformError> {
        for counter_byte_order in &self.plan.counter_byte_orders {
            for seed_order in &self.plan.seed_orders {
                for counter_reset in &self.plan.counter_resets {
                    for parser_format in &self.plan.parser_formats {
                        if !self.try_candidate(
                            search,
                            seed_locator,
                            payload_locator,
                            RelationalSha256CounterXor {
                                initial_counter,
                                counter_width,
                                counter_byte_order: *counter_byte_order,
                                seed_order: *seed_order,
                            },
                            *counter_reset,
                            *parser_format,
                        )? {
                            return Ok(false);
                        }
                    }
                }
            }
        }
        Ok(true)
    }

    fn try_candidate(
        &self,
        search: &mut SearchState,
        seed_locator: &LocatorCandidate,
        payload_locator: &LocatorCandidate,
        operation: RelationalSha256CounterXor,
        counter_reset: RelationalCounterReset,
        parser_format: crate::artifact::ArtifactValidationFormat,
    ) -> Result<bool, RelationalTransformError> {
        if search.candidates_examined == self.plan.limits.max_candidates {
            search.stop(RelationalSearchLimit::CandidateCount);
            search.omitted_candidates = 1;
            search.omitted_candidates_exact = false;
            return Ok(false);
        }
        if let Some(job) = self.job {
            job.check_cancelled()?;
            job.increment(Counter::CandidatesExamined, 1)?;
        }
        search.candidates_examined += 1;
        let rule = make_rule(
            seed_locator,
            payload_locator,
            operation,
            counter_reset,
            parser_format,
            self.plan,
        );
        evaluate_candidate(
            self.samples,
            self.plan,
            self.job,
            self.prepared,
            search,
            rule,
        )
    }
}

fn make_rule(
    seed_locator: &LocatorCandidate,
    payload_locator: &LocatorCandidate,
    operation: RelationalSha256CounterXor,
    counter_reset: RelationalCounterReset,
    parser_format: crate::artifact::ArtifactValidationFormat,
    plan: &RelationalTransformPlan,
) -> RelationalTransformRule {
    RelationalTransformRule {
        seed_locator: seed_locator.locator.clone(),
        payload_locator: payload_locator.locator.clone(),
        operation: RelationalOperationTemplate::Sha256CounterXor(operation),
        counter_reset,
        parser_format,
        parser_scope: plan.parser_scope,
    }
}

fn evaluate_candidate(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
    job: Option<&Job>,
    prepared: &PreparedSearch,
    search: &mut SearchState,
    rule: RelationalTransformRule,
) -> Result<bool, RelationalTransformError> {
    let discovery = evaluate_split(
        samples,
        &prepared.discovery_groups,
        Some(&prepared.discovery_indexes),
        &rule,
        plan.limits,
        &mut search.work_bytes,
    )?;
    if discovery.supported_sessions.is_empty() {
        if let Some(job) = job {
            job.increment(Counter::CandidatesRejected, 1)?;
        }
        if search.work_bytes == plan.limits.max_work_bytes {
            stop_for_work_limit(search, true);
            return Ok(false);
        }
        return Ok(true);
    }
    let heldout = evaluate_heldout(samples, plan, prepared, search, &rule, &discovery)?;
    let status = candidate_status(&discovery, &heldout, plan.parser_scope);
    count_rejected_candidate(job, status)?;
    retain_candidate(
        search,
        plan.limits,
        RelationalTransformCandidate {
            rule,
            discovery,
            heldout,
            status,
        },
    )?;
    if search.work_bytes >= plan.limits.max_work_bytes {
        stop_for_work_limit(search, false);
        return Ok(false);
    }
    Ok(true)
}

fn evaluate_heldout(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
    prepared: &PreparedSearch,
    search: &mut SearchState,
    rule: &RelationalTransformRule,
    discovery: &RelationalFit,
) -> Result<RelationalFit, RelationalTransformError> {
    if prepared.heldout_groups.is_empty() {
        return Ok(empty_fit(RelationalFitStatus::NotEvaluated));
    }
    if !matches!(
        discovery.status,
        RelationalFitStatus::ConstraintsSatisfied
            | RelationalFitStatus::TransformConstraintsSatisfied
    ) {
        return Ok(empty_fit(RelationalFitStatus::NotEvaluated));
    }
    evaluate_split(
        samples,
        &prepared.heldout_groups,
        None,
        rule,
        plan.limits,
        &mut search.work_bytes,
    )
}

fn count_rejected_candidate(
    job: Option<&Job>,
    status: RelationalTransformStatus,
) -> Result<(), RelationalTransformError> {
    if !matches!(
        status,
        RelationalTransformStatus::HeldoutConstraintsSatisfied
            | RelationalTransformStatus::TransformSupportedAcrossSessions
    ) && let Some(job) = job
    {
        job.increment(Counter::CandidatesRejected, 1)?;
    }
    Ok(())
}

fn retain_candidate(
    search: &mut SearchState,
    limits: RelationalTransformLimits,
    candidate: RelationalTransformCandidate,
) -> Result<(), RelationalTransformError> {
    if search.candidates.len() < limits.max_retained_candidates {
        search
            .candidates
            .try_reserve(1)
            .map_err(|_| RelationalTransformError::AllocationFailed)?;
        search.candidates.push(candidate);
    } else {
        search.omitted_candidates = search.omitted_candidates.checked_add(1).ok_or(
            RelationalTransformError::InvalidPlan("omitted relational candidate count overflowed"),
        )?;
        search.omitted_candidates_exact = true;
        search.record_limit(RelationalSearchLimit::RetainedCandidates);
    }
    Ok(())
}

fn stop_for_work_limit(search: &mut SearchState, one_candidate_omitted: bool) {
    search.stop(RelationalSearchLimit::WorkBytes);
    if one_candidate_omitted {
        search.omitted_candidates = 1;
    }
    search.omitted_candidates_exact = false;
}

fn build_report(
    search: SearchState,
    prepared: PreparedSearch,
    limits: RelationalTransformLimits,
) -> RelationalTransformReport {
    RelationalTransformReport {
        split_basis: HoldoutBasis::CompleteSessions,
        discovery_sessions: prepared.discovery_sessions,
        heldout_sessions: prepared.heldout_sessions,
        candidates: search.candidates,
        candidates_examined: search.candidates_examined,
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
    }
}
