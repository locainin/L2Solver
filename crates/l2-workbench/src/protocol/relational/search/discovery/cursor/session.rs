//! Own the preparation shared by successive slices of one immutable cohort

use super::{
    CandidateParameters, Job, Position, PreparedSearch, RelationalAppliedOutput,
    RelationalCandidateEvaluation, RelationalEvaluationError, RelationalRecordSample,
    RelationalReplayHistory, RelationalSearchCursor, RelationalSearchStep,
    RelationalTransformCandidate, RelationalTransformError, RelationalTransformEvaluationContext,
    RelationalTransformEvaluationOptions, RelationalTransformPlan, RetentionMode, SearchContext,
    SearchSettings, SearchState, StepBounds, attach_history, build_report, candidate_parameters,
    drive, identity, invalid_cursor, prepare_search,
};
use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

/// A bounded relational search over one immutably borrowed cohort and plan
///
/// The input digest and search preparation are computed once when this session starts. Each
/// live cursor carries its prepared state between slices. Restore a serialized cursor through
/// this session before continuing; the history remains exclusively borrowed until the session
/// is dropped, preserving the lookup boundary used by the original search.
pub struct RelationalSearchSession<'input, 'bytes> {
    pub(super) samples: &'input [RelationalRecordSample<'bytes>],
    pub(super) plan: &'input RelationalTransformPlan,
    pub(super) job: Option<&'input Job>,
    pub(super) options: RelationalTransformEvaluationOptions,
    pub(super) history: Option<&'input mut RelationalReplayHistory>,
    pub(super) prepared: Option<PreparedSearch>,
    pub(super) identity: [u8; 32],
    pub(super) session_id: u64,
    pub(super) complete: bool,
    parameters: Vec<CandidateParameters>,
}

impl fmt::Debug for RelationalSearchSession<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelationalSearchSession")
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}

impl<'input, 'bytes> RelationalSearchSession<'input, 'bytes> {
    /// Prepare a search over an immutable cohort and an optional dedicated replay history
    ///
    /// Cancellation is checked while grouping messages, enumerating selectors and locators,
    /// and hashing bounded chunks of input. The same history is borrowed for all live slices
    /// and can be read using [`Self::history`] at a checkpoint
    ///
    /// Reserve [`Self::preparation_memory_bytes`] before constructing the session and keep that
    /// allowance until its cursor and any report state moved from preparation have been consumed
    ///
    /// # Errors
    /// Returns an error for cancellation, invalid inputs or plans, or allocation failure
    pub fn new(
        samples: &'input [RelationalRecordSample<'bytes>],
        plan: &'input RelationalTransformPlan,
        job: Option<&'input Job>,
        options: RelationalTransformEvaluationOptions,
        history: Option<&'input mut RelationalReplayHistory>,
    ) -> Result<Self, RelationalTransformError> {
        if let Some(job) = job {
            job.check_cancelled()?;
        }
        super::partition::validate_resumable_plan(plan, job)?;
        if options.max_retained_output_bytes > plan.limits.max_total_bytes {
            return Err(RelationalTransformError::InvalidPlan(
                "retained evaluator outputs exceed the aggregate byte limit",
            ));
        }
        let prepared = prepare_search(samples, plan, job)?;
        let digest = identity(samples, plan, options, job)?;
        let parameters = candidate_parameters(plan)?;
        let id = NEXT_SESSION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| {
                RelationalTransformError::InvalidPlan("relational session identity exhausted")
            })?;
        Ok(Self {
            samples,
            plan,
            job,
            options,
            history,
            prepared: Some(prepared),
            identity: digest,
            session_id: id,
            complete: false,
            parameters,
        })
    }

    /// Return the active history for persistence at a completed-candidate boundary
    #[must_use]
    pub fn history(&self) -> Option<&RelationalReplayHistory> {
        self.history.as_deref()
    }

    /// Continue for a bounded number of candidate and locator traversal actions
    ///
    /// The initial locator, anchor, and prefix-ranking stages finish before the first pause. A
    /// later slice may finish earlier when a selected search limit is reached. A live cursor
    /// belongs to the session that produced it; use checkpoint restoration for a new session.
    /// History hits and skipped aliases count toward the traversal quantum, so a pause may
    /// advance the search without increasing the number of newly examined candidates.
    ///
    /// # Errors
    /// Returns an error for an invalid cursor, zero budget, cancellation, or evaluator failure
    #[expect(
        clippy::too_many_lines,
        reason = "keep the search and candidate-boundary transitions together"
    )]
    pub fn step<T, E, F>(
        &mut self,
        cursor: Option<RelationalSearchCursor<T>>,
        candidate_budget: usize,
        mut evaluator: F,
    ) -> Result<RelationalSearchStep<T>, RelationalEvaluationError<E>>
    where
        F: FnMut(
            &RelationalTransformEvaluationContext<'_>,
            &RelationalTransformCandidate,
            &[RelationalAppliedOutput],
            &[RelationalAppliedOutput],
        ) -> Result<RelationalCandidateEvaluation<T>, E>,
    {
        if let Some(job) = self.job {
            job.check_cancelled()
                .map_err(RelationalTransformError::from)?;
        }
        if self.complete || candidate_budget == 0 {
            return Err(invalid_cursor().into());
        }
        let samples = self.samples;
        let plan = self.plan;
        let job = self.job;
        let settings = SearchSettings {
            retention_mode: RetentionMode::EvaluatorPriority,
            max_retained_output_bytes: self.options.max_retained_output_bytes,
            capture_outputs_for_evaluator: true,
        };
        let first_step = cursor.is_none();
        let (mut search, initial_pairs, pre_evaluated, mut position, mut prepared, mut schedule) =
            if let Some(cursor) = cursor {
                if cursor.session_id != self.session_id
                    || cursor.identity != self.identity
                    || self.prepared.is_some()
                {
                    return Err(invalid_cursor().into());
                }
                (
                    attach_history(cursor.search, self.history.as_deref_mut()),
                    cursor.initial_pairs,
                    cursor.pre_evaluated,
                    cursor.position,
                    cursor.prepared,
                    cursor.schedule,
                )
            } else {
                let mut prepared = self.prepared.take().ok_or(invalid_cursor())?;
                if let Some(history) = self.history.as_deref_mut() {
                    history.prepare(plan.limits);
                }
                let mut search = SearchState::new(self.history.as_deref_mut());
                search.prefix_probe_complete = false;
                search.locator_candidates_examined =
                    prepared.seed_locators.len() + prepared.payload_locators.len();
                let mut context = SearchContext {
                    samples,
                    plan,
                    job,
                    prepared: &mut prepared,
                    settings,
                    candidate_parameters: &self.parameters,
                    anchor_work_limit: plan.limits.max_work_bytes,
                    anchor_candidate_limit: plan.limits.max_candidates,
                    active_work_limit: plan.limits.max_work_bytes,
                    active_candidate_limit: plan.limits.max_candidates,
                };
                let Some(mut initial) =
                    context.search_initial_pair_window(&mut search, &mut evaluator)?
                else {
                    if let Some(history) = search.history.as_deref_mut() {
                        history.finish();
                    }
                    self.complete = true;
                    return Ok(RelationalSearchStep::Complete(build_report(
                        search,
                        prepared,
                        plan.limits,
                    )?));
                };
                context.prepare_anchored_payloads(&mut search)?;
                if !context.search_ranked_anchor_candidates(
                    &mut search,
                    &mut initial.pre_evaluated,
                    &mut evaluator,
                )? {
                    if let Some(history) = search.history.as_deref_mut() {
                        history.finish();
                    }
                    self.complete = true;
                    return Ok(RelationalSearchStep::Complete(build_report(
                        search,
                        prepared,
                        plan.limits,
                    )?));
                }
                (
                    search,
                    initial.pairs,
                    initial.pre_evaluated,
                    Position {
                        stage: super::PairStage::Initial { next: 0 },
                        current: None,
                    },
                    prepared,
                    None,
                )
            };
        // Startup work belongs to the first slice even when ranking exceeds its requested budget
        let pause_at = if first_step {
            candidate_budget
        } else {
            search.candidates_examined.saturating_add(candidate_budget)
        };
        let context = SearchContext {
            samples,
            plan,
            job,
            prepared: &mut prepared,
            settings,
            candidate_parameters: &self.parameters,
            anchor_work_limit: plan.limits.max_work_bytes,
            anchor_candidate_limit: plan.limits.max_candidates,
            active_work_limit: plan.limits.max_work_bytes,
            active_candidate_limit: plan.limits.max_candidates,
        };
        let completed = drive(
            &context,
            &mut search,
            &initial_pairs,
            &pre_evaluated,
            &mut position,
            &mut schedule,
            StepBounds {
                candidate_end: pause_at,
                traversal: candidate_budget,
            },
            &mut evaluator,
        )?;
        if completed {
            if let Some(history) = search.history.as_deref_mut() {
                history.finish();
            }
            self.complete = true;
            return Ok(RelationalSearchStep::Complete(build_report(
                search,
                prepared,
                plan.limits,
            )?));
        }
        let search = attach_history(search, None);
        Ok(RelationalSearchStep::Paused(RelationalSearchCursor {
            identity: self.identity,
            session_id: self.session_id,
            search,
            prepared,
            schedule,
            initial_pairs,
            pre_evaluated,
            position,
        }))
    }
}
