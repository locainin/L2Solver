//! Candidate-boundary continuation for across-session relational searches

use super::{
    CandidateId, CandidateParameters, INITIAL_RANK_ORDERED_PAIR_WINDOW, LocatorCandidate,
    LocatorPairSchedule, PAIR_STREAM_ROTATION, PairDomain, PreparedSearch, RankedPairEntry,
    RankedPairStream, RelationalAppliedOutput, RelationalCandidateEvaluation,
    RelationalCandidateEvaluationReport, RelationalCandidateOutputs, RelationalEvaluationError,
    RelationalFit, RelationalFitStatus, RelationalRecordSample, RelationalReplayHistory,
    RelationalSessionId, RelationalSha256CounterXor, RelationalTransformCandidate,
    RelationalTransformError, RelationalTransformEvaluationContext,
    RelationalTransformEvaluationOptions, RelationalTransformPlan, RelationalTransformRule,
    RelationalTransformStatus, RetainedCandidate, RetentionMode, SearchContext, SearchSettings,
    SearchState, SessionGroup, build_report, candidate_parameters, candidate_status,
    locator_pair_overlaps, pair_stream_cue_rank, prepare_search, validate_plan,
};
use crate::{derivation::CounterWidth, job::Job};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cmp::Reverse,
    collections::{BTreeSet, BinaryHeap},
    error::Error,
    fmt,
    io::{self, Write},
};

const CURSOR_VERSION: u32 = 1;

/// A saved search boundary, including retained candidate evidence and caller assessments
///
/// The associated history and job work snapshot must be restored from the same committed
/// generation. The first boundary follows the initial candidate and prefix-ranking stages.
pub struct RelationalSearchCursor<T> {
    identity: [u8; 32],
    history_identity: Option<[u8; 32]>,
    search: SearchState<'static, T>,
    payload_locators: Vec<LocatorCandidate>,
    absolute_locators_complete: bool,
    initial_pairs: Vec<(usize, usize)>,
    pre_evaluated: BTreeSet<CandidateId>,
    position: Position,
}

impl<T> fmt::Debug for RelationalSearchCursor<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelationalSearchCursor")
            .field("candidates_examined", &self.search.candidates_examined)
            .finish_non_exhaustive()
    }
}

impl<T> RelationalSearchCursor<T> {
    /// Number of complete candidate attempts charged before this boundary
    #[must_use]
    pub const fn candidates_examined(&self) -> usize {
        self.search.candidates_examined
    }
}

/// Search completion or a boundary that can be committed and resumed
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "avoid a fallible heap allocation at each candidate boundary"
)]
pub enum RelationalSearchStep<T> {
    /// No further work is scheduled under this plan
    Complete(RelationalCandidateEvaluationReport<T>),
    /// More work remains and no candidate is partially committed
    Paused(RelationalSearchCursor<T>),
}

/// A rejected cursor or caller-owned assessment conversion failure
#[derive(Debug)]
pub enum RelationalCursorError<E> {
    /// The stored representation is corrupt or unsupported
    InvalidCheckpoint,
    /// The encoded checkpoint exceeds the caller's byte ceiling
    CheckpointTooLarge,
    /// Bounded storage could not be reserved
    AllocationFailed,
    /// The caller rejected an assessment during conversion
    Assessment(E),
}

impl<E: fmt::Display> fmt::Display for RelationalCursorError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCheckpoint => f.write_str("invalid relational search checkpoint"),
            Self::CheckpointTooLarge => {
                f.write_str("relational search checkpoint exceeds its byte limit")
            }
            Self::AllocationFailed => f.write_str("relational search checkpoint allocation failed"),
            Self::Assessment(error) => write!(f, "relational assessment checkpoint: {error}"),
        }
    }
}
impl<E: Error + 'static> Error for RelationalCursorError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Assessment(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Position {
    stage: PairStage,
    current: Option<PairPosition>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
enum PairStage {
    Initial { next: usize },
    Absolute { schedule: Option<SavedSchedule> },
    Anchored { next: usize },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairPosition {
    seed: usize,
    payload: usize,
    parameters: ParameterPosition,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ParameterPosition {
    width: usize,
    initial: usize,
    order: usize,
    seed_order: usize,
    reset: usize,
    format: usize,
    candidate_index: usize,
}

pub(super) enum ParameterAction {
    Alias,
    Candidate(usize, CandidateParameters),
}

impl ParameterPosition {
    pub(super) fn next(
        &mut self,
        plan: &RelationalTransformPlan,
    ) -> Result<Option<ParameterAction>, RelationalTransformError> {
        while let Some(&width) = plan.counter_widths.get(self.width) {
            let Some(&initial) = plan.initial_counters.get(self.initial) else {
                self.width += 1;
                self.initial = 0;
                continue;
            };
            if initial > width.maximum_counter() {
                self.initial += 1;
                continue;
            }
            let Some(&order) = plan.counter_byte_orders.get(self.order) else {
                self.initial += 1;
                self.order = 0;
                continue;
            };
            if width == CounterWidth::OneByte && self.order > 0 {
                self.order += 1;
                return Ok(Some(ParameterAction::Alias));
            }
            let seed_order = *plan
                .seed_orders
                .get(self.seed_order)
                .ok_or(invalid_cursor())?;
            let reset = *plan
                .counter_resets
                .get(self.reset)
                .ok_or(invalid_cursor())?;
            let format = *plan
                .parser_formats
                .get(self.format)
                .ok_or(invalid_cursor())?;
            let index = self.candidate_index;
            self.candidate_index = index.checked_add(1).ok_or(invalid_cursor())?;
            self.format += 1;
            if self.format == plan.parser_formats.len() {
                self.format = 0;
                self.reset += 1;
                if self.reset == plan.counter_resets.len() {
                    self.reset = 0;
                    self.seed_order += 1;
                    if self.seed_order == plan.seed_orders.len() {
                        self.seed_order = 0;
                        self.order += 1;
                    }
                }
            }
            return Ok(Some(ParameterAction::Candidate(
                index,
                CandidateParameters {
                    operation: RelationalSha256CounterXor {
                        initial_counter: initial,
                        counter_width: width,
                        counter_byte_order: order,
                        seed_order,
                    },
                    counter_reset: reset,
                    parser_format: format,
                },
            )));
        }
        Ok(None)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "validate all parameter dimensions together"
    )]
    fn valid(&self, plan: &RelationalTransformPlan) -> bool {
        let Some(&width) = plan.counter_widths.get(self.width) else {
            return false;
        };
        let Some(&initial) = plan.initial_counters.get(self.initial) else {
            return false;
        };
        if initial > width.maximum_counter()
            || self.order > plan.counter_byte_orders.len()
            || self.seed_order >= plan.seed_orders.len()
            || self.reset >= plan.counter_resets.len()
            || self.format >= plan.parser_formats.len()
        {
            return false;
        }
        let Some(per_order) = plan
            .seed_orders
            .len()
            .checked_mul(plan.counter_resets.len())
            .and_then(|value| value.checked_mul(plan.parser_formats.len()))
        else {
            return false;
        };
        let mut expected = 0_usize;
        for (width_index, candidate_width) in
            plan.counter_widths.iter().enumerate().take(self.width + 1)
        {
            let canonical_orders = if *candidate_width == CounterWidth::OneByte {
                1
            } else {
                plan.counter_byte_orders.len()
            };
            let Some(per_initial) = canonical_orders.checked_mul(per_order) else {
                return false;
            };
            let before = if width_index == self.width {
                self.initial
            } else {
                plan.initial_counters.len()
            };
            let valid_initials = plan
                .initial_counters
                .iter()
                .take(before)
                .filter(|value| **value <= candidate_width.maximum_counter())
                .count();
            let Some(prefix) = valid_initials
                .checked_mul(per_initial)
                .and_then(|value| expected.checked_add(value))
            else {
                return false;
            };
            expected = prefix;
        }
        let canonical_before = if width == CounterWidth::OneByte {
            self.order.min(1)
        } else {
            self.order
        };
        let Some(prefix) = canonical_before
            .checked_mul(per_order)
            .and_then(|value| expected.checked_add(value))
        else {
            return false;
        };
        expected = prefix;
        let inside_order = self.order < plan.counter_byte_orders.len()
            && (width != CounterWidth::OneByte || self.order == 0);
        if inside_order {
            let Some(offset) = self
                .seed_order
                .checked_mul(plan.counter_resets.len())
                .and_then(|value| value.checked_add(self.reset))
                .and_then(|value| value.checked_mul(plan.parser_formats.len()))
                .and_then(|value| value.checked_add(self.format))
                .and_then(|value| expected.checked_add(value))
            else {
                return false;
            };
            expected = offset;
        } else if self.seed_order != 0 || self.reset != 0 || self.format != 0 {
            return false;
        }
        expected == self.candidate_index
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedSchedule {
    initial_pair_cursor: usize,
    stream_cursor: usize,
    header: Vec<Reverse<RankedPairEntry>>,
    aligned: Vec<Reverse<RankedPairEntry>>,
    fallback: Vec<Reverse<RankedPairEntry>>,
}

impl SavedSchedule {
    fn save(schedule: LocatorPairSchedule<'_>) -> Self {
        Self {
            initial_pair_cursor: schedule.initial_pair_cursor,
            stream_cursor: schedule.stream_cursor,
            header: schedule.header_aligned.pending.into_vec(),
            aligned: schedule.aligned.pending.into_vec(),
            fallback: schedule.fallback.pending.into_vec(),
        }
    }

    fn restore<'a>(
        self,
        seeds: &'a [LocatorCandidate],
        payloads: &'a [LocatorCandidate],
    ) -> Result<LocatorPairSchedule<'a>, RelationalTransformError> {
        let mut schedule = LocatorPairSchedule::new(seeds, payloads)?;
        if self.initial_pair_cursor > schedule.initial_pair_count
            || self.stream_cursor >= PAIR_STREAM_ROTATION.len()
        {
            return Err(invalid_cursor());
        }
        restore_stream(&schedule.domain, &mut schedule.header_aligned, self.header)?;
        restore_stream(&schedule.domain, &mut schedule.aligned, self.aligned)?;
        restore_stream(&schedule.domain, &mut schedule.fallback, self.fallback)?;
        schedule.initial_pair_cursor = self.initial_pair_cursor;
        schedule.stream_cursor = self.stream_cursor;
        Ok(schedule)
    }
}

fn restore_stream(
    domain: &PairDomain<'_>,
    stream: &mut RankedPairStream,
    entries: Vec<Reverse<RankedPairEntry>>,
) -> Result<(), RelationalTransformError> {
    if entries.len() > stream.rows.len() {
        return Err(invalid_cursor());
    }
    let mut seeds = Vec::new();
    seeds
        .try_reserve_exact(stream.rows.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    seeds.resize(stream.rows.len(), None);
    for Reverse(item) in &stream.pending {
        let slot = seeds.get_mut(item.row_index).ok_or(invalid_cursor())?;
        *slot = Some(item.seed_index);
    }
    let mut seen = Vec::new();
    seen.try_reserve_exact(stream.rows.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    seen.resize(stream.rows.len(), false);
    for Reverse(entry) in &entries {
        let row = *stream.rows.get(entry.row_index).ok_or(invalid_cursor())?;
        let payload = domain
            .payloads
            .get(entry.payload_order_index)
            .ok_or(invalid_cursor())?;
        let observed = seen.get_mut(entry.row_index).ok_or(invalid_cursor())?;
        if *observed
            || domain.next_payload_order(row, stream.kind, entry.payload_order_index)
                != Some(entry.payload_order_index)
            || payload.candidate_index != entry.payload_index
            || entry.seed_index >= domain.seeds.len()
            || entry.cue_rank != pair_stream_cue_rank(domain, stream.kind, entry.seed_index)
            || entry.pair_rank != entry.seed_index.saturating_add(entry.payload_index)
        {
            return Err(invalid_cursor());
        }
        // A row is assigned to one seed when its stream is built
        if seeds.get(entry.row_index).copied().flatten() != Some(entry.seed_index) {
            return Err(invalid_cursor());
        }
        *observed = true;
    }
    stream.pending = BinaryHeap::from(entries);
    Ok(())
}

const fn invalid_cursor() -> RelationalTransformError {
    RelationalTransformError::InvalidInput("invalid or incompatible relational search cursor")
}

struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn identity(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
    options: RelationalTransformEvaluationOptions,
) -> Result<[u8; 32], RelationalTransformError> {
    let mut writer = HashWriter(Sha256::new());
    writer.0.update(b"l2-relational-search-cursor-v1");
    serde_json::to_writer(&mut writer, plan).map_err(|_| invalid_cursor())?;
    writer
        .0
        .update(options.max_retained_output_bytes.to_le_bytes());
    writer.0.update(samples.len().to_le_bytes());
    for sample in samples {
        writer.0.update(sample.sample.to_le_bytes());
        writer.0.update(sample.session_order.to_le_bytes());
        writer.0.update(sample.context.session.to_le_bytes());
        writer.0.update([match sample.context.direction {
            crate::protocol::Direction::FirstToSecond => 0,
            crate::protocol::Direction::SecondToFirst => 1,
        }]);
        for bytes in [
            sample.context.source.as_bytes(),
            sample.context.scope.as_bytes(),
            sample.bytes,
        ] {
            writer.0.update(bytes.len().to_le_bytes());
            writer.0.update(bytes);
        }
    }
    Ok(writer.0.finalize().into())
}

macro_rules! move_search {
    ($old:expr, $candidates:expr, $history:expr) => {{
        let old = $old;
        SearchState {
            candidates: $candidates,
            history: $history,
            candidates_examined: old.candidates_examined,
            history_reused_rejections: old.history_reused_rejections,
            history_reused_published: old.history_reused_published,
            history_recording_omissions: old.history_recording_omissions,
            equivalent_candidate_aliases: old.equivalent_candidate_aliases,
            omitted_candidates: old.omitted_candidates,
            omitted_candidates_exact: old.omitted_candidates_exact,
            work_bytes: old.work_bytes,
            search_exhaustive: old.search_exhaustive,
            search_limit: old.search_limit,
            search_limits: old.search_limits,
            locator_candidates_examined: old.locator_candidates_examined,
            prefix_probe_hypotheses_examined: old.prefix_probe_hypotheses_examined,
            prefix_probes_examined: old.prefix_probes_examined,
            prefix_probe_cache_reuses: old.prefix_probe_cache_reuses,
            prefix_probe_candidates_with_novelty: old.prefix_probe_candidates_with_novelty,
            prefix_probe_work_bytes: old.prefix_probe_work_bytes,
            prefix_probe_complete: old.prefix_probe_complete,
            output_bytes_retained: old.output_bytes_retained,
            output_capture_omissions: old.output_capture_omissions,
        }
    }};
}

mod checkpoint;
pub(super) use checkpoint::deserialize_candidate;

fn attach_history<'h, T>(
    mut search: SearchState<'_, T>,
    history: Option<&'h mut RelationalReplayHistory>,
) -> SearchState<'h, T> {
    let candidates = std::mem::take(&mut search.candidates);
    move_search!(search, candidates, history)
}

fn history_identity(
    history: Option<&RelationalReplayHistory>,
) -> Result<Option<[u8; 32]>, RelationalTransformError> {
    history
        .map(RelationalReplayHistory::checkpoint_identity)
        .transpose()
}

/// Continue an across-session search for at least the requested number of complete candidates
///
/// The initial locator, anchor, and prefix-ranking stages finish before the first pause. A later
/// step may finish earlier when the search reaches a selected limit. The caller must restore the
/// history and job contribution from the same committed generation before resuming.
///
/// # Errors
/// Returns an error for incompatible inputs or cursor state, cancellation, or evaluator failure
#[expect(
    clippy::too_many_arguments,
    reason = "the step mirrors the existing evaluator API and adds its continuation"
)]
#[expect(
    clippy::too_many_lines,
    reason = "keep checkpoint restoration and search transitions together"
)]
pub fn step_relational_transform_candidates_with_evaluator_and_history<T, E, F>(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
    job: Option<&Job>,
    options: RelationalTransformEvaluationOptions,
    mut history: Option<&mut RelationalReplayHistory>,
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
    if let Some(job) = job {
        job.check_cancelled()
            .map_err(RelationalTransformError::from)?;
    }
    validate_plan(plan)?;
    if candidate_budget == 0
        || plan.parser_scope != super::super::super::model::RelationalParserScope::AcrossSessions
    {
        return Err(RelationalEvaluationError::Search(
            RelationalTransformError::InvalidPlan(
                "resumable relational search requires a positive step and across-session parser scope",
            ),
        ));
    }
    if options.max_retained_output_bytes > plan.limits.max_total_bytes {
        return Err(RelationalEvaluationError::Search(
            RelationalTransformError::InvalidPlan(
                "retained evaluator outputs exceed the aggregate byte limit",
            ),
        ));
    }
    let mut prepared = prepare_search(samples, plan)?;
    let identity = identity(samples, plan, options)?;
    let parameters = candidate_parameters(plan)?;
    let settings = SearchSettings {
        retention_mode: RetentionMode::EvaluatorPriority,
        max_retained_output_bytes: options.max_retained_output_bytes,
        capture_outputs_for_evaluator: true,
    };

    let first_step = cursor.is_none();
    let (mut search, initial_pairs, pre_evaluated, mut position) = if let Some(cursor) = cursor {
        if cursor.identity != identity
            || cursor.history_identity != history_identity(history.as_deref())?
        {
            return Err(RelationalEvaluationError::Search(invalid_cursor()));
        }
        prepared.payload_locators = cursor.payload_locators;
        prepared.absolute_locators_complete = cursor.absolute_locators_complete;
        validate_cursor(
            samples,
            &cursor.search,
            &prepared,
            &cursor.initial_pairs,
            &cursor.pre_evaluated,
            &cursor.position,
            plan,
            options,
        )?;
        (
            attach_history(cursor.search, history),
            cursor.initial_pairs,
            cursor.pre_evaluated,
            cursor.position,
        )
    } else {
        if let Some(history) = history.as_deref_mut() {
            history.prepare(plan.limits);
        }
        let mut search = SearchState::new(history);
        search.prefix_probe_complete = false;
        search.locator_candidates_examined =
            prepared.seed_locators.len() + prepared.payload_locators.len();
        let mut context = SearchContext {
            samples,
            plan,
            job,
            prepared: &mut prepared,
            settings,
            candidate_parameters: &parameters,
            anchor_work_limit: plan.limits.max_work_bytes,
            anchor_candidate_limit: plan.limits.max_candidates,
            active_work_limit: plan.limits.max_work_bytes,
            active_candidate_limit: plan.limits.max_candidates,
        };
        let Some(mut initial) = context.search_initial_pair_window(&mut search, &mut evaluator)?
        else {
            if let Some(history) = search.history.as_deref_mut() {
                history.finish();
            }
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
                stage: PairStage::Initial { next: 0 },
                current: None,
            },
        )
    };
    let started_at = search.candidates_examined;
    // Include initial and ranked work in the first requested step
    let pause_at = if first_step {
        candidate_budget
    } else {
        started_at.saturating_add(candidate_budget)
    };
    let context = SearchContext {
        samples,
        plan,
        job,
        prepared: &mut prepared,
        settings,
        candidate_parameters: &parameters,
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
        pause_at,
        &mut evaluator,
    )?;
    if completed {
        if let Some(history) = search.history.as_deref_mut() {
            history.finish();
        }
        return Ok(RelationalSearchStep::Complete(build_report(
            search,
            prepared,
            plan.limits,
        )?));
    }
    let history_identity = history_identity(search.history.as_deref())?;
    let search = attach_history(search, None);
    Ok(RelationalSearchStep::Paused(RelationalSearchCursor {
        identity,
        history_identity,
        search,
        payload_locators: prepared.payload_locators,
        absolute_locators_complete: prepared.absolute_locators_complete,
        initial_pairs,
        pre_evaluated,
        position,
    }))
}

#[expect(
    clippy::too_many_lines,
    reason = "keep the candidate boundary and phase transitions together"
)]
fn drive<T, E, F>(
    context: &SearchContext<'_, '_>,
    search: &mut SearchState<'_, T>,
    initial: &[(usize, usize)],
    pre_evaluated: &BTreeSet<CandidateId>,
    position: &mut Position,
    pause_at: usize,
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
    let mut schedule = match &mut position.stage {
        PairStage::Absolute { schedule } => match schedule.take() {
            Some(saved) => Some(saved.restore(
                &context.prepared.seed_locators,
                &context.prepared.payload_locators,
            )?),
            None => Some(LocatorPairSchedule::new(
                &context.prepared.seed_locators,
                &context.prepared.payload_locators,
            )?),
        },
        _ => None,
    };
    loop {
        if search.candidates_examined >= pause_at {
            if let PairStage::Absolute { schedule: saved } = &mut position.stage {
                *saved = schedule.take().map(SavedSchedule::save);
            }
            return Ok(false);
        }
        if position.current.is_none() {
            let pair = match &mut position.stage {
                PairStage::Initial { next } => {
                    if let Some(&pair) = initial.get(*next) {
                        *next += 1;
                        Some(pair)
                    } else {
                        position.stage = PairStage::Absolute { schedule: None };
                        schedule = Some(LocatorPairSchedule::new(
                            &context.prepared.seed_locators,
                            &context.prepared.payload_locators,
                        )?);
                        continue;
                    }
                }
                PairStage::Absolute { .. } => {
                    let Some(active) = schedule.as_mut() else {
                        return Err(invalid_cursor().into());
                    };
                    let next = loop {
                        let Some(pair) = active.next() else {
                            break None;
                        };
                        if initial.contains(&pair) {
                            continue;
                        }
                        let Some(locators) = context.locator_pair(pair.0, pair.1) else {
                            continue;
                        };
                        if !locator_pair_overlaps(
                            context.samples,
                            &context.prepared.discovery_indexes,
                            locators,
                        ) {
                            break Some(pair);
                        }
                    };
                    if next.is_none() {
                        position.stage = PairStage::Anchored { next: 0 };
                        schedule = None;
                        continue;
                    }
                    next
                }
                PairStage::Anchored { next } => {
                    let mut pair = None;
                    while let Some(payload) = context.prepared.payload_locators.get(*next) {
                        let index = *next;
                        *next += 1;
                        if let Some(seed) = payload.anchor_seed_index {
                            pair = Some((seed, index));
                            break;
                        }
                    }
                    if pair.is_none() {
                        return Ok(true);
                    }
                    pair
                }
            };
            if let Some((seed, payload)) = pair {
                position.current = Some(PairPosition {
                    seed,
                    payload,
                    parameters: ParameterPosition::default(),
                });
            }
        }
        let current = position.current.as_mut().ok_or(invalid_cursor())?;
        let action = current.parameters.next(context.plan)?;
        match action {
            None => position.current = None,
            Some(ParameterAction::Alias) => context.count_equivalent_candidate_aliases(search)?,
            Some(ParameterAction::Candidate(index, parameters)) => {
                let id = CandidateId {
                    seed: current.seed,
                    payload: current.payload,
                    parameter: index,
                };
                if pre_evaluated.contains(&id) {
                    continue;
                }
                let pair = context
                    .locator_pair(current.seed, current.payload)
                    .ok_or(invalid_cursor())?;
                if !context.try_candidate(
                    search,
                    pair.seed_locator,
                    pair.payload_locator,
                    parameters,
                    evaluator,
                )? {
                    return Ok(true);
                }
            }
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "validate one cursor against its complete search context"
)]
#[expect(
    clippy::too_many_lines,
    reason = "check related cursor invariants before doing more work"
)]
fn validate_cursor<T>(
    samples: &[RelationalRecordSample<'_>],
    search: &SearchState<'_, T>,
    prepared: &PreparedSearch,
    initial: &[(usize, usize)],
    pre_evaluated: &BTreeSet<CandidateId>,
    position: &Position,
    plan: &RelationalTransformPlan,
    options: RelationalTransformEvaluationOptions,
) -> Result<(), RelationalTransformError> {
    let limits = plan.limits;
    if search.candidates_examined > limits.max_candidates
        || search.work_bytes > limits.max_work_bytes
        || search.candidates.len() > limits.max_retained_candidates
        || search.output_bytes_retained > options.max_retained_output_bytes
        || search.prefix_probe_work_bytes > search.work_bytes
        || prepared.payload_locators.len() > limits.max_locator_candidates
        || initial.len() > INITIAL_RANK_ORDERED_PAIR_WINDOW
        || search.locator_candidates_examined
            != prepared
                .seed_locators
                .len()
                .saturating_add(prepared.payload_locators.len())
        || search.output_capture_omissions > search.candidates.len()
        || search.search_limit != search.search_limits.first().copied()
    {
        return Err(invalid_cursor());
    }
    for locator in &prepared.payload_locators {
        if locator.locator.marker.len() > limits.max_marker_bytes
            || locator.selector.marker.len() > limits.max_marker_bytes
            || locator
                .anchor_seed_index
                .is_some_and(|index| index >= prepared.seed_locators.len())
        {
            return Err(invalid_cursor());
        }
    }
    let in_domain = |seed: usize, payload: usize| {
        seed < prepared.seed_locators.len() && payload < prepared.payload_locators.len()
    };
    if initial
        .iter()
        .any(|&(seed, payload)| !in_domain(seed, payload))
        || pre_evaluated.len()
            > limits
                .max_candidates
                .saturating_add(INITIAL_RANK_ORDERED_PAIR_WINDOW)
        || pre_evaluated
            .iter()
            .any(|id| !in_domain(id.seed, id.payload) || id.parameter >= limits.max_candidates)
        || position
            .current
            .as_ref()
            .is_some_and(|pair| !in_domain(pair.seed, pair.payload) || !pair.parameters.valid(plan))
    {
        return Err(invalid_cursor());
    }
    match &position.stage {
        PairStage::Initial { next } if *next > initial.len() => return Err(invalid_cursor()),
        PairStage::Anchored { next } if *next > prepared.payload_locators.len() => {
            return Err(invalid_cursor());
        }
        _ => {}
    }
    let mut bytes = 0_usize;
    let mut omissions = 0_usize;
    let mut orders = BTreeSet::new();
    for retained in &search.candidates {
        if retained.search_order == 0
            || retained.search_order > search.candidates_examined
            || !orders.insert(retained.search_order)
            || retained.candidate.rule.parser_scope != plan.parser_scope
            || retained.candidate.status
                != candidate_status(
                    &retained.candidate.discovery,
                    &retained.candidate.heldout,
                    plan.parser_scope,
                )
        {
            return Err(invalid_cursor());
        }
        validate_fit(&retained.candidate.discovery, &prepared.discovery_groups)?;
        validate_fit(&retained.candidate.heldout, &prepared.heldout_groups)?;
        if let Some(outputs) = &retained.outputs {
            validate_outputs(
                samples,
                &prepared.discovery_groups,
                &retained.candidate.discovery,
                &outputs.discovery,
            )?;
            validate_outputs(
                samples,
                &prepared.heldout_groups,
                &retained.candidate.heldout,
                &outputs.heldout,
            )?;
        }
        let actual = retained
            .outputs
            .as_ref()
            .map_or(Some(0), |outputs| {
                outputs
                    .discovery
                    .iter()
                    .chain(&outputs.heldout)
                    .try_fold(0_usize, |sum, output| sum.checked_add(output.bytes.len()))
            })
            .ok_or(invalid_cursor())?;
        if actual != retained.captured_output_bytes
            || (retained.output_capture_omitted && retained.outputs.is_some())
        {
            return Err(invalid_cursor());
        }
        bytes = bytes.checked_add(actual).ok_or(invalid_cursor())?;
        omissions += usize::from(retained.output_capture_omitted);
    }
    if bytes != search.output_bytes_retained || omissions != search.output_capture_omissions {
        return Err(invalid_cursor());
    }
    Ok(())
}

fn validate_fit(
    fit: &RelationalFit,
    groups: &[SessionGroup],
) -> Result<(), RelationalTransformError> {
    if fit.checks.is_empty() {
        return if fit.status == RelationalFitStatus::NotEvaluated
            && fit.supported_sessions.is_empty()
            && fit.contradicted_sessions.is_empty()
            && fit.unresolved_sessions.is_empty()
        {
            Ok(())
        } else {
            Err(invalid_cursor())
        };
    }
    if fit.checks.len() != groups.len()
        || fit
            .checks
            .iter()
            .zip(groups)
            .any(|(check, group)| check.session != group.id)
    {
        return Err(invalid_cursor());
    }
    let supported = fit
        .checks
        .iter()
        .filter(|check| check.status == RelationalFitStatus::TransformConstraintsSatisfied)
        .map(|check| &check.session);
    let contradicted = fit
        .checks
        .iter()
        .filter(|check| check.status == RelationalFitStatus::Contradicted)
        .map(|check| &check.session);
    let unresolved = fit
        .checks
        .iter()
        .filter(|check| check.status == RelationalFitStatus::UnresolvedOnBudget)
        .map(|check| &check.session);
    if !supported.eq(fit.supported_sessions.iter())
        || !contradicted.eq(fit.contradicted_sessions.iter())
        || !unresolved.eq(fit.unresolved_sessions.iter())
    {
        return Err(invalid_cursor());
    }
    let expected = if !fit.contradicted_sessions.is_empty() {
        RelationalFitStatus::Contradicted
    } else if !fit.unresolved_sessions.is_empty() {
        RelationalFitStatus::UnresolvedOnBudget
    } else if fit.supported_sessions.len() == fit.checks.len() {
        RelationalFitStatus::TransformConstraintsSatisfied
    } else {
        return Err(invalid_cursor());
    };
    if fit.status != expected {
        return Err(invalid_cursor());
    }
    Ok(())
}

fn validate_outputs(
    samples: &[RelationalRecordSample<'_>],
    groups: &[SessionGroup],
    fit: &RelationalFit,
    outputs: &[RelationalAppliedOutput],
) -> Result<(), RelationalTransformError> {
    if outputs.len() != fit.supported_sessions.len() {
        return Err(invalid_cursor());
    }
    for (output, session) in outputs.iter().zip(&fit.supported_sessions) {
        let group = groups
            .iter()
            .find(|group| group.id == *session)
            .ok_or(invalid_cursor())?;
        let check = fit
            .checks
            .iter()
            .find(|check| check.session == *session)
            .ok_or(invalid_cursor())?;
        let digest = check.output_sha256.as_deref().ok_or(invalid_cursor())?;
        if output.session != *session
            || output.session_order != group.session_order
            || check.seed_sample != Some(output.seed_sample)
            || check.output_length != Some(output.bytes.len())
            || !output.parser_validation_deferred
            || !crate::hashing::sha256_matches(&output.bytes, digest)
            || output.payload_mappings.len() != check.payload_samples.len()
            || !group.sample_indices.iter().any(|&index| {
                samples
                    .get(index)
                    .is_some_and(|sample| sample.sample == output.seed_sample)
            })
        {
            return Err(invalid_cursor());
        }
        let mut output_end = 0_usize;
        for (mapping, sample_id) in output.payload_mappings.iter().zip(&check.payload_samples) {
            let sample = group
                .sample_indices
                .iter()
                .filter_map(|&index| samples.get(index))
                .find(|sample| sample.sample == *sample_id)
                .ok_or(invalid_cursor())?;
            let source_length = mapping
                .source_range
                .end
                .checked_sub(mapping.source_range.start)
                .ok_or(invalid_cursor())?;
            let output_length = mapping
                .output_range
                .end
                .checked_sub(mapping.output_range.start)
                .ok_or(invalid_cursor())?;
            if mapping.sample != *sample_id
                || mapping.source_range.end > sample.bytes.len()
                || mapping.output_range.start != output_end
                || mapping.output_range.end > output.bytes.len()
                || source_length != output_length
            {
                return Err(invalid_cursor());
            }
            output_end = mapping.output_range.end;
        }
        if output_end != output.bytes.len() {
            return Err(invalid_cursor());
        }
    }
    Ok(())
}
