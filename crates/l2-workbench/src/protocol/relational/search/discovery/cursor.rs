//! Candidate-boundary continuation for across-session relational searches

use super::{
    CandidateId, CandidateParameters, INITIAL_RANK_ORDERED_PAIR_WINDOW, LocatorCandidate,
    LocatorPair, LocatorPairSchedule, PAIR_STREAM_ROTATION, PairDomain, PairStreamRow,
    PayloadFamilyIndex, PayloadHeaderGroup, PayloadRankGroup, PreparedSearch, RankedLocatorFamily,
    RankedPairEntry, RankedPairStream, RankedPayloadLocator, RelationalAppliedOutput,
    RelationalCandidateEvaluation, RelationalCandidateEvaluationReport, RelationalCandidateOutputs,
    RelationalEvaluationError, RelationalFit, RelationalFitStatus, RelationalOperationTemplate,
    RelationalRecordSample, RelationalReplayHistory, RelationalSessionId,
    RelationalSha256CounterXor, RelationalTransformCandidate, RelationalTransformError,
    RelationalTransformEvaluationContext, RelationalTransformEvaluationOptions,
    RelationalTransformPlan, RelationalTransformRule, RelationalTransformStatus, RetainedCandidate,
    RetentionMode, SearchContext, SearchSettings, SearchState, SeedHeaderGroup, SeedRankGroup,
    SessionGroup, build_report, candidate_parameters, candidate_status, locator_pair_overlaps,
    pair_stream_cue_rank, prepare_search, validate_plan,
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

// Change this version when saved search order or continuation semantics change
const CURSOR_VERSION: u32 = 1;

/// A saved search boundary, including retained candidate evidence and caller assessments
///
/// The associated history and job work snapshot must be restored from the same committed
/// generation. The first boundary follows the initial candidate and prefix-ranking stages.
pub struct RelationalSearchCursor<T> {
    identity: [u8; 32],
    session_id: u64,
    search: SearchState<'static, T>,
    prepared: PreparedSearch,
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
    /// Aggregate metadata admission rejected the decoded checkpoint
    Memory(crate::job::JsonMemoryError),
    /// Preparing the restored search failed or was cancelled
    Search(RelationalTransformError),
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
            Self::Memory(error) => write!(f, "relational checkpoint memory: {error}"),
            Self::Search(error) => write!(f, "relational checkpoint search: {error}"),
            Self::AllocationFailed => f.write_str("relational search checkpoint allocation failed"),
            Self::Assessment(error) => write!(f, "relational assessment checkpoint: {error}"),
        }
    }
}
impl<E: Error + 'static> Error for RelationalCursorError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Assessment(error) => Some(error),
            Self::Memory(error) => Some(error),
            Self::Search(error) => Some(error),
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
        if self.width == 0
            && self.initial == 0
            && self.order == 0
            && self.seed_order == 0
            && self.reset == 0
            && self.format == 0
            && self.candidate_index == 0
        {
            return true;
        }
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

    fn validate(
        &self,
        seeds: &[LocatorCandidate],
        payloads: &[LocatorCandidate],
    ) -> Result<(), RelationalTransformError> {
        let schedule = LocatorPairSchedule::new(seeds, payloads)?;
        if self.initial_pair_cursor > schedule.initial_pair_count
            || self.stream_cursor >= PAIR_STREAM_ROTATION.len()
        {
            return Err(invalid_cursor());
        }
        validate_stream(&schedule.domain, &schedule.header_aligned, &self.header)?;
        validate_stream(&schedule.domain, &schedule.aligned, &self.aligned)?;
        validate_stream(&schedule.domain, &schedule.fallback, &self.fallback)
    }
}

fn restore_stream(
    domain: &PairDomain<'_>,
    stream: &mut RankedPairStream,
    entries: Vec<Reverse<RankedPairEntry>>,
) -> Result<(), RelationalTransformError> {
    validate_stream(domain, stream, &entries)?;
    stream.pending = BinaryHeap::from(entries);
    Ok(())
}

fn validate_stream(
    domain: &PairDomain<'_>,
    stream: &RankedPairStream,
    entries: &[Reverse<RankedPairEntry>],
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
    for Reverse(entry) in entries {
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
    job: Option<&Job>,
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
            // Check between bounded chunks while hashing large immutable cohorts
            for chunk in bytes.chunks(64 * 1024) {
                if let Some(job) = job {
                    job.check_cancelled()?;
                }
                writer.0.update(chunk);
            }
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

mod session;
mod validation;
pub use session::RelationalSearchSession;
use validation::restoration_scratch_bytes;
use validation::validate_cursor;

#[derive(Clone, Copy)]
struct StepBounds {
    candidate_end: usize,
    traversal: usize,
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
    bounds: StepBounds,
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
    let mut traversed = 0_usize;
    loop {
        check_traversal_cancellation(context.job, traversed)?;
        // Cached rejections and skipped pairs still consume bounded traversal time
        if search.candidates_examined >= bounds.candidate_end || traversed >= bounds.traversal {
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
                        traversed += 1;
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
                PairStage::Absolute { schedule: saved } => {
                    let next = loop {
                        check_traversal_cancellation(context.job, traversed)?;
                        if traversed >= bounds.traversal {
                            *saved = schedule.take().map(SavedSchedule::save);
                            return Ok(false);
                        }
                        let Some(pair) = schedule.as_mut().ok_or(invalid_cursor())?.next() else {
                            break None;
                        };
                        traversed += 1;
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
                        check_traversal_cancellation(context.job, traversed)?;
                        if traversed >= bounds.traversal {
                            return Ok(false);
                        }
                        traversed += 1;
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
        if traversed >= bounds.traversal {
            if let PairStage::Absolute { schedule: saved } = &mut position.stage {
                *saved = schedule.take().map(SavedSchedule::save);
            }
            return Ok(false);
        }
        let action = current.parameters.next(context.plan)?;
        traversed += 1;
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

fn check_traversal_cancellation(
    job: Option<&Job>,
    traversed: usize,
) -> Result<(), RelationalTransformError> {
    if traversed.is_multiple_of(256)
        && let Some(job) = job
    {
        job.check_cancelled()?;
    }
    Ok(())
}
