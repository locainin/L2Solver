//! Bound the live session's input indexes and locator preparation before allocating them

use super::{
    CandidateId, CandidateParameters, LocatorCandidate, RelationalRecordSample,
    RelationalSearchSession, RelationalSessionId, RelationalTransformPlan, SessionGroup,
};
use crate::protocol::relational::model::Selector;

impl RelationalSearchSession<'_, '_> {
    /// Return a conservative logical allocation allowance for session preparation
    ///
    /// Reserve this amount before calling [`Self::new`] and retain the lease until the session,
    /// its cursor, and any report state moved from the preparation have been consumed. The
    /// estimate covers selector proposals and marker storage, collection growth overlap,
    /// grouping contexts, locator heaps, the live pair scheduler, and pre-evaluated identities
    /// The logical allowance does not measure allocator metadata or process RSS
    ///
    /// Startup ranking, the search's retained results, evaluator state, cache, and checkpoint
    /// validation need their own allowances. `None` means a bound could not be represented and
    /// must be treated as a resource failure before constructing the session
    #[must_use]
    pub fn preparation_memory_bytes(
        samples: &[RelationalRecordSample<'_>],
        plan: &RelationalTransformPlan,
    ) -> Option<u64> {
        let limits = plan.limits;
        let mut proposals = 0_usize;
        let mut marker_bytes = 0_usize;
        let mut context_bytes = 0_usize;
        let mut max_marker = 0_usize;
        for sample in samples {
            let offsets = sample
                .bytes
                .len()
                .min(limits.max_marker_offset.saturating_add(1));
            let width = sample.bytes.len().min(limits.max_marker_bytes);
            let count = offsets.checked_mul(width)?;
            proposals = proposals.checked_add(count)?;
            marker_bytes = marker_bytes.checked_add(count.checked_mul(width)?)?;
            context_bytes = context_bytes
                .checked_add(sample.context.source.len())?
                .checked_add(sample.context.scope.len())?;
            max_marker = max_marker.max(width);
        }
        // B-tree and vector allowances include spare entries and old/new growth overlap
        let selector_entry = 4_usize.checked_mul(
            size_of::<Selector>()
                .checked_add(size_of::<Vec<usize>>())?
                .checked_add(6 * size_of::<usize>())?,
        )?;
        let grouping = grouping_memory_bytes(samples.len(), context_bytes)?;
        let locator_entry = 8_usize
            .checked_mul(size_of::<LocatorCandidate>())?
            .checked_add(8_usize.checked_mul(max_marker)?)?;
        let mut parameters = 1_usize;
        for count in [
            plan.counter_widths.len(),
            plan.initial_counters.len(),
            plan.counter_byte_orders.len(),
            plan.seed_orders.len(),
            plan.counter_resets.len(),
            plan.parser_formats.len(),
        ] {
            parameters = parameters.saturating_mul(count).min(limits.max_candidates);
        }
        let total = proposals
            .checked_mul(selector_entry)?
            .checked_add(marker_bytes.checked_mul(4)?)?
            .checked_add(grouping)?
            .checked_add(
                limits
                    .max_locator_candidates
                    .checked_mul(2)?
                    .checked_mul(locator_entry)?,
            )?
            .checked_add(parameters.checked_mul(4 * size_of::<CandidateParameters>())?)?
            .checked_add(super::validation::schedule_memory_bytes(
                limits.max_locator_candidates,
                limits.max_locator_candidates,
            )?)?
            .checked_add(
                limits
                    .max_candidates
                    .checked_add(super::INITIAL_RANK_ORDERED_PAIR_WINDOW)?
                    .checked_mul(4 * (size_of::<CandidateId>() + 4 * size_of::<usize>()))?,
            )?;
        u64::try_from(total).ok()
    }
}

pub(super) fn grouping_memory_bytes(samples: usize, context_bytes: usize) -> Option<usize> {
    let sample_entry = 8_usize.checked_mul(
        size_of::<RelationalSessionId>()
            .checked_add(size_of::<SessionGroup>())?
            .checked_add(size_of::<[usize; 8]>())?,
    )?;
    samples
        .checked_mul(sample_entry)?
        .checked_add(context_bytes.checked_mul(8)?)
}
