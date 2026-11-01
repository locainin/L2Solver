//! Validate saved producer parameters and prepare only the canonical session split

use super::{
    Job, RelationalCursorError, RelationalRecordSample, RelationalRestoreBudget,
    RelationalSessionId, RelationalTransformError, RelationalTransformPlan,
    RelationalTransformRule, SessionGroup,
};
use crate::{
    job::{MemoryBudget, MemoryLease},
    protocol::{RelationalParserScope, RelationalTransformLimits},
};
use std::{convert::Infallible, mem::size_of_val};

// Logical work policy v1 allows for tree comparisons and moves at each level
const GROUPING_TREE_COMPARISONS_PER_LEVEL: usize = 16;
const GROUPING_SORT_COMPARISONS_PER_LEVEL: usize = 8;

/// Prepare the canonical complete-session split under separate verification limits
///
/// The returned lease covers grouping and both result vectors. Keep it until the vectors and
/// any data moved from them have been dropped. Logical work policy v1 accounts for grouping
/// and source/scope comparisons, but does not guarantee a CPU-instruction or wall-time bound
///
/// # Errors
/// Returns an error for invalid input, cancellation, allocation failure, or exhausted limits
pub fn prepare_relational_session_partition(
    samples: &[RelationalRecordSample<'_>],
    limits: RelationalTransformLimits,
    job: Option<&Job>,
    memory: &MemoryBudget,
    work: &mut RelationalRestoreBudget,
) -> Result<
    (
        Vec<RelationalSessionId>,
        Vec<RelationalSessionId>,
        MemoryLease,
    ),
    RelationalCursorError<Infallible>,
> {
    super::checkpoint::check_job(job)?;
    let scan_work = samples
        .len()
        .checked_mul(size_of::<RelationalRecordSample<'_>>())
        .and_then(|bytes| bytes.checked_add(size_of::<usize>()))
        .ok_or(RelationalCursorError::RestoreWorkLimit)?;
    charge(work, scan_work)?;
    let mut context_bytes = 0_usize;
    let mut longest_context = 0_usize;
    for (index, sample) in samples.iter().enumerate() {
        if index.is_multiple_of(256) {
            super::checkpoint::check_job(job)?;
        }
        let bytes = sample
            .context
            .source
            .len()
            .checked_add(sample.context.scope.len())
            .ok_or(RelationalCursorError::RestoreWorkLimit)?;
        context_bytes = context_bytes
            .checked_add(bytes)
            .ok_or(RelationalCursorError::RestoreWorkLimit)?;
        longest_context = longest_context.max(bytes);
    }
    // Account for sample-ID and session-ID tree operations and capture-order sorting
    let levels = usize::try_from(usize::BITS - samples.len().leading_zeros())
        .ok()
        .and_then(|count| count.checked_add(1))
        .ok_or(RelationalCursorError::RestoreWorkLimit)?;
    let key_bytes = longest_context
        .checked_add(size_of::<u64>())
        .ok_or(RelationalCursorError::RestoreWorkLimit)?;
    let per_level = key_bytes
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(size_of::<u64>()))
        .and_then(|bytes| bytes.checked_mul(GROUPING_TREE_COMPARISONS_PER_LEVEL))
        .and_then(|bytes| {
            bytes.checked_add(
                size_of::<SessionGroup>().checked_mul(GROUPING_TREE_COMPARISONS_PER_LEVEL)?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(key_bytes.checked_mul(GROUPING_SORT_COMPARISONS_PER_LEVEL)?)
        })
        .ok_or(RelationalCursorError::RestoreWorkLimit)?;
    let grouping_work = samples
        .len()
        .checked_mul(levels)
        .and_then(|operations| operations.checked_mul(per_level))
        .and_then(|bytes| bytes.checked_add(context_bytes.checked_mul(8)?))
        .ok_or(RelationalCursorError::RestoreWorkLimit)?;
    charge(work, grouping_work)?;
    let admitted = super::preparation::grouping_memory_bytes(samples.len(), context_bytes)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(RelationalCursorError::CheckpointTooLarge)?;
    let lease = super::checkpoint::reserve(memory, admitted)?;
    let mut check_cancelled =
        || job.map_or(Ok(()), |job| job.check_cancelled().map_err(Into::into));
    let (discovery, heldout) =
        super::super::partition_sessions(samples, limits, &mut check_cancelled)
            .map_err(RelationalCursorError::Search)?;
    let discovery = session_ids(discovery, job)?;
    let heldout = session_ids(heldout, job)?;
    super::checkpoint::check_job(job)?;
    Ok((discovery, heldout, lease))
}

fn session_ids(
    groups: Vec<SessionGroup>,
    job: Option<&Job>,
) -> Result<Vec<RelationalSessionId>, RelationalCursorError<Infallible>> {
    let mut ids = Vec::new();
    ids.try_reserve_exact(groups.len())
        .map_err(|_| RelationalCursorError::AllocationFailed)?;
    for (index, group) in groups.into_iter().enumerate() {
        if index.is_multiple_of(256) {
            super::checkpoint::check_job(job)?;
        }
        ids.push(group.id);
    }
    Ok(ids)
}

/// Validate a saved producer's operation and parser parameters against a resumable plan
///
/// This checks allowed parameters, not historical enumeration or locator provenance. Plan
/// validation and the membership scans are charged before they inspect the untrusted rule
///
/// # Errors
/// Returns an error for invalid plans, incompatible parameters, exhausted work, or cancellation
pub fn validate_relational_producer_parameters(
    plan: &RelationalTransformPlan,
    rule: &RelationalTransformRule,
    job: Option<&Job>,
    work: &mut RelationalRestoreBudget,
) -> Result<(), RelationalCursorError<Infallible>> {
    super::checkpoint::check_job(job)?;
    let dimensions = [
        (
            plan.parser_formats.len(),
            size_of_val(plan.parser_formats.as_slice()),
        ),
        (
            plan.counter_widths.len(),
            size_of_val(plan.counter_widths.as_slice()),
        ),
        (
            plan.counter_byte_orders.len(),
            size_of_val(plan.counter_byte_orders.as_slice()),
        ),
        (
            plan.seed_orders.len(),
            size_of_val(plan.seed_orders.as_slice()),
        ),
        (
            plan.initial_counters.len(),
            size_of_val(plan.initial_counters.as_slice()),
        ),
        (
            plan.counter_resets.len(),
            size_of_val(plan.counter_resets.as_slice()),
        ),
    ];
    let validation_work = dimensions
        .into_iter()
        .try_fold(
            size_of::<RelationalTransformRule>(),
            |total, (count, bytes)| total.checked_add(count.checked_add(1)?.checked_mul(bytes)?),
        )
        .and_then(|bytes| {
            bytes.checked_add(
                plan.counter_widths
                    .len()
                    .checked_mul(plan.initial_counters.len())?
                    .checked_mul(size_of::<u64>())?,
            )
        })
        .ok_or(RelationalCursorError::RestoreWorkLimit)?;
    charge(work, validation_work)?;
    validate_resumable_plan(plan, job).map_err(RelationalCursorError::Search)?;
    let result = super::validation::validate_rule_parameters(rule, plan);
    super::checkpoint::check_job(job)?;
    result.map_err(|_| RelationalCursorError::InvalidCheckpoint)
}

pub(super) fn validate_resumable_plan(
    plan: &RelationalTransformPlan,
    job: Option<&Job>,
) -> Result<(), RelationalTransformError> {
    let mut check_cancelled =
        || job.map_or(Ok(()), |job| job.check_cancelled().map_err(Into::into));
    super::validate_plan(plan, &mut check_cancelled)?;
    if plan.parser_scope != RelationalParserScope::AcrossSessions {
        return Err(RelationalTransformError::InvalidPlan(
            "resumable relational search requires across-session parser scope",
        ));
    }
    Ok(())
}

const fn charge(
    work: &mut RelationalRestoreBudget,
    bytes: usize,
) -> Result<(), RelationalCursorError<Infallible>> {
    if work.try_charge_verification(bytes) {
        Ok(())
    } else {
        Err(RelationalCursorError::RestoreWorkLimit)
    }
}
