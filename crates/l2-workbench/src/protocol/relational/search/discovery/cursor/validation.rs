//! Validate restored relational state and exact source provenance before assessment decoding

use super::super::super::replay::saved_output_validation_record_bytes;
use super::{
    CandidateId, CounterWidth, INITIAL_RANK_ORDERED_PAIR_WINDOW, Job, LocatorCandidate,
    LocatorPair, PairStage, PairStreamRow, PayloadFamilyIndex, PayloadHeaderGroup,
    PayloadRankGroup, Position, PreparedSearch, RankedLocatorFamily, RankedPairEntry,
    RankedPayloadLocator, RelationalAppliedOutput, RelationalFit, RelationalFitStatus,
    RelationalOperationTemplate, RelationalRecordSample, RelationalTransformError,
    RelationalTransformEvaluationOptions, RelationalTransformPlan, RelationalTransformRule,
    SearchState, SeedHeaderGroup, SeedRankGroup, SessionGroup, candidate_status, invalid_cursor,
    locator_pair_overlaps,
};
use crate::protocol::{RelationalCoordinateBasis, RelationalSessionCheck};
use std::collections::BTreeSet;

// Account for the scheduler's sized vectors and per-session locator resolution scratch
pub(super) fn restoration_scratch_bytes<T>(
    prepared: &PreparedSearch,
    payloads: &[LocatorCandidate],
    search: &SearchState<'_, T>,
    position: &Position,
    pre_evaluated_count: usize,
) -> Result<u64, RelationalTransformError> {
    let schedule = schedule_scratch_bytes(prepared, payloads, position)?;
    let records = prepared
        .discovery_groups
        .iter()
        .chain(&prepared.heldout_groups)
        .map(|group| group.sample_indices.len())
        .max()
        .unwrap_or(0);
    let context_bytes = prepared
        .discovery_groups
        .iter()
        .chain(&prepared.heldout_groups)
        .try_fold(0_usize, |maximum, group| {
            group
                .id
                .source
                .len()
                .checked_add(group.id.scope.len())
                .map(|bytes| maximum.max(bytes))
        })
        .ok_or_else(invalid_cursor)?;
    let markers = search
        .candidates
        .iter()
        .map(|retained| {
            retained
                .candidate
                .rule
                .seed_locator
                .marker
                .len()
                .max(retained.candidate.rule.payload_locator.marker.len())
        })
        .max()
        .unwrap_or(0);
    let set_entries = pre_evaluated_count
        .checked_add(search.candidates.len())
        .ok_or_else(invalid_cursor)?;
    let set_bytes = set_entries
        .checked_mul(2 * size_of::<CandidateId>() + 4 * size_of::<usize>())
        .ok_or_else(invalid_cursor)?;
    let scratch = records
        .checked_mul(saved_output_validation_record_bytes())
        .and_then(|bytes| {
            markers
                .checked_mul(2)
                .and_then(|markers| bytes.checked_add(markers))
        })
        .and_then(|bytes| bytes.checked_add(schedule))
        .and_then(|bytes| bytes.checked_add(set_bytes))
        .and_then(|bytes| bytes.checked_add(2 * super::output::CHUNK_BYTES))
        .and_then(|bytes| {
            context_bytes
                .checked_mul(2)
                .and_then(|context| bytes.checked_add(context))
        })
        .ok_or_else(invalid_cursor)?;
    u64::try_from(scratch).map_err(|_| invalid_cursor())
}

fn schedule_scratch_bytes(
    prepared: &PreparedSearch,
    payloads: &[LocatorCandidate],
    position: &Position,
) -> Result<usize, RelationalTransformError> {
    if matches!(position.stage, PairStage::Absolute { .. }) {
        schedule_memory_bytes(prepared.seed_locators.len(), payloads.len())
            .ok_or_else(invalid_cursor)
    } else {
        Ok(0)
    }
}

pub(super) fn schedule_memory_bytes(seeds: usize, payloads: usize) -> Option<usize> {
    const SEED_BYTES: usize = 4 * size_of::<RankedLocatorFamily>()
        + 2 * size_of::<SeedRankGroup>()
        + 2 * size_of::<SeedHeaderGroup>()
        + 6 * size_of::<PairStreamRow>()
        + 6 * size_of::<RankedPairEntry>();
    const PAYLOAD_BYTES: usize = 2 * size_of::<RankedPayloadLocator>()
        + 2 * size_of::<PayloadRankGroup>()
        + 2 * size_of::<PayloadHeaderGroup>()
        + 2 * size_of::<PayloadFamilyIndex<'static>>();
    seeds
        .checked_mul(SEED_BYTES)?
        .checked_add(payloads.checked_mul(PAYLOAD_BYTES)?)
}

#[expect(
    clippy::too_many_arguments,
    reason = "validate one cursor against its complete search context"
)]
#[expect(
    clippy::too_many_lines,
    reason = "check related cursor invariants before doing more work"
)]
pub(super) fn validate_cursor<T>(
    samples: &[RelationalRecordSample<'_>],
    search: &SearchState<'_, T>,
    prepared: &PreparedSearch,
    initial: &[(usize, usize)],
    pre_evaluated: &BTreeSet<CandidateId>,
    position: &Position,
    plan: &RelationalTransformPlan,
    options: RelationalTransformEvaluationOptions,
    job: Option<&Job>,
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
        || search.prefix_probes_examined > search.prefix_probe_hypotheses_examined
        || search.prefix_probe_cache_reuses > search.prefix_probe_hypotheses_examined
        || search.prefix_probe_candidates_with_novelty > search.prefix_probes_examined
        || search
            .search_limits
            .iter()
            .enumerate()
            .any(|(index, limit)| {
                search
                    .search_limits
                    .iter()
                    .take(index)
                    .any(|previous| previous == limit)
            })
    {
        return Err(invalid_cursor());
    }
    for (index, locator) in prepared.payload_locators.iter().enumerate() {
        if index.is_multiple_of(256)
            && let Some(job) = job
        {
            job.check_cancelled()?;
        }
        if locator.locator.marker.len() > limits.max_marker_bytes
            || locator.locator.marker.is_empty()
            || locator.selector.marker.len() > limits.max_marker_bytes
            || locator.selector.marker.is_empty()
            || locator.locator.value_length.is_some()
            || locator.locator.declared_length.is_some()
            || locator
                .anchor_seed_index
                .is_some_and(|index| index >= prepared.seed_locators.len())
        {
            return Err(invalid_cursor());
        }
        match locator.anchor_seed_index {
            Some(index) => {
                let seed = prepared
                    .seed_locators
                    .get(index)
                    .ok_or_else(invalid_cursor)?;
                if locator.selector != seed.selector
                    || locator.locator.coordinate_basis != RelationalCoordinateBasis::SeedRangeEndV1
                    || locator.locator.direction != seed.selector.direction
                {
                    return Err(invalid_cursor());
                }
            }
            None => {
                if locator.locator.coordinate_basis != RelationalCoordinateBasis::MessageStartV1
                    || locator.selector.direction != locator.locator.direction
                    || locator.selector.marker_offset != locator.locator.marker_offset
                    || locator.selector.marker != locator.locator.marker
                    || locator.locator.value_offset > limits.max_locator_offset
                    || locator.selector.marker_offset > limits.max_marker_offset
                {
                    return Err(invalid_cursor());
                }
            }
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
    match (&position.stage, &position.current) {
        (PairStage::Initial { next }, current) => {
            if *next > initial.len()
                || current.as_ref().is_some_and(|pair| {
                    next.checked_sub(1)
                        .and_then(|index| initial.get(index))
                        .copied()
                        != Some((pair.seed, pair.payload))
                })
            {
                return Err(invalid_cursor());
            }
        }
        (PairStage::Anchored { next }, current) => {
            if *next > prepared.payload_locators.len()
                || current.as_ref().is_some_and(|pair| {
                    next.checked_sub(1) != Some(pair.payload)
                        || prepared
                            .payload_locators
                            .get(pair.payload)
                            .and_then(|locator| locator.anchor_seed_index)
                            != Some(pair.seed)
                })
            {
                return Err(invalid_cursor());
            }
        }
        (PairStage::Absolute { .. }, Some(pair)) => {
            let seed = prepared
                .seed_locators
                .get(pair.seed)
                .ok_or(invalid_cursor())?;
            let payload = prepared
                .payload_locators
                .get(pair.payload)
                .ok_or(invalid_cursor())?;
            if payload.anchor_seed_index.is_some()
                || initial.contains(&(pair.seed, pair.payload))
                || locator_pair_overlaps(
                    samples,
                    &prepared.discovery_indexes,
                    LocatorPair {
                        seed_index: pair.seed,
                        payload_index: pair.payload,
                        seed_locator: seed,
                        payload_locator: payload,
                    },
                )
            {
                return Err(invalid_cursor());
            }
        }
        (PairStage::Absolute { .. }, None) => {}
    }
    if matches!(&position.stage, PairStage::Absolute { schedule: None }) {
        return Err(invalid_cursor());
    }
    let mut bytes = 0_usize;
    let mut omissions = 0_usize;
    let mut orders = BTreeSet::new();
    for retained in &search.candidates {
        if let Some(job) = job {
            job.check_cancelled()?;
        }
        if retained.search_order == 0
            || retained.search_order > search.candidates_examined
            || !orders.insert(retained.search_order)
            || retained.candidate.discovery.supported_sessions.is_empty()
            || retained.candidate.status
                != candidate_status(
                    &retained.candidate.discovery,
                    &retained.candidate.heldout,
                    plan.parser_scope,
                )
        {
            return Err(invalid_cursor());
        }
        validate_rule(&retained.candidate.rule, prepared, plan)?;
        validate_fit(
            samples,
            &retained.candidate.discovery,
            &prepared.discovery_groups,
        )?;
        validate_fit(
            samples,
            &retained.candidate.heldout,
            &prepared.heldout_groups,
        )?;
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
            || (options.max_retained_output_bytes == 0
                && (retained.output_capture_omitted || retained.outputs.is_some()))
            || (options.max_retained_output_bytes > 0
                && retained.outputs.is_none()
                && !retained.output_capture_omitted)
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

fn validate_rule(
    rule: &RelationalTransformRule,
    prepared: &PreparedSearch,
    plan: &RelationalTransformPlan,
) -> Result<(), RelationalTransformError> {
    validate_rule_parameters(rule, plan)?;
    let has_seed = prepared
        .seed_locators
        .iter()
        .any(|seed| seed.locator == rule.seed_locator);
    let in_domain = has_seed
        && prepared.payload_locators.iter().any(|payload| {
            payload.locator == rule.payload_locator
                && payload.anchor_seed_index.is_none_or(|anchor| {
                    prepared
                        .seed_locators
                        .get(anchor)
                        .is_some_and(|seed| seed.locator == rule.seed_locator)
                })
        });
    if in_domain {
        Ok(())
    } else {
        Err(invalid_cursor())
    }
}

pub(super) fn validate_rule_parameters(
    rule: &RelationalTransformRule,
    plan: &RelationalTransformPlan,
) -> Result<(), RelationalTransformError> {
    let RelationalOperationTemplate::Sha256CounterXor(operation) = rule.operation;
    if rule.parser_scope != plan.parser_scope
        || !plan.parser_formats.contains(&rule.parser_format)
        || !plan.counter_widths.contains(&operation.counter_width)
        || !plan
            .counter_byte_orders
            .contains(&operation.counter_byte_order)
        || !plan.seed_orders.contains(&operation.seed_order)
        || !plan.initial_counters.contains(&operation.initial_counter)
        || operation.initial_counter > operation.counter_width.maximum_counter()
        || !plan.counter_resets.contains(&rule.counter_reset)
        || (operation.counter_width == CounterWidth::OneByte
            && plan.counter_byte_orders.first() != Some(&operation.counter_byte_order))
    {
        return Err(invalid_cursor());
    }
    Ok(())
}

fn validate_fit(
    samples: &[RelationalRecordSample<'_>],
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
    validate_checks(samples, &fit.checks, groups)?;
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

fn validate_checks(
    samples: &[RelationalRecordSample<'_>],
    checks: &[RelationalSessionCheck],
    groups: &[SessionGroup],
) -> Result<(), RelationalTransformError> {
    for (check, group) in checks.iter().zip(groups) {
        let contains = |sample_id: u64| {
            group
                .sample_indices
                .iter()
                .filter_map(|&index| samples.get(index))
                .any(|sample| sample.sample == sample_id)
        };
        let mut ordered = group
            .sample_indices
            .iter()
            .filter_map(|&index| samples.get(index));
        if check.seed_sample.is_some_and(|sample| !contains(sample))
            || check
                .payload_samples
                .iter()
                .any(|id| !ordered.any(|sample| sample.sample == *id))
        {
            return Err(invalid_cursor());
        }
        if check.status == RelationalFitStatus::TransformConstraintsSatisfied
            && (check.falsification.is_some()
                || check.output_length.is_none()
                || check
                    .output_sha256
                    .as_deref()
                    .is_none_or(|digest| !crate::hashing::is_sha256_digest(digest)))
        {
            return Err(invalid_cursor());
        }
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
        if output.session != *session
            || output.session_order != group.session_order
            || check.seed_sample != Some(output.seed_sample)
            || check.output_length != Some(output.bytes.len())
            || !output.parser_validation_deferred
            || output.payload_mappings.len() != check.payload_samples.len()
            || !group.sample_indices.iter().any(|&index| {
                samples
                    .get(index)
                    .is_some_and(|sample| sample.sample == output.seed_sample)
            })
        {
            return Err(invalid_cursor());
        }
        validate_mappings(samples, group, check, output)?;
    }
    Ok(())
}

fn validate_mappings(
    samples: &[RelationalRecordSample<'_>],
    group: &SessionGroup,
    check: &RelationalSessionCheck,
    output: &RelationalAppliedOutput,
) -> Result<(), RelationalTransformError> {
    let mut output_end = 0_usize;
    let mut ordered = group
        .sample_indices
        .iter()
        .filter_map(|&index| samples.get(index));
    for (mapping, sample_id) in output.payload_mappings.iter().zip(&check.payload_samples) {
        let sample = ordered
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
    Ok(())
}
