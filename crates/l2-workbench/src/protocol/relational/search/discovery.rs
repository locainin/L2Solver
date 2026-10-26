use super::super::model::{
    RelationalAppliedOutput, RelationalCandidateEvaluation, RelationalCandidateEvaluationReport,
    RelationalCandidateOutputs, RelationalCounterReset, RelationalEvaluationError, RelationalFit,
    RelationalFitStatus, RelationalOperationTemplate, RelationalRecordSample,
    RelationalRetainedEvaluation, RelationalSearchLimit, RelationalSha256CounterXor,
    RelationalTransformCandidate, RelationalTransformError, RelationalTransformEvaluationContext,
    RelationalTransformEvaluationOptions, RelationalTransformLimits, RelationalTransformPlan,
    RelationalTransformReport, RelationalTransformRule, RelationalTransformStatus, Selector,
};
use super::{
    input::{
        SessionGroup, build_selector_indexes, group_sessions, shared_selectors, validate_plan,
    },
    locator::{
        LocatorCandidate, locator_ranges_overlap, locator_start_rank, payload_locators,
        seed_locators,
    },
    replay::{EvaluatedSplit, candidate_status, empty_fit, evaluate_split},
};
use crate::{
    job::{Counter, Job, Phase},
    protocol::{HoldoutBasis, RelationalSessionId},
};
use std::{cmp::Reverse, collections::BinaryHeap, convert::Infallible};

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

type RelativeStartRank = (u8, usize);
type HeaderStartRank = (usize, usize, usize);

#[derive(Clone, Copy)]
struct RankedLocatorFamily<'a> {
    selector: &'a Selector,
    relative_start: RelativeStartRank,
    header_start: HeaderStartRank,
}

#[derive(Clone, Copy)]
struct RankedPayloadLocator<'a> {
    selector: &'a Selector,
    relative_start: RelativeStartRank,
    header_start: HeaderStartRank,
    candidate_index: usize,
}

#[derive(Clone, Copy)]
struct PayloadRankGroup {
    relative_start: RelativeStartRank,
    start: usize,
    end: usize,
}

#[derive(Clone, Copy)]
struct PayloadHeaderGroup {
    relative_start: RelativeStartRank,
    header_start: HeaderStartRank,
    start: usize,
    end: usize,
}

#[derive(Clone, Copy)]
struct SeedRankGroup {
    relative_start: RelativeStartRank,
    count: usize,
    same_family_count: usize,
    header_pair_count: usize,
}

#[derive(Clone, Copy)]
struct SeedHeaderGroup {
    relative_start: RelativeStartRank,
    header_start: HeaderStartRank,
    count: usize,
    same_family_count: usize,
}

#[derive(Clone, Copy)]
struct PayloadFamilyIndex<'a> {
    selector: &'a Selector,
    relative_start: RelativeStartRank,
    ordered_index: usize,
}

struct PairDomain<'a> {
    seeds: Vec<RankedLocatorFamily<'a>>,
    seed_groups: Vec<SeedRankGroup>,
    seed_header_groups: Vec<SeedHeaderGroup>,
    payloads: Vec<RankedPayloadLocator<'a>>,
    payload_groups: Vec<PayloadRankGroup>,
    payload_header_groups: Vec<PayloadHeaderGroup>,
    payload_families: Vec<PayloadFamilyIndex<'a>>,
}

#[derive(Clone, Copy)]
struct PairStreamRow {
    payload_group: Option<usize>,
    header_group: Option<usize>,
    same_family_payload: Option<usize>,
}

#[derive(Clone, Copy)]
enum PairStreamKind {
    HeaderAligned,
    Aligned,
    Fallback,
}

struct RankedPairStream {
    kind: PairStreamKind,
    rows: Vec<PairStreamRow>,
    pending: BinaryHeap<Reverse<RankedPairEntry>>,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct RankedPairEntry {
    cue_rank: usize,
    pair_rank: usize,
    seed_index: usize,
    payload_index: usize,
    row_index: usize,
    payload_order_index: usize,
}

struct LocatorPairSchedule<'a> {
    domain: PairDomain<'a>,
    header_aligned: RankedPairStream,
    aligned: RankedPairStream,
    fallback: RankedPairStream,
    initial_pair_count: usize,
    initial_pair_cursor: usize,
    stream_cursor: usize,
}

// Keep the established best-ranked pair choices ahead of cue promotion
const INITIAL_RANK_ORDERED_PAIR_WINDOW: usize = 2;
// Give matching header layouts a bounded share while preserving the prior two-to-one fallback mix
const PAIR_STREAM_ROTATION: [PairStreamKind; 7] = [
    PairStreamKind::HeaderAligned,
    PairStreamKind::Aligned,
    PairStreamKind::Aligned,
    PairStreamKind::Fallback,
    PairStreamKind::Aligned,
    PairStreamKind::Aligned,
    PairStreamKind::Fallback,
];

impl<'a> PairDomain<'a> {
    fn new(
        seed_candidates: &'a [LocatorCandidate],
        payload_candidates: &'a [LocatorCandidate],
    ) -> Result<Self, RelationalTransformError> {
        let seeds = ranked_seed_families(seed_candidates)?;
        let payloads = ranked_payload_locators(payload_candidates)?;
        let payload_groups = payload_rank_groups(&payloads)?;
        let payload_header_groups = payload_header_groups(&payloads)?;
        let payload_families = payload_family_index(&payloads)?;
        let seed_header_groups = seed_header_groups(&seeds, &payload_families)?;
        let seed_groups = seed_rank_groups(
            &seeds,
            &seed_header_groups,
            &payload_groups,
            &payload_header_groups,
            &payload_families,
        )?;

        Ok(Self {
            seeds,
            seed_groups,
            seed_header_groups,
            payloads,
            payload_groups,
            payload_header_groups,
            payload_families,
        })
    }

    fn payload_group(&self, rank: RelativeStartRank) -> Option<usize> {
        self.payload_groups
            .binary_search_by_key(&rank, |group| group.relative_start)
            .ok()
    }

    fn same_family_payload(&self, rank: RelativeStartRank, selector: &Selector) -> Option<usize> {
        let ordered_index = self.payload_families.partition_point(|family| {
            family.relative_start < rank
                || (family.relative_start == rank && family.selector < selector)
        });
        self.payload_families.get(ordered_index).and_then(|family| {
            (family.relative_start == rank && family.selector == selector)
                .then_some(family.ordered_index)
        })
    }

    fn header_group(
        &self,
        relative_start: RelativeStartRank,
        header_start: HeaderStartRank,
    ) -> Option<usize> {
        self.payload_header_groups
            .binary_search_by_key(&(relative_start, header_start), |group| {
                (group.relative_start, group.header_start)
            })
            .ok()
    }

    fn specific_header_group(
        &self,
        relative_start: RelativeStartRank,
        header_start: HeaderStartRank,
    ) -> Option<usize> {
        let header_pairs = self.header_aligned_pair_count(relative_start, header_start);
        let relative_pairs = self.relative_aligned_pair_count(relative_start);
        (header_pairs > 0 && header_pairs < relative_pairs)
            .then(|| self.header_group(relative_start, header_start))
            .flatten()
    }

    fn relative_aligned_pair_count(&self, rank: RelativeStartRank) -> usize {
        let Some(seed_group) = self
            .seed_groups
            .binary_search_by_key(&rank, |group| group.relative_start)
            .ok()
            .and_then(|index| self.seed_groups.get(index))
        else {
            return 0;
        };
        let Some(payload_group) = self
            .payload_group(rank)
            .and_then(|index| self.payload_groups.get(index))
        else {
            return 0;
        };
        seed_group
            .count
            .saturating_mul(payload_group.end - payload_group.start)
            .saturating_sub(seed_group.same_family_count)
    }

    fn aligned_pair_count(&self, rank: RelativeStartRank) -> usize {
        let Some(seed_group) = self
            .seed_groups
            .binary_search_by_key(&rank, |group| group.relative_start)
            .ok()
            .and_then(|index| self.seed_groups.get(index))
        else {
            return 0;
        };
        let Some(payload_group) = self
            .payload_group(rank)
            .and_then(|index| self.payload_groups.get(index))
        else {
            return 0;
        };
        seed_group
            .count
            .saturating_mul(payload_group.end - payload_group.start)
            .saturating_sub(seed_group.same_family_count)
            .saturating_sub(seed_group.header_pair_count)
    }

    fn header_aligned_pair_count(
        &self,
        relative_start: RelativeStartRank,
        header_start: HeaderStartRank,
    ) -> usize {
        let Some(seed_group) = self
            .seed_header_groups
            .binary_search_by_key(&(relative_start, header_start), |group| {
                (group.relative_start, group.header_start)
            })
            .ok()
            .and_then(|index| self.seed_header_groups.get(index))
        else {
            return 0;
        };
        let Some(payload_group) = self
            .header_group(relative_start, header_start)
            .and_then(|index| self.payload_header_groups.get(index))
        else {
            return 0;
        };
        seed_group
            .count
            .saturating_mul(payload_group.end - payload_group.start)
            .saturating_sub(seed_group.same_family_count)
    }

    fn next_payload_order(
        &self,
        row: PairStreamRow,
        kind: PairStreamKind,
        cursor: usize,
    ) -> Option<usize> {
        let payload_count = self.payloads.len();
        if cursor >= payload_count {
            return None;
        }
        let group = row
            .payload_group
            .and_then(|group_index| self.payload_groups.get(group_index));

        match kind {
            PairStreamKind::HeaderAligned => {
                let group = row
                    .header_group
                    .and_then(|group_index| self.payload_header_groups.get(group_index))?;
                let candidate_index = cursor.max(group.start);
                let candidate_index = if row.same_family_payload == Some(candidate_index) {
                    candidate_index.saturating_add(1)
                } else {
                    candidate_index
                };
                (candidate_index < group.end).then_some(candidate_index)
            }
            PairStreamKind::Aligned => {
                let group = group?;
                let mut candidate_index = cursor.max(group.start);
                if let Some(header_group) = row
                    .header_group
                    .and_then(|group_index| self.payload_header_groups.get(group_index))
                    && candidate_index >= header_group.start
                    && candidate_index < header_group.end
                {
                    candidate_index = header_group.end;
                }
                if row.same_family_payload == Some(candidate_index) {
                    candidate_index = candidate_index.saturating_add(1);
                }
                (candidate_index < group.end).then_some(candidate_index)
            }
            PairStreamKind::Fallback => {
                let Some(group) = group else {
                    return Some(cursor);
                };
                if cursor < group.start || cursor >= group.end {
                    return Some(cursor);
                }
                if let Some(same_family) = row
                    .same_family_payload
                    .filter(|same_family| *same_family >= cursor && *same_family < group.end)
                {
                    return Some(same_family);
                }
                (group.end < payload_count).then_some(group.end)
            }
        }
    }
}

fn ranked_seed_families(
    candidates: &[LocatorCandidate],
) -> Result<Vec<RankedLocatorFamily<'_>>, RelationalTransformError> {
    let mut seeds = Vec::new();
    seeds
        .try_reserve_exact(candidates.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    for candidate in candidates {
        seeds.push(RankedLocatorFamily {
            selector: &candidate.selector,
            relative_start: locator_start_rank(candidate),
            header_start: header_start_rank(candidate),
        });
    }
    Ok(seeds)
}

fn ranked_payload_locators(
    candidates: &[LocatorCandidate],
) -> Result<Vec<RankedPayloadLocator<'_>>, RelationalTransformError> {
    let mut payloads = Vec::new();
    payloads
        .try_reserve_exact(candidates.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    for (candidate_index, candidate) in candidates.iter().enumerate() {
        payloads.push(RankedPayloadLocator {
            selector: &candidate.selector,
            relative_start: locator_start_rank(candidate),
            header_start: header_start_rank(candidate),
            candidate_index,
        });
    }
    // Keep both relative-start groups and their more specific header groups contiguous
    payloads.sort_unstable_by_key(|candidate| {
        (
            candidate.relative_start,
            candidate.header_start,
            candidate.candidate_index,
        )
    });
    Ok(payloads)
}

const fn header_start_rank(candidate: &LocatorCandidate) -> HeaderStartRank {
    (
        candidate.selector.marker_offset,
        candidate.selector.marker.len(),
        candidate.locator.value_offset,
    )
}

fn payload_rank_groups(
    payloads: &[RankedPayloadLocator<'_>],
) -> Result<Vec<PayloadRankGroup>, RelationalTransformError> {
    let mut groups = Vec::new();
    let Some(first) = payloads.first() else {
        return Ok(groups);
    };
    groups
        .try_reserve(payloads.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let mut current_rank = first.relative_start;
    let mut group_start = 0;
    for (ordered_index, candidate) in payloads.iter().enumerate().skip(1) {
        if candidate.relative_start != current_rank {
            groups.push(PayloadRankGroup {
                relative_start: current_rank,
                start: group_start,
                end: ordered_index,
            });
            current_rank = candidate.relative_start;
            group_start = ordered_index;
        }
    }
    groups.push(PayloadRankGroup {
        relative_start: current_rank,
        start: group_start,
        end: payloads.len(),
    });
    Ok(groups)
}

fn payload_header_groups(
    payloads: &[RankedPayloadLocator<'_>],
) -> Result<Vec<PayloadHeaderGroup>, RelationalTransformError> {
    let mut groups = Vec::new();
    let Some(first) = payloads.first() else {
        return Ok(groups);
    };
    groups
        .try_reserve(payloads.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let mut current_key = (first.relative_start, first.header_start);
    let mut group_start = 0;
    for (ordered_index, candidate) in payloads.iter().enumerate().skip(1) {
        let candidate_key = (candidate.relative_start, candidate.header_start);
        if candidate_key != current_key {
            groups.push(PayloadHeaderGroup {
                relative_start: current_key.0,
                header_start: current_key.1,
                start: group_start,
                end: ordered_index,
            });
            current_key = candidate_key;
            group_start = ordered_index;
        }
    }
    groups.push(PayloadHeaderGroup {
        relative_start: current_key.0,
        header_start: current_key.1,
        start: group_start,
        end: payloads.len(),
    });
    groups.sort_unstable_by_key(|group| (group.relative_start, group.header_start));
    Ok(groups)
}

fn payload_family_index<'a>(
    payloads: &[RankedPayloadLocator<'a>],
) -> Result<Vec<PayloadFamilyIndex<'a>>, RelationalTransformError> {
    let mut families = Vec::new();
    families
        .try_reserve_exact(payloads.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    for (ordered_index, candidate) in payloads.iter().enumerate() {
        families.push(PayloadFamilyIndex {
            selector: candidate.selector,
            relative_start: candidate.relative_start,
            ordered_index,
        });
    }
    families.sort_unstable_by(|left, right| {
        left.relative_start
            .cmp(&right.relative_start)
            .then_with(|| left.selector.cmp(right.selector))
            .then_with(|| left.ordered_index.cmp(&right.ordered_index))
    });
    Ok(families)
}

fn seed_rank_groups(
    seeds: &[RankedLocatorFamily<'_>],
    seed_header_groups: &[SeedHeaderGroup],
    payload_groups: &[PayloadRankGroup],
    payload_header_groups: &[PayloadHeaderGroup],
    payload_families: &[PayloadFamilyIndex<'_>],
) -> Result<Vec<SeedRankGroup>, RelationalTransformError> {
    let mut groups = relative_seed_groups(seeds, payload_families)?;
    count_specific_header_pairs(
        &mut groups,
        seed_header_groups,
        payload_groups,
        payload_header_groups,
    );
    Ok(groups)
}

fn relative_seed_groups(
    seeds: &[RankedLocatorFamily<'_>],
    payload_families: &[PayloadFamilyIndex<'_>],
) -> Result<Vec<SeedRankGroup>, RelationalTransformError> {
    let mut ordered_seeds = Vec::new();
    ordered_seeds
        .try_reserve_exact(seeds.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    ordered_seeds.extend_from_slice(seeds);
    ordered_seeds.sort_unstable_by(|left, right| {
        left.relative_start
            .cmp(&right.relative_start)
            .then_with(|| left.selector.cmp(right.selector))
    });

    let mut groups = Vec::new();
    groups
        .try_reserve(ordered_seeds.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let mut current_rank = None;
    let mut count = 0_usize;
    let mut same_family_count = 0_usize;
    for seed in ordered_seeds {
        if current_rank.is_some_and(|rank| rank != seed.relative_start) {
            if let Some(relative_start) = current_rank {
                groups.push(SeedRankGroup {
                    relative_start,
                    count,
                    same_family_count,
                    header_pair_count: 0,
                });
            }
            count = 0;
            same_family_count = 0;
        }
        current_rank = Some(seed.relative_start);
        count = count.saturating_add(1);
        let same_family_payload = payload_families
            .binary_search_by(|family| {
                family
                    .relative_start
                    .cmp(&seed.relative_start)
                    .then_with(|| family.selector.cmp(seed.selector))
            })
            .ok()
            .and_then(|index| payload_families.get(index));
        if same_family_payload.is_some() {
            same_family_count = same_family_count.saturating_add(1);
        }
    }
    if let Some(relative_start) = current_rank {
        groups.push(SeedRankGroup {
            relative_start,
            count,
            same_family_count,
            header_pair_count: 0,
        });
    }
    Ok(groups)
}

fn count_specific_header_pairs(
    seed_groups: &mut [SeedRankGroup],
    seed_header_groups: &[SeedHeaderGroup],
    payload_groups: &[PayloadRankGroup],
    payload_header_groups: &[PayloadHeaderGroup],
) {
    for seed_group in seed_groups {
        let Some(payload_group_index) = payload_groups
            .binary_search_by_key(&seed_group.relative_start, |group| group.relative_start)
            .ok()
        else {
            continue;
        };
        let Some(payload_group) = payload_groups.get(payload_group_index) else {
            continue;
        };
        let relative_pair_count = seed_group
            .count
            .saturating_mul(payload_group.end - payload_group.start)
            .saturating_sub(seed_group.same_family_count);
        let mut header_group_index = seed_header_groups
            .partition_point(|group| group.relative_start < seed_group.relative_start);
        while let Some(seed_header_group) = seed_header_groups.get(header_group_index)
            && seed_header_group.relative_start == seed_group.relative_start
        {
            header_group_index = header_group_index.saturating_add(1);
            let Some(payload_header_group_index) = payload_header_groups
                .binary_search_by_key(
                    &(
                        seed_header_group.relative_start,
                        seed_header_group.header_start,
                    ),
                    |group| (group.relative_start, group.header_start),
                )
                .ok()
            else {
                continue;
            };
            let Some(payload_header_group) = payload_header_groups.get(payload_header_group_index)
            else {
                continue;
            };
            let header_pair_count = seed_header_group
                .count
                .saturating_mul(payload_header_group.end - payload_header_group.start)
                .saturating_sub(seed_header_group.same_family_count);
            if header_pair_count > 0 && header_pair_count < relative_pair_count {
                seed_group.header_pair_count = seed_group
                    .header_pair_count
                    .saturating_add(header_pair_count);
            }
        }
    }
}

fn seed_header_groups(
    seeds: &[RankedLocatorFamily<'_>],
    payload_families: &[PayloadFamilyIndex<'_>],
) -> Result<Vec<SeedHeaderGroup>, RelationalTransformError> {
    let mut ordered_seeds = Vec::new();
    ordered_seeds
        .try_reserve_exact(seeds.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    ordered_seeds.extend_from_slice(seeds);
    ordered_seeds.sort_unstable_by_key(|seed| (seed.relative_start, seed.header_start));

    let mut groups = Vec::new();
    groups
        .try_reserve(ordered_seeds.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let mut current_key = None;
    let mut count = 0_usize;
    let mut same_family_count = 0_usize;
    for seed in ordered_seeds {
        let key = (seed.relative_start, seed.header_start);
        if current_key.is_some_and(|current| current != key) {
            if let Some((relative_start, header_start)) = current_key {
                groups.push(SeedHeaderGroup {
                    relative_start,
                    header_start,
                    count,
                    same_family_count,
                });
            }
            count = 0;
            same_family_count = 0;
        }
        current_key = Some(key);
        count = count.saturating_add(1);
        if payload_families
            .binary_search_by(|family| {
                family
                    .relative_start
                    .cmp(&seed.relative_start)
                    .then_with(|| family.selector.cmp(seed.selector))
            })
            .is_ok()
        {
            same_family_count = same_family_count.saturating_add(1);
        }
    }
    if let Some((relative_start, header_start)) = current_key {
        groups.push(SeedHeaderGroup {
            relative_start,
            header_start,
            count,
            same_family_count,
        });
    }
    Ok(groups)
}

impl RankedPairStream {
    fn new(
        domain: &PairDomain<'_>,
        kind: PairStreamKind,
    ) -> Result<Self, RelationalTransformError> {
        let mut rows = Vec::new();
        rows.try_reserve_exact(domain.seeds.len())
            .map_err(|_| RelationalTransformError::AllocationFailed)?;
        let mut pending = BinaryHeap::new();
        pending
            .try_reserve(domain.seeds.len())
            .map_err(|_| RelationalTransformError::AllocationFailed)?;

        for (seed_index, seed) in domain.seeds.iter().enumerate() {
            let row = PairStreamRow {
                payload_group: domain.payload_group(seed.relative_start),
                header_group: domain.specific_header_group(seed.relative_start, seed.header_start),
                same_family_payload: domain.same_family_payload(seed.relative_start, seed.selector),
            };
            let Some(payload_order_index) = domain.next_payload_order(row, kind, 0) else {
                continue;
            };
            let Some(payload) = domain.payloads.get(payload_order_index) else {
                continue;
            };
            let row_index = rows.len();
            rows.push(row);
            pending.push(Reverse(RankedPairEntry {
                cue_rank: pair_stream_cue_rank(domain, kind, seed_index),
                pair_rank: seed_index.saturating_add(payload.candidate_index),
                seed_index,
                payload_index: payload.candidate_index,
                row_index,
                payload_order_index,
            }));
        }

        Ok(Self {
            kind,
            rows,
            pending,
        })
    }

    fn next(&mut self, domain: &PairDomain<'_>) -> Option<(usize, usize)> {
        let Reverse(entry) = self.pending.pop()?;
        let row = *self.rows.get(entry.row_index)?;
        let next_cursor = entry.payload_order_index.saturating_add(1);
        if let Some(next_order_index) = domain.next_payload_order(row, self.kind, next_cursor)
            && let Some(next_payload) = domain.payloads.get(next_order_index)
        {
            self.pending.push(Reverse(RankedPairEntry {
                cue_rank: pair_stream_cue_rank(domain, self.kind, entry.seed_index),
                pair_rank: entry
                    .seed_index
                    .saturating_add(next_payload.candidate_index),
                seed_index: entry.seed_index,
                payload_index: next_payload.candidate_index,
                row_index: entry.row_index,
                payload_order_index: next_order_index,
            }));
        }
        Some((entry.seed_index, entry.payload_index))
    }
}

fn pair_stream_cue_rank(domain: &PairDomain<'_>, kind: PairStreamKind, seed_index: usize) -> usize {
    match kind {
        PairStreamKind::HeaderAligned => domain.seeds.get(seed_index).map_or(usize::MAX, |seed| {
            domain.header_aligned_pair_count(seed.relative_start, seed.header_start)
        }),
        PairStreamKind::Fallback => 0,
        PairStreamKind::Aligned => domain.seeds.get(seed_index).map_or(usize::MAX, |seed| {
            domain.aligned_pair_count(seed.relative_start)
        }),
    }
}

impl<'a> LocatorPairSchedule<'a> {
    fn new(
        seed_candidates: &'a [LocatorCandidate],
        payload_candidates: &'a [LocatorCandidate],
    ) -> Result<Self, RelationalTransformError> {
        let domain = PairDomain::new(seed_candidates, payload_candidates)?;
        let header_aligned = RankedPairStream::new(&domain, PairStreamKind::HeaderAligned)?;
        let aligned = RankedPairStream::new(&domain, PairStreamKind::Aligned)?;
        let fallback = RankedPairStream::new(&domain, PairStreamKind::Fallback)?;
        let initial_pair_count = seed_candidates
            .len()
            .saturating_mul(payload_candidates.len())
            .min(INITIAL_RANK_ORDERED_PAIR_WINDOW);
        Ok(Self {
            domain,
            header_aligned,
            aligned,
            fallback,
            initial_pair_count,
            initial_pair_cursor: 0,
            stream_cursor: 0,
        })
    }

    fn next(&mut self) -> Option<(usize, usize)> {
        if self.initial_pair_cursor < self.initial_pair_count {
            let payload_count = self.domain.payloads.len();
            let seed_index = self.initial_pair_cursor / payload_count;
            let payload_index = self.initial_pair_cursor % payload_count;
            self.initial_pair_cursor += 1;
            return Some((seed_index, payload_index));
        }
        loop {
            let pair = self.next_stream_pair()?;
            if !self.is_in_initial_window(pair) {
                return Some(pair);
            }
        }
    }

    fn next_stream_pair(&mut self) -> Option<(usize, usize)> {
        for _ in 0..PAIR_STREAM_ROTATION.len() {
            let stream = self.stream_cursor;
            self.stream_cursor = (self.stream_cursor + 1) % PAIR_STREAM_ROTATION.len();
            let pair = match PAIR_STREAM_ROTATION.get(stream)? {
                PairStreamKind::HeaderAligned => self.header_aligned.next(&self.domain),
                PairStreamKind::Aligned => self.aligned.next(&self.domain),
                PairStreamKind::Fallback => self.fallback.next(&self.domain),
            };
            if pair.is_some() {
                return pair;
            }
        }
        None
    }

    const fn is_in_initial_window(&self, (seed_index, payload_index): (usize, usize)) -> bool {
        let payload_count = self.domain.payloads.len();
        if payload_count == 0 {
            return false;
        }
        let full_rows = self.initial_pair_count / payload_count;
        let partial_row_length = self.initial_pair_count % payload_count;
        seed_index < full_rows || (seed_index == full_rows && payload_index < partial_row_length)
    }
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
        let mut pair_schedule = LocatorPairSchedule::new(
            &self.prepared.seed_locators,
            &self.prepared.payload_locators,
        )
        .map_err(RelationalEvaluationError::Search)?;
        while let Some((seed_index, payload_index)) = pair_schedule.next() {
            let (Some(seed_locator), Some(payload_locator)) = (
                self.prepared.seed_locators.get(seed_index),
                self.prepared.payload_locators.get(payload_index),
            ) else {
                continue;
            };
            let overlaps = locator_ranges_overlap(
                self.samples,
                &self.prepared.discovery_indexes,
                &seed_locator.selector,
                &payload_locator.selector,
                &seed_locator.locator,
                &payload_locator.locator,
            );
            if overlaps {
                continue;
            }
            if !self.search_locator_pair(search, seed_locator, payload_locator, evaluator)? {
                return Ok(());
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
        let discovery_unresolved_on_budget =
            discovery_evaluation.fit.status == RelationalFitStatus::UnresolvedOnBudget;
        if discovery_evaluation.fit.supported_sessions.is_empty() {
            if discovery_evaluation.fit.status == RelationalFitStatus::Contradicted
                && let Some(job) = self.job
            {
                job.increment(Counter::CandidatesRejected, 1)
                    .map_err(RelationalTransformError::from)?;
            }
            if discovery_unresolved_on_budget
                || search.work_bytes == self.plan.limits.max_work_bytes
            {
                stop_for_work_limit(search, true)?;
            }
            if search.work_bytes == self.plan.limits.max_work_bytes {
                return Ok(false);
            }
            return Ok(true);
        }
        if discovery_unresolved_on_budget {
            search.stop(RelationalSearchLimit::WorkBytes);
            search.omitted_candidates_exact = false;
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
        if heldout.status == RelationalFitStatus::UnresolvedOnBudget {
            search.stop(RelationalSearchLimit::WorkBytes);
            search.omitted_candidates_exact = false;
        }
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
    if matches!(
        status,
        RelationalTransformStatus::ContradictedByHeldoutSession
            | RelationalTransformStatus::DiscoveryContradicted
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
