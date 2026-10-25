use serde::Serialize;
use std::collections::HashSet;

use super::{
    BoundaryExtractionReport, BoundaryStatus, ByteRunSample, FramingKind, HoldoutBasis,
    MessageRole, MessageSample, ProtocolError, ProtocolLimits,
    boundaries::{extract_boundaries_with_statuses, inferred_hypotheses, validate_run_fields},
    sampling::{SampleSplit, split_indices, validate_limits},
};

const LIMITATIONS: [&str; 4] = [
    "Bootstrap hypotheses interpret supplied contiguous runs and do not establish a protocol grammar",
    "Fixed-size hypotheses tile every discovery run into at least two frames and may fit coincidental bytes",
    "Contextual discovery and holdout sets contain complete source, scope, and session groups",
    "Retained ranges, candidate hypotheses, and inferred prefix offsets remain subject to the supplied budgets",
];
const NO_INDEPENDENT_HOLDOUT: &str = "No independent holdout run group was available; hypotheses remain discovery-only and unresolved on separate runs";
const HYPOTHESIS_REPORT_SHARE_DIVISOR: usize = 4;

/// Evidence basis available for validating bootstrap hypotheses
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FramingValidationBasis {
    /// No independent run or complete session group was available for holdout
    DiscoveryOnly,
    /// At least one run group was held out from candidate generation
    HeldOutRuns,
}

/// Materialized boundary interpretations for one bootstrapped byte run
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FramingBootstrapRunReport {
    /// Per-hypothesis ranges, aliases, and any incomplete or invalid suffix
    pub boundaries: BoundaryExtractionReport,
    /// Candidate kinds omitted while this discovery run contributed hypotheses
    /// This is `None` for held-out runs, which do not contribute hypotheses
    pub candidate_generation_omissions: Option<usize>,
}

/// Framing hypotheses inferred from contiguous runs and checked across held-out runs
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FramingBootstrapReport {
    /// Deterministically ordered unique hypothesis preview retained from discovery runs
    pub hypotheses: Vec<FramingKind>,
    /// Materialized hypotheses applied to runs used for candidate generation
    pub discovery: Vec<FramingBootstrapRunReport>,
    /// Materialized hypotheses applied to runs kept out of candidate generation
    pub holdout: Vec<FramingBootstrapRunReport>,
    /// Run identifiers used to generate candidate hypotheses
    pub discovery_samples: Vec<u64>,
    /// Run identifiers held out from candidate generation
    pub holdout_samples: Vec<u64>,
    /// Basis used to separate discovery from holdout
    pub split_basis: HoldoutBasis,
    /// Whether independent held-out runs were available for checking hypotheses
    pub validation_basis: FramingValidationBasis,
    /// Candidate derivation slots omitted across discovery runs
    pub omitted_candidates: usize,
    /// Candidate hypotheses omitted from the retained hypothesis preview
    pub omitted_hypothesis_details: usize,
    /// Candidate boundary details omitted across materialized runs
    pub omitted_candidate_details: usize,
    /// Alias candidate references omitted across materialized runs
    pub omitted_alias_candidates: usize,
    /// Inclusive maximum offset searched for inferred length fields
    pub prefix_offset_limit: usize,
    /// Whether every candidate in the configured search plan was evaluated
    pub search_exhaustive_within_plan: bool,
    /// Whether all hypothesis, candidate, frame, and alias details were retained
    pub report_details_complete: bool,
    /// Limits on interpreting inferred ranges as a protocol grammar
    pub limitations: Vec<&'static str>,
}

/// Full framing hypotheses evaluated by one bootstrap analysis
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FramingBootstrapExecutionPlan {
    /// Deterministically ordered hypotheses materialized against every discovery and holdout run
    /// Search omissions are described by the paired report's `search_exhaustive_within_plan` field
    pub hypotheses: Vec<FramingKind>,
    /// Hypotheses that produced only complete boundaries on every available run
    /// This list is computed before bounded report details are retained
    pub surviving_hypotheses: Vec<FramingKind>,
}

/// In-memory execution plan paired with its bounded report
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FramingBootstrapExecution {
    /// Full typed plan used to evaluate the supplied runs
    pub execution_plan: FramingBootstrapExecutionPlan,
    /// Bounded evidence preview and explicit omission counts
    pub report: FramingBootstrapReport,
}

/// Infer framing candidates from contiguous runs and materialize them on discovery and holdout runs
///
/// Contextual inputs are split by complete source, scope, and session groups. Inputs
/// without context are split in supplied order. When no independent holdout group
/// exists, all runs remain in discovery and the report marks validation as unresolved
/// Each evaluated hypothesis is materialized on every available run
///
/// # Errors
/// Returns an error when input is empty or run identities, contexts, or selected budgets are invalid
pub fn bootstrap_framing_with_limits(
    runs: &[ByteRunSample<'_>],
    limits: ProtocolLimits,
) -> Result<FramingBootstrapReport, ProtocolError> {
    bootstrap_framing_with_execution_plan(runs, limits).map(|result| result.report)
}

/// Infer framing candidates and retain the complete evaluated plan beside its bounded report
///
/// The execution plan contains every unique hypothesis generated within the configured candidate
/// limit. Each plan hypothesis is applied to every available run, even when report budgets omit
/// hypothesis previews or candidate details. The paired report records search omissions so a
/// truncated search is not mistaken for an exhaustive one
///
/// # Errors
/// Returns an error when input is empty or run identities, contexts, or selected budgets are invalid
pub fn bootstrap_framing_with_execution_plan(
    runs: &[ByteRunSample<'_>],
    limits: ProtocolLimits,
) -> Result<FramingBootstrapExecution, ProtocolError> {
    let contextual = validate_runs(runs, limits)?;
    let samples = split_samples(runs)?;
    let (split, validation_basis) = split_runs(&samples, contextual)?;
    let plan = prepare_hypotheses(runs, &split.discovery, limits)?;
    let (mut survives, mut statuses) = evaluation_buffers(plan.hypotheses.len(), limits)?;
    let discovery = materialize_runs(
        runs,
        &split.discovery,
        &plan.hypotheses,
        plan.per_run_limits,
        Some(&plan.discovery_omissions),
        &mut survives,
        &mut statuses,
    )?;
    let holdout = materialize_runs(
        runs,
        &split.holdout,
        &plan.hypotheses,
        plan.per_run_limits,
        None,
        &mut survives,
        &mut statuses,
    )?;
    let surviving_hypotheses = retained_survivors(&plan.hypotheses, &survives)?;

    let omitted_candidates = discovery
        .iter()
        .filter_map(|run| run.candidate_generation_omissions)
        .try_fold(0_usize, usize::checked_add)
        .ok_or(ProtocolError::InvalidLimits)?;
    let detail_summary = summarize_detail_omissions(&discovery, &holdout)?;
    let search_exhaustive_within_plan = omitted_candidates == 0;
    let report_details_complete = plan.omitted_hypothesis_details == 0 && detail_summary.complete;

    let additional_limitations =
        usize::from(validation_basis == FramingValidationBasis::DiscoveryOnly);
    let limitation_count = LIMITATIONS
        .len()
        .checked_add(additional_limitations)
        .ok_or(ProtocolError::InvalidLimits)?;
    let mut limitations = Vec::new();
    limitations
        .try_reserve_exact(limitation_count)
        .map_err(|_| ProtocolError::AllocationFailed)?;
    limitations.extend_from_slice(&LIMITATIONS);
    if validation_basis == FramingValidationBasis::DiscoveryOnly {
        limitations.push(NO_INDEPENDENT_HOLDOUT);
    }

    Ok(FramingBootstrapExecution {
        execution_plan: FramingBootstrapExecutionPlan {
            hypotheses: plan.hypotheses,
            surviving_hypotheses,
        },
        report: FramingBootstrapReport {
            hypotheses: plan.report_hypotheses,
            discovery,
            holdout,
            discovery_samples: sample_ids(runs, &split.discovery)?,
            holdout_samples: sample_ids(runs, &split.holdout)?,
            split_basis: split.basis,
            validation_basis,
            omitted_candidates,
            omitted_hypothesis_details: plan.omitted_hypothesis_details,
            omitted_candidate_details: detail_summary.omitted_candidate_details,
            omitted_alias_candidates: detail_summary.omitted_alias_candidates,
            prefix_offset_limit: limits.max_prefix_offset,
            search_exhaustive_within_plan,
            report_details_complete,
            limitations,
        },
    })
}

struct HypothesisPlan {
    hypotheses: Vec<FramingKind>,
    report_hypotheses: Vec<FramingKind>,
    discovery_omissions: Vec<usize>,
    omitted_hypothesis_details: usize,
    per_run_limits: ProtocolLimits,
}

fn prepare_hypotheses(
    runs: &[ByteRunSample<'_>],
    discovery_indices: &[usize],
    limits: ProtocolLimits,
) -> Result<HypothesisPlan, ProtocolError> {
    let (mut hypotheses, mut discovery_omissions) =
        collect_hypotheses(runs, discovery_indices, limits)?;
    append_fixed_size_hypotheses(
        runs,
        discovery_indices,
        limits,
        &mut hypotheses,
        &mut discovery_omissions,
    )?;
    // Keep a small preview of the search plan while reserving most report space for run details
    let hypothesis_report_share = limits.max_report_bytes / HYPOTHESIS_REPORT_SHARE_DIVISOR;
    let retained_hypothesis_count =
        (hypothesis_report_share / std::mem::size_of::<FramingKind>()).min(hypotheses.len());
    let omitted_hypothesis_details = hypotheses
        .len()
        .checked_sub(retained_hypothesis_count)
        .ok_or(ProtocolError::InvalidLimits)?;
    let report_hypotheses = retained_hypotheses(&hypotheses, retained_hypothesis_count)?;
    let hypothesis_storage = retained_hypothesis_count
        .checked_mul(std::mem::size_of::<FramingKind>())
        .ok_or(ProtocolError::InvalidLimits)?;
    // Divide the remaining detail allowance evenly across discovery and holdout runs
    let per_run_limits = limits_for_one_report(limits, runs.len(), hypothesis_storage)?;
    Ok(HypothesisPlan {
        hypotheses,
        report_hypotheses,
        discovery_omissions,
        omitted_hypothesis_details,
        per_run_limits,
    })
}

struct DetailOmissionSummary {
    omitted_candidate_details: usize,
    omitted_alias_candidates: usize,
    complete: bool,
}

fn summarize_detail_omissions(
    discovery: &[FramingBootstrapRunReport],
    holdout: &[FramingBootstrapRunReport],
) -> Result<DetailOmissionSummary, ProtocolError> {
    let mut summary = DetailOmissionSummary {
        omitted_candidate_details: 0,
        omitted_alias_candidates: 0,
        complete: true,
    };
    for run in discovery.iter().chain(holdout) {
        summary.omitted_candidate_details = summary
            .omitted_candidate_details
            .checked_add(run.boundaries.omitted_candidate_details)
            .ok_or(ProtocolError::InvalidLimits)?;
        summary.omitted_alias_candidates = summary
            .omitted_alias_candidates
            .checked_add(run.boundaries.omitted_alias_candidates)
            .ok_or(ProtocolError::InvalidLimits)?;
        summary.complete &= run.boundaries.report_details_complete;
    }
    Ok(summary)
}

fn append_fixed_size_hypotheses(
    runs: &[ByteRunSample<'_>],
    discovery_indices: &[usize],
    limits: ProtocolLimits,
    hypotheses: &mut Vec<FramingKind>,
    omissions: &mut [usize],
) -> Result<(), ProtocolError> {
    let Some(first_index) = discovery_indices.first().copied() else {
        return Ok(());
    };
    let first_run = runs
        .get(first_index)
        .ok_or(ProtocolError::InsufficientRuns { count: runs.len() })?;
    let mut sizes = fixed_size_divisors(first_run.bytes.len(), limits.max_message_bytes)?;
    for index in discovery_indices.iter().copied().skip(1) {
        let run = runs
            .get(index)
            .ok_or(ProtocolError::InsufficientRuns { count: runs.len() })?;
        sizes.retain(|size| run.bytes.len() / 2 >= *size && run.bytes.len().is_multiple_of(*size));
    }

    let mut seen = HashSet::new();
    seen.try_reserve(hypotheses.len())
        .map_err(|_| ProtocolError::AllocationFailed)?;
    seen.extend(hypotheses.iter().map(FramingKindKey::from));
    let first_omission_slot = omissions
        .get_mut(first_index)
        .ok_or(ProtocolError::InsufficientRuns { count: runs.len() })?;
    for size in sizes {
        let kind = FramingKind::FixedSize { bytes: size };
        let key = FramingKindKey::from(&kind);
        if seen.contains(&key) {
            continue;
        }
        if hypotheses.len() == limits.max_candidates {
            *first_omission_slot = first_omission_slot
                .checked_add(1)
                .ok_or(ProtocolError::InvalidLimits)?;
            continue;
        }
        hypotheses
            .try_reserve(1)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        seen.try_reserve(1)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        seen.insert(key);
        hypotheses.push(kind);
    }
    Ok(())
}

fn fixed_size_divisors(
    run_length: usize,
    maximum_message_bytes: usize,
) -> Result<Vec<usize>, ProtocolError> {
    let mut sizes = Vec::new();
    let mut divisor = 1_usize;
    while divisor <= run_length / divisor {
        if run_length.is_multiple_of(divisor) {
            let paired = run_length / divisor;
            if divisor <= maximum_message_bytes && paired >= 2 {
                sizes
                    .try_reserve(1)
                    .map_err(|_| ProtocolError::AllocationFailed)?;
                sizes.push(divisor);
            }
            if paired <= maximum_message_bytes && divisor >= 2 {
                sizes
                    .try_reserve(1)
                    .map_err(|_| ProtocolError::AllocationFailed)?;
                sizes.push(paired);
            }
        }
        divisor = divisor.checked_add(1).ok_or(ProtocolError::InvalidLimits)?;
    }
    sizes.sort_unstable();
    sizes.dedup();
    Ok(sizes)
}

fn collect_hypotheses(
    runs: &[ByteRunSample<'_>],
    discovery_indices: &[usize],
    limits: ProtocolLimits,
) -> Result<(Vec<FramingKind>, Vec<usize>), ProtocolError> {
    let mut hypotheses = Vec::new();
    let mut seen = HashSet::new();
    let mut omissions = Vec::new();
    omissions
        .try_reserve_exact(runs.len())
        .map_err(|_| ProtocolError::AllocationFailed)?;
    omissions.resize(runs.len(), 0);
    for index in discovery_indices {
        let run = runs
            .get(*index)
            .ok_or(ProtocolError::InsufficientRuns { count: runs.len() })?;
        let (inferred, inferred_omissions) =
            inferred_hypotheses(run.bytes, limits.max_prefix_offset, limits.max_candidates)?;
        let mut omitted_for_run = inferred_omissions;

        for candidate in inferred {
            let key = FramingKindKey::from(&candidate);
            if seen.contains(&key) {
                continue;
            }
            if hypotheses.len() == limits.max_candidates {
                omitted_for_run = omitted_for_run
                    .checked_add(1)
                    .ok_or(ProtocolError::InvalidLimits)?;
            } else {
                hypotheses
                    .try_reserve(1)
                    .map_err(|_| ProtocolError::AllocationFailed)?;
                seen.try_reserve(1)
                    .map_err(|_| ProtocolError::AllocationFailed)?;
                seen.insert(key);
                hypotheses.push(candidate);
            }
        }
        let slot = omissions
            .get_mut(*index)
            .ok_or(ProtocolError::InsufficientRuns { count: runs.len() })?;
        *slot = omitted_for_run;
    }

    if hypotheses.is_empty() {
        return Err(ProtocolError::NoFramingCandidates);
    }
    Ok((hypotheses, omissions))
}

fn materialize_runs(
    runs: &[ByteRunSample<'_>],
    indices: &[usize],
    hypotheses: &[FramingKind],
    limits: ProtocolLimits,
    omissions: Option<&[usize]>,
    survives: &mut [bool],
    statuses: &mut [BoundaryStatus],
) -> Result<Vec<FramingBootstrapRunReport>, ProtocolError> {
    if survives.len() != hypotheses.len() || statuses.len() != hypotheses.len() {
        return Err(ProtocolError::InvalidLimits);
    }
    let mut reports = Vec::new();
    reports
        .try_reserve_exact(indices.len())
        .map_err(|_| ProtocolError::AllocationFailed)?;
    for index in indices {
        let run = runs
            .get(*index)
            .ok_or(ProtocolError::InsufficientRuns { count: runs.len() })?;
        let boundaries = extract_boundaries_with_statuses(run, hypotheses, limits, Some(statuses))?;
        for (survives, status) in survives.iter_mut().zip(statuses.iter()) {
            *survives &= *status == BoundaryStatus::Complete;
        }
        let candidate_generation_omissions = omissions
            .map(|values| {
                values
                    .get(*index)
                    .copied()
                    .ok_or(ProtocolError::InsufficientRuns { count: runs.len() })
            })
            .transpose()?;
        reports.push(FramingBootstrapRunReport {
            boundaries,
            candidate_generation_omissions,
        });
    }
    Ok(reports)
}

fn evaluation_buffers(
    candidate_count: usize,
    limits: ProtocolLimits,
) -> Result<(Vec<bool>, Vec<BoundaryStatus>), ProtocolError> {
    if candidate_count > limits.max_candidates {
        return Err(ProtocolError::TooManyCandidates {
            count: candidate_count,
            maximum: limits.max_candidates,
        });
    }
    let mut survives = Vec::new();
    survives
        .try_reserve_exact(candidate_count)
        .map_err(|_| ProtocolError::AllocationFailed)?;
    survives.resize(candidate_count, true);
    let mut statuses = Vec::new();
    statuses
        .try_reserve_exact(candidate_count)
        .map_err(|_| ProtocolError::AllocationFailed)?;
    statuses.resize(candidate_count, BoundaryStatus::InvalidCandidate);
    Ok((survives, statuses))
}

fn retained_survivors(
    hypotheses: &[FramingKind],
    survives: &[bool],
) -> Result<Vec<FramingKind>, ProtocolError> {
    if hypotheses.len() != survives.len() {
        return Err(ProtocolError::InvalidLimits);
    }
    let survivor_count = survives
        .iter()
        .filter(|survives| **survives)
        .try_fold(0_usize, |count, _| {
            count.checked_add(1).ok_or(ProtocolError::InvalidLimits)
        })?;
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(survivor_count)
        .map_err(|_| ProtocolError::AllocationFailed)?;
    retained.extend(
        hypotheses
            .iter()
            .zip(survives)
            .filter(|(_, survives)| **survives)
            .map(|(hypothesis, _)| hypothesis.clone()),
    );
    Ok(retained)
}

fn validate_runs(
    runs: &[ByteRunSample<'_>],
    limits: ProtocolLimits,
) -> Result<bool, ProtocolError> {
    validate_limits(limits)?;
    if runs.is_empty() {
        return Err(ProtocolError::InsufficientRuns { count: runs.len() });
    }
    if runs.len() > limits.max_samples {
        return Err(ProtocolError::TooManySamples {
            count: runs.len(),
            maximum: limits.max_samples,
        });
    }

    let contextual = runs.iter().any(|run| run.context.is_some());
    let mut identifiers = HashSet::new();
    identifiers
        .try_reserve(runs.len())
        .map_err(|_| ProtocolError::AllocationFailed)?;
    let mut total_bytes = 0_usize;
    for run in runs {
        validate_run_fields(run, limits)?;
        if !identifiers.insert(run.sample) {
            return Err(ProtocolError::InvalidSampleId { sample: run.sample });
        }
        total_bytes =
            total_bytes
                .checked_add(run.bytes.len())
                .ok_or(ProtocolError::TotalBytesTooLarge {
                    total: usize::MAX,
                    maximum: limits.max_total_bytes,
                })?;
        if total_bytes > limits.max_total_bytes {
            return Err(ProtocolError::TotalBytesTooLarge {
                total: total_bytes,
                maximum: limits.max_total_bytes,
            });
        }

        if contextual && run.context.is_none() {
            return Err(ProtocolError::IncompleteContext { sample: run.sample });
        }
    }
    Ok(contextual)
}

fn split_runs(
    samples: &[MessageSample<'_>],
    contextual: bool,
) -> Result<(SampleSplit, FramingValidationBasis), ProtocolError> {
    if !contextual && samples.len() == 1 {
        return Ok((
            discovery_only_split(samples.len(), HoldoutBasis::SampleOrder)?,
            FramingValidationBasis::DiscoveryOnly,
        ));
    }

    match split_indices(samples, contextual) {
        Ok(split) => Ok((split, FramingValidationBasis::HeldOutRuns)),
        Err(ProtocolError::InsufficientSessionGroups { count }) if contextual && count == 1 => {
            Ok((
                discovery_only_split(samples.len(), HoldoutBasis::CompleteSessions)?,
                FramingValidationBasis::DiscoveryOnly,
            ))
        }
        Err(error) => Err(error),
    }
}

fn discovery_only_split(
    sample_count: usize,
    basis: HoldoutBasis,
) -> Result<SampleSplit, ProtocolError> {
    let mut discovery = Vec::new();
    discovery
        .try_reserve_exact(sample_count)
        .map_err(|_| ProtocolError::AllocationFailed)?;
    discovery.extend(0..sample_count);
    Ok(SampleSplit {
        discovery,
        holdout: Vec::new(),
        basis,
    })
}

fn split_samples<'a>(runs: &[ByteRunSample<'a>]) -> Result<Vec<MessageSample<'a>>, ProtocolError> {
    let mut samples = Vec::new();
    samples
        .try_reserve_exact(runs.len())
        .map_err(|_| ProtocolError::AllocationFailed)?;
    for run in runs {
        samples.push(MessageSample {
            sample: run.sample,
            role: MessageRole::Unclassified,
            bytes: run.bytes,
            context: run.context.clone(),
        });
    }
    Ok(samples)
}

fn sample_ids(runs: &[ByteRunSample<'_>], indices: &[usize]) -> Result<Vec<u64>, ProtocolError> {
    let mut samples = Vec::new();
    samples
        .try_reserve_exact(indices.len())
        .map_err(|_| ProtocolError::AllocationFailed)?;
    for index in indices {
        let run = runs
            .get(*index)
            .ok_or(ProtocolError::InsufficientRuns { count: runs.len() })?;
        samples.push(run.sample);
    }
    Ok(samples)
}

fn retained_hypotheses(
    hypotheses: &[FramingKind],
    retained_count: usize,
) -> Result<Vec<FramingKind>, ProtocolError> {
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(retained_count)
        .map_err(|_| ProtocolError::AllocationFailed)?;
    retained.extend(hypotheses.iter().take(retained_count).cloned());
    Ok(retained)
}

fn limits_for_one_report(
    mut limits: ProtocolLimits,
    run_count: usize,
    hypothesis_storage: usize,
) -> Result<ProtocolLimits, ProtocolError> {
    let remaining_report_bytes = limits
        .max_report_bytes
        .checked_sub(hypothesis_storage)
        .ok_or(ProtocolError::InvalidLimits)?;
    let per_run_report_bytes = remaining_report_bytes
        .checked_div(run_count)
        .ok_or(ProtocolError::InvalidLimits)?;
    limits.max_report_bytes = per_run_report_bytes.max(1);
    Ok(limits)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum FramingKindKey {
    Delimiter(u8),
    FixedSize(usize),
    LengthPrefix {
        offset: usize,
        width: usize,
        byte_order: ByteOrderKey,
        meaning: LengthMeaningKey,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ByteOrderKey {
    BigEndian,
    LittleEndian,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum LengthMeaningKey {
    WholeMessage,
    BytesAfterField,
}

impl From<&FramingKind> for FramingKindKey {
    fn from(kind: &FramingKind) -> Self {
        match kind {
            FramingKind::Delimiter { byte } => Self::Delimiter(*byte),
            FramingKind::FixedSize { bytes } => Self::FixedSize(*bytes),
            FramingKind::LengthPrefix {
                offset,
                width,
                byte_order,
                meaning,
            } => Self::LengthPrefix {
                offset: *offset,
                width: *width,
                byte_order: match byte_order {
                    super::ByteOrder::BigEndian => ByteOrderKey::BigEndian,
                    super::ByteOrder::LittleEndian => ByteOrderKey::LittleEndian,
                },
                meaning: match meaning {
                    super::LengthMeaning::WholeMessage => LengthMeaningKey::WholeMessage,
                    super::LengthMeaning::BytesAfterField => LengthMeaningKey::BytesAfterField,
                },
            },
        }
    }
}
