use sha2::{Digest, Sha256};

mod next;
use super::{
    BoundaryAliasGroup, BoundaryCandidate, BoundaryExtractionReport, BoundaryStatus, ByteOrder,
    ByteRange, ByteRunSample, FramingKind, LengthMeaning, MessageContext, ProtocolError,
    ProtocolLimits, sampling::validate_limits,
};
pub(super) use next::{NextBoundary, next_boundary, next_boundary_parts};

const LIMITATIONS: [&str; 3] = [
    "Candidate partitions are interpretations of the observed run and do not establish a protocol grammar",
    "Candidates with identical observed ranges remain aliases until another run separates their predictions",
    "Inferred length prefixes use the reported inclusive offset limit and widths 1, 2, 4, and 8; other layouts remain untested",
];
const NEXT_OBSERVATION_WITH_ALIASES: &str = "Capture another contiguous run where the remaining candidate interpretations predict different boundaries";
const NEXT_OBSERVATION: &str = "Capture another contiguous run to check whether the candidate still partitions the observed bytes";

/// One complete candidate range or the remaining bytes after a rule stops
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameBoundary {
    /// A byte range selected by the caller-supplied framing rule
    Frame(ByteRange),
    /// Remaining bytes where the rule could not produce another complete range
    Tail {
        /// Exact unframed suffix
        range: ByteRange,
        /// Why the rule stopped at this suffix
        status: BoundaryStatus,
    },
}

/// Incrementally apply one explicit rule without retaining a bounded report preview
pub struct FrameBoundaryIter<'a> {
    bytes: &'a [u8],
    kind: &'a FramingKind,
    cursor: usize,
    finished: bool,
}

impl Iterator for FrameBoundaryIter<'_> {
    type Item = FrameBoundary;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished || self.cursor == self.bytes.len() {
            self.finished = true;
            return None;
        }

        let start = self.cursor;
        match next_boundary(self.bytes, start, self.kind) {
            NextBoundary::Frame(end) => {
                self.cursor = end;
                Some(FrameBoundary::Frame(ByteRange { start, end }))
            }
            NextBoundary::Incomplete => {
                self.finished = true;
                Some(FrameBoundary::Tail {
                    range: ByteRange {
                        start,
                        end: self.bytes.len(),
                    },
                    status: BoundaryStatus::IncompleteTail,
                })
            }
            NextBoundary::Invalid => {
                self.finished = true;
                Some(FrameBoundary::Tail {
                    range: ByteRange {
                        start,
                        end: self.bytes.len(),
                    },
                    status: BoundaryStatus::InvalidCandidate,
                })
            }
        }
    }
}

/// Apply an explicit framing rule lazily over a contiguous byte slice
///
/// Each complete range is yielded before a possible incomplete or invalid suffix
#[must_use]
pub const fn frame_boundaries<'a>(bytes: &'a [u8], kind: &'a FramingKind) -> FrameBoundaryIter<'a> {
    FrameBoundaryIter {
        bytes,
        kind,
        cursor: 0,
        finished: false,
    }
}

/// Apply caller-selected boundary interpretations to one contiguous run
///
/// Every returned range is tentative. An incomplete suffix is kept separate so a
/// truncated capture never becomes a claimed message boundary
///
/// # Errors
/// Returns an error when the run, hypotheses, context, or analysis budgets are invalid
pub fn extract_boundaries(
    run: &ByteRunSample<'_>,
    hypotheses: &[FramingKind],
) -> Result<BoundaryExtractionReport, ProtocolError> {
    extract_boundaries_with_limits(run, hypotheses, ProtocolLimits::default())
}

/// Apply explicit hypotheses under caller-selected checked resource budgets
///
/// # Errors
/// Returns an error when the run, hypotheses, context, or analysis budgets are invalid
pub fn extract_boundaries_with_limits(
    run: &ByteRunSample<'_>,
    hypotheses: &[FramingKind],
    limits: ProtocolLimits,
) -> Result<BoundaryExtractionReport, ProtocolError> {
    extract_boundaries_with_statuses(run, hypotheses, limits, None)
}

/// Apply hypotheses while exposing each evaluated candidate state to an internal caller
pub(super) fn extract_boundaries_with_statuses(
    run: &ByteRunSample<'_>,
    hypotheses: &[FramingKind],
    limits: ProtocolLimits,
    statuses: Option<&mut [BoundaryStatus]>,
) -> Result<BoundaryExtractionReport, ProtocolError> {
    validate_run(run, limits)?;
    if hypotheses.is_empty() {
        return Err(ProtocolError::NoFramingCandidates);
    }
    if hypotheses.len() > limits.max_candidates {
        return Err(ProtocolError::TooManyCandidates {
            count: hypotheses.len(),
            maximum: limits.max_candidates,
        });
    }
    if statuses
        .as_ref()
        .is_some_and(|values| values.len() != hypotheses.len())
    {
        return Err(ProtocolError::InvalidLimits);
    }
    let details = extract_candidates(run.bytes, hypotheses, limits, statuses)?;
    build_report(
        run.sample,
        run.context.clone(),
        details,
        0,
        limits.max_prefix_offset,
    )
}

/// Infer delimiter and length-prefix interpretations over a bounded contiguous run
///
/// # Errors
/// Returns an error when the run, context, or default analysis budgets are invalid
pub fn infer_run_boundaries(
    run: &ByteRunSample<'_>,
) -> Result<BoundaryExtractionReport, ProtocolError> {
    infer_run_boundaries_with_limits(run, ProtocolLimits::default())
}

/// Infer delimiter and length-prefix interpretations under checked resource budgets
///
/// # Errors
/// Returns an error when the run, context, or analysis budgets are invalid
pub fn infer_run_boundaries_with_limits(
    run: &ByteRunSample<'_>,
    limits: ProtocolLimits,
) -> Result<BoundaryExtractionReport, ProtocolError> {
    validate_run(run, limits)?;
    let (hypotheses, omitted_candidates) =
        inferred_hypotheses(run.bytes, limits.max_prefix_offset, limits.max_candidates)?;
    let details = extract_candidates(run.bytes, &hypotheses, limits, None)?;
    build_report(
        run.sample,
        run.context.clone(),
        details,
        omitted_candidates,
        limits.max_prefix_offset,
    )
}

pub(super) fn validate_run(
    run: &ByteRunSample<'_>,
    limits: ProtocolLimits,
) -> Result<(), ProtocolError> {
    validate_limits(limits)?;
    validate_run_fields(run, limits)
}

pub(super) fn validate_run_fields(
    run: &ByteRunSample<'_>,
    limits: ProtocolLimits,
) -> Result<(), ProtocolError> {
    if run.sample == 0 {
        return Err(ProtocolError::InvalidSampleId { sample: run.sample });
    }
    if run.bytes.len() > limits.max_run_bytes {
        return Err(ProtocolError::RunTooLarge {
            sample: run.sample,
            length: run.bytes.len(),
            maximum: limits.max_run_bytes,
        });
    }
    if run.bytes.len() > limits.max_total_bytes {
        return Err(ProtocolError::TotalBytesTooLarge {
            total: run.bytes.len(),
            maximum: limits.max_total_bytes,
        });
    }
    if run.context.as_ref().is_some_and(|context| {
        context.source.is_empty() || context.scope.is_empty() || context.session == 0
    }) {
        return Err(ProtocolError::InvalidContext { sample: run.sample });
    }
    Ok(())
}

pub(super) fn inferred_hypotheses(
    bytes: &[u8],
    max_prefix_offset: usize,
    max_candidates: usize,
) -> Result<(Vec<FramingKind>, usize), ProtocolError> {
    let mut frequencies = [0_usize; 256];
    for byte in bytes {
        if let Some(frequency) = frequencies.get_mut(usize::from(*byte)) {
            *frequency += 1;
        }
    }
    let delimiter_count = frequencies.iter().filter(|count| **count >= 2).count();
    let mut delimiters = Vec::new();
    delimiters
        .try_reserve_exact(delimiter_count)
        .map_err(|_| ProtocolError::AllocationFailed)?;
    for (byte, count) in frequencies.iter().enumerate() {
        if *count >= 2 {
            delimiters.push(FramingKind::Delimiter {
                byte: u8::try_from(byte).map_err(|_| ProtocolError::InvalidLimits)?,
            });
        }
    }
    let offset_count = max_prefix_offset
        .checked_add(1)
        .ok_or(ProtocolError::InvalidLimits)?;
    let prefix_count = offset_count
        .checked_mul(14)
        .ok_or(ProtocolError::InvalidLimits)?;
    let total_count = delimiters
        .len()
        .checked_add(prefix_count)
        .ok_or(ProtocolError::InvalidLimits)?;
    let target = total_count.min(max_candidates);
    let omitted = total_count - target;
    let mut hypotheses = Vec::new();
    hypotheses
        .try_reserve_exact(target)
        .map_err(|_| ProtocolError::AllocationFailed)?;
    hypotheses.extend(delimiters.into_iter().take(target));
    'standard_prefixes: for offset in 0..=max_prefix_offset {
        for width in [1_usize, 2, 4] {
            let byte_orders = if width == 1 {
                &[ByteOrder::BigEndian][..]
            } else {
                &[ByteOrder::BigEndian, ByteOrder::LittleEndian][..]
            };
            for byte_order in byte_orders {
                for meaning in [LengthMeaning::WholeMessage, LengthMeaning::BytesAfterField] {
                    if hypotheses.len() == target {
                        break 'standard_prefixes;
                    }
                    hypotheses.push(FramingKind::LengthPrefix {
                        offset,
                        width,
                        byte_order: *byte_order,
                        meaning,
                    });
                }
            }
        }
    }
    if hypotheses.len() < target {
        'wide_prefixes: for offset in 0..=max_prefix_offset {
            for byte_order in [ByteOrder::BigEndian, ByteOrder::LittleEndian] {
                for meaning in [LengthMeaning::WholeMessage, LengthMeaning::BytesAfterField] {
                    if hypotheses.len() == target {
                        break 'wide_prefixes;
                    }
                    hypotheses.push(FramingKind::LengthPrefix {
                        offset,
                        width: 8,
                        byte_order,
                        meaning,
                    });
                }
            }
        }
    }
    Ok((hypotheses, omitted))
}

fn extract_candidates(
    bytes: &[u8],
    hypotheses: &[FramingKind],
    limits: ProtocolLimits,
    mut statuses: Option<&mut [BoundaryStatus]>,
) -> Result<CandidateDetails, ProtocolError> {
    let mut budget = ReportBudget::new(limits.max_report_bytes);
    let mut candidates = Vec::new();
    let mut aliases = Vec::<AliasGroupWork>::new();
    let candidate_metadata_bytes = std::mem::size_of::<BoundaryCandidate>();
    let retained_candidate_count =
        (limits.max_report_bytes / candidate_metadata_bytes).min(hypotheses.len());
    let retained_metadata_bytes = retained_candidate_count
        .checked_mul(candidate_metadata_bytes)
        .ok_or(ProtocolError::InvalidLimits)?;
    // Reserve candidate records before frame previews so early ranges cannot crowd later candidates
    if !budget.try_charge(retained_metadata_bytes) {
        return Err(ProtocolError::InvalidLimits);
    }
    candidates
        .try_reserve_exact(retained_candidate_count)
        .map_err(|_| ProtocolError::AllocationFailed)?;

    for (candidate_index, kind) in hypotheses.iter().enumerate() {
        let keep_candidate = candidate_index < retained_candidate_count;
        let maximum_frames = if keep_candidate {
            limits.max_retained_frames
        } else {
            0
        };

        let (candidate, fingerprint) = extract_one(bytes, kind, maximum_frames, &mut budget)?;
        if let Some(values) = statuses.as_deref_mut() {
            *values
                .get_mut(candidate_index)
                .ok_or(ProtocolError::InvalidLimits)? = candidate.status;
        }
        if !keep_candidate {
            continue;
        }

        let candidate_index = candidates.len();
        candidates.push(candidate);
        retain_alias_membership(
            bytes,
            &candidates,
            &mut aliases,
            candidate_index,
            fingerprint,
        )?;
    }

    let (aliases, omitted_alias_candidates) = retain_alias_groups(aliases, &mut budget)?;
    Ok(CandidateDetails {
        candidates,
        aliases,
        evaluated_candidates: hypotheses.len(),
        omitted_details: hypotheses
            .len()
            .checked_sub(retained_candidate_count)
            .ok_or(ProtocolError::InvalidLimits)?,
        omitted_alias_candidates,
    })
}

fn extract_one(
    bytes: &[u8],
    kind: &FramingKind,
    maximum_frames: usize,
    budget: &mut ReportBudget,
) -> Result<(BoundaryCandidate, [u8; 32]), ProtocolError> {
    let mut result = BoundaryCandidate {
        kind: kind.clone(),
        frames: Vec::new(),
        frame_count: 0,
        omitted_frames: 0,
        trailing: None,
        status: BoundaryStatus::Complete,
        issue_offset: None,
    };
    let mut signature = Sha256::new();
    let mut cursor = 0_usize;
    while cursor < bytes.len() {
        let next = next_boundary(bytes, cursor, kind);
        match next {
            NextBoundary::Frame(end) => {
                // Keep a digest of every range, including ranges omitted from the report
                signature.update([0]);
                signature.update(cursor.to_be_bytes());
                signature.update(end.to_be_bytes());
                retain_boundary(&mut result, cursor, end, maximum_frames, budget)?;
                cursor = end;
            }
            NextBoundary::Incomplete => {
                result.status = BoundaryStatus::IncompleteTail;
                result.issue_offset = Some(cursor);
                signature.update([1]);
                signature.update(cursor.to_be_bytes());
                signature.update(bytes.len().to_be_bytes());
                result.trailing = Some(ByteRange {
                    start: cursor,
                    end: bytes.len(),
                });
                break;
            }
            NextBoundary::Invalid => {
                result.status = BoundaryStatus::InvalidCandidate;
                result.issue_offset = Some(cursor);
                signature.update([2]);
                signature.update(cursor.to_be_bytes());
                signature.update(bytes.len().to_be_bytes());
                result.trailing = Some(ByteRange {
                    start: cursor,
                    end: bytes.len(),
                });
                break;
            }
        }
    }
    signature.update([match result.status {
        BoundaryStatus::Complete => 3,
        BoundaryStatus::IncompleteTail => 4,
        BoundaryStatus::InvalidCandidate => 5,
    }]);
    signature.update(result.frame_count.to_be_bytes());
    Ok((result, signature.finalize().into()))
}

fn retain_boundary(
    result: &mut BoundaryCandidate,
    start: usize,
    end: usize,
    maximum_frames: usize,
    budget: &mut ReportBudget,
) -> Result<(), ProtocolError> {
    result.frame_count = result
        .frame_count
        .checked_add(1)
        .ok_or(ProtocolError::InvalidLimits)?;
    if result.frames.len() >= maximum_frames {
        result.omitted_frames = result
            .omitted_frames
            .checked_add(1)
            .ok_or(ProtocolError::InvalidLimits)?;
        return Ok(());
    }

    let range_bytes = std::mem::size_of::<ByteRange>();
    if !budget.try_charge(range_bytes) {
        result.omitted_frames = result
            .omitted_frames
            .checked_add(1)
            .ok_or(ProtocolError::InvalidLimits)?;
        return Ok(());
    }
    result
        .frames
        .try_reserve_exact(1)
        .map_err(|_| ProtocolError::AllocationFailed)?;
    result.frames.push(ByteRange { start, end });
    Ok(())
}

fn retain_alias_membership(
    bytes: &[u8],
    candidates: &[BoundaryCandidate],
    groups: &mut Vec<AliasGroupWork>,
    candidate_index: usize,
    fingerprint: [u8; 32],
) -> Result<(), ProtocolError> {
    let candidate = candidates
        .get(candidate_index)
        .ok_or(ProtocolError::InvalidLimits)?;
    let key = AliasKey {
        frame_count: candidate.frame_count,
        trailing: candidate.trailing,
        status: candidate.status,
        fingerprint,
    };

    // Fingerprints narrow lookup; the boundary walk confirms that retained candidates really match
    let first_equal = groups.partition_point(|group| group.key < key);
    let mut insertion_index = first_equal;
    while let Some(group) = groups.get_mut(insertion_index) {
        if group.key != key {
            break;
        }
        let representative = candidates
            .get(group.representative)
            .ok_or(ProtocolError::InvalidLimits)?;
        if same_partition(bytes, &representative.kind, &candidate.kind) {
            if let Some(members) = group.members.as_mut() {
                members
                    .try_reserve_exact(1)
                    .map_err(|_| ProtocolError::AllocationFailed)?;
                members.push(candidate_index);
            } else {
                let mut members = Vec::new();
                members
                    .try_reserve_exact(2)
                    .map_err(|_| ProtocolError::AllocationFailed)?;
                members.push(group.representative);
                members.push(candidate_index);
                group.members = Some(members);
            }
            return Ok(());
        }
        insertion_index = insertion_index
            .checked_add(1)
            .ok_or(ProtocolError::InvalidLimits)?;
    }

    groups
        .try_reserve_exact(1)
        .map_err(|_| ProtocolError::AllocationFailed)?;
    groups.insert(
        insertion_index,
        AliasGroupWork {
            key,
            representative: candidate_index,
            members: None,
        },
    );
    Ok(())
}

fn retain_alias_groups(
    groups: Vec<AliasGroupWork>,
    budget: &mut ReportBudget,
) -> Result<(Vec<BoundaryAliasGroup>, usize), ProtocolError> {
    let mut aliases = Vec::new();
    let mut omitted_alias_candidates = 0_usize;

    for group in groups {
        let Some(candidate_indices) = group.members else {
            continue;
        };
        let index_bytes = candidate_indices
            .len()
            .checked_mul(std::mem::size_of::<usize>())
            .ok_or(ProtocolError::InvalidLimits)?;
        let group_bytes = std::mem::size_of::<BoundaryAliasGroup>()
            .checked_add(index_bytes)
            .ok_or(ProtocolError::InvalidLimits)?;
        if budget.try_charge(group_bytes) {
            aliases
                .try_reserve_exact(1)
                .map_err(|_| ProtocolError::AllocationFailed)?;
            aliases.push(BoundaryAliasGroup { candidate_indices });
        } else {
            omitted_alias_candidates = omitted_alias_candidates
                .checked_add(candidate_indices.len())
                .ok_or(ProtocolError::InvalidLimits)?;
        }
    }
    Ok((aliases, omitted_alias_candidates))
}

fn build_report(
    sample: u64,
    context: Option<MessageContext>,
    details: CandidateDetails,
    omitted_candidates: usize,
    prefix_offset_limit: usize,
) -> Result<BoundaryExtractionReport, ProtocolError> {
    let report_details_complete = details.omitted_details == 0
        && details.omitted_alias_candidates == 0
        && details
            .candidates
            .iter()
            .all(|candidate| candidate.omitted_frames == 0);
    let mut limitations = Vec::new();
    // Keep the small static explanation list fallible with the rest of report construction
    limitations
        .try_reserve_exact(LIMITATIONS.len())
        .map_err(|_| ProtocolError::AllocationFailed)?;
    limitations.extend_from_slice(&LIMITATIONS);
    Ok(BoundaryExtractionReport {
        sample,
        context,
        candidates: details.candidates,
        omitted_candidates,
        evaluated_candidates: details.evaluated_candidates,
        omitted_candidate_details: details.omitted_details,
        omitted_alias_candidates: details.omitted_alias_candidates,
        prefix_offset_limit,
        search_exhaustive_within_plan: omitted_candidates == 0,
        report_details_complete,
        next_observation: if details.aliases.is_empty() && details.omitted_alias_candidates == 0 {
            NEXT_OBSERVATION
        } else {
            NEXT_OBSERVATION_WITH_ALIASES
        },
        aliases: details.aliases,
        limitations,
    })
}

struct CandidateDetails {
    candidates: Vec<BoundaryCandidate>,
    aliases: Vec<BoundaryAliasGroup>,
    evaluated_candidates: usize,
    omitted_details: usize,
    omitted_alias_candidates: usize,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AliasKey {
    frame_count: usize,
    trailing: Option<ByteRange>,
    status: BoundaryStatus,
    fingerprint: [u8; 32],
}

struct AliasGroupWork {
    key: AliasKey,
    representative: usize,
    members: Option<Vec<usize>>,
}

struct ReportBudget {
    remaining: usize,
}

impl ReportBudget {
    const fn new(maximum: usize) -> Self {
        Self { remaining: maximum }
    }

    const fn try_charge(&mut self, bytes: usize) -> bool {
        let Some(remaining) = self.remaining.checked_sub(bytes) else {
            return false;
        };
        self.remaining = remaining;
        true
    }
}

fn same_partition(bytes: &[u8], left: &FramingKind, right: &FramingKind) -> bool {
    let mut left_cursor = 0;
    let mut right_cursor = 0;
    loop {
        if left_cursor == bytes.len() || right_cursor == bytes.len() {
            return left_cursor == right_cursor;
        }
        match (
            next_boundary(bytes, left_cursor, left),
            next_boundary(bytes, right_cursor, right),
        ) {
            (NextBoundary::Frame(left_end), NextBoundary::Frame(right_end))
                if left_end == right_end =>
            {
                left_cursor = left_end;
                right_cursor = right_end;
            }
            (NextBoundary::Incomplete, NextBoundary::Incomplete)
            | (NextBoundary::Invalid, NextBoundary::Invalid) => {
                return left_cursor == right_cursor;
            }
            _ => return false,
        }
    }
}

#[cfg(test)]
#[path = "../../tests/protocol/boundary_parts.rs"]
mod boundary_parts_tests;
