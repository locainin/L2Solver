//! Bounded selection of byte ranges for the canonical syntax proposer
//!
//! Explicit protocol or format cues and maximal encoding runs select complete regions
//! The existing proposer checks each selected region, and the derivation engine executes
//! a Slice followed by the selected operation against the original immutable input

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    derivation::Operation,
    protocol::ByteRange,
    recovery::proposals::{
        TransformProposal, TransformProposalBudget, TransformProposalReport, propose_transforms,
        transform_proposal_scan_work_bound,
    },
};

/// Maximum distinct ranges syntax-checked for one input under shared default recovery policy
pub const DEFAULT_MAX_TRANSFORM_REGIONS_PER_INPUT: usize = 16;

/// Maximum work and retained bytes for bounded region discovery
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformRegionLimits {
    /// Maximum source bytes examined by automatic cue discovery
    pub max_scan_bytes: usize,
    /// Maximum explicit caller cues accepted for examination
    pub max_cues: usize,
    /// Maximum distinct ranges retained for syntax assessment
    pub max_regions: usize,
    /// Maximum length of one syntax-assessed region
    pub max_region_bytes: usize,
    /// Maximum aggregate region bytes syntax-assessed in one pass
    pub max_total_region_bytes: usize,
}

impl TransformRegionLimits {
    /// Build the shared recovery policy for a source with a known maximum input size
    #[must_use]
    pub const fn for_input(maximum_input_bytes: usize) -> Self {
        Self {
            max_scan_bytes: maximum_input_bytes,
            max_cues: 0,
            max_regions: DEFAULT_MAX_TRANSFORM_REGIONS_PER_INPUT,
            max_region_bytes: maximum_input_bytes,
            max_total_region_bytes: maximum_input_bytes,
        }
    }
}

/// One exact range supplied by an existing protocol or artifact cue
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegionCue {
    /// Half-open range in the unchanged source buffer
    pub range: ByteRange,
    /// Existing observation that selected this range
    pub origin: RegionCueOrigin,
}

/// Stable reference to the existing observation that selected a region
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RegionCueOrigin {
    /// Framing inference selected a message range
    MessageFrame {
        /// Zero-based message index in the framing report
        message_index: usize,
        /// Zero-based frame index within that message
        frame_index: usize,
    },
    /// Repeated-region observation selected a cohort range
    RepeatedObservation {
        /// Index in the paired observation report's region list
        region_index: usize,
    },
    /// Retained byte window that supports one per-sample length constraint
    LengthObservation {
        /// Index in the observation report's constraint list
        constraint_index: usize,
        /// Index in the same report's retained byte observations
        byte_observation_index: usize,
    },
    /// Repeated record-boundary inference selected a record range
    RecordBoundary {
        /// Zero-based message index in the repeated-boundary report
        message_index: usize,
    },
    /// Existing signature or offset analysis selected an exact range
    RecognizedOffset {
        /// Index in the existing signature catalogue or offset report
        signature_index: usize,
    },
    /// A maximal token made only from canonical encoding alphabet bytes
    EncodingRun,
    /// Two occurrences of the same delimiter selected the bytes between them
    RepeatedDelimiter {
        /// Delimiter byte observed in the source
        delimiter: u8,
        /// Offset of the delimiter before the selected range
        preceding_offset: usize,
        /// Offset of the delimiter after the selected range
        following_offset: usize,
    },
}

/// One bounded region and the syntax decisions scoped to its exact range
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransformRegion {
    /// Half-open range in the original source buffer
    pub range: ByteRange,
    /// Existing protocol, signature, or lexical cues supporting this range
    pub cue_origins: Vec<RegionCueOrigin>,
    /// Syntax assessments and Slice-prefixed recipes scoped to this region
    pub proposal_report: TransformProposalReport,
}

/// Counts for work or candidate regions omitted by caller-selected limits
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransformRegionOmissions {
    /// Source bytes beyond the automatic cue scan limit
    pub scan_bytes: usize,
    /// Explicit cues omitted by the cue limit
    pub cues: usize,
    /// Invalid or out-of-bounds explicit cues
    pub invalid_cues: usize,
    /// Distinct candidate ranges omitted by the region limit
    pub regions: usize,
    /// Candidate bytes omitted by per-region or aggregate byte limits
    pub region_bytes: usize,
    /// Open encoding or delimiter regions that reached the scan boundary
    pub incomplete_regions: usize,
}

/// Region scan coverage and explicit omissions
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransformRegionCoverage {
    /// Number of source bytes examined by automatic cue discovery
    pub examined_bytes: usize,
    /// True only when all input bytes and retained explicit cues were examined
    pub complete: bool,
    /// Candidate work omitted by the configured limits
    pub omissions: TransformRegionOmissions,
}

/// Deterministic region proposals and the limits that narrowed their negative scope
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransformRegionReport {
    /// Distinct retained ranges in ascending source-offset order
    pub regions: Vec<TransformRegion>,
    /// Automatic scan coverage and counts for every omitted candidate
    pub coverage: TransformRegionCoverage,
}

/// Reserve work for cue discovery and all maximum-size region syntax passes
#[must_use]
pub fn transform_region_scan_work_bound(limits: TransformRegionLimits) -> Option<usize> {
    let operation_work = limits
        .max_total_region_bytes
        .checked_mul(crate::recovery::proposals::TRANSFORM_PROPOSAL_OPERATION_COUNT)?;
    let report_work = limits.max_regions.checked_mul(6)?;
    let region_work = operation_work.checked_add(report_work)?;
    limits
        .max_scan_bytes
        .checked_mul(2)
        .and_then(|scan_work| scan_work.checked_add(limits.max_cues))
        .and_then(|work| work.checked_add(region_work))
}

/// Reserve work for the existing whole-input pass and one bounded region pass
#[must_use]
pub fn transform_discovery_scan_work_bound(input_length: usize) -> Option<usize> {
    transform_proposal_scan_work_bound(input_length)?.checked_add(transform_region_scan_work_bound(
        TransformRegionLimits::for_input(input_length),
    )?)
}

/// Discover bounded regions and run the canonical syntax proposer on each complete range
///
/// Automatic cues are maximal runs of Base64 alphabet bytes and adjacent intervals between
/// repeated delimiters. Caller cues can retain frame, observation, record, or signature origins.
/// Repeated exact ranges share one report and retain every independent cue origin.
///
/// The proposer sees only the complete bytes in each range. It does not trim padding, repair
/// syntax, or search the interior for smaller substrings. Every retained recipe starts with an
/// exact Slice operation over the original input.
#[must_use]
pub fn propose_region_transforms(
    input: &[u8],
    explicit_cues: &[RegionCue],
    limits: TransformRegionLimits,
    proposal_budget: TransformProposalBudget,
) -> TransformRegionReport {
    let mut omissions = TransformRegionOmissions::default();
    let mut candidates = BTreeMap::<ByteRange, Vec<RegionCueOrigin>>::new();

    let cue_count = explicit_cues.len().min(limits.max_cues);
    omissions.cues = explicit_cues.len().saturating_sub(cue_count);
    for cue in explicit_cues.iter().take(cue_count) {
        if !valid_range(cue.range, input.len()) {
            omissions.invalid_cues = omissions.invalid_cues.saturating_add(1);
            continue;
        }
        add_candidate(
            &mut candidates,
            cue.range,
            cue.origin.clone(),
            limits.max_regions,
            &mut omissions,
        );
    }

    let scan_length = input.len().min(limits.max_scan_bytes);
    omissions.scan_bytes = input.len().saturating_sub(scan_length);
    omissions.incomplete_regions = scan_automatic_cues(
        input,
        scan_length,
        limits.max_regions,
        &mut candidates,
        &mut omissions,
    );

    let mut retained_bytes = 0_usize;
    let mut regions = Vec::new();
    for (range, cue_origins) in candidates {
        let length = range.end - range.start;
        if length > limits.max_region_bytes {
            omissions.region_bytes = omissions.region_bytes.saturating_add(length);
            continue;
        }
        let Some(next_total) = retained_bytes.checked_add(length) else {
            omissions.region_bytes = omissions.region_bytes.saturating_add(length);
            continue;
        };
        if next_total > limits.max_total_region_bytes {
            omissions.region_bytes = omissions.region_bytes.saturating_add(length);
            continue;
        }
        retained_bytes = next_total;

        let Some(region_bytes) = input.get(range.start..range.end) else {
            omissions.invalid_cues = omissions.invalid_cues.saturating_add(1);
            continue;
        };
        let mut proposal_report = propose_transforms(region_bytes, proposal_budget);
        prefix_slice(&mut proposal_report.proposals, range);
        regions.push(TransformRegion {
            range,
            cue_origins,
            proposal_report,
        });
    }

    let complete = omissions == TransformRegionOmissions::default();
    TransformRegionReport {
        regions,
        coverage: TransformRegionCoverage {
            examined_bytes: scan_length,
            complete,
            omissions,
        },
    }
}

const fn valid_range(range: ByteRange, input_length: usize) -> bool {
    range.start < range.end && range.end <= input_length
}

fn add_candidate(
    candidates: &mut BTreeMap<ByteRange, Vec<RegionCueOrigin>>,
    range: ByteRange,
    origin: RegionCueOrigin,
    maximum: usize,
    omissions: &mut TransformRegionOmissions,
) {
    if let Some(origins) = candidates.get_mut(&range) {
        if !origins.contains(&origin) {
            origins.push(origin);
        }
        return;
    }
    if candidates.len() >= maximum {
        omissions.regions = omissions.regions.saturating_add(1);
        return;
    }
    candidates.insert(range, vec![origin]);
}

fn scan_automatic_cues(
    input: &[u8],
    scan_length: usize,
    maximum_regions: usize,
    candidates: &mut BTreeMap<ByteRange, Vec<RegionCueOrigin>>,
    omissions: &mut TransformRegionOmissions,
) -> usize {
    let mut open_encoding_run = None;
    let mut delimiter_offsets: [Option<usize>; DELIMITERS.len()] = [None; DELIMITERS.len()];
    let mut incomplete_regions = 0_usize;

    for (offset, byte) in input.iter().copied().take(scan_length).enumerate() {
        if is_encoding_byte(byte) {
            open_encoding_run.get_or_insert(offset);
        } else if let Some(start) = open_encoding_run.take() {
            let range = ByteRange { start, end: offset };
            if range.start != 0 || range.end != input.len() {
                add_candidate(
                    candidates,
                    range,
                    RegionCueOrigin::EncodingRun,
                    maximum_regions,
                    omissions,
                );
            }
        }

        if let Some(delimiter_index) = delimiter_index(byte) {
            let previous = delimiter_offsets.get(delimiter_index).copied().flatten();
            if let Some(previous) = previous {
                let range = ByteRange {
                    start: previous + 1,
                    end: offset,
                };
                if range.start < range.end {
                    add_candidate(
                        candidates,
                        range,
                        RegionCueOrigin::RepeatedDelimiter {
                            delimiter: byte,
                            preceding_offset: previous,
                            following_offset: offset,
                        },
                        maximum_regions,
                        omissions,
                    );
                }
            }
            if let Some(previous_offset) = delimiter_offsets.get_mut(delimiter_index) {
                *previous_offset = Some(offset);
            }
        }
    }

    if let Some(start) = open_encoding_run {
        if scan_length == input.len() {
            if start != 0 || scan_length != input.len() {
                add_candidate(
                    candidates,
                    ByteRange {
                        start,
                        end: scan_length,
                    },
                    RegionCueOrigin::EncodingRun,
                    maximum_regions,
                    omissions,
                );
            }
        } else {
            incomplete_regions = incomplete_regions.saturating_add(1);
        }
    }
    if scan_length < input.len()
        && input
            .get(scan_length)
            .copied()
            .and_then(delimiter_index)
            .is_some_and(|index| delimiter_offsets.get(index).is_some_and(Option::is_some))
    {
        incomplete_regions = incomplete_regions.saturating_add(1);
    }
    incomplete_regions
}

fn prefix_slice(proposals: &mut [TransformProposal], range: ByteRange) {
    for proposal in proposals {
        proposal.recipe.steps.insert(
            0,
            Operation::Slice {
                start: range.start,
                length: Some(range.end - range.start),
            },
        );
    }
}

const fn is_encoding_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
}

const DELIMITERS: [u8; 7] = [b':', b'|', b';', b',', b'\n', b'\r', b'\t'];

const fn delimiter_index(byte: u8) -> Option<usize> {
    match byte {
        b':' => Some(0),
        b'|' => Some(1),
        b';' => Some(2),
        b',' => Some(3),
        b'\n' => Some(4),
        b'\r' => Some(5),
        b'\t' => Some(6),
        _ => None,
    }
}
