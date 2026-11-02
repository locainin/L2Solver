//! Validation for mapping, function, and trace evidence used by code links

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    endpoint::{TraceCorrelation, TraceIoEvent, TraceIoReport, TracePacketRange},
    evidence::SourceRange,
};

use super::super::{
    AnalysisFunction, ArtifactReport, MAX_R2_FUNCTION_BYTES, MAX_R2_FUNCTIONS, inspect,
};
use super::model::{CodeLinkError, CodeLinkLimits, RuntimeModuleMap, RuntimeModuleMapping};

pub(super) const fn validate_limits(limits: CodeLinkLimits) -> Result<(), CodeLinkError> {
    if limits.max_mappings == 0 || limits.max_links == 0 {
        return Err(CodeLinkError::InvalidLimits);
    }
    Ok(())
}

pub(super) fn validate_sha256(value: &str, field: &'static str) -> Result<(), CodeLinkError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CodeLinkError::InvalidHash { field });
    }
    Ok(())
}

pub(super) struct ValidatedRuntimeRange {
    pub(super) mapping: RuntimeModuleMapping,
    pub(super) index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum IndexedRangeMatch {
    Missing,
    Unique(usize),
    Ambiguous,
}

struct RangeSegment {
    start: u64,
    end: u64,
    matched: IndexedRangeMatch,
}

struct RangeBoundary {
    position: u64,
    range_index: usize,
    starts: bool,
}

/// Partition valid ranges into non-overlapping spans for binary-search lookups
pub(super) struct RangeLookupIndex {
    segments: Vec<RangeSegment>,
}

impl RangeLookupIndex {
    /// Build disjoint lookup spans while retaining the original range positions
    pub(super) fn from_ranges(ranges: impl IntoIterator<Item = (u64, u64, usize)>) -> Self {
        let mut boundaries = Vec::new();
        for (start, end, range_index) in ranges {
            boundaries.push(RangeBoundary {
                position: start,
                range_index,
                starts: true,
            });
            boundaries.push(RangeBoundary {
                position: end,
                range_index,
                starts: false,
            });
        }
        // End boundaries sort before starts at a shared half-open edge
        boundaries.sort_unstable_by_key(|boundary| (boundary.position, boundary.starts));

        let mut segments: Vec<RangeSegment> =
            Vec::with_capacity(boundaries.len().saturating_sub(1));
        let mut active = BTreeSet::new();
        let mut boundary_index = 0;
        while let Some(boundary) = boundaries.get(boundary_index) {
            let position = boundary.position;
            // Apply every change at this address before describing the next span
            while boundaries
                .get(boundary_index)
                .is_some_and(|candidate| candidate.position == position)
            {
                let Some(candidate) = boundaries.get(boundary_index) else {
                    break;
                };
                if candidate.starts {
                    active.insert(candidate.range_index);
                } else {
                    active.remove(&candidate.range_index);
                }
                boundary_index += 1;
            }

            let Some(next_boundary) = boundaries.get(boundary_index) else {
                break;
            };
            if position < next_boundary.position {
                let matched = match (active.iter().next(), active.iter().nth(1)) {
                    (None, _) => IndexedRangeMatch::Missing,
                    (Some(index), None) => IndexedRangeMatch::Unique(*index),
                    (Some(_), Some(_)) => IndexedRangeMatch::Ambiguous,
                };
                // Merge equal neighboring results to keep binary search compact
                if let Some(previous) = segments.last_mut()
                    && previous.end == position
                    && previous.matched == matched
                {
                    previous.end = next_boundary.position;
                } else {
                    segments.push(RangeSegment {
                        start: position,
                        end: next_boundary.position,
                        matched,
                    });
                }
            }
        }
        Self { segments }
    }

    pub(super) fn lookup(&self, address: u64) -> IndexedRangeMatch {
        // Locate the last span that starts no later than the requested address
        let partition = self
            .segments
            .partition_point(|segment| segment.start <= address);
        let Some(segment) = partition
            .checked_sub(1)
            .and_then(|index| self.segments.get(index))
        else {
            return IndexedRangeMatch::Missing;
        };
        if address < segment.end {
            segment.matched
        } else {
            IndexedRangeMatch::Missing
        }
    }
}

pub(super) fn validate_mappings(
    mapping: &RuntimeModuleMap,
    limits: CodeLinkLimits,
    binary_length: Option<usize>,
) -> Result<Vec<ValidatedRuntimeRange>, CodeLinkError> {
    if mapping.mappings.is_empty() {
        return Err(CodeLinkError::EmptyMappingDocument);
    }
    if mapping.mappings.len() > limits.max_mappings {
        return Err(CodeLinkError::LimitExceeded {
            field: "mappings",
            maximum: limits.max_mappings,
        });
    }
    mapping
        .mappings
        .iter()
        .copied()
        .enumerate()
        .map(|(index, range)| {
            let Some(length) = range.runtime_end.checked_sub(range.runtime_start) else {
                return Err(CodeLinkError::InvalidMapping { index });
            };
            if length == 0 {
                return Err(CodeLinkError::InvalidMapping { index });
            }
            let Some(file_end) = range.file_offset.checked_add(length) else {
                return Err(CodeLinkError::InvalidMapping { index });
            };
            let (Ok(_), Ok(_)) = (
                usize::try_from(range.file_offset),
                usize::try_from(file_end),
            ) else {
                return Err(CodeLinkError::InvalidMapping { index });
            };
            if binary_length
                .is_some_and(|length| usize::try_from(file_end).is_ok_and(|end| end > length))
            {
                return Err(CodeLinkError::InvalidMapping { index });
            }
            Ok(ValidatedRuntimeRange {
                mapping: range,
                index,
            })
        })
        .collect()
}

pub(super) struct ValidatedFunction<'a> {
    pub(super) function: &'a AnalysisFunction,
    pub(super) file_end: usize,
}

pub(super) struct IndexedTraceEvent<'event, 'correlation> {
    pub(super) event: &'event TraceIoEvent,
    pub(super) correlation: Option<&'correlation TraceCorrelation>,
}

pub(super) fn validate_functions<'a>(
    functions: &'a [AnalysisFunction],
    binary_source: Option<&[u8]>,
) -> Result<Vec<ValidatedFunction<'a>>, CodeLinkError> {
    if functions.len() > MAX_R2_FUNCTIONS {
        return Err(CodeLinkError::LimitExceeded {
            field: "static functions",
            maximum: MAX_R2_FUNCTIONS,
        });
    }
    let binary_report = binary_source
        .map(inspect)
        .transpose()
        .map_err(CodeLinkError::Artifact)?;
    functions
        .iter()
        .enumerate()
        .map(|(index, function)| {
            validate_function(function, index, binary_source, binary_report.as_ref())
        })
        .collect()
}

fn validate_function<'a>(
    function: &'a AnalysisFunction,
    index: usize,
    binary_source: Option<&[u8]>,
    binary_report: Option<&ArtifactReport>,
) -> Result<ValidatedFunction<'a>, CodeLinkError> {
    let invalid = || CodeLinkError::InvalidFunction { index };
    if function.name.is_empty()
        || function.code_length == 0
        || function.code_length > MAX_R2_FUNCTION_BYTES
        || function.code_length.checked_mul(2) != Some(function.code_bytes_hex.len())
        || function.code_sha256.len() != 64
        || !function
            .code_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    let code = decode_hex(&function.code_bytes_hex).ok_or_else(invalid)?;
    if !crate::sha256(&code).eq_ignore_ascii_case(&function.code_sha256) {
        return Err(invalid());
    }
    let file_end = function
        .file_offset
        .checked_add(function.code_length)
        .ok_or_else(invalid)?;
    function
        .address
        .checked_add(u64::try_from(function.code_length).map_err(|_| invalid())?)
        .ok_or_else(invalid)?;
    if let Some(bytes) = binary_source
        && (file_end > bytes.len()
            || bytes.get(function.file_offset..file_end) != Some(code.as_slice()))
    {
        return Err(invalid());
    }
    if let Some(report) = binary_report {
        let mapped = report
            .executable_file_offset_for_address(function.address, function.code_length)
            .map_err(CodeLinkError::Artifact)?;
        if mapped != function.file_offset {
            return Err(invalid());
        }
    }
    Ok(ValidatedFunction { function, file_end })
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[high, low]| {
            Some(crate::hex::decode_nibble(high)? * 16 + crate::hex::decode_nibble(low)?)
        })
        .collect()
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct SourceKey {
    source: String,
    packet: Option<u64>,
    offset: u64,
    length: u64,
}

impl From<&SourceRange> for SourceKey {
    fn from(range: &SourceRange) -> Self {
        Self {
            source: range.source.clone(),
            packet: range.packet,
            offset: range.offset,
            length: range.length,
        }
    }
}

pub(super) fn index_correlations<'a>(
    trace: &'a TraceIoReport,
    correlations: &'a [TraceCorrelation],
) -> Result<Vec<IndexedTraceEvent<'a, 'a>>, CodeLinkError> {
    let mut events = BTreeMap::new();
    // Validate each event range once and keep its original position
    for (index, event) in trace.events.iter().enumerate() {
        validate_trace_range(
            &event.source_range,
            &trace.source_sha256,
            trace.source_length,
        )?;
        if events
            .insert(SourceKey::from(&event.source_range), index)
            .is_some()
        {
            return Err(CodeLinkError::DuplicateTraceEvent);
        }
    }
    let mut indexed = vec![None; trace.events.len()];
    for correlation in correlations {
        let key = SourceKey::from(&correlation.trace_source_range);
        let Some(&event_index) = events.get(&key) else {
            return Err(CodeLinkError::CorrelationWithoutEvent);
        };
        let Some(event_correlation) = indexed.get_mut(event_index) else {
            return Err(CodeLinkError::CorrelationWithoutEvent);
        };
        if event_correlation.replace(correlation).is_some() {
            return Err(CodeLinkError::DuplicateTraceCorrelation);
        }
    }
    Ok(trace
        .events
        .iter()
        .zip(indexed)
        .map(|(event, correlation)| IndexedTraceEvent { event, correlation })
        .collect())
}

pub(super) fn validate_trace_range(
    range: &SourceRange,
    expected_source: &str,
    source_length: u64,
) -> Result<(), CodeLinkError> {
    let Some(end) = range.offset.checked_add(range.length) else {
        return Err(CodeLinkError::InvalidTraceRange);
    };
    if range.source != expected_source || range.length == 0 || end > source_length {
        return Err(CodeLinkError::InvalidTraceRange);
    }
    Ok(())
}

pub(super) fn validate_packet_ranges(ranges: &[TracePacketRange]) -> Result<(), CodeLinkError> {
    for range in ranges {
        if range.source.is_empty()
            || range.packet == 0
            || range.length == 0
            || range.offset.checked_add(range.length).is_none()
        {
            return Err(CodeLinkError::InvalidTraceRange);
        }
    }
    Ok(())
}
