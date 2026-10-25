//! Bounded TCP payload sequence ranges with source observations and unresolved overlaps
//!
//! This maps captured bytes to an explicit modular sequence range. It does not
//! identify a connection generation or model what an endpoint accepted

mod model;
mod spans;

pub use model::{Observation, RangeReport, Segment, Span, SpanStatus};
use std::{error::Error, fmt};

/// Largest one-sided TCP sequence range that avoids modular-distance ambiguity
pub const MAX_RANGE_BYTES: usize = 0x7fff_ffff;
pub const MAX_SEGMENT_BYTES: usize = 65_535;
pub const MAX_OBSERVATIONS: usize = 1_024;
pub const MAX_RETAINED_BYTES: usize = 4 * 1024 * 1024;

/// A checked range or source-location error, before any observation is retained
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangeError(&'static str);

impl fmt::Display for RangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for RangeError {}

/// Retained source bytes are canonical; coverage and conflict spans are derived once
pub struct TcpRange {
    start_sequence: u32,
    length: usize,
    observations: Vec<Observation>,
    // Cache the byte total so each quota check stays constant-time
    retained_bytes: usize,
    omitted_observations: u64,
    // Only omission locations survive when the byte observation itself cannot fit
    omitted_coverage: Vec<bool>,
    max_observations: usize,
    max_retained_bytes: usize,
}

impl TcpRange {
    /// Select one bounded payload sequence interval, allowing a single modular wrap
    ///
    /// # Errors
    /// Rejects zero length and ranges that cross TCP's half-sequence-space boundary
    pub fn new(start_sequence: u32, length: usize) -> Result<Self, RangeError> {
        Self::new_with_limits(start_sequence, length, MAX_OBSERVATIONS, MAX_RETAINED_BYTES)
    }

    /// Select one modular range with caller-configured source-observation quotas
    ///
    /// # Errors
    /// Rejects non-representable ranges, zero budgets, or checked allocation failures
    pub fn new_with_limits(
        start_sequence: u32,
        length: usize,
        max_observations: usize,
        max_retained_bytes: usize,
    ) -> Result<Self, RangeError> {
        if !(1..=MAX_RANGE_BYTES).contains(&length) {
            return Err(RangeError(
                "TCP range length must be below half the sequence space",
            ));
        }
        if max_observations == 0 || max_retained_bytes == 0 {
            return Err(RangeError("TCP observation budgets must be positive"));
        }
        let mut omitted_coverage = Vec::new();
        omitted_coverage
            .try_reserve_exact(length)
            .map_err(|_| RangeError("TCP range omission map allocation failed"))?;
        omitted_coverage.resize(length, false);
        Ok(Self {
            start_sequence,
            length,
            observations: Vec::new(),
            retained_bytes: 0,
            omitted_observations: 0,
            omitted_coverage,
            max_observations,
            max_retained_bytes,
        })
    }

    /// Retain the intersecting payload or literal SYN/FIN/RST control observation
    ///
    /// Returns true only when an observation was retained. Outside payloads and
    /// bare acknowledgements need no retained record. Any actual quota omission
    /// freezes further retention, while its affected positions remain visible
    ///
    /// # Errors
    /// Rejects overlong segments or overflowing source-frame locations
    pub fn observe(&mut self, segment: Segment<'_>) -> Result<bool, RangeError> {
        if segment.payload.len() > MAX_SEGMENT_BYTES {
            return Err(RangeError("TCP segment payload exceeds 65535 bytes"));
        }
        segment
            .payload_frame_offset
            .checked_add(segment.payload.len())
            .ok_or(RangeError("TCP payload frame range overflows"))?;
        let data_sequence = segment
            .sequence
            .wrapping_add(u32::from(segment.flags & 0x02 != 0));
        let (range_offset, skip, length) = self.intersection(data_sequence, segment.payload.len());
        // FIN, SYN, and RST are the three low control bits
        let has_control = segment.flags.trailing_zeros() < 3;
        if length == 0 && !has_control {
            return Ok(false);
        }
        if self.omitted_observations != 0
            || self.observations.len() >= self.max_observations
            || length > self.max_retained_bytes - self.retained_bytes
        {
            self.omitted_observations += 1;
            for omitted in self
                .omitted_coverage
                .iter_mut()
                .skip(range_offset)
                .take(length)
            {
                *omitted = true;
            }
            return Ok(false);
        }
        // The intersection already bounds skip and length inside the source payload
        let bytes = segment
            .payload
            .iter()
            .skip(skip)
            .take(length)
            .copied()
            .collect();
        self.observations.push(Observation {
            packet_index: segment.packet_index,
            sequence: segment.sequence,
            flags: segment.flags,
            payload_frame_offset: segment.payload_frame_offset + skip,
            range_offset,
            bytes,
        });
        self.retained_bytes += length;
        Ok(true)
    }

    fn intersection(&self, sequence: u32, payload_length: usize) -> (usize, usize, usize) {
        // Both intervals are much shorter than half the sequence space
        let forward = sequence.wrapping_sub(self.start_sequence);
        let behind = self.start_sequence.wrapping_sub(sequence);
        if let Ok(offset) = usize::try_from(forward)
            && offset < self.length
        {
            return (offset, 0, payload_length.min(self.length - offset));
        }
        if let Ok(skip) = usize::try_from(behind)
            && skip < payload_length
        {
            return (0, skip, self.length.min(payload_length - skip));
        }
        (0, 0, 0)
    }

    /// Finish a value-consistency report without choosing among conflicting packets
    #[must_use]
    pub fn finish(self) -> RangeReport {
        spans::finish(
            self.start_sequence,
            self.length,
            self.observations,
            self.omitted_observations,
            &self.omitted_coverage,
        )
    }
}
