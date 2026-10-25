use serde::Serialize;

/// Borrowed TCP payload and its exact source location, already bounded by the caller
#[derive(Clone, Copy, Debug)]
pub struct Segment<'a> {
    pub packet_index: u32,
    pub payload_frame_offset: usize,
    pub sequence: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

/// One clipped source observation; repeated packets remain independently addressable
#[derive(Debug, Serialize)]
pub struct Observation {
    pub packet_index: u32,
    pub sequence: u32,
    pub flags: u8,
    /// Zero-based offset of these bytes in the original captured frame
    pub payload_frame_offset: usize,
    /// Zero-based offset inside the requested payload sequence range
    pub range_offset: usize,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanStatus {
    /// At least one retained value, with no disagreement among retained observations
    Observed,
    Conflict,
    /// No retained value; omitted observations may still cover this position
    Gap,
}

/// Adjacent positions with the same value status and omission coverage
#[derive(Debug, Serialize)]
pub struct Span {
    pub offset: usize,
    pub length: usize,
    pub status: SpanStatus,
    pub omitted_observation: bool,
    /// Only unambiguous retained values are rendered as bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<Vec<u8>>,
}

#[derive(Debug, Serialize)]
pub struct RangeReport {
    pub start_sequence: u32,
    pub length: usize,
    pub observed_bytes: usize,
    pub missing_bytes: usize,
    pub conflicting_bytes: usize,
    pub omitted_bytes: usize,
    pub omitted_observations: u64,
    pub observations: Vec<Observation>,
    pub spans: Vec<Span>,
}

impl RangeReport {
    /// Every requested position has one retained value and no relevant record was omitted
    ///
    /// This does not establish TCP connection identity, validity, or endpoint acceptance
    #[must_use]
    pub const fn has_unique_coverage(&self) -> bool {
        self.missing_bytes == 0 && self.conflicting_bytes == 0 && self.omitted_observations == 0
    }
}
