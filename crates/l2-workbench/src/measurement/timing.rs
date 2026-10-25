use super::{MAX_SAMPLES, MeasurementError};
use serde::Serialize;

const MAX_CLOCK_ID_BYTES: usize = 128;
const MAX_SCOPE_ID_BYTES: usize = 256;
const MAX_CLOCK_EXPONENT: u8 = 127;
const TIMING_LIMITATION: &str = "Only adjacent exact ticks sharing one supplied scope and clock identity are compared; no clock synchronization or wall-clock estimate is inferred";

/// Exact timebase facts supplied with a packet series
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Clock {
    /// Caller-supplied clock identity, such as a source and capture clock label
    pub id: String,
    /// Caller-supplied interface or capture scope
    pub scope: String,
    /// Timestamp radix, either decimal 10 or binary 2
    pub radix: u8,
    /// Power of the radix that defines one source tick
    pub exponent: u8,
    /// Exact source-provided offset in seconds
    pub offset_seconds: i64,
}

impl Clock {
    /// Construct a clock after checking its identity and source resolution
    ///
    /// # Errors
    /// Returns an error for an empty or oversized identity, unsupported radix,
    /// oversized exponent, or control characters
    pub fn new(
        id: impl Into<String>,
        scope: impl Into<String>,
        radix: u8,
        exponent: u8,
        offset_seconds: i64,
    ) -> Result<Self, MeasurementError> {
        let clock = Self {
            id: id.into(),
            scope: scope.into(),
            radix,
            exponent,
            offset_seconds,
        };
        clock.validate()?;
        Ok(clock)
    }

    fn validate(&self) -> Result<(), MeasurementError> {
        if self.id.is_empty()
            || self.id.len() > MAX_CLOCK_ID_BYTES
            || self.id.chars().any(char::is_control)
            || self.scope.is_empty()
            || self.scope.len() > MAX_SCOPE_ID_BYTES
            || self.scope.chars().any(char::is_control)
            || !matches!(self.radix, 2 | 10)
            || self.exponent > MAX_CLOCK_EXPONENT
        {
            return Err(MeasurementError::InvalidClock);
        }
        Ok(())
    }

    fn same_timebase(&self, other: &Self) -> bool {
        self.id == other.id
            && self.radix == other.radix
            && self.exponent == other.exponent
            && self.offset_seconds == other.offset_seconds
    }
}

/// One packet's exact source tick value, or an explicit missing timestamp
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TimedSample {
    /// One-based packet index in the input capture
    pub packet: u64,
    /// Clock identity and resolution that applied to this sample
    pub clock: Clock,
    /// Exact unsigned source tick count, if present
    pub ticks: Option<u64>,
}

/// Outcome for one adjacent packet pair
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntervalStatus {
    /// Both samples share one exact clock and ticks move forward or stay equal
    Measured,
    /// Either sample lacks a source timestamp
    MissingTimestamp,
    /// The next source tick count is less than the preceding value
    Backwards,
    /// Adjacent samples have different capture scopes
    ScopeMismatch,
    /// Adjacent samples do not share an exact clock identity and resolution
    ClockMismatch,
}

/// One adjacent packet interval with no cross-clock conversion
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TimingInterval {
    /// Earlier packet in supplied order
    pub from_packet: u64,
    /// Later packet in supplied order
    pub to_packet: u64,
    /// Why a tick delta is available or withheld
    pub status: IntervalStatus,
    /// Nonnegative difference in the source's exact tick units
    pub delta_ticks: Option<u64>,
}

/// Exact per-series timing measurements and the limits on comparison
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TimingReport {
    /// Number of ordered packet samples supplied
    pub sample_count: usize,
    /// True only when all samples share one scope and exact clock definition
    pub comparable: bool,
    /// Number of samples without timestamps
    pub missing_samples: usize,
    /// Adjacent pairs with a backward tick sequence
    pub backwards_intervals: usize,
    /// Adjacent pairs with different capture scopes
    pub scope_mismatches: usize,
    /// Adjacent pairs with the same scope but different clock definitions
    pub clock_mismatches: usize,
    /// Adjacent intervals in supplied packet order
    pub intervals: Vec<TimingInterval>,
    /// Limits on interpreting the measured tick differences
    pub limitations: Vec<&'static str>,
}

/// Measure adjacent packet timestamps only within the same exact scope and clock
///
/// Ticks remain in source units. The function does not sort packets, normalize
/// clocks, or invent values for missing or backward timestamps
///
/// # Errors
/// Returns an error for an empty or oversized series, invalid clocks, or packet
/// indices that are not strictly increasing and nonzero
pub fn measure_timing(samples: &[TimedSample]) -> Result<TimingReport, MeasurementError> {
    if samples.is_empty() || samples.len() > MAX_SAMPLES {
        return Err(MeasurementError::InvalidTimingSeries);
    }
    for sample in samples {
        if sample.packet == 0 {
            return Err(MeasurementError::InvalidPacketOrder);
        }
        sample.clock.validate()?;
    }
    if samples.windows(2).any(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_some_and(|(first, second)| first.packet >= second.packet)
    }) {
        return Err(MeasurementError::InvalidPacketOrder);
    }
    let first = samples
        .first()
        .ok_or(MeasurementError::InvalidTimingSeries)?;
    let comparable = samples.iter().all(|sample| {
        sample.clock.scope == first.clock.scope && sample.clock.same_timebase(&first.clock)
    });
    let missing_samples = samples
        .iter()
        .filter(|sample| sample.ticks.is_none())
        .count();
    let mut intervals = Vec::with_capacity(samples.windows(2).count());
    let mut backwards_intervals = 0_usize;
    let mut scope_mismatches = 0_usize;
    let mut clock_mismatches = 0_usize;
    for pair in samples.windows(2) {
        let earlier = pair.first().ok_or(MeasurementError::InvalidTimingSeries)?;
        let later = pair.get(1).ok_or(MeasurementError::InvalidTimingSeries)?;
        let (status, delta_ticks) = if earlier.clock.scope != later.clock.scope {
            scope_mismatches += 1;
            (IntervalStatus::ScopeMismatch, None)
        } else if !earlier.clock.same_timebase(&later.clock) {
            clock_mismatches += 1;
            (IntervalStatus::ClockMismatch, None)
        } else if let (Some(start), Some(end)) = (earlier.ticks, later.ticks) {
            if end < start {
                backwards_intervals += 1;
                (IntervalStatus::Backwards, None)
            } else {
                (IntervalStatus::Measured, Some(end - start))
            }
        } else {
            (IntervalStatus::MissingTimestamp, None)
        };
        intervals.push(TimingInterval {
            from_packet: earlier.packet,
            to_packet: later.packet,
            status,
            delta_ticks,
        });
    }
    Ok(TimingReport {
        sample_count: samples.len(),
        comparable,
        missing_samples,
        backwards_intervals,
        scope_mismatches,
        clock_mismatches,
        intervals,
        limitations: vec![TIMING_LIMITATION],
    })
}
