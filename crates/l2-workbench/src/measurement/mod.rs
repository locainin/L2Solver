//! Bounded byte, timing, and sample-layout measurements without protocol verdicts

mod bytes;
mod error;
mod layout;
mod timing;

pub use bytes::{ByteProfile, measure_bytes};
pub use error::MeasurementError;
pub use layout::{
    ByteOrder, ConstantPrefixReport, FitSummary, LengthFieldCandidate, LengthFieldReport,
    LengthFieldResult, LengthMeaning, MAX_LAYOUT_COUNTEREXAMPLES, MAX_PREFIX_BYTES, MessageSample,
    PredictionCounterexample, PrefixFitSummary, PrefixMismatch, evaluate_constant_prefix,
    evaluate_length_fields,
};
pub use timing::{
    Clock, IntervalStatus, TimedSample, TimingInterval, TimingReport, measure_timing,
};

/// Maximum bytes in an explicit imported message sample
pub const MAX_SAMPLE_BYTES: usize = 1024 * 1024;
/// Maximum total bytes across one measurement request
pub const MAX_MEASURED_BYTES: usize = 16 * 1024 * 1024;
/// Maximum samples accepted by one measurement request
pub const MAX_SAMPLES: usize = 4_096;
