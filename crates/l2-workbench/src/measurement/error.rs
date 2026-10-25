use core::fmt;

/// A bounded carrier measurement or candidate evaluation failure
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MeasurementError {
    /// A required measurement sample set is empty or too small
    InsufficientSamples { count: usize, minimum: usize },
    /// A sample request exceeded the hard sample count limit
    TooManySamples { count: usize, maximum: usize },
    /// One message exceeded its byte limit
    SampleTooLarge { length: usize, maximum: usize },
    /// A sample set exceeded its aggregate byte limit
    TotalBytesExceeded { length: usize, maximum: usize },
    /// Message sample identifiers were zero or repeated
    InvalidSampleId,
    /// A length-field test needs varying message lengths
    ConstantSampleLengths,
    /// An explicit prefix width is outside the supported bound
    InvalidPrefixWidth { width: usize, maximum: usize },
    /// A prefix baseline sample is too short for the requested width
    PrefixBaselineTooShort,
    /// A timing series is empty or exceeds its sample limit
    InvalidTimingSeries,
    /// Timing samples are not in strict packet order
    InvalidPacketOrder,
    /// A timing clock has an invalid name, scope, radix, or exponent
    InvalidClock,
}

impl fmt::Display for MeasurementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSamples { count, minimum } => write!(
                formatter,
                "measurement has {count} samples; at least {minimum} are required"
            ),
            Self::TooManySamples { count, maximum } => {
                write!(
                    formatter,
                    "measurement has {count} samples; maximum is {maximum}"
                )
            }
            Self::SampleTooLarge { length, maximum } => {
                write!(formatter, "sample has {length} bytes; maximum is {maximum}")
            }
            Self::TotalBytesExceeded { length, maximum } => {
                write!(
                    formatter,
                    "samples contain {length} bytes; maximum is {maximum}"
                )
            }
            Self::InvalidSampleId => {
                formatter.write_str("measurement sample identifiers must be unique and nonzero")
            }
            Self::ConstantSampleLengths => {
                formatter.write_str("length-field testing requires varying message lengths")
            }
            Self::InvalidPrefixWidth { width, maximum } => {
                write!(
                    formatter,
                    "prefix width {width} must be from 1 through {maximum}"
                )
            }
            Self::PrefixBaselineTooShort => {
                formatter.write_str("first discovery sample is shorter than the prefix width")
            }
            Self::InvalidTimingSeries => {
                formatter.write_str("timing series is empty or exceeds its sample bound")
            }
            Self::InvalidPacketOrder => {
                formatter.write_str("timing samples must use strictly increasing packet indices")
            }
            Self::InvalidClock => {
                formatter.write_str("invalid timing clock identity or resolution")
            }
        }
    }
}

impl std::error::Error for MeasurementError {}
