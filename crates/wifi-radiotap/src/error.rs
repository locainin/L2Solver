use core::fmt;

/// Structural radiotap decode failures
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    Truncated {
        context: &'static str,
        needed: usize,
        available: usize,
    },
    UnsupportedVersion(u8),
    InvalidHeaderLength {
        declared: usize,
        minimum: usize,
    },
    PresenceWordLimit {
        maximum: usize,
    },
    InvalidFieldLayout {
        field: u16,
    },
}

impl DecodeError {
    pub(crate) const fn truncated(context: &'static str, needed: usize, available: usize) -> Self {
        Self::Truncated {
            context,
            needed,
            available,
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                context,
                needed,
                available,
            } => write!(
                formatter,
                "truncated radiotap {context}: need {needed} bytes, have {available}"
            ),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported radiotap version {version}")
            }
            Self::InvalidHeaderLength { declared, minimum } => write!(
                formatter,
                "invalid radiotap header length {declared}, minimum is {minimum}"
            ),
            Self::PresenceWordLimit { maximum } => {
                write!(formatter, "radiotap presence words exceed limit {maximum}")
            }
            Self::InvalidFieldLayout { field } => {
                write!(formatter, "invalid radiotap field {field} layout")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Failures while writing a canonical supported-field radiotap header
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncodeError {
    OutputTooSmall { needed: usize, available: usize },
    LengthOverflow,
    InternalRange,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputTooSmall { needed, available } => write!(
                formatter,
                "radiotap output needs {needed} bytes, only {available} available"
            ),
            Self::LengthOverflow => formatter.write_str("radiotap encoded length overflow"),
            Self::InternalRange => formatter.write_str("radiotap encoder range invariant failed"),
        }
    }
}

impl std::error::Error for EncodeError {}
