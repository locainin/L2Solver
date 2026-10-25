use core::fmt;

/// Structural failures while decoding an IEEE 802.11 MAC frame
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The frame ended before a required field
    Truncated {
        context: &'static str,
        needed: usize,
        available: usize,
    },
    /// Only protocol version zero is defined for ordinary 802.11 frames
    UnsupportedVersion(u8),
    /// A fixed-width field could not be represented by the requested layout
    InvalidLayout(&'static str),
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
                "truncated 802.11 {context}: need {needed} bytes, have {available}"
            ),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported 802.11 protocol version {version}")
            }
            Self::InvalidLayout(context) => write!(formatter, "invalid 802.11 {context}"),
        }
    }
}

impl std::error::Error for DecodeError {}
