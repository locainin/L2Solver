use core::fmt;

/// Failures while interpreting a management frame body
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagementError {
    NotManagement,
    ProtectedBody,
    TruncatedBody {
        context: &'static str,
        needed: usize,
        available: usize,
    },
    TruncatedElement {
        offset: usize,
        needed: usize,
        available: usize,
    },
    InvalidElement {
        id: u8,
        reason: &'static str,
    },
    ElementLimit {
        maximum: usize,
    },
    LengthOverflow,
}

impl ManagementError {
    pub(crate) const fn truncated_body(
        context: &'static str,
        needed: usize,
        available: usize,
    ) -> Self {
        Self::TruncatedBody {
            context,
            needed,
            available,
        }
    }
}

impl fmt::Display for ManagementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotManagement => formatter.write_str("802.11 frame is not management traffic"),
            Self::ProtectedBody => {
                formatter.write_str("protected 802.11 management body cannot be decoded")
            }
            Self::TruncatedBody {
                context,
                needed,
                available,
            } => write!(
                formatter,
                "truncated 802.11 {context}: need {needed} bytes, have {available}"
            ),
            Self::TruncatedElement {
                offset,
                needed,
                available,
            } => write!(
                formatter,
                "truncated 802.11 information element at {offset}: need {needed} bytes, have {available}"
            ),
            Self::InvalidElement { id, reason } => {
                write!(
                    formatter,
                    "invalid 802.11 information element {id}: {reason}"
                )
            }
            Self::ElementLimit { maximum } => {
                write!(
                    formatter,
                    "802.11 information elements exceed limit {maximum}"
                )
            }
            Self::LengthOverflow => formatter.write_str("802.11 management length overflow"),
        }
    }
}

impl std::error::Error for ManagementError {}

/// Failures while decoding RSN or WPA security information
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecurityError {
    WrongElement,
    Truncated {
        context: &'static str,
        needed: usize,
        available: usize,
    },
    UnsupportedVersion(u16),
    EmptySuiteList(&'static str),
    ListLimit {
        context: &'static str,
        count: usize,
        maximum: usize,
    },
    InvalidPmf,
    TrailingBytes(usize),
    LengthOverflow,
}

impl fmt::Display for SecurityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongElement => formatter.write_str("information element is not RSN or WPA"),
            Self::Truncated {
                context,
                needed,
                available,
            } => write!(
                formatter,
                "truncated {context}: need {needed} bytes, have {available}"
            ),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported security element version {version}")
            }
            Self::EmptySuiteList(context) => write!(formatter, "empty {context} suite list"),
            Self::ListLimit {
                context,
                count,
                maximum,
            } => write!(
                formatter,
                "{context} suite count {count} exceeds limit {maximum}"
            ),
            Self::InvalidPmf => formatter.write_str("PMF required bit set without PMF capability"),
            Self::TrailingBytes(count) => {
                write!(
                    formatter,
                    "security element has {count} unexplained trailing bytes"
                )
            }
            Self::LengthOverflow => formatter.write_str("security element length overflow"),
        }
    }
}

impl std::error::Error for SecurityError {}
