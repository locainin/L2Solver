use core::fmt;

/// Failure to create a valid controlled-agent identity
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentIdError {
    /// The all-zero value is reserved as an invalid sentinel
    ReservedZero,
}

impl fmt::Display for AgentIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReservedZero => formatter.write_str("agent ID must not be all zeroes"),
        }
    }
}

impl std::error::Error for AgentIdError {}

/// Failure to create a checked canary identity tuple
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanaryIdentityError {
    /// A directional identity must connect distinct agents
    SameAgent,
}

impl fmt::Display for CanaryIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameAgent => {
                formatter.write_str("canary source and destination agents must differ")
            }
        }
    }
}

impl std::error::Error for CanaryIdentityError {}

/// Failure to create checked canary payload fields
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanaryError {
    /// The identity tuple could not be constructed from its endpoint values
    Identity(CanaryIdentityError),
    /// Canary sequences are one based
    ZeroSequence,
}

impl fmt::Display for CanaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(error) => error.fmt(formatter),
            Self::ZeroSequence => formatter.write_str("canary sequence must be nonzero"),
        }
    }
}

impl From<CanaryIdentityError> for CanaryError {
    fn from(error: CanaryIdentityError) -> Self {
        Self::Identity(error)
    }
}

impl std::error::Error for CanaryError {}

/// Failures encountered before a canary payload can be trusted
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The payload ended before the fixed wire length
    Truncated { needed: usize, available: usize },
    /// The payload contains bytes beyond the fixed wire length
    TrailingBytes { expected: usize, actual: usize },
    /// The payload version is not understood by this crate
    UnsupportedVersion { value: u8 },
    /// The fixed-time HMAC comparison rejected the tag
    InvalidTag,
    /// The authenticated run identity is the reserved all-zero sentinel
    ZeroRunId,
    /// The authenticated agent identity is the reserved all-zero sentinel
    ZeroAgentId,
    /// The authenticated direction uses one agent at both ends
    SameAgent,
    /// The authenticated canary sequence is zero
    ZeroSequence,
    /// An authenticated field does not match the receiving context
    UnexpectedRun,
    /// An authenticated source identity does not match the receiving context
    UnexpectedSourceAgent,
    /// An authenticated destination identity does not match the receiving context
    UnexpectedDestinationAgent,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { needed, available } => {
                write!(
                    formatter,
                    "canary payload is truncated: need {needed} bytes, have {available}"
                )
            }
            Self::TrailingBytes { expected, actual } => write!(
                formatter,
                "canary payload has trailing bytes: expected {expected} bytes, received {actual}"
            ),
            Self::UnsupportedVersion { value } => {
                write!(formatter, "unsupported canary version {value}")
            }
            Self::InvalidTag => formatter.write_str("canary authentication tag is invalid"),
            Self::ZeroRunId => formatter.write_str("canary run identity must not be all zeroes"),
            Self::ZeroAgentId => {
                formatter.write_str("canary agent identity must not be all zeroes")
            }
            Self::SameAgent => {
                formatter.write_str("canary source and destination agents must differ")
            }
            Self::ZeroSequence => formatter.write_str("canary sequence must be nonzero"),
            Self::UnexpectedRun => formatter.write_str("canary run identity is unexpected"),
            Self::UnexpectedSourceAgent => {
                formatter.write_str("canary source agent identity is unexpected")
            }
            Self::UnexpectedDestinationAgent => {
                formatter.write_str("canary destination agent identity is unexpected")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Secret-key length validation failures
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyError {
    /// The key is shorter than the cryptographic policy permits
    TooShort { length: usize, min: usize },
    /// The key is longer than the bounded in-memory key representation
    TooLong { length: usize, max: usize },
    /// The long-term relationship key does not belong to the sending agent
    AgentKeyMismatch,
    /// The signed run differs from the session authorization
    RunMismatch,
    /// The signed source differs from the session authorization
    SourceMismatch,
    /// The signed destination differs from the session authorization
    DestinationMismatch,
    /// The keyed derivation primitive rejected checked key material
    DerivationFailed,
    /// A private key or wire representation violated its checked bounds
    InternalInvariant,
}

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { length, min } => {
                write!(formatter, "secret key has {length} bytes; minimum is {min}")
            }
            Self::TooLong { length, max } => {
                write!(formatter, "secret key has {length} bytes; maximum is {max}")
            }
            Self::AgentKeyMismatch => {
                formatter.write_str("agent relationship key does not belong to the source agent")
            }
            Self::RunMismatch => formatter.write_str("canary run is outside the session key scope"),
            Self::SourceMismatch => {
                formatter.write_str("canary source is outside the session key scope")
            }
            Self::DestinationMismatch => {
                formatter.write_str("canary destination is outside the session key scope")
            }
            Self::DerivationFailed => formatter.write_str("session key derivation failed"),
            Self::InternalInvariant => formatter.write_str("canary key invariant failed"),
        }
    }
}

impl std::error::Error for KeyError {}

/// Replay-window rejection from a bounded guard
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayError {
    /// The identity already has a sequence at least as new as the candidate
    NonIncreasing { previous: u64, sequence: u64 },
    /// The guard has reached its fixed identity-entry limit
    IdentityLimit { max: usize },
}

impl fmt::Display for ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonIncreasing { previous, sequence } => write!(
                formatter,
                "canary sequence {sequence} is not greater than previously accepted {previous}"
            ),
            Self::IdentityLimit { max } => {
                write!(
                    formatter,
                    "replay guard identity limit of {max} entries reached"
                )
            }
        }
    }
}

impl std::error::Error for ReplayError {}
