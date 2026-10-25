//! Detailed bounded planning and observation errors

use core::fmt;

use crate::{AgentId, SegmentId};

/// Validation failures produced before a plan can be used
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanError {
    /// The number of agents exceeds the fixed planner bound
    AgentLimitExceeded { count: usize, maximum: usize },
    /// The number of segments exceeds the fixed planner bound
    SegmentLimitExceeded { count: usize, maximum: usize },
    /// The number of explicit directed rules exceeds the fixed planner bound
    RuleLimitExceeded { count: usize, maximum: usize },
    /// The generated source to destination probes exceed the fixed bound
    ProbeLimitExceeded { count: usize, maximum: usize },
    /// A checked arithmetic operation could not represent a probe count
    ProbeCountOverflow,
    /// The configured attempts value is outside the allowed inclusive range
    AttemptsOutOfRange {
        source: SegmentId,
        destination: SegmentId,
        attempts: u8,
        minimum: u8,
        maximum: u8,
    },
    /// A segment identifier occurs more than once
    DuplicateSegment { segment: SegmentId },
    /// An agent identity occurs more than once
    DuplicateAgent { agent: AgentId },
    /// A directed source and destination pair occurs more than once
    DuplicateRule {
        source: SegmentId,
        destination: SegmentId,
    },
    /// An agent points at a segment absent from the segment inventory
    UnknownAgentSegment { agent: AgentId, segment: SegmentId },
    /// A directed rule points at an absent source segment
    UnknownSourceSegment { segment: SegmentId },
    /// A directed rule points at an absent destination segment
    UnknownDestinationSegment { segment: SegmentId },
    /// A rule has no controlled agent on its source segment
    NoSourceAgents {
        source: SegmentId,
        destination: SegmentId,
    },
    /// A rule has no controlled agent on its destination segment
    NoDestinationAgents {
        source: SegmentId,
        destination: SegmentId,
    },
    /// A same-segment rule has fewer than two distinct controlled agents
    NoDistinctAgentPairs { segment: SegmentId },
    /// The generated sequence material would exceed its representable range
    SequenceOverflow,
}

impl fmt::Display for PlanError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AgentLimitExceeded { count, maximum } => {
                write!(output, "agent count {count} exceeds maximum {maximum}")
            }
            Self::SegmentLimitExceeded { count, maximum } => {
                write!(output, "segment count {count} exceeds maximum {maximum}")
            }
            Self::RuleLimitExceeded { count, maximum } => {
                write!(
                    output,
                    "directed rule count {count} exceeds maximum {maximum}"
                )
            }
            Self::ProbeLimitExceeded { count, maximum } => {
                write!(
                    output,
                    "planned probe count {count} exceeds maximum {maximum}"
                )
            }
            Self::ProbeCountOverflow => output.write_str("planned probe count overflowed"),
            Self::AttemptsOutOfRange {
                source,
                destination,
                attempts,
                minimum,
                maximum,
            } => write!(
                output,
                "rule {source:?}->{destination:?} has {attempts} attempts; range is {minimum}..={maximum}"
            ),
            Self::DuplicateSegment { segment } => {
                write!(output, "segment {segment:?} is declared more than once")
            }
            Self::DuplicateAgent { agent } => {
                write!(output, "agent {agent:?} is declared more than once")
            }
            Self::DuplicateRule {
                source,
                destination,
            } => write!(
                output,
                "rule {source:?}->{destination:?} is declared more than once"
            ),
            Self::UnknownAgentSegment { agent, segment } => write!(
                output,
                "agent {agent:?} points at unknown segment {segment:?}"
            ),
            Self::UnknownSourceSegment { segment } => {
                write!(output, "rule source segment {segment:?} is unknown")
            }
            Self::UnknownDestinationSegment { segment } => {
                write!(output, "rule destination segment {segment:?} is unknown")
            }
            Self::NoSourceAgents {
                source,
                destination,
            } => write!(
                output,
                "rule {source:?}->{destination:?} has no source agents"
            ),
            Self::NoDestinationAgents {
                source,
                destination,
            } => write!(
                output,
                "rule {source:?}->{destination:?} has no destination agents"
            ),
            Self::NoDistinctAgentPairs { segment } => write!(
                output,
                "same-segment rule {segment:?}->{segment:?} needs at least two distinct agents"
            ),
            Self::SequenceOverflow => output.write_str("probe sequence material overflowed"),
        }
    }
}

impl std::error::Error for PlanError {}

/// Failures while binding one authenticated canary to exact Ethernet bytes
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlannedFrameError {
    /// The planned probe could not form a checked canary
    Canary(l2_canary::CanaryError),
    /// The session key did not authorize the planned canary
    Key(l2_canary::KeyError),
    /// The complete Ethernet frame was not structurally valid
    Frame(l2_core::DecodeError),
    /// The frame did not carry the canary protocol `EtherType`
    WrongEtherType,
    /// The frame payload differed from the authenticated canary bytes
    CanaryPayloadMismatch,
    /// The complete frame length could not be represented as an unsigned 64-bit count
    FrameLengthOverflow,
}

impl fmt::Display for PlannedFrameError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canary(error) => write!(output, "planned canary is invalid: {error}"),
            Self::Key(error) => write!(output, "planned canary key scope is invalid: {error}"),
            Self::Frame(error) => write!(output, "planned Ethernet frame is invalid: {error}"),
            Self::WrongEtherType => {
                output.write_str("planned frame does not use the canary EtherType")
            }
            Self::CanaryPayloadMismatch => {
                output.write_str("planned frame payload does not match the authenticated canary")
            }
            Self::FrameLengthOverflow => {
                output.write_str("planned frame length exceeds the supported count range")
            }
        }
    }
}

impl std::error::Error for PlannedFrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canary(error) => Some(error),
            Self::Key(error) => Some(error),
            Self::Frame(error) => Some(error),
            Self::WrongEtherType | Self::CanaryPayloadMismatch | Self::FrameLengthOverflow => None,
        }
    }
}

/// Failures while authenticating a wire observation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluationError {
    /// The canary payload failed l2-canary verification
    Verification(l2_canary::DecodeError),
    /// The claimed observation point did not match its checked receiver window
    Receipt(ReceiptError),
}

impl fmt::Display for EvaluationError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verification(error) => {
                write!(output, "canary observation verification failed: {error}")
            }
            Self::Receipt(error) => write!(output, "canary arrival claim is invalid: {error}"),
        }
    }
}

impl std::error::Error for EvaluationError {}

impl From<l2_canary::DecodeError> for EvaluationError {
    fn from(error: l2_canary::DecodeError) -> Self {
        Self::Verification(error)
    }
}

impl From<ReceiptError> for EvaluationError {
    fn from(error: ReceiptError) -> Self {
        Self::Receipt(error)
    }
}

/// Invalid or contradictory execution evidence
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptError {
    /// Run identity cannot be the all-zero sentinel
    ZeroRunId,
    /// Probe sequences are one based
    ZeroSequence,
    /// A frame commitment or receipt needs a concrete digest
    ZeroFrameHash,
    /// A frame claim must contain one structurally valid Ethernet frame
    InvalidFrame,
    /// A frame length could not be represented as an unsigned 64-bit count
    FrameLengthOverflow,
    /// A transmit receipt was supplied before the expected frame commitment
    MissingCommitment,
    /// A destination arrival lacks a matching recorded transmit receipt
    MissingTransmitReceipt,
    /// A transmit receipt hash differs from the expected frame commitment
    CommitmentMismatch,
    /// A canary probe commitment does not contain its exact planned canary
    CommitmentCanaryMismatch,
    /// A second commitment changes the expected frame hash for one probe
    ConflictingCommitment,
    /// A commitment cannot be added after its transmit receipt is recorded
    LateCommitment,
    /// A clock-domain identity cannot be the zero sentinel
    ZeroClockDomain,
    /// Local clock ticks are one based
    ZeroClockTicks,
    /// Controller event identities are one based
    ZeroControllerEvent,
    /// Controller event run identities cannot be the zero sentinel
    ZeroControllerRun,
    /// Controller event identities use different run identities
    ControllerRunMismatch,
    /// Controller events name a different probe sequence
    ControllerSequenceMismatch,
    /// A controller ordinal is already owned by another event in this consumer
    ControllerEventReuse { ordinal: u64 },
    /// A local observation interval used two clock domains
    ClockDomainMismatch,
    /// Observation close time precedes its armed time
    InvalidWindow,
    /// Controller lifecycle events are not strictly ordered
    InvalidControllerOrder,
    /// A receiver window does not causally contain its matching transmit
    CausalCoverageMissing,
    /// The transmit interface differs from the planned interface binding
    InterfaceMismatch,
    /// The frame commitment does not use the source agent's planned interface
    SourceInterfaceMismatch,
    /// The receiver window does not use the destination agent's planned interface
    DestinationInterfaceMismatch,
    /// A destination-arrival claim names a different receiver interface
    ObservationInterfaceMismatch,
    /// A destination-arrival stamp falls outside the receiver's local window
    ObservationOutsideWindow,
    /// A destination-arrival claim and its window identify different evidence
    ObservationScopeMismatch,
    /// No planned probe has this run and sequence
    UnknownProbe,
    /// The receipt names a receiver other than the planned destination
    WrongReceiver,
    /// Evidence for one probe changed after it was recorded
    ConflictingReceipt,
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroRunId => output.write_str("receipt run ID must not be all zeroes"),
            Self::ZeroSequence => output.write_str("receipt probe sequence must be nonzero"),
            Self::ZeroFrameHash => output.write_str("transmit frame hash must be nonzero"),
            Self::InvalidFrame => output.write_str("transmit claim is not a valid Ethernet frame"),
            Self::FrameLengthOverflow => {
                output.write_str("transmit frame length exceeds the supported count range")
            }
            Self::MissingCommitment => {
                output.write_str("transmit receipt requires an expected frame commitment")
            }
            Self::MissingTransmitReceipt => {
                output.write_str("canary arrival requires a recorded transmit receipt")
            }
            Self::CommitmentMismatch => output.write_str(
                "transmit receipt frame hash does not match the expected frame commitment",
            ),
            Self::CommitmentCanaryMismatch => {
                output.write_str("transmit commitment does not contain the exact planned canary")
            }
            Self::ConflictingCommitment => output.write_str(
                "expected frame commitment conflicts with evidence already recorded for this probe",
            ),
            Self::LateCommitment => output.write_str(
                "expected frame commitment cannot be recorded after its transmit receipt",
            ),
            Self::ZeroClockDomain => output.write_str("clock domain must be nonzero"),
            Self::ZeroClockTicks => output.write_str("local clock ticks must be nonzero"),
            Self::ZeroControllerEvent => output.write_str("controller event must be nonzero"),
            Self::ZeroControllerRun => {
                output.write_str("controller event run ID must not be all zeroes")
            }
            Self::ControllerRunMismatch => {
                output.write_str("controller events must belong to one run")
            }
            Self::ControllerSequenceMismatch => {
                output.write_str("controller events must name one probe sequence")
            }
            Self::ControllerEventReuse { ordinal } => write!(
                output,
                "controller event ordinal {ordinal} is already assigned to another operation"
            ),
            Self::ClockDomainMismatch => {
                output.write_str("observation window local stamps use different clock domains")
            }
            Self::InvalidWindow => output.write_str("observation window closes before it is armed"),
            Self::InvalidControllerOrder => {
                output.write_str("controller lifecycle events must be strictly ordered")
            }
            Self::CausalCoverageMissing => {
                output.write_str("observation window does not causally cover the transmit")
            }
            Self::InterfaceMismatch => {
                output.write_str("transmit interface does not match its commitment")
            }
            Self::SourceInterfaceMismatch => {
                output.write_str("transmit commitment does not use the planned source interface")
            }
            Self::DestinationInterfaceMismatch => output
                .write_str("observation window does not use the planned destination interface"),
            Self::ObservationInterfaceMismatch => {
                output.write_str("canary observation interface does not match its receiver window")
            }
            Self::ObservationOutsideWindow => {
                output.write_str("canary observation stamp is outside its receiver window")
            }
            Self::ObservationScopeMismatch => {
                output.write_str("canary observation and receiver window use different scope")
            }
            Self::UnknownProbe => output.write_str("receipt does not identify a planned probe"),
            Self::WrongReceiver => output.write_str("observation receipt names the wrong receiver"),
            Self::ConflictingReceipt => {
                output.write_str("receipt conflicts with evidence already recorded for this probe")
            }
        }
    }
}

impl std::error::Error for ReceiptError {}
