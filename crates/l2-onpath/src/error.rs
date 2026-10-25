//! Errors at the bounded on-path planning and evidence boundaries

use core::fmt;
use std::net::IpAddr;

use crate::{
    AddressFamily, AgentId, CheckKind, InterfaceBindingRequest, NeighborDisposition, StimulusId,
};
use l2_segmentation::ClockDomainId;

/// Invalid values that cannot identify a controlled endpoint or receipt
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    /// An authenticated run or endpoint identity used the reserved zero value
    ZeroIdentity,
    /// Evidence belonged to another assessment run
    RunMismatch,
    /// A MAC address contained no identity bits
    ZeroMac,
    /// A broadcast MAC cannot be an endpoint identity
    BroadcastMac,
    /// A multicast MAC cannot be an endpoint identity
    MulticastMac,
    /// An unspecified IP address cannot identify a neighbor
    UnspecifiedAddress,
    /// The IPv4 broadcast address cannot identify one neighbor
    BroadcastAddress,
    /// A multicast IP address cannot identify one neighbor
    MulticastAddress,
    /// A loopback IP address never identifies an on-link neighbor
    LoopbackAddress,
    /// An address was not valid for the selected protocol family
    FamilyMismatch,
    /// A stimulus identifier is one based
    ZeroStimulusId,
    /// A sequence number is one based
    ZeroSequence,
    /// Receipt identities do not name the same authenticated canary
    EvidenceScopeMismatch,
    /// A blocked path claim lacked a complete loss-free receiver window
    IncompleteObservationWindow,
    /// A receiver window did not causally contain the claimed transmission
    CausalCoverageMissing,
}

impl fmt::Display for ModelError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroIdentity => output.write_str("on-path identity must not be all zeroes"),
            Self::RunMismatch => output.write_str("on-path evidence belongs to another run"),
            Self::ZeroMac => output.write_str("endpoint MAC must not be all zeroes"),
            Self::BroadcastMac => output.write_str("endpoint MAC must not be broadcast"),
            Self::MulticastMac => output.write_str("endpoint MAC must be unicast"),
            Self::UnspecifiedAddress => output.write_str("neighbor address must be specified"),
            Self::BroadcastAddress => {
                output.write_str("neighbor address must not be IPv4 broadcast")
            }
            Self::MulticastAddress => output.write_str("neighbor address must be unicast"),
            Self::LoopbackAddress => output.write_str("neighbor address must not be loopback"),
            Self::FamilyMismatch => output.write_str("neighbor address family does not match"),
            Self::ZeroStimulusId => output.write_str("stimulus ID must be nonzero"),
            Self::ZeroSequence => output.write_str("stimulus sequence must be nonzero"),
            Self::EvidenceScopeMismatch => {
                output.write_str("canary transmit and receiver evidence do not share one scope")
            }
            Self::IncompleteObservationWindow => {
                output.write_str("blocked canary requires a complete loss-free receiver window")
            }
            Self::CausalCoverageMissing => {
                output.write_str("canary receiver window does not causally cover its transmit")
            }
        }
    }
}

impl std::error::Error for ModelError {}

/// Invalid bounded packet, byte, or time limits
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetError {
    /// At least one bounded packet is required
    ZeroPackets,
    /// At least one bounded byte is required
    ZeroBytes,
    /// At least one bounded millisecond is required
    ZeroDuration,
    /// A duration timebase must define at least one tick per millisecond
    ZeroTicksPerMillisecond,
    /// The packet limit exceeds the crate ceiling
    PacketsExceeded { value: u64, maximum: u64 },
    /// The byte limit exceeds the crate ceiling
    BytesExceeded { value: u64, maximum: u64 },
    /// The duration limit exceeds the crate ceiling
    DurationExceeded { value: u64, maximum: u64 },
}

impl fmt::Display for BudgetError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroPackets => output.write_str("packet budget must be nonzero"),
            Self::ZeroBytes => output.write_str("byte budget must be nonzero"),
            Self::ZeroDuration => output.write_str("duration budget must be nonzero"),
            Self::ZeroTicksPerMillisecond => {
                output.write_str("duration clock must use at least one tick per millisecond")
            }
            Self::PacketsExceeded { value, maximum } => {
                write!(output, "packet budget {value} exceeds maximum {maximum}")
            }
            Self::BytesExceeded { value, maximum } => {
                write!(output, "byte budget {value} exceeds maximum {maximum}")
            }
            Self::DurationExceeded { value, maximum } => {
                write!(
                    output,
                    "duration budget {value} exceeds maximum {maximum}ms"
                )
            }
        }
    }
}

impl std::error::Error for BudgetError {}

/// Plan construction failures that occur before any endpoint can be armed
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanError {
    /// The supplied run identity was reserved
    InvalidRunId,
    /// Planned evidence uses a different run identity
    WrongRun,
    /// The endpoint collection exceeded its fixed bound
    EndpointLimitExceeded { count: usize, maximum: usize },
    /// The stimulus collection exceeded its fixed bound
    StimulusLimitExceeded { count: usize, maximum: usize },
    /// The canary collection exceeded its fixed bound
    CanaryLimitExceeded { count: usize, maximum: usize },
    /// A checked endpoint key was repeated
    DuplicateEndpoint {
        endpoint: AgentId,
        family: AddressFamily,
    },
    /// A check kind was repeated
    DuplicateCheck { kind: CheckKind },
    /// A stimulus ID was repeated
    DuplicateStimulus { id: StimulusId },
    /// A stimulus sequence was repeated
    DuplicateStimulusSequence { sequence: u64 },
    /// A canary or stimulus reused another planned transmit sequence
    DuplicateTransmitSequence { sequence: u64 },
    /// A stimulus points at a check that was not selected
    UnknownCheck { kind: CheckKind },
    /// A stimulus points at an endpoint absent from the plan
    UnknownEndpoint { endpoint: AgentId },
    /// A stimulus does not use the selected protocol family
    WrongFamily {
        check: CheckKind,
        family: AddressFamily,
    },
    /// A canary points at a stimulus absent from the plan
    UnknownStimulus { id: StimulusId },
    /// A canary source differs from the endpoint exercised by its stimulus
    CanarySourceMismatch { expected: AgentId, actual: AgentId },
    /// A canary identity was repeated
    DuplicateCanary,
    /// An exact transmit commitment was repeated
    DuplicateCommitment { sequence: u64 },
    /// An endpoint cleanup commitment was repeated
    DuplicateCleanupCommitment {
        endpoint: AgentId,
        family: AddressFamily,
    },
    /// The exact transmit commitment collection exceeded its fixed bound
    CommitmentLimitExceeded { count: usize, maximum: usize },
    /// An exact transmit commitment changed for an existing sequence
    ConflictingCommitment { sequence: u64 },
    /// A commitment sequence is not owned by a planned stimulus or canary
    UnknownCommitmentSequence { sequence: u64 },
    /// A canary commitment does not contain the exact planned canary
    CommitmentCanaryMismatch { sequence: u64 },
    /// A canary commitment does not use the source endpoint's planned interface
    CommitmentInterfaceMismatch { sequence: u64 },
    /// A non-canary stimulus commitment incorrectly carries canary material
    UnexpectedCanaryCommitment { sequence: u64 },
    /// A model value could not be used in a plan
    Model(ModelError),
}

impl fmt::Display for PlanError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRunId => output.write_str("on-path run ID must not be all zeroes"),
            Self::WrongRun => output.write_str("planned canary run ID does not match the plan"),
            Self::EndpointLimitExceeded { count, maximum } => {
                write!(output, "endpoint count {count} exceeds maximum {maximum}")
            }
            Self::StimulusLimitExceeded { count, maximum } => {
                write!(output, "stimulus count {count} exceeds maximum {maximum}")
            }
            Self::CanaryLimitExceeded { count, maximum } => {
                write!(output, "canary count {count} exceeds maximum {maximum}")
            }
            Self::DuplicateEndpoint { endpoint, family } => {
                write!(
                    output,
                    "endpoint {endpoint:?} has duplicate {family:?} binding"
                )
            }
            Self::DuplicateCheck { kind } => write!(output, "check {kind:?} is repeated"),
            Self::DuplicateStimulus { id } => write!(output, "stimulus {id:?} is repeated"),
            Self::DuplicateStimulusSequence { sequence } => {
                write!(output, "stimulus sequence {sequence} is repeated")
            }
            Self::DuplicateTransmitSequence { sequence } => {
                write!(output, "transmit sequence {sequence} is already planned")
            }
            Self::UnknownCheck { kind } => {
                write!(output, "stimulus references unknown check {kind:?}")
            }
            Self::UnknownEndpoint { endpoint } => {
                write!(output, "stimulus references unknown endpoint {endpoint:?}")
            }
            Self::WrongFamily { check, family } => {
                write!(output, "check {check:?} cannot target {family:?}")
            }
            Self::UnknownStimulus { id } => write!(output, "canary references unknown {id:?}"),
            Self::CanarySourceMismatch { expected, actual } => write!(
                output,
                "canary source {actual:?} does not match stimulus endpoint {expected:?}"
            ),
            Self::DuplicateCanary => output.write_str("canary expectation is repeated"),
            Self::DuplicateCleanupCommitment { endpoint, family } => write!(
                output,
                "cleanup commitment for {endpoint:?} {family:?} is repeated"
            ),
            Self::CommitmentLimitExceeded { count, maximum } => {
                write!(output, "commitment count {count} exceeds maximum {maximum}")
            }
            Self::DuplicateCommitment { sequence } => {
                write!(
                    output,
                    "transmit commitment for sequence {sequence} is repeated"
                )
            }
            Self::ConflictingCommitment { sequence } => {
                write!(
                    output,
                    "transmit commitment for sequence {sequence} conflicts"
                )
            }
            Self::UnknownCommitmentSequence { sequence } => {
                write!(
                    output,
                    "transmit commitment references unknown sequence {sequence}"
                )
            }
            Self::CommitmentCanaryMismatch { sequence } => write!(
                output,
                "transmit commitment for canary sequence {sequence} contains different material"
            ),
            Self::CommitmentInterfaceMismatch { sequence } => write!(
                output,
                "transmit commitment for canary sequence {sequence} uses the wrong source interface"
            ),
            Self::UnexpectedCanaryCommitment { sequence } => write!(
                output,
                "stimulus commitment for sequence {sequence} contains canary material"
            ),
            Self::Model(error) => write!(output, "invalid on-path model value: {error}"),
        }
    }
}

impl std::error::Error for PlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Model(error) => Some(error),
            Self::InvalidRunId
            | Self::WrongRun
            | Self::EndpointLimitExceeded { .. }
            | Self::StimulusLimitExceeded { .. }
            | Self::CanaryLimitExceeded { .. }
            | Self::DuplicateEndpoint { .. }
            | Self::DuplicateCheck { .. }
            | Self::DuplicateStimulus { .. }
            | Self::DuplicateStimulusSequence { .. }
            | Self::DuplicateTransmitSequence { .. }
            | Self::UnknownCheck { .. }
            | Self::UnknownEndpoint { .. }
            | Self::WrongFamily { .. }
            | Self::UnknownStimulus { .. }
            | Self::CanarySourceMismatch { .. }
            | Self::DuplicateCanary
            | Self::DuplicateCommitment { .. }
            | Self::DuplicateCleanupCommitment { .. }
            | Self::CommitmentLimitExceeded { .. }
            | Self::ConflictingCommitment { .. }
            | Self::UnknownCommitmentSequence { .. }
            | Self::CommitmentCanaryMismatch { .. }
            | Self::CommitmentInterfaceMismatch { .. }
            | Self::UnexpectedCanaryCommitment { .. } => None,
        }
    }
}

impl From<ModelError> for PlanError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

/// Invalid or contradictory evidence submitted to an active session
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptError {
    /// A receipt belongs to another assessment run
    WrongRun,
    /// A receipt names an endpoint absent from the immutable plan
    UnknownEndpoint { endpoint: AgentId },
    /// A receipt names a stimulus absent from the immutable plan
    UnknownStimulus { id: StimulusId },
    /// A receipt has a sequence different from the planned stimulus
    WrongSequence { expected: u64, actual: u64 },
    /// A receipt has a family different from the planned endpoint
    WrongFamily {
        expected: AddressFamily,
        actual: AddressFamily,
    },
    /// A receiver observation names the wrong endpoint
    WrongReceiver,
    /// A receiver observation does not use the endpoint's planned interface
    ObservationInterfaceMismatch,
    /// An endpoint lifecycle receipt does not use its planned interface
    EndpointInterfaceMismatch {
        expected: InterfaceBindingRequest,
        actual: InterfaceBindingRequest,
    },
    /// A receipt changed after an identical receipt had been accepted
    ConflictingReceipt,
    /// A canary does not belong to the immutable canary expectations
    UnknownCanary,
    /// A transition or canary observation lost capture records
    CaptureLoss,
    /// A restoration did not match the original binding
    RestorationMismatch,
    /// A cleanup observation uses a different planned address
    CleanupBindingAddressMismatch { expected: IpAddr, actual: IpAddr },
    /// An unsuccessful cleanup incorrectly claims the original binding
    UnrestoredBindingMatchesOriginal,
    /// The initial binding receipt did not match the planned original
    OriginalBindingMismatch,
    /// A required lifecycle receipt was not present
    MissingReceipt,
    /// A transmit receipt has no predeclared exact frame commitment
    MissingCommitment { sequence: u64 },
    /// A transmit receipt hash differs from its predeclared exact frame commitment
    CommitmentMismatch { sequence: u64 },
    /// A transmit receipt interface differs from its predeclared interface commitment
    InterfaceMismatch { sequence: u64 },
    /// A transition window does not causally cover its committed transmit
    CausalCoverageMissing,
    /// A transition disposition does not belong to its planned check category
    IncompatibleDisposition {
        check: CheckKind,
        disposition: NeighborDisposition,
    },
    /// An observed binding names a different controlled endpoint
    ObservedBindingEndpointMismatch { expected: AgentId, actual: AgentId },
    /// An observed binding uses a different address family
    ObservedBindingFamilyMismatch {
        expected: AddressFamily,
        actual: AddressFamily,
    },
    /// An observed binding uses a different planned address
    ObservedBindingAddressMismatch { expected: IpAddr, actual: IpAddr },
    /// A binding-changing accepted disposition lacks changed binding evidence
    MissingChangedBinding { disposition: NeighborDisposition },
    /// A clean or rejected disposition carries a changed binding
    UnexpectedChangedBinding { disposition: NeighborDisposition },
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongRun => output.write_str("receipt run ID does not match the session"),
            Self::UnknownEndpoint { endpoint } => fmt_unknown_endpoint(output, *endpoint),
            Self::UnknownStimulus { id } => write!(output, "receipt references unknown {id:?}"),
            Self::WrongSequence { expected, actual } => {
                fmt_wrong_sequence(output, *actual, *expected)
            }
            Self::WrongFamily { expected, actual } => fmt_wrong_family(output, *actual, *expected),
            Self::WrongReceiver => output.write_str("receipt names the wrong receiver"),
            Self::ObservationInterfaceMismatch => {
                output.write_str("receipt does not use the planned receiver interface")
            }
            Self::EndpointInterfaceMismatch { expected, actual } => {
                fmt_endpoint_interface(output, *actual, *expected)
            }
            Self::ConflictingReceipt => output.write_str("receipt conflicts with prior evidence"),
            Self::UnknownCanary => output.write_str("authenticated canary is outside the plan"),
            Self::CaptureLoss => output.write_str("capture loss prevents a clean observation"),
            Self::RestorationMismatch => {
                output.write_str("cleanup did not restore the original binding")
            }
            Self::CleanupBindingAddressMismatch { expected, actual } => {
                fmt_display_binding_mismatch(
                    output, "cleanup", "address", actual, "planned", expected,
                )
            }
            Self::UnrestoredBindingMatchesOriginal => {
                output.write_str("unsuccessful cleanup cannot claim the original binding")
            }
            Self::OriginalBindingMismatch => {
                output.write_str("original binding receipt does not match the plan")
            }
            Self::MissingReceipt => output.write_str("required lifecycle evidence is missing"),
            Self::MissingCommitment { sequence } => {
                fmt_transmit_receipt(output, *sequence, "has no commitment")
            }
            Self::CommitmentMismatch { sequence } => {
                fmt_transmit_receipt(output, *sequence, "does not match its commitment")
            }
            Self::InterfaceMismatch { sequence } => {
                fmt_transmit_receipt(output, *sequence, "uses a different interface")
            }
            Self::CausalCoverageMissing => {
                output.write_str("transition window does not causally cover its committed transmit")
            }
            Self::IncompatibleDisposition { check, disposition } => write!(
                output,
                "disposition {disposition:?} is not valid for check {check:?}"
            ),
            Self::ObservedBindingEndpointMismatch { expected, actual } => {
                fmt_debug_binding_mismatch(
                    output, "observed", "endpoint", actual, "planned", expected,
                )
            }
            Self::ObservedBindingFamilyMismatch { expected, actual } => fmt_debug_binding_mismatch(
                output, "observed", "family", actual, "receipt", expected,
            ),
            Self::ObservedBindingAddressMismatch { expected, actual } => {
                fmt_display_binding_mismatch(
                    output, "observed", "address", actual, "planned", expected,
                )
            }
            Self::MissingChangedBinding { disposition } => write!(
                output,
                "accepted disposition {disposition:?} requires changed binding evidence"
            ),
            Self::UnexpectedChangedBinding { disposition } => write!(
                output,
                "disposition {disposition:?} cannot carry changed binding evidence"
            ),
        }
    }
}

fn fmt_debug_binding_mismatch<T: fmt::Debug>(
    output: &mut fmt::Formatter<'_>,
    binding: &str,
    field: &str,
    actual: &T,
    expected_context: &str,
    expected: &T,
) -> fmt::Result {
    write!(
        output,
        "{binding} binding {field} {actual:?} does not match {expected_context} {field} {expected:?}"
    )
}

fn fmt_unknown_endpoint(output: &mut fmt::Formatter<'_>, endpoint: AgentId) -> fmt::Result {
    write!(output, "receipt references unknown endpoint {endpoint:?}")
}

fn fmt_wrong_sequence(output: &mut fmt::Formatter<'_>, actual: u64, expected: u64) -> fmt::Result {
    write!(output, "receipt sequence is {actual}, expected {expected}")
}

fn fmt_wrong_family(
    output: &mut fmt::Formatter<'_>,
    actual: AddressFamily,
    expected: AddressFamily,
) -> fmt::Result {
    write!(
        output,
        "receipt family is {actual:?}, expected {expected:?}"
    )
}

fn fmt_endpoint_interface(
    output: &mut fmt::Formatter<'_>,
    actual: InterfaceBindingRequest,
    expected: InterfaceBindingRequest,
) -> fmt::Result {
    write!(
        output,
        "endpoint receipt uses interface {actual:?}, expected {expected:?}"
    )
}

fn fmt_transmit_receipt(
    output: &mut fmt::Formatter<'_>,
    sequence: u64,
    issue: &str,
) -> fmt::Result {
    write!(output, "transmit receipt for sequence {sequence} {issue}")
}

fn fmt_display_binding_mismatch<T: fmt::Display>(
    output: &mut fmt::Formatter<'_>,
    binding: &str,
    field: &str,
    actual: &T,
    expected_context: &str,
    expected: &T,
) -> fmt::Result {
    write!(
        output,
        "{binding} binding {field} {actual} does not match {expected_context} {field} {expected}"
    )
}

impl std::error::Error for ReceiptError {}

/// Session lifecycle or authenticated observation failures
#[derive(Debug)]
pub enum SessionError {
    /// An operation was attempted outside its allowed lifecycle phase
    WrongPhase {
        operation: &'static str,
        phase: crate::AssessmentPhase,
    },
    /// A precheck did not establish a safe bounded starting point
    PrecheckIncomplete,
    /// Exact cleanup frame reservations are incomplete for the controlled endpoints
    CleanupCommitmentsIncomplete,
    /// The timestamp uses a different monotonic clock domain
    ReceiptClockDomainMismatch {
        expected: ClockDomainId,
        actual: ClockDomainId,
    },
    /// The supplied receipt clock moved behind the previous accepted receipt
    ReceiptClockMovedBackwards { previous: u64, actual: u64 },
    /// Experiment evidence exceeded the selected check's duration ceiling
    DurationBudgetExceeded {
        elapsed_ticks: u128,
        limit_ticks: u128,
    },
    /// Experiment traffic would consume the reserved cleanup packet or byte budget
    ResourceBudgetExceeded {
        check: CheckKind,
        packets: u128,
        bytes: u128,
        packet_limit: u64,
        byte_limit: u64,
    },
    /// A checked budget usage counter could not be represented
    BudgetCounterOverflow,
    /// A checked model value could not be converted into session evidence
    Model(ModelError),
    /// The receipt was invalid or contradictory
    Receipt(ReceiptError),
    /// The shared segmentation observation window rejected its fields
    Segmentation(l2_segmentation::ReceiptError),
    /// The authenticated canary wire failed structural or cryptographic checks
    Canary(l2_canary::DecodeError),
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongPhase { operation, phase } => {
                write!(output, "cannot {operation} while session is in {phase:?}")
            }
            Self::PrecheckIncomplete => output.write_str("precheck did not complete cleanly"),
            Self::CleanupCommitmentsIncomplete => {
                output.write_str("one exact cleanup frame must be reserved per endpoint")
            }
            Self::ReceiptClockDomainMismatch { expected, actual } => write!(
                output,
                "receipt clock domain {actual:?} does not match session domain {expected:?}"
            ),
            Self::ReceiptClockMovedBackwards { previous, actual } => write!(
                output,
                "receipt clock tick {actual} precedes the previous accepted tick {previous}"
            ),
            Self::DurationBudgetExceeded {
                elapsed_ticks,
                limit_ticks,
            } => write!(
                output,
                "session elapsed {elapsed_ticks} ticks exceeds duration limit {limit_ticks} ticks"
            ),
            Self::ResourceBudgetExceeded {
                check,
                packets,
                bytes,
                packet_limit,
                byte_limit,
            } => write!(
                output,
                "check {check:?} would use {packets} packets and {bytes} bytes including cleanup reserve; limits are {packet_limit} packets and {byte_limit} bytes"
            ),
            Self::BudgetCounterOverflow => {
                output.write_str("on-path budget usage exceeds its checked counter")
            }
            Self::Model(error) => write!(output, "invalid on-path model value: {error}"),
            Self::Receipt(error) => write!(output, "invalid on-path receipt: {error}"),
            Self::Segmentation(error) => write!(output, "invalid observation window: {error}"),
            Self::Canary(error) => {
                write!(output, "authenticated canary verification failed: {error}")
            }
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Receipt(error) => Some(error),
            Self::Segmentation(error) => Some(error),
            Self::Canary(error) => Some(error),
            Self::Model(error) => Some(error),
            Self::WrongPhase { .. }
            | Self::PrecheckIncomplete
            | Self::CleanupCommitmentsIncomplete
            | Self::ReceiptClockDomainMismatch { .. }
            | Self::ReceiptClockMovedBackwards { .. }
            | Self::DurationBudgetExceeded { .. }
            | Self::ResourceBudgetExceeded { .. }
            | Self::BudgetCounterOverflow => None,
        }
    }
}

impl From<ReceiptError> for SessionError {
    fn from(error: ReceiptError) -> Self {
        Self::Receipt(error)
    }
}

impl From<ModelError> for SessionError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<l2_segmentation::ReceiptError> for SessionError {
    fn from(error: l2_segmentation::ReceiptError) -> Self {
        Self::Segmentation(error)
    }
}
