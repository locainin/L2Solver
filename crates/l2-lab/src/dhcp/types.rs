//! Input, virtual message, and observed state values

use std::net::Ipv4Addr;

use l2_canary::{AgentId, RunId};
use l2_scenario::RunReport;
use l2_segmentation::EvaluationStatus;

use crate::{Cancellation, ObservationMode};

/// A server's modeled attachment and DHCP server identifier
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Server {
    agent: AgentId,
    identifier: Ipv4Addr,
}

impl Server {
    /// Associate an attachment identity with a DHCP server identifier
    #[must_use]
    pub const fn new(agent: AgentId, identifier: Ipv4Addr) -> Self {
        Self { agent, identifier }
    }

    /// Return the modeled sending attachment
    #[must_use]
    pub const fn agent(self) -> AgentId {
        self.agent
    }

    /// Return the DHCP server identifier
    #[must_use]
    pub const fn identifier(self) -> Ipv4Addr {
        self.identifier
    }
}

/// Explicit synthetic topology, expected server, transactions, and address limit
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Recorded identity for reproducible evidence
    pub run_id: RunId,
    /// Client used for the authorized-only positive control
    pub control_client: AgentId,
    /// Client exposed to the competing server
    pub client: AgentId,
    /// Server expected to serve both clients
    pub authorized_server: Server,
    /// Competing server on a separate modeled attachment
    pub rogue_server: Server,
    /// Address offered to the control client
    pub control_address: Ipv4Addr,
    /// Address offered to the test client by the authorized server
    pub authorized_address: Ipv4Addr,
    /// Address offered to the test client by the competing server
    pub rogue_address: Ipv4Addr,
    /// Nonzero control exchange transaction identifier
    pub control_transaction: u32,
    /// Distinct nonzero competing exchange transaction identifier
    pub transaction: u32,
    /// Maximum assignments expected from the authorized server in this run
    pub authorized_lease_limit: u8,
}

/// Separate virtual ingress policy, keyed by sending attachment, not claimed ID
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressPolicy {
    /// Deliver server responses only from this attachment
    TrustOnly(AgentId),
    /// Check offers against this attachment but let all acknowledgements through
    TrustOffersOnly(AgentId),
    /// Deliver every server response, including untrusted ones
    AllowAll,
}

impl IngressPolicy {
    pub(super) fn permits(self, source: AgentId, kind: MessageKind) -> bool {
        match self {
            Self::TrustOnly(trusted) => trusted == source,
            Self::TrustOffersOnly(trusted) => kind != MessageKind::Offer || trusted == source,
            Self::AllowAll => true,
        }
    }
}

/// One controlled fault in the modeled exchange or cleanup
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Fault {
    /// Normal server and cleanup behavior
    #[default]
    None,
    /// The control server does not issue its offer
    MissingControlOffer,
    /// The control server does not issue its acknowledgement
    MissingControlAck,
    /// The authorized server does not issue its target offer
    MissingTargetOffer,
    /// The authorized server does not issue its target acknowledgement
    MissingTargetAck,
    /// The target acknowledgement has a different transaction identifier
    WrongTargetTransaction,
    /// The target acknowledgement names a different offered address
    WrongTargetAddress,
    /// The target client ignores an otherwise matching acknowledgement
    TargetClientDoesNotBind,
    /// The target server acknowledges without retaining its binding
    TargetServerDoesNotBind,
    /// The rogue server claims the authorized server identifier
    RogueSpoofsIdentifier,
    /// The rogue acknowledgement copies the selected authorized ID and address
    RogueSpoofsSelectedReply,
    /// Leave modeled state in place after attempting cleanup
    CleanupNotRestored,
}

/// Per-run observer, cancellation, and fault controls
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Options {
    /// Receiver capture conditions for server offers and acknowledgements
    pub receiver: ObservationMode,
    /// Conditions for snapshots of client and server state
    pub state: ObservationMode,
    /// Boundary at which scheduled dispatch stops
    pub cancellation: Cancellation,
    /// Controlled fault to inject
    pub fault: Fault,
}

/// Modeled `DHCPv4` message types used by this selected exchange
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    /// Client requests offers
    Discover,
    /// Server proposes one address
    Offer,
    /// Client selects one server and address
    Request,
    /// Server acknowledges the selected address
    Ack,
}

/// One synthetic message observed at its sender or the client receiver
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Message {
    /// Schedule sequence and virtual timestamp in milliseconds
    pub sequence: u64,
    /// Message category
    pub kind: MessageKind,
    /// Modeled attachment that sent the message
    pub source: AgentId,
    /// Client participating in this exchange
    pub client: AgentId,
    /// Transaction identifier carried by the message
    pub transaction: u32,
    /// Server identifier advertised or selected, when present
    pub server_identifier: Option<Ipv4Addr>,
    /// Offered, requested, or acknowledged address, when present
    pub address: Option<Ipv4Addr>,
}

impl Message {
    // The client and evaluator compare the same selection fields
    pub(super) fn same_assignment(&self, other: &Self) -> bool {
        self.transaction == other.transaction
            && self.server_identifier == other.server_identifier
            && self.address == other.address
    }
}

/// A client's address binding attributed to one modeled server attachment
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lease {
    /// Client to which the address was assigned
    pub client: AgentId,
    /// Server attachment that made the assignment
    pub server: AgentId,
    /// Transaction used for the assignment
    pub transaction: u32,
    /// Assigned IPv4 address
    pub address: Ipv4Addr,
}

/// Complete mutable model state for one client exchange
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExchangeSnapshot {
    /// First offer selected by the modeled client, if any
    pub selected_offer: Option<Message>,
    /// Whether the modeled client sent a request for the selected offer
    pub requested: bool,
    /// Binding observed at the client
    pub client_lease: Option<Lease>,
    /// Binding observed at the selected server
    pub server_lease: Option<Lease>,
}

/// State observed independently from the sender and receiver transcript
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StateSnapshot {
    pub(super) control: ExchangeSnapshot,
    pub(super) target: ExchangeSnapshot,
}

impl StateSnapshot {
    /// Return control and target client bindings in stable order
    #[must_use]
    pub const fn client_leases(&self) -> [Option<Lease>; 2] {
        [self.control.client_lease, self.target.client_lease]
    }

    /// Return control and target server bindings in stable order
    #[must_use]
    pub const fn server_leases(&self) -> [Option<Lease>; 2] {
        [self.control.server_lease, self.target.server_lease]
    }

    /// Return the positive-control exchange state
    #[must_use]
    pub const fn control(&self) -> &ExchangeSnapshot {
        &self.control
    }

    /// Return the competing-server exchange state
    #[must_use]
    pub const fn target(&self) -> &ExchangeSnapshot {
        &self.target
    }
}

/// Decisive observation or missing condition for this DHCP assessment
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Both exchanges, guard behavior, limits, and restoration were observed
    Consistent,
    /// An unauthorized server response reached the client
    UnauthorizedResponse,
    /// An acknowledgement contradicted the request or selected offer
    InconsistentAcknowledgement,
    /// An observed client or server binding contradicted the expected state
    InconsistentLease,
    /// The authorized server exceeded the configured assignment limit
    LeaseLimitExceeded,
    /// Observed state after restoration differs from the pre-run state
    CleanupMismatch,
    /// Cancellation interrupted the scheduled exchange
    IncompleteRun,
    /// Receiver capture was unavailable or reported loss
    ReceiverIncomplete,
    /// State observations were unavailable or reported loss
    StateIncomplete,
    /// A required stimulus or positive-control response was missing
    MissingMessage,
}

impl Outcome {
    /// Map the DHCP-specific finding to the shared conservative status
    #[must_use]
    pub const fn status(self) -> EvaluationStatus {
        match self {
            Self::Consistent => EvaluationStatus::Pass,
            Self::UnauthorizedResponse
            | Self::InconsistentAcknowledgement
            | Self::InconsistentLease
            | Self::LeaseLimitExceeded
            | Self::CleanupMismatch => EvaluationStatus::Fail,
            Self::IncompleteRun
            | Self::ReceiverIncomplete
            | Self::StateIncomplete
            | Self::MissingMessage => EvaluationStatus::Inconclusive,
        }
    }
}

/// Modeled transcript, independently observed state, verdict, and scheduler report
#[derive(Debug, Eq, PartialEq)]
pub struct Run {
    pub(super) config: Config,
    pub(super) policy: IngressPolicy,
    pub(super) options: Options,
    pub(super) sent: Vec<Message>,
    pub(super) received: Vec<Message>,
    pub(super) before: Option<StateSnapshot>,
    pub(super) during: Option<StateSnapshot>,
    pub(super) after: Option<StateSnapshot>,
    pub(super) execution: RunReport,
    pub(super) outcome: Outcome,
}

impl Run {
    /// Return the recorded identity for this deterministic run
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.config.run_id
    }

    /// Return the topology and expected authorization used for this run
    #[must_use]
    pub const fn config(&self) -> Config {
        self.config
    }

    /// Return the independently selected virtual ingress policy
    #[must_use]
    pub const fn ingress_policy(&self) -> IngressPolicy {
        self.policy
    }

    /// Return the recorded observer, cancellation, and fault conditions
    #[must_use]
    pub const fn options(&self) -> Options {
        self.options
    }

    /// Return actual modeled messages emitted at their sender
    #[must_use]
    pub fn sent(&self) -> &[Message] {
        &self.sent
    }

    /// Return server messages independently observed at the client
    #[must_use]
    pub fn received(&self) -> &[Message] {
        &self.received
    }

    /// Return state observed before the run, if available
    #[must_use]
    pub const fn state_before(&self) -> Option<&StateSnapshot> {
        self.before.as_ref()
    }

    /// Return state observed after dispatch but before restoration, if available
    #[must_use]
    pub const fn state_during(&self) -> Option<&StateSnapshot> {
        self.during.as_ref()
    }

    /// Return state independently observed after restoration, if available
    #[must_use]
    pub const fn state_after(&self) -> Option<&StateSnapshot> {
        self.after.as_ref()
    }

    /// Return bounded scheduler accounting and the verified cleanup claim
    #[must_use]
    pub const fn execution(&self) -> RunReport {
        self.execution
    }

    /// Return the evidence-based reason for the outcome
    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// Return the DHCP-specific conservative result
    #[must_use]
    pub const fn status(&self) -> EvaluationStatus {
        self.outcome.status()
    }
}
