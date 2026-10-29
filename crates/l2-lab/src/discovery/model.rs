//! Input policy and observed values for the synthetic neighbor receiver

use l2_canary::AgentId;
use l2_segmentation::{EvaluationStatus, PacketReference};

/// Discovery protocol selected for a controlled synthetic frame
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    /// IEEE LLDP over Ethernet II
    Lldp,
    /// CDP over IEEE 802.3 LLC/SNAP
    Cdp,
}

impl Protocol {
    pub(crate) const fn capture_code(self) -> u8 {
        match self {
            Self::Lldp => 1,
            Self::Cdp => 2,
        }
    }
}

/// Claimed device and port bytes as represented by the selected protocol
///
/// LLDP values include their subtype octet. CDP values are the raw device-ID
/// and port-ID TLV values. These bytes are synthetic and are not authenticated
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity<'a> {
    device: &'a [u8],
    port: &'a [u8],
}

impl<'a> Identity<'a> {
    /// Borrow expected or observed identity bytes without interpreting text
    #[must_use]
    pub const fn new(device: &'a [u8], port: &'a [u8]) -> Self {
        Self { device, port }
    }

    /// Return the device or chassis identifier bytes
    #[must_use]
    pub const fn device(self) -> &'a [u8] {
        self.device
    }

    /// Return the port identifier bytes
    #[must_use]
    pub const fn port(self) -> &'a [u8] {
        self.port
    }
}

/// Independently specified policy for one synthetic receiver event
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Expectation<'a> {
    /// The receiver must learn the configured identity
    Accepted(Identity<'a>),
    /// The receiver must reject the frame without changing this neighbor
    Rejected,
    /// The receiver must remove the configured existing identity
    Withdrawn(Identity<'a>),
}

/// One scheduled frame and its independent expected receiver outcome
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Probe<'a> {
    pub(crate) sequence: u64,
    pub(crate) at_millis: u64,
    pub(crate) source: AgentId,
    pub(crate) protocol: Protocol,
    pub(crate) frame: &'a [u8],
    pub(crate) expectation: Expectation<'a>,
}

impl<'a> Probe<'a> {
    /// Describe one frame; admission checks all bounds before execution
    #[must_use]
    pub const fn new(
        sequence: u64,
        at_millis: u64,
        source: AgentId,
        protocol: Protocol,
        frame: &'a [u8],
        expectation: Expectation<'a>,
    ) -> Self {
        Self {
            sequence,
            at_millis,
            source,
            protocol,
            frame,
            expectation,
        }
    }
}

/// Actual transition reported by the modeled receiver
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observed<'a> {
    /// A valid, nonzero-hold advertisement was accepted
    Accepted(Identity<'a>),
    /// The frame was rejected before it could change this neighbor
    Rejected,
    /// A valid zero-hold advertisement requested withdrawal
    Withdrawn(Identity<'a>),
}

/// One complete receiver-side observation and its source-scoped evidence
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation<'a> {
    pub(crate) sequence: u64,
    pub(crate) at_millis: u64,
    pub(crate) source: AgentId,
    pub(crate) protocol: Protocol,
    pub(crate) frame: &'a [u8],
    pub(crate) observed: Observed<'a>,
    pub(crate) before: Option<Identity<'a>>,
    pub(crate) after: Option<Identity<'a>>,
    pub(crate) reference: PacketReference,
}

impl<'a> Observation<'a> {
    /// Return the scheduled probe sequence
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    /// Return the virtual millisecond offset
    #[must_use]
    pub const fn at_millis(self) -> u64 {
        self.at_millis
    }
    /// Return the synthetic sending-agent label
    #[must_use]
    pub const fn source(self) -> AgentId {
        self.source
    }
    /// Return the expected protocol framing used by the receiver
    #[must_use]
    pub const fn protocol(self) -> Protocol {
        self.protocol
    }
    /// Borrow the exact delivered frame including its Ethernet header
    #[must_use]
    pub const fn frame(self) -> &'a [u8] {
        self.frame
    }
    /// Return the observed receiver decision
    #[must_use]
    pub const fn observed(self) -> Observed<'a> {
        self.observed
    }
    /// Return the neighbor state after expiry and before this frame
    #[must_use]
    pub const fn before(self) -> Option<Identity<'a>> {
        self.before
    }
    /// Return the neighbor state immediately after this frame
    #[must_use]
    pub const fn after(self) -> Option<Identity<'a>> {
        self.after
    }
    /// Return a one-based reference into the synthetic capture stream
    #[must_use]
    pub const fn reference(self) -> PacketReference {
        self.reference
    }
}

/// Policy result for one dispatched stimulus
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Check<'a> {
    pub(crate) expectation: Expectation<'a>,
    pub(crate) sequence: u64,
    pub(crate) status: EvaluationStatus,
    pub(crate) evidence: Option<PacketReference>,
}

impl<'a> Check<'a> {
    /// Return the independently supplied policy for this probe
    #[must_use]
    pub const fn expectation(self) -> Expectation<'a> {
        self.expectation
    }
    /// Return the scheduled probe sequence
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    /// Return the evidence-based policy result
    #[must_use]
    pub const fn status(self) -> EvaluationStatus {
        self.status
    }
    /// Return captured evidence, if the observer recorded the event
    #[must_use]
    pub const fn evidence(self) -> Option<PacketReference> {
        self.evidence
    }
}
