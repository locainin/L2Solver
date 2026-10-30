//! Source-backed EAP Request observations and malformed frame evidence

use l2_capture::CapturedFrame;
use l2_onpath::MacAddress;

use crate::RunSummary;

use super::wire::Request;

/// What the scoped capture actually establishes
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dot1xStatus {
    /// At least one scoped EAP Request was captured
    Observed,
    /// No scoped EAP Request was captured
    Inconclusive,
}

/// Destination accepted for a scoped EAP Request
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dot1xDestination {
    /// The selected interface's unicast MAC
    SelectedInterface,
    /// The link-local 802.1X PAE group address
    PaeGroup,
}

/// The recognizable field that made an EAPOL frame unusable
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MalformedReason {
    /// The Ethernet sender was not a unicast identity
    SourceMac,
    /// The EAPOL version, header, or declared body length was invalid
    EapolHeader,
    /// The EAP header or its declared length was invalid
    EapHeader,
    /// The Request type, Notification message, or expanded type header was invalid
    RequestType,
}

/// One scoped EAP Request and the exact received frame
#[derive(Debug)]
pub struct Dot1xObservation {
    pub(super) request: Request,
    pub(super) frame: CapturedFrame,
}

impl Dot1xObservation {
    /// Return the unauthenticated Ethernet sender
    #[must_use]
    pub const fn source_mac(&self) -> MacAddress {
        self.request.source
    }

    /// Return which local destination received the frame
    #[must_use]
    pub const fn destination(&self) -> Dot1xDestination {
        self.request.destination
    }

    /// Return the EAPOL protocol version observed on the wire
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.request.version
    }

    /// Return the authenticator-chosen EAP Request identifier
    #[must_use]
    pub const fn identifier(&self) -> u8 {
        self.request.identifier
    }

    /// Return the EAP Request type without interpreting method data
    #[must_use]
    pub const fn request_type(&self) -> u8 {
        self.request.type_code
    }

    /// Borrow the original packet and its capture provenance
    #[must_use]
    pub const fn frame(&self) -> &CapturedFrame {
        &self.frame
    }
}

/// One recognizable but malformed scoped EAPOL frame
#[derive(Debug)]
pub struct Dot1xMalformed {
    pub(super) reason: MalformedReason,
    pub(super) frame: CapturedFrame,
}

impl Dot1xMalformed {
    /// Return the field group that failed validation
    #[must_use]
    pub const fn reason(&self) -> MalformedReason {
        self.reason
    }

    /// Borrow the original malformed packet and its capture provenance
    #[must_use]
    pub const fn frame(&self) -> &CapturedFrame {
        &self.frame
    }
}

/// Evidence observed after one Start, with shared transport accounting
///
/// Start has no transaction identifier. The selected destination and capture
/// window associate requests with the operation but cannot prove causation,
/// source identity, successful authentication, or port enforcement
#[derive(Debug)]
pub struct Dot1xReport {
    pub(super) observations: Vec<Dot1xObservation>,
    pub(super) malformed: Vec<Dot1xMalformed>,
    pub(super) unrelated_packets: u32,
    pub(super) summary: RunSummary,
}

impl Dot1xReport {
    /// Classify captured requests without inferring a result from silence
    #[must_use]
    pub const fn status(&self) -> Dot1xStatus {
        if self.observations.is_empty() {
            Dot1xStatus::Inconclusive
        } else {
            Dot1xStatus::Observed
        }
    }

    /// Borrow requests in capture order, including repeated packets
    #[must_use]
    pub fn observations(&self) -> &[Dot1xObservation] {
        &self.observations
    }

    /// Borrow recognizable malformed frames in capture order
    #[must_use]
    pub fn malformed(&self) -> &[Dot1xMalformed] {
        &self.malformed
    }

    /// Count complete scoped frames outside the supported request profile
    #[must_use]
    pub const fn unrelated_packets(&self) -> u32 {
        self.unrelated_packets
    }

    /// Borrow transport, capture-quality, and termination accounting
    #[must_use]
    pub const fn summary(&self) -> &RunSummary {
        &self.summary
    }
}
