//! Checked ARP announcement semantics for controlled neighbor assessments

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
};

use crate::{AddressFamily, CheckKind, ControlledEndpoint, RunId, Stimulus, TxCommitment};

// This profile accepts one Ethernet/IPv4 ARP announcement and minimum-frame padding
const MAX_FRAME_LEN: usize = 60;
const ETHERNET_DATALINK: u32 = 1;
const ARP_ETHER_TYPE: &[u8] = &[0x08, 0x06];

/// The sender's relationship to the declared neighbor
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArpAnnouncementKind {
    /// The neighbor announces its own checked identity
    Control,
    /// A different controlled sender announces the neighbor's address
    Conflict,
}

/// An ARP scope or frame did not satisfy the selected announcement profile
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArpProofError {
    /// Only the initial ARP susceptibility check is supported
    UnsupportedCheck,
    /// The stimulus does not identify the declared sender
    SenderMismatch,
    /// Every role must have a checked IPv4 binding
    Ipv4Required,
    /// Every role must use the Ethernet data-link type
    NonEthernetInterface,
    /// The observer must be a different agent from both sender and subject
    DuplicateAgent,
    /// One agent was supplied with conflicting bindings or interfaces
    ConflictingIdentity,
    /// Different agents cannot share one namespace and interface index
    DuplicateInterface,
    /// Different agents cannot share a configured IPv4 address
    DuplicateAddress,
    /// Different agents cannot share a configured Ethernet address
    DuplicateMac,
    /// The input exceeds this profile's maximum complete-frame size
    FrameTooLong { length: usize },
    /// The Ethernet type is missing, tagged, or not ARP
    WrongEtherType,
    /// The shared Ethernet decoder rejected the input
    Ethernet(l2_core::DecodeError),
    /// The Ethernet destination is not broadcast
    WrongDestination,
    /// The Ethernet source does not match the planned sender
    WrongSource,
    /// The shared ARP decoder rejected the supported Ethernet/IPv4 layout
    InvalidArp,
    /// The ARP operation is not a request
    WrongOperation,
    /// The ARP sender hardware address does not match the planned sender
    WrongSenderHardware,
    /// The ARP sender or target protocol address differs from the subject
    WrongProtocolAddress,
    /// The ARP target hardware address is not zero
    WrongTargetHardware,
    /// The canonical frame commitment could not be constructed
    Commitment(l2_segmentation::ReceiptError),
}

impl fmt::Display for ArpProofError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCheck => output.write_str("unsupported ARP check"),
            Self::SenderMismatch => output.write_str("stimulus sender does not match the scope"),
            Self::Ipv4Required => output.write_str("ARP scope requires IPv4 bindings"),
            Self::NonEthernetInterface => {
                output.write_str("ARP scope requires Ethernet interfaces")
            }
            Self::DuplicateAgent => output.write_str("ARP observer must be a different agent"),
            Self::ConflictingIdentity => {
                output.write_str("one agent has conflicting endpoint identities")
            }
            Self::DuplicateInterface => output.write_str("different agents share an interface"),
            Self::DuplicateAddress => output.write_str("different agents share an IPv4 address"),
            Self::DuplicateMac => output.write_str("different agents share a MAC address"),
            Self::FrameTooLong { length } => write!(
                output,
                "ARP frame length {length} exceeds {MAX_FRAME_LEN} bytes"
            ),
            Self::WrongEtherType => output.write_str("frame does not carry untagged ARP"),
            Self::Ethernet(error) => write!(output, "invalid Ethernet frame: {error}"),
            Self::WrongDestination => {
                output.write_str("ARP announcement destination is not broadcast")
            }
            Self::WrongSource => output.write_str("Ethernet source does not match the sender"),
            Self::InvalidArp => output.write_str("invalid Ethernet/IPv4 ARP packet"),
            Self::WrongOperation => output.write_str("ARP announcement is not a request"),
            Self::WrongSenderHardware => {
                output.write_str("ARP sender hardware does not match the sender")
            }
            Self::WrongProtocolAddress => {
                output.write_str("ARP protocol addresses do not match the subject")
            }
            Self::WrongTargetHardware => {
                output.write_str("ARP target hardware address is not zero")
            }
            Self::Commitment(error) => write!(output, "ARP frame commitment failed: {error}"),
        }
    }
}

impl std::error::Error for ArpProofError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ethernet(error) => Some(error),
            Self::Commitment(error) => Some(error),
            _ => None,
        }
    }
}

/// Checked sender, observer, and subject for one planned ARP stimulus
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpScope {
    stimulus: Stimulus,
    sender: ControlledEndpoint,
    observer: ControlledEndpoint,
    subject: ControlledEndpoint,
}

impl ArpScope {
    /// Check identities without assigning a caller-selected outcome or role
    ///
    /// # Errors
    /// Rejects another check, mismatched sender, non-IPv4 or non-Ethernet roles,
    /// aliased observers, or conflicting agent and interface identities
    pub fn new(
        stimulus: Stimulus,
        sender: ControlledEndpoint,
        observer: ControlledEndpoint,
        subject: ControlledEndpoint,
    ) -> Result<Self, ArpProofError> {
        validate_stimulus(stimulus, sender)?;
        validate_roles(sender, observer, subject)?;
        Ok(Self {
            stimulus,
            sender,
            observer,
            subject,
        })
    }

    /// Return the planned stimulus and its sequence
    #[must_use]
    pub const fn stimulus(self) -> Stimulus {
        self.stimulus
    }

    /// Return the endpoint that supplies the ARP frame
    #[must_use]
    pub const fn sender(self) -> ControlledEndpoint {
        self.sender
    }

    /// Return the endpoint whose neighbor cache will be observed
    #[must_use]
    pub const fn observer(self) -> ControlledEndpoint {
        self.observer
    }

    /// Return the endpoint whose address is claimed
    #[must_use]
    pub const fn subject(self) -> ControlledEndpoint {
        self.subject
    }

    /// Derive control or conflict from the checked role identities
    #[must_use]
    pub fn kind(self) -> ArpAnnouncementKind {
        if self.sender.id() == self.subject.id() {
            ArpAnnouncementKind::Control
        } else {
            ArpAnnouncementKind::Conflict
        }
    }
}

fn validate_stimulus(stimulus: Stimulus, sender: ControlledEndpoint) -> Result<(), ArpProofError> {
    if stimulus.check() != CheckKind::ArpSpoofSusceptibility {
        return Err(ArpProofError::UnsupportedCheck);
    }
    if stimulus.endpoint() != sender.id() {
        return Err(ArpProofError::SenderMismatch);
    }
    Ok(())
}

fn validate_roles(
    sender: ControlledEndpoint,
    observer: ControlledEndpoint,
    subject: ControlledEndpoint,
) -> Result<(), ArpProofError> {
    for endpoint in [sender, observer, subject] {
        validate_endpoint(endpoint)?;
    }
    // The observer is never allowed to stand in for another role
    validate_distinct(sender, observer)?;
    if sender.id() == subject.id() {
        if sender != subject {
            return Err(ArpProofError::ConflictingIdentity);
        }
    } else {
        validate_distinct(sender, subject)?;
        validate_distinct(observer, subject)?;
    }
    Ok(())
}

fn validate_endpoint(endpoint: ControlledEndpoint) -> Result<(), ArpProofError> {
    if endpoint.family() != AddressFamily::Ipv4 {
        return Err(ArpProofError::Ipv4Required);
    }
    if endpoint.interface().datalink() != ETHERNET_DATALINK {
        return Err(ArpProofError::NonEthernetInterface);
    }
    Ok(())
}

fn validate_distinct(
    left: ControlledEndpoint,
    right: ControlledEndpoint,
) -> Result<(), ArpProofError> {
    if left.id() == right.id() {
        return Err(ArpProofError::DuplicateAgent);
    }
    let left_interface = left.interface();
    let right_interface = right.interface();
    // Datalink metadata is not part of the namespace and ifindex identity
    if left_interface.namespace_device() == right_interface.namespace_device()
        && left_interface.namespace_inode() == right_interface.namespace_inode()
        && left_interface.ifindex() == right_interface.ifindex()
    {
        return Err(ArpProofError::DuplicateInterface);
    }
    if left.binding().address() == right.binding().address() {
        return Err(ArpProofError::DuplicateAddress);
    }
    if left.binding().mac() == right.binding().mac() {
        return Err(ArpProofError::DuplicateMac);
    }
    Ok(())
}

/// One checked ARP announcement and its canonical exact-frame commitment
///
/// This value validates planned bytes and roles only; it does not prove a frame
/// was sent or observed, or establish a network-control verdict
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedArpAnnouncement {
    scope: ArpScope,
    commitment: TxCommitment,
}

impl ValidatedArpAnnouncement {
    /// Validate a bounded FCS-free frame and commit its exact bytes
    ///
    /// The input may omit Ethernet minimum-frame padding or contain at most
    /// eighteen arbitrary padding bytes. This is a selected model profile, not
    /// a claim that shorter input is a complete physical wire frame. The caller
    /// must exclude any FCS because padding and FCS bytes cannot be distinguished
    /// by this byte-only interface
    ///
    /// # Errors
    /// Rejects frames outside the profile or inconsistent with the checked scope
    pub fn from_frame(
        run: RunId,
        scope: ArpScope,
        exact_frame: &[u8],
    ) -> Result<Self, ArpProofError> {
        let frame = decode_arp_frame(exact_frame)?;
        validate_announcement(scope, &frame)?;
        // The commitment hashes the same complete bytes that were just validated
        let commitment = TxCommitment::from_frame_claim(
            run.into_bytes(),
            scope.stimulus.sequence(),
            scope.sender.interface(),
            exact_frame,
        )
        .map_err(ArpProofError::Commitment)?;
        Ok(Self { scope, commitment })
    }

    /// Return the checked sender, observer, subject, and stimulus
    #[must_use]
    pub const fn scope(self) -> ArpScope {
        self.scope
    }

    /// Return the one canonical exact-frame transmit commitment
    #[must_use]
    pub const fn commitment(self) -> TxCommitment {
        self.commitment
    }
}

fn decode_arp_frame(exact_frame: &[u8]) -> Result<l2_core::EthernetFrame<'_>, ArpProofError> {
    if exact_frame.len() > MAX_FRAME_LEN {
        return Err(ArpProofError::FrameTooLong {
            length: exact_frame.len(),
        });
    }
    // Reject tagged or other types before the shared decoder can allocate tags
    if exact_frame.get(12..14) != Some(ARP_ETHER_TYPE) {
        return Err(ArpProofError::WrongEtherType);
    }
    l2_core::decode(exact_frame).map_err(ArpProofError::Ethernet)
}

fn validate_announcement(
    scope: ArpScope,
    frame: &l2_core::EthernetFrame<'_>,
) -> Result<(), ArpProofError> {
    if frame.destination != [0xff; 6] {
        return Err(ArpProofError::WrongDestination);
    }
    if frame.source != scope.sender.binding().mac().bytes() {
        return Err(ArpProofError::WrongSource);
    }
    let arp = l2_discovery::arp_packet(frame).ok_or(ArpProofError::InvalidArp)?;
    validate_arp_fields(scope, arp)
}

fn validate_arp_fields(scope: ArpScope, arp: l2_discovery::ArpPacket) -> Result<(), ArpProofError> {
    if arp.operation != 1 {
        return Err(ArpProofError::WrongOperation);
    }
    if arp.sender_mac != scope.sender.binding().mac().bytes() {
        return Err(ArpProofError::WrongSenderHardware);
    }
    if IpAddr::V4(Ipv4Addr::from(arp.sender_ip)) != scope.subject.binding().address()
        || IpAddr::V4(Ipv4Addr::from(arp.target_ip)) != scope.subject.binding().address()
    {
        return Err(ArpProofError::WrongProtocolAddress);
    }
    if arp.target_mac != [0; 6] {
        return Err(ArpProofError::WrongTargetHardware);
    }
    Ok(())
}
