//! Structurally checked controller and observation claims
//!
//! Public constructors validate field relationships only. These values do not
//! prove that a helper, physical agent, interface, or kernel produced them

use l2_canary::{Canary, ID_LEN, VerifiedCanary};
use l2_capture::PacketReference;
use l2_helper_protocol::InterfaceBindingRequest;
use sha2::{Digest, Sha256};

use crate::{AgentId, PlannedCanaryFrame, ReceiptError};

/// Checked identity for one local monotonic clock domain
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClockDomainId([u8; ID_LEN]);

impl ClockDomainId {
    /// Construct a nonzero clock-domain identity
    ///
    /// # Errors
    /// Returns [`ReceiptError::ZeroClockDomain`] for the reserved zero value
    pub fn new(value: [u8; ID_LEN]) -> Result<Self, ReceiptError> {
        if value.iter().all(|byte| *byte == 0) {
            Err(ReceiptError::ZeroClockDomain)
        } else {
            Ok(Self(value))
        }
    }

    /// Return the recorded clock-domain identity
    #[must_use]
    pub const fn get(self) -> [u8; ID_LEN] {
        self.0
    }
}

/// A checked timestamp from one local clock domain
///
/// The type deliberately does not implement [`Ord`] or [`PartialOrd`]. Local
/// ticks from separate hosts cannot be ordered safely by the type system
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ClockStamp {
    domain: ClockDomainId,
    ticks: u64,
}

impl ClockStamp {
    /// Construct one nonzero local clock stamp
    ///
    /// # Errors
    /// Returns a clock-domain or tick validation error
    pub const fn new(domain: ClockDomainId, ticks: u64) -> Result<Self, ReceiptError> {
        if ticks == 0 {
            return Err(ReceiptError::ZeroClockTicks);
        }
        Ok(Self { domain, ticks })
    }

    /// Return the local clock domain
    #[must_use]
    pub const fn domain(self) -> ClockDomainId {
        self.domain
    }

    /// Return the local monotonic tick value
    #[must_use]
    pub const fn ticks(self) -> u64 {
        self.ticks
    }
}

/// Checked event identity from the controller causal stream
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ControllerEvent {
    run_id: [u8; ID_LEN],
    sequence: u64,
    ordinal: u64,
}

impl ControllerEvent {
    /// Construct a nonzero controller event identity within one run
    ///
    /// # Errors
    /// Returns a validation error for a zero run or ordinal
    pub fn new(run_id: [u8; ID_LEN], sequence: u64, ordinal: u64) -> Result<Self, ReceiptError> {
        if run_id.iter().all(|byte| *byte == 0) {
            Err(ReceiptError::ZeroControllerRun)
        } else if sequence == 0 {
            Err(ReceiptError::ZeroSequence)
        } else if ordinal == 0 {
            Err(ReceiptError::ZeroControllerEvent)
        } else {
            Ok(Self {
                run_id,
                sequence,
                ordinal,
            })
        }
    }

    /// Return the run containing the controller event
    #[must_use]
    pub const fn run_id(self) -> [u8; ID_LEN] {
        self.run_id
    }

    /// Return the exact operation sequence owning this event
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Return the one-based causal ordinal
    #[must_use]
    pub const fn ordinal(self) -> u64 {
        self.ordinal
    }
}

/// Causal and local timing fields for one claimed transmit
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxTiming {
    local_commit: ClockStamp,
    committed: ControllerEvent,
}

impl TxTiming {
    /// Construct transmit timing from local and controller claims
    #[must_use]
    pub const fn new(local_commit: ClockStamp, committed: ControllerEvent) -> Self {
        Self {
            local_commit,
            committed,
        }
    }

    /// Return the local commit stamp
    #[must_use]
    pub const fn local_commit(self) -> ClockStamp {
        self.local_commit
    }

    /// Return the controller event that committed the transmit
    #[must_use]
    pub const fn committed_event(self) -> ControllerEvent {
        self.committed
    }
}

/// Local and controller timing for one bounded observation window
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationWindowTiming {
    local_armed: ClockStamp,
    local_closed: ClockStamp,
    arm_ack: ControllerEvent,
    close_issued: ControllerEvent,
    complete: ControllerEvent,
}

impl ObservationWindowTiming {
    /// Construct checked local and causal window timing
    ///
    /// Local bounds are compared only after proving that they belong to the
    /// same domain. Controller events form the cross-host causal order
    ///
    /// # Errors
    /// Returns an error for mixed local domains, reversed local bounds, or
    /// equal/reversed controller lifecycle events
    pub fn new(
        local_armed: ClockStamp,
        local_closed: ClockStamp,
        arm_ack: ControllerEvent,
        close_issued: ControllerEvent,
        complete: ControllerEvent,
    ) -> Result<Self, ReceiptError> {
        if local_armed.domain() != local_closed.domain() {
            return Err(ReceiptError::ClockDomainMismatch);
        }
        if local_closed.ticks() < local_armed.ticks() {
            return Err(ReceiptError::InvalidWindow);
        }
        if arm_ack.run_id() != close_issued.run_id() || close_issued.run_id() != complete.run_id() {
            return Err(ReceiptError::ControllerRunMismatch);
        }
        if arm_ack.sequence() != close_issued.sequence()
            || close_issued.sequence() != complete.sequence()
        {
            return Err(ReceiptError::ControllerSequenceMismatch);
        }
        if !(arm_ack.ordinal() < close_issued.ordinal()
            && close_issued.ordinal() < complete.ordinal())
        {
            return Err(ReceiptError::InvalidControllerOrder);
        }
        Ok(Self {
            local_armed,
            local_closed,
            arm_ack,
            close_issued,
            complete,
        })
    }

    /// Return the local armed stamp
    #[must_use]
    pub const fn local_armed(self) -> ClockStamp {
        self.local_armed
    }

    /// Return the local closed stamp
    #[must_use]
    pub const fn local_closed(self) -> ClockStamp {
        self.local_closed
    }

    /// Return the controller arm acknowledgement event
    #[must_use]
    pub const fn arm_ack(self) -> ControllerEvent {
        self.arm_ack
    }

    /// Return the controller close-issued event
    #[must_use]
    pub const fn close_issued(self) -> ControllerEvent {
        self.close_issued
    }

    /// Return the controller completion event
    #[must_use]
    pub const fn complete(self) -> ControllerEvent {
        self.complete
    }
}

/// Semantic subject bound to one exact planned transmission
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitmentSubject {
    /// The bytes are structurally valid but have no protocol-specific meaning
    UnboundFrameClaim,
    /// The bytes carry this exact authenticated canary
    Canary(Canary),
}

/// Checked expected hash and interface for one exact planned transmission
///
/// A commitment records the complete frame digest and the interface binding
/// that a future send boundary must use
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxCommitment {
    run_id: [u8; ID_LEN],
    sequence: u64,
    interface: InterfaceBindingRequest,
    frame_hash: [u8; 32],
    frame_length: u64,
    subject: CommitmentSubject,
}

impl TxCommitment {
    /// Derive a generic frame commitment from the exact complete bytes
    ///
    /// # Errors
    /// Rejects a sentinel run identity, sequence zero, or invalid Ethernet frame
    pub fn from_frame_claim(
        run_id: [u8; ID_LEN],
        sequence: u64,
        interface: InterfaceBindingRequest,
        frame: &[u8],
    ) -> Result<Self, ReceiptError> {
        if run_id.iter().all(|byte| *byte == 0) {
            return Err(ReceiptError::ZeroRunId);
        }
        if sequence == 0 {
            return Err(ReceiptError::ZeroSequence);
        }
        // Commitments represent complete frames, not arbitrary digest claims
        l2_core::decode(frame).map_err(|_| ReceiptError::InvalidFrame)?;
        let frame_hash: [u8; 32] = Sha256::digest(frame).into();
        let frame_length =
            u64::try_from(frame.len()).map_err(|_| ReceiptError::FrameLengthOverflow)?;
        if frame_hash.iter().all(|byte| *byte == 0) {
            return Err(ReceiptError::ZeroFrameHash);
        }
        Ok(Self {
            run_id,
            sequence,
            interface,
            frame_hash,
            frame_length,
            subject: CommitmentSubject::UnboundFrameClaim,
        })
    }

    /// Bind a canary commitment to one checked planned frame
    #[must_use]
    pub const fn from_planned_frame(
        frame: &PlannedCanaryFrame,
        interface: InterfaceBindingRequest,
    ) -> Self {
        let canary = frame.canary();
        Self {
            run_id: canary.run_id().into_bytes(),
            sequence: canary.sequence(),
            interface,
            frame_hash: frame.frame_hash(),
            frame_length: frame.frame_length(),
            subject: CommitmentSubject::Canary(canary),
        }
    }

    /// Return the committed run identity
    #[must_use]
    pub const fn run_id(self) -> [u8; ID_LEN] {
        self.run_id
    }

    /// Return the one-based planned probe sequence
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Return the expected send-interface binding
    #[must_use]
    pub const fn interface(self) -> InterfaceBindingRequest {
        self.interface
    }

    /// Return the expected exact frame hash
    #[must_use]
    pub const fn frame_hash(self) -> [u8; 32] {
        self.frame_hash
    }

    /// Return the exact byte count committed for this frame
    #[must_use]
    pub const fn frame_length(self) -> u64 {
        self.frame_length
    }

    /// Return the exact canary bound into this commitment, when present
    #[must_use]
    pub const fn planned_canary(self) -> Option<Canary> {
        match self.subject {
            CommitmentSubject::Canary(canary) => Some(canary),
            CommitmentSubject::UnboundFrameClaim => None,
        }
    }

    /// Return what protocol meaning, if any, is bound to the exact bytes
    #[must_use]
    pub const fn subject(self) -> CommitmentSubject {
        self.subject
    }
}

/// A caller-supplied claim that one planned frame reached a send boundary
///
/// Construction checks structure only. A future execution boundary must issue
/// an opaque authority receipt before this can prove physical or kernel activity
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxReceipt {
    run_id: [u8; ID_LEN],
    sequence: u64,
    interface: InterfaceBindingRequest,
    frame_hash: [u8; 32],
    timing: TxTiming,
}

impl TxReceipt {
    /// Construct a structurally checked transmit claim
    ///
    /// # Errors
    /// Rejects sentinel identities, sequence zero, or an empty hash
    pub fn new(
        run_id: [u8; ID_LEN],
        sequence: u64,
        interface: InterfaceBindingRequest,
        frame_hash: [u8; 32],
        timing: TxTiming,
    ) -> Result<Self, ReceiptError> {
        if run_id.iter().all(|byte| *byte == 0) {
            return Err(ReceiptError::ZeroRunId);
        }
        if sequence == 0 {
            return Err(ReceiptError::ZeroSequence);
        }
        if frame_hash.iter().all(|byte| *byte == 0) {
            return Err(ReceiptError::ZeroFrameHash);
        }
        if timing.committed_event().run_id() != run_id {
            return Err(ReceiptError::ControllerRunMismatch);
        }
        if timing.committed_event().sequence() != sequence {
            return Err(ReceiptError::ControllerSequenceMismatch);
        }
        Ok(Self {
            run_id,
            sequence,
            interface,
            frame_hash,
            timing,
        })
    }

    /// Return the committed run identity
    #[must_use]
    pub const fn run_id(self) -> [u8; ID_LEN] {
        self.run_id
    }

    /// Return the one-based planned probe sequence
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Return the claimed interface binding used for the send
    #[must_use]
    pub const fn interface(self) -> InterfaceBindingRequest {
        self.interface
    }

    /// Return the claimed exact frame hash handed to the send boundary
    #[must_use]
    pub const fn frame_hash(self) -> [u8; 32] {
        self.frame_hash
    }

    /// Return the typed local and controller timing evidence
    #[must_use]
    pub const fn timing(self) -> TxTiming {
        self.timing
    }

    /// Return the controller event that committed the send
    #[must_use]
    pub const fn committed_event(self) -> ControllerEvent {
        self.timing.committed_event()
    }

    /// Return the local stamp captured when the send committed
    #[must_use]
    pub const fn local_commit(self) -> ClockStamp {
        self.timing.local_commit()
    }
}

/// A caller-supplied claim about one bounded receiver interval
///
/// Construction does not attest that the named receiver or interface collected
/// traffic. It only keeps later causal and structural checks explicit
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationWindowReceipt {
    run_id: [u8; ID_LEN],
    sequence: u64,
    receiver: AgentId,
    receiver_interface: InterfaceBindingRequest,
    timing: ObservationWindowTiming,
    capture_loss: u64,
    complete: bool,
}

impl ObservationWindowReceipt {
    /// Construct a structurally checked receiver-window claim
    ///
    /// # Errors
    /// Rejects sentinel identities or timing values rejected by
    /// [`ObservationWindowTiming::new`]
    pub fn new(
        run_id: [u8; ID_LEN],
        sequence: u64,
        receiver: AgentId,
        receiver_interface: InterfaceBindingRequest,
        timing: ObservationWindowTiming,
        capture_loss: u64,
        complete: bool,
    ) -> Result<Self, ReceiptError> {
        if run_id.iter().all(|byte| *byte == 0) {
            return Err(ReceiptError::ZeroRunId);
        }
        if sequence == 0 {
            return Err(ReceiptError::ZeroSequence);
        }
        if timing.arm_ack().run_id() != run_id {
            return Err(ReceiptError::ControllerRunMismatch);
        }
        if timing.arm_ack().sequence() != sequence {
            return Err(ReceiptError::ControllerSequenceMismatch);
        }
        Ok(Self {
            run_id,
            sequence,
            receiver,
            receiver_interface,
            timing,
            capture_loss,
            complete,
        })
    }

    /// Return the committed run identity
    #[must_use]
    pub const fn run_id(self) -> [u8; ID_LEN] {
        self.run_id
    }

    /// Return the one-based planned probe sequence
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Return the expected receiver identity
    #[must_use]
    pub const fn receiver(self) -> AgentId {
        self.receiver
    }

    /// Return the interface claimed by the receiver window
    #[must_use]
    pub const fn receiver_interface(self) -> InterfaceBindingRequest {
        self.receiver_interface
    }

    /// Return the typed local and controller timing fields
    #[must_use]
    pub const fn timing(self) -> ObservationWindowTiming {
        self.timing
    }

    /// Return the local armed stamp
    #[must_use]
    pub const fn armed_at(self) -> ClockStamp {
        self.timing.local_armed()
    }

    /// Return the local closed stamp
    #[must_use]
    pub const fn closed_at(self) -> ClockStamp {
        self.timing.local_closed()
    }

    /// Return capture records lost during the interval
    #[must_use]
    pub const fn capture_loss(self) -> u64 {
        self.capture_loss
    }

    /// Return whether the controller completed the interval
    #[must_use]
    pub const fn complete(self) -> bool {
        self.complete
    }

    /// Return whether the controller event chain covers the committed send
    /// causally
    #[must_use]
    pub fn causally_covers(self, transmit: TxReceipt) -> bool {
        self.run_id == transmit.run_id
            && self.sequence == transmit.sequence
            && self.timing.arm_ack().run_id() == transmit.committed_event().run_id()
            && self.timing.arm_ack().ordinal() < transmit.committed_event().ordinal()
            && transmit.committed_event().ordinal() < self.timing.close_issued().ordinal()
            && self.timing.close_issued().ordinal() < self.timing.complete().ordinal()
    }

    /// Return whether the supplied claims structurally support causal absence
    #[must_use]
    pub fn proves_complete_absence_for(self, transmit: TxReceipt) -> bool {
        self.complete && self.capture_loss == 0 && self.causally_covers(transmit)
    }
}

/// An authenticated canary tied to one claimed receiver observation point
///
/// This type prevents a source or independent TAP observation from being
/// confused with destination arrival by requiring receiver, interface, and
/// local-window agreement. It remains a structurally checked caller claim
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanaryArrivalReceipt {
    verified: VerifiedCanary,
    receiver: AgentId,
    window: ObservationWindowReceipt,
    observed_interface: InterfaceBindingRequest,
    observed_at: ClockStamp,
    evidence_packet: PacketReference,
}

impl CanaryArrivalReceipt {
    /// Bind authenticated bytes to the receiver that claims the observation
    ///
    /// # Errors
    /// Rejects mismatched run, probe, receiver, interface, clock domain, local
    /// window bounds, or a zero evidence reference
    pub fn from_verified(
        verified: VerifiedCanary,
        window: ObservationWindowReceipt,
        observed_interface: InterfaceBindingRequest,
        observed_at: ClockStamp,
        evidence_packet: PacketReference,
    ) -> Result<Self, ReceiptError> {
        let canary = *verified.as_canary();
        if window.run_id() != canary.run_id().into_bytes() || window.sequence() != canary.sequence()
        {
            return Err(ReceiptError::ObservationScopeMismatch);
        }
        if window.receiver() != canary.destination_agent_id() {
            return Err(ReceiptError::WrongReceiver);
        }
        if window.receiver_interface() != observed_interface {
            return Err(ReceiptError::ObservationInterfaceMismatch);
        }
        if observed_at.domain() != window.armed_at().domain() {
            return Err(ReceiptError::ClockDomainMismatch);
        }
        if observed_at.ticks() < window.armed_at().ticks()
            || observed_at.ticks() > window.closed_at().ticks()
        {
            return Err(ReceiptError::ObservationOutsideWindow);
        }
        Ok(Self {
            verified,
            receiver: window.receiver(),
            window,
            observed_interface,
            observed_at,
            evidence_packet,
        })
    }

    /// Return the authenticated canary fields
    #[must_use]
    pub const fn canary(self) -> Canary {
        self.verified.into_canary()
    }

    /// Return the authenticated wrapper for replay validation inside this crate
    pub(crate) const fn verified(self) -> VerifiedCanary {
        self.verified
    }

    /// Return the receiver that claims the destination observation
    #[must_use]
    pub const fn receiver(self) -> AgentId {
        self.receiver
    }

    /// Return the checked receiver window
    #[must_use]
    pub const fn window(self) -> ObservationWindowReceipt {
        self.window
    }

    /// Return the interface claimed as the observation point
    #[must_use]
    pub const fn observed_interface(self) -> InterfaceBindingRequest {
        self.observed_interface
    }

    /// Return the receiver-local observation stamp
    #[must_use]
    pub const fn observed_at(self) -> ClockStamp {
        self.observed_at
    }

    /// Return the packet evidence reference
    #[must_use]
    pub const fn evidence_packet(self) -> PacketReference {
        self.evidence_packet
    }

    /// Return the digest of the exact authenticated canary payload
    #[must_use]
    pub const fn wire_sha256(self) -> [u8; 32] {
        self.verified.wire_sha256()
    }
}
