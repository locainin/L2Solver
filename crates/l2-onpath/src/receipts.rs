//! Structurally checked lifecycle and observation claims
//!
//! Public constructors validate relationships only. They do not prove that a
//! helper, kernel, interface, or physical agent produced the supplied values

use l2_canary::{Canary, ID_LEN, VerifiedCanary};
use l2_segmentation::PacketReference;
use l2_segmentation::{CanaryArrivalReceipt, ClockStamp, ObservationWindowReceipt, TxReceipt};

use crate::{
    AddressFamily, AgentId, InterfaceBindingRequest, ModelError, NeighborBinding,
    NeighborDisposition, StimulusId,
};

/// Reuse the segmentation transmit claim for a bounded frame
pub use l2_segmentation::TxReceipt as CommittedTxReceipt;

/// Reuse the segmentation observation-window claim
pub use l2_segmentation::ObservationWindowReceipt as NeighborWindowReceipt;

fn checked_run(run_id: [u8; ID_LEN]) -> Result<(), ModelError> {
    if run_id == [0; ID_LEN] {
        Err(ModelError::ZeroIdentity)
    } else {
        Ok(())
    }
}

/// Result of a precheck before any endpoint state can be armed
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrecheckReceipt {
    run_id: [u8; ID_LEN],
    endpoint_count: u16,
    capture_loss: u64,
    complete: bool,
}

impl PrecheckReceipt {
    /// Construct a precheck result with explicit endpoint and capture facts
    ///
    /// # Errors
    /// Returns [`ModelError`] when the run identity is invalid
    pub fn new(
        run_id: [u8; ID_LEN],
        endpoint_count: u16,
        capture_loss: u64,
        complete: bool,
    ) -> Result<Self, ModelError> {
        checked_run(run_id)?;
        Ok(Self {
            run_id,
            endpoint_count,
            capture_loss,
            complete,
        })
    }

    /// Construct a clean precheck that records the endpoint count explicitly
    ///
    /// # Errors
    /// Returns [`ModelError`] when the run identity is invalid
    pub fn complete_for_endpoints(
        run_id: [u8; ID_LEN],
        endpoint_count: u16,
    ) -> Result<Self, ModelError> {
        Self::new(run_id, endpoint_count, 0, true)
    }

    /// Return the run identity
    #[must_use]
    pub const fn run_id(self) -> [u8; ID_LEN] {
        self.run_id
    }

    /// Return the number of endpoints checked by the precheck
    #[must_use]
    pub const fn endpoint_count(self) -> u16 {
        self.endpoint_count
    }

    /// Return capture records lost during the precheck
    #[must_use]
    pub const fn capture_loss(self) -> u64 {
        self.capture_loss
    }

    /// Return whether all precheck operations completed
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.complete
    }

    /// Return whether this precheck is safe to authorize endpoint arming
    #[must_use]
    pub const fn is_clean(self) -> bool {
        self.complete && self.capture_loss == 0
    }
}

/// Caller-supplied snapshot of one original neighbor binding
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalBindingReceipt {
    run_id: [u8; ID_LEN],
    binding: NeighborBinding,
    interface: InterfaceBindingRequest,
    evidence_origin: EvidenceOrigin,
}

/// Whether an original binding has a source-qualified capture reference
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceOrigin {
    /// The binding claim points at one packet in an exact capture source
    Packet(PacketReference),
    /// No external evidence reference was supplied for the binding claim
    Unavailable,
}

impl EvidenceOrigin {
    /// Return the packet reference when one was supplied
    #[must_use]
    pub const fn packet(self) -> Option<PacketReference> {
        match self {
            Self::Packet(packet) => Some(packet),
            Self::Unavailable => None,
        }
    }
}

impl OriginalBindingReceipt {
    /// Construct a binding snapshot before a stimulus can be committed
    ///
    /// # Errors
    /// Returns [`ModelError`] when the run identity is invalid
    pub fn new(
        run_id: [u8; ID_LEN],
        binding: NeighborBinding,
        interface: InterfaceBindingRequest,
        evidence_origin: EvidenceOrigin,
    ) -> Result<Self, ModelError> {
        checked_run(run_id)?;
        Ok(Self {
            run_id,
            binding,
            interface,
            evidence_origin,
        })
    }

    /// Return the run identity
    #[must_use]
    pub const fn run_id(self) -> [u8; ID_LEN] {
        self.run_id
    }

    /// Return the captured original binding
    #[must_use]
    pub const fn binding(self) -> NeighborBinding {
        self.binding
    }

    /// Return the interface on which the original binding was observed
    #[must_use]
    pub const fn interface(self) -> InterfaceBindingRequest {
        self.interface
    }
    /// Return the explicit origin of the original-binding evidence
    #[must_use]
    pub const fn evidence_origin(self) -> EvidenceOrigin {
        self.evidence_origin
    }
}

/// Caller-supplied claim that a controlled endpoint was armed
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArmReceipt {
    run_id: [u8; ID_LEN],
    endpoint: AgentId,
    family: AddressFamily,
    interface: InterfaceBindingRequest,
}

impl ArmReceipt {
    /// Construct one endpoint-arm receipt
    ///
    /// # Errors
    /// Returns [`ModelError`] when the run identity is invalid
    pub fn new(
        run_id: [u8; ID_LEN],
        endpoint: AgentId,
        family: AddressFamily,
        interface: InterfaceBindingRequest,
    ) -> Result<Self, ModelError> {
        checked_run(run_id)?;
        Ok(Self {
            run_id,
            endpoint,
            family,
            interface,
        })
    }

    /// Return the run identity
    #[must_use]
    pub const fn run_id(self) -> [u8; ID_LEN] {
        self.run_id
    }

    /// Return the endpoint identity
    #[must_use]
    pub const fn endpoint(self) -> AgentId {
        self.endpoint
    }

    /// Return the armed address family
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        self.family
    }

    /// Return the exact interface armed for the endpoint
    #[must_use]
    pub const fn interface(self) -> InterfaceBindingRequest {
        self.interface
    }
}

/// A committed, bounded transmit receipt tied to one planned stimulus
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StimulusReceipt {
    run_id: [u8; ID_LEN],
    stimulus: StimulusId,
    tx: TxReceipt,
    evidence_packet: PacketReference,
}

impl StimulusReceipt {
    /// Construct a receipt from the shared segmentation transmit claim
    ///
    /// # Errors
    /// Returns [`ModelError`] when the run or shared receipt sequence is invalid
    pub fn new(
        run_id: [u8; ID_LEN],
        stimulus: StimulusId,
        tx: TxReceipt,
        evidence_packet: PacketReference,
    ) -> Result<Self, ModelError> {
        checked_run(run_id)?;
        if tx.run_id() != run_id {
            return Err(ModelError::RunMismatch);
        }
        if tx.sequence() == 0 {
            return Err(ModelError::ZeroSequence);
        }
        Ok(Self {
            run_id,
            stimulus,
            tx,
            evidence_packet,
        })
    }

    /// Return the run identity
    #[must_use]
    pub const fn run_id(self) -> [u8; ID_LEN] {
        self.run_id
    }

    /// Return the planned stimulus identity
    #[must_use]
    pub const fn stimulus(self) -> StimulusId {
        self.stimulus
    }

    /// Return the shared committed transmit receipt
    #[must_use]
    pub const fn tx(self) -> TxReceipt {
        self.tx
    }

    /// Return the sequence claimed at the send boundary
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.tx.sequence()
    }

    /// Return the caller-supplied packet reference
    #[must_use]
    pub const fn evidence_packet(self) -> PacketReference {
        self.evidence_packet
    }
}

/// Neighbor or switch state observed after one committed stimulus
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NeighborTransitionReceipt {
    run_id: [u8; ID_LEN],
    stimulus: StimulusId,
    family: AddressFamily,
    disposition: NeighborDisposition,
    window: ObservationWindowReceipt,
    observed_binding: Option<NeighborBinding>,
}

impl NeighborTransitionReceipt {
    /// Construct a transition receipt from a shared bounded observation window
    ///
    /// # Errors
    /// Returns [`ModelError`] when the run does not match the observation window
    pub fn new(
        run_id: [u8; ID_LEN],
        stimulus: StimulusId,
        family: AddressFamily,
        disposition: NeighborDisposition,
        window: ObservationWindowReceipt,
    ) -> Result<Self, ModelError> {
        checked_run(run_id)?;
        if window.run_id() != run_id {
            return Err(ModelError::RunMismatch);
        }
        Ok(Self {
            run_id,
            stimulus,
            family,
            disposition,
            window,
            observed_binding: None,
        })
    }

    /// Attach an observed binding to a transition for identity-conflict review
    #[must_use]
    pub const fn with_observed_binding(mut self, binding: NeighborBinding) -> Self {
        self.observed_binding = Some(binding);
        self
    }

    /// Return the run identity
    #[must_use]
    pub const fn run_id(self) -> [u8; ID_LEN] {
        self.run_id
    }

    /// Return the stimulus identity
    #[must_use]
    pub const fn stimulus(self) -> StimulusId {
        self.stimulus
    }

    /// Return the observed address family
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        self.family
    }

    /// Return the transition disposition
    #[must_use]
    pub const fn disposition(self) -> NeighborDisposition {
        self.disposition
    }

    /// Return the shared observation window
    #[must_use]
    pub const fn window(self) -> ObservationWindowReceipt {
        self.window
    }

    /// Return the observed conflicting or restored binding, when supplied
    #[must_use]
    pub const fn observed_binding(self) -> Option<NeighborBinding> {
        self.observed_binding
    }
}

/// Whether the authenticated canary arrived at the observation receiver
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanaryTraversal {
    /// The authenticated payload arrived at its destination
    Arrived,
    /// A complete loss-free observation window recorded its absence
    NotObserved,
}

/// Caller-supplied transmit and receiver evidence for one raw canary wire
///
/// This value groups the claims without verifying their relationship. The
/// session checks them against the authenticated canary before changing state
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanaryWireEvidence {
    transmit: TxReceipt,
    window: ObservationWindowReceipt,
    observed_interface: InterfaceBindingRequest,
    observed_at: ClockStamp,
    evidence_packet: PacketReference,
}

impl CanaryWireEvidence {
    /// Group the transmit receipt and receiver-side provenance for one wire
    #[must_use]
    pub const fn new(
        transmit: TxReceipt,
        window: ObservationWindowReceipt,
        observed_interface: InterfaceBindingRequest,
        observed_at: ClockStamp,
        evidence_packet: PacketReference,
    ) -> Self {
        Self {
            transmit,
            window,
            observed_interface,
            observed_at,
            evidence_packet,
        }
    }

    /// Return the caller-supplied transmit receipt
    #[must_use]
    pub const fn transmit(self) -> TxReceipt {
        self.transmit
    }

    /// Return the receiver observation window
    #[must_use]
    pub const fn window(self) -> ObservationWindowReceipt {
        self.window
    }

    /// Return the interface observed by the receiver
    #[must_use]
    pub const fn observed_interface(self) -> InterfaceBindingRequest {
        self.observed_interface
    }

    /// Return the local timestamp of the observed canary
    #[must_use]
    pub const fn observed_at(self) -> ClockStamp {
        self.observed_at
    }

    /// Return the packet reference for the observation
    #[must_use]
    pub const fn evidence_packet(self) -> PacketReference {
        self.evidence_packet
    }
}

/// A structurally checked canary traversal claim; raw wire bytes are not retained
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedCanaryReceipt {
    canary: Canary,
    transmit: TxReceipt,
    window: ObservationWindowReceipt,
    evidence_packet: PacketReference,
    traversal: CanaryTraversal,
}

impl AuthenticatedCanaryReceipt {
    /// Build an arrival claim from a receiver-scoped canary observation
    ///
    /// # Errors
    /// Returns [`ModelError`] when packet, run, sequence, or receiver evidence is invalid
    pub fn from_arrival(
        arrival: CanaryArrivalReceipt,
        transmit: TxReceipt,
    ) -> Result<Self, ModelError> {
        let canary = arrival.canary();
        let window = arrival.window();
        if transmit.run_id() != canary.run_id().into_bytes()
            || transmit.sequence() != canary.sequence()
        {
            return Err(ModelError::EvidenceScopeMismatch);
        }
        if !window.causally_covers(transmit) {
            return Err(ModelError::CausalCoverageMissing);
        }
        Ok(Self {
            canary,
            transmit,
            window,
            evidence_packet: arrival.evidence_packet(),
            traversal: CanaryTraversal::Arrived,
        })
    }

    /// Build an authenticated absence receipt for a blocked path
    ///
    /// The supplied window must be complete and loss free. A caller can only
    /// claim absence for a canary that was authenticated before observation.
    ///
    /// # Errors
    /// Returns [`ModelError`] when the authenticated fields or observation window is invalid
    pub fn from_verified_blocked(
        verified: VerifiedCanary,
        transmit: TxReceipt,
        window: ObservationWindowReceipt,
        evidence_packet: PacketReference,
    ) -> Result<Self, ModelError> {
        let canary = verified.into_canary();
        if transmit.run_id() != canary.run_id().into_bytes()
            || transmit.sequence() != canary.sequence()
            || window.run_id() != canary.run_id().into_bytes()
            || window.sequence() != canary.sequence()
            || window.receiver() != canary.destination_agent_id()
        {
            return Err(ModelError::EvidenceScopeMismatch);
        }
        if !window.proves_complete_absence_for(transmit) {
            return Err(ModelError::IncompleteObservationWindow);
        }
        Ok(Self {
            canary,
            transmit,
            window,
            evidence_packet,
            traversal: CanaryTraversal::NotObserved,
        })
    }

    /// Return the authenticated canary fields
    #[must_use]
    pub const fn canary(self) -> Canary {
        self.canary
    }

    /// Return the caller-supplied canary transmit claim
    #[must_use]
    pub const fn transmit(self) -> TxReceipt {
        self.transmit
    }

    /// Return the shared receiver observation window
    #[must_use]
    pub const fn window(self) -> ObservationWindowReceipt {
        self.window
    }

    /// Return the packet evidence reference
    #[must_use]
    pub const fn evidence_packet(self) -> PacketReference {
        self.evidence_packet
    }

    /// Return whether the authenticated canary arrived or was absent
    #[must_use]
    pub const fn traversal(self) -> CanaryTraversal {
        self.traversal
    }
}

/// Evidence of one binding observed after cleanup
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupReceipt {
    run_id: [u8; ID_LEN],
    interface: InterfaceBindingRequest,
    observed_binding: NeighborBinding,
    restored: bool,
    capture_loss: u64,
    transmit: TxReceipt,
    evidence_packet: PacketReference,
}

impl CleanupReceipt {
    /// Construct one post-cleanup binding receipt
    ///
    /// # Errors
    /// Returns [`ModelError`] when the run identity is invalid
    pub fn new(
        run_id: [u8; ID_LEN],
        interface: InterfaceBindingRequest,
        observed_binding: NeighborBinding,
        restored: bool,
        transmit: TxReceipt,
        evidence_packet: PacketReference,
    ) -> Result<Self, ModelError> {
        checked_run(run_id)?;
        Ok(Self {
            run_id,
            interface,
            observed_binding,
            restored,
            capture_loss: 0,
            transmit,
            evidence_packet,
        })
    }

    /// Add explicit cleanup capture-loss evidence
    #[must_use]
    pub const fn with_capture_loss(mut self, capture_loss: u64) -> Self {
        self.capture_loss = capture_loss;
        self
    }

    /// Return the run identity
    #[must_use]
    pub const fn run_id(&self) -> [u8; ID_LEN] {
        self.run_id
    }

    /// Return the restored endpoint identity
    #[must_use]
    pub const fn endpoint(&self) -> AgentId {
        self.observed_binding.endpoint()
    }

    /// Return the restored address family
    #[must_use]
    pub const fn family(&self) -> AddressFamily {
        self.observed_binding.family()
    }

    /// Return the interface on which cleanup was verified
    #[must_use]
    pub const fn interface(&self) -> InterfaceBindingRequest {
        self.interface
    }

    /// Return the binding observed after cleanup
    #[must_use]
    pub const fn observed_binding(&self) -> NeighborBinding {
        self.observed_binding
    }

    /// Return whether restoration was explicitly successful
    #[must_use]
    pub const fn restored(&self) -> bool {
        self.restored
    }

    /// Return cleanup capture loss
    #[must_use]
    pub const fn capture_loss(&self) -> u64 {
        self.capture_loss
    }
    /// Return the exact cleanup transmit claim
    #[must_use]
    pub const fn transmit(&self) -> TxReceipt {
        self.transmit
    }

    /// Return the packet evidence reference
    #[must_use]
    pub const fn evidence_packet(&self) -> PacketReference {
        self.evidence_packet
    }
}
