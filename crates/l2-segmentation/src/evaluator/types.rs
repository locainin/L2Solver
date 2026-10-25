//! Public context and result types for conservative evaluation

use l2_canary::Canary;

use crate::{
    CanaryArrivalReceipt, ClockStamp, ControllerEvent, InterfaceBindingRequest,
    ObservationWindowReceipt, Plan, RuleExpectation, SegmentId, TxCommitment, TxReceipt,
};

/// Capture integrity state supplied by the capture owner
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureQuality {
    /// Every planned attempt had a complete capture opportunity
    Complete,
    /// Capture completeness is uncertain or known to be incomplete
    Incomplete,
    /// Capture reported one or more dropped records
    Dropped,
}

/// Sender and receiver conditions used when interpreting absence
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluationContext {
    /// Whether all planned source senders were available
    pub sender_available: bool,
    /// Whether all planned destination receivers were available
    pub receiver_available: bool,
    /// Integrity state for the capture window
    pub capture_quality: CaptureQuality,
    /// Whether collection was cancelled before the observation window closed
    pub cancelled: bool,
}

impl EvaluationContext {
    /// Construct an evaluation context from explicit collection facts
    #[must_use]
    pub const fn new(
        sender_available: bool,
        receiver_available: bool,
        capture_quality: CaptureQuality,
        cancelled: bool,
    ) -> Self {
        Self {
            sender_available,
            receiver_available,
            capture_quality,
            cancelled,
        }
    }

    /// Construct the only context that permits a deny absence pass
    #[must_use]
    pub const fn healthy() -> Self {
        Self::new(true, true, CaptureQuality::Complete, false)
    }

    /// Whether sender, receiver, capture, and cancellation conditions are complete
    #[must_use]
    pub const fn supports_absence_pass(self) -> bool {
        self.sender_available
            && self.receiver_available
            && matches!(self.capture_quality, CaptureQuality::Complete)
            && !self.cancelled
    }
}

/// Coarse result assigned to one directed policy rule or a complete report
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluationStatus {
    /// Evidence supports the configured behavior
    Pass,
    /// Evidence directly contradicts the configured behavior
    Fail,
    /// Evidence is not sufficient for a safe conclusion
    Inconclusive,
}

/// Why an authenticated observation was not counted for the plan
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationRejection {
    /// The canary was not observed by its planned destination receiver
    WrongObservationPoint,
    /// The authenticated canary belongs to another run
    WrongRun,
    /// The authenticated source agent is outside this plan
    WrongSource,
    /// The authenticated destination agent is outside this plan
    WrongDestination,
    /// The source and destination pair is outside this plan
    WrongDirection,
    /// The sequence does not identify a planned probe
    WrongSequence,
    /// The sequence identifies a planned probe with different nonce material
    WrongNonce,
    /// The exact planned canary was already counted
    Duplicate,
    /// The exact planned canary arrived below an accepted sequence
    Stale,
    /// The bounded replay guard could not retain another identity
    ReplayLimit,
}

/// Result of adding one already-authenticated observation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationDisposition {
    /// The matching planned receipt was accepted once
    Accepted,
    /// The receipt was safely ignored with a specific reason
    Ignored(ObservationRejection),
}

/// One accepted arrival with its exact transmit and observation claim chain
///
/// These fields remain structurally checked caller claims until a future
/// execution boundary replaces them with opaque authority-issued receipts
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArrivalEvidence {
    arrival: CanaryArrivalReceipt,
    commitment: TxCommitment,
    transmit: TxReceipt,
}

impl ArrivalEvidence {
    pub(super) const fn new(
        arrival: &CanaryArrivalReceipt,
        commitment: &TxCommitment,
        transmit: &TxReceipt,
    ) -> Self {
        Self {
            arrival: *arrival,
            commitment: *commitment,
            transmit: *transmit,
        }
    }

    /// Return the exact authenticated canary fields
    #[must_use]
    pub const fn canary(self) -> Canary {
        self.arrival.canary()
    }

    /// Return the packet reference supplied by the observation owner
    #[must_use]
    pub const fn packet_reference(self) -> crate::PacketReference {
        self.arrival.evidence_packet()
    }

    /// Return the exact interface committed for transmission
    #[must_use]
    pub const fn source_interface(self) -> InterfaceBindingRequest {
        self.commitment.interface()
    }

    /// Return the exact receiver interface where arrival was claimed
    #[must_use]
    pub const fn observation_interface(self) -> InterfaceBindingRequest {
        self.arrival.observed_interface()
    }

    /// Return the receiver-local observation timestamp
    #[must_use]
    pub const fn observed_at(self) -> ClockStamp {
        self.arrival.observed_at()
    }

    /// Return the digest of the exact authenticated canary payload
    #[must_use]
    pub const fn canary_wire_sha256(self) -> [u8; 32] {
        self.arrival.wire_sha256()
    }

    /// Return the digest of the exact complete frame committed for sending
    #[must_use]
    pub const fn frame_sha256(self) -> [u8; 32] {
        self.commitment.frame_hash()
    }

    /// Return the controller event that committed the transmit
    #[must_use]
    pub const fn transmit_event(self) -> ControllerEvent {
        self.transmit.committed_event()
    }

    /// Return the complete receiver-window claim
    #[must_use]
    pub const fn window(self) -> ObservationWindowReceipt {
        self.arrival.window()
    }

    /// Return the complete arrival claim
    #[must_use]
    pub const fn arrival(self) -> CanaryArrivalReceipt {
        self.arrival
    }

    /// Return the exact planned-frame commitment
    #[must_use]
    pub const fn commitment(self) -> TxCommitment {
        self.commitment
    }

    /// Return the matching transmit claim
    #[must_use]
    pub const fn transmit(self) -> TxReceipt {
        self.transmit
    }
}

/// One completed loss-free absence proof for an exact planned canary frame
///
/// The chain retains the committed full-frame hash, send event, receiver
/// interface, and causally ordered observation window used by a deny-path pass
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbsenceEvidence {
    canary: Canary,
    commitment: TxCommitment,
    transmit: TxReceipt,
    window: ObservationWindowReceipt,
}

impl AbsenceEvidence {
    pub(super) const fn new(
        canary: Canary,
        commitment: TxCommitment,
        transmit: TxReceipt,
        window: ObservationWindowReceipt,
    ) -> Self {
        Self {
            canary,
            commitment,
            transmit,
            window,
        }
    }

    /// Return the exact planned authenticated canary fields
    #[must_use]
    pub const fn canary(self) -> Canary {
        self.canary
    }

    /// Return the exact interface committed for transmission
    #[must_use]
    pub const fn source_interface(self) -> InterfaceBindingRequest {
        self.commitment.interface()
    }

    /// Return the destination interface covered by the receiver window
    #[must_use]
    pub const fn observation_interface(self) -> InterfaceBindingRequest {
        self.window.receiver_interface()
    }

    /// Return the digest of the exact complete frame committed for sending
    #[must_use]
    pub const fn frame_sha256(self) -> [u8; 32] {
        self.commitment.frame_hash()
    }

    /// Return the exact planned-frame commitment
    #[must_use]
    pub const fn commitment(self) -> TxCommitment {
        self.commitment
    }

    /// Return the matching transmit claim
    #[must_use]
    pub const fn transmit(self) -> TxReceipt {
        self.transmit
    }

    /// Return the complete receiver window that established absence
    #[must_use]
    pub const fn window(self) -> ObservationWindowReceipt {
        self.window
    }

    /// Return the controller event that committed the transmit
    #[must_use]
    pub const fn transmit_event(self) -> ControllerEvent {
        self.transmit.committed_event()
    }
}

/// One directed rule's conservative evaluation result
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleResult {
    pub(super) source: SegmentId,
    pub(super) destination: SegmentId,
    pub(super) expectation: RuleExpectation,
    pub(super) status: EvaluationStatus,
    pub(super) planned_attempts: usize,
    pub(super) matching_receipts: usize,
    pub(super) missing_attempts: usize,
    pub(super) evidence: Vec<ArrivalEvidence>,
    pub(super) absence_evidence: Vec<AbsenceEvidence>,
    pub(super) limitations: Vec<String>,
}

impl RuleResult {
    /// Return the rule source segment
    #[must_use]
    pub const fn source(&self) -> SegmentId {
        self.source
    }

    /// Return the rule destination segment
    #[must_use]
    pub const fn destination(&self) -> SegmentId {
        self.destination
    }

    /// Return the explicit expected behavior
    #[must_use]
    pub const fn expectation(&self) -> RuleExpectation {
        self.expectation
    }

    /// Return the conservative status
    #[must_use]
    pub const fn status(&self) -> EvaluationStatus {
        self.status
    }

    /// Return the number of probes planned for the directed rule
    #[must_use]
    pub const fn planned_attempts(&self) -> usize {
        self.planned_attempts
    }

    /// Return the number of unique matching receipts accepted
    #[must_use]
    pub const fn matching_receipts(&self) -> usize {
        self.matching_receipts
    }

    /// Return the planned probes without a matching receipt
    #[must_use]
    pub const fn missing_attempts(&self) -> usize {
        self.missing_attempts
    }

    /// Return complete accepted arrival evidence in stable probe order
    #[must_use]
    pub fn evidence(&self) -> &[ArrivalEvidence] {
        &self.evidence
    }

    /// Return complete loss-free absence chains in stable probe order
    #[must_use]
    pub fn absence_evidence(&self) -> &[AbsenceEvidence] {
        &self.absence_evidence
    }

    /// Return bounded explanations for uncertainty or scope
    #[must_use]
    pub fn limitations(&self) -> &[String] {
        &self.limitations
    }
}

/// Complete ordered evaluation for all directed rules in a plan
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationReport {
    pub(super) plan: Plan,
    pub(super) results: Vec<RuleResult>,
}

impl EvaluationReport {
    /// Return the exact immutable plan that produced these results
    #[must_use]
    pub const fn plan(&self) -> &Plan {
        &self.plan
    }

    /// Return directed results in the plan's stable order
    #[must_use]
    pub fn results(&self) -> &[RuleResult] {
        &self.results
    }

    /// Return the most conservative status across all directed rules
    #[must_use]
    pub fn overall_status(&self) -> EvaluationStatus {
        if self.results.is_empty() {
            return EvaluationStatus::Inconclusive;
        }
        let mut status = EvaluationStatus::Pass;
        for result in &self.results {
            match result.status {
                EvaluationStatus::Fail => return EvaluationStatus::Fail,
                EvaluationStatus::Inconclusive => status = EvaluationStatus::Inconclusive,
                EvaluationStatus::Pass => {}
            }
        }
        status
    }
}
