//! Ordered lifecycle gates and receipt ingestion

use std::collections::BTreeMap;

use l2_canary::{SessionKey, UnverifiedCanary};
use l2_segmentation::{ClockStamp, ObservationWindowReceipt, PacketReference};

use crate::{
    AddressFamily, ArmReceipt, AssessmentPlan, AuthenticatedCanaryReceipt, BudgetTimebase,
    CanaryWireEvidence, CleanupReceipt, NeighborTransitionReceipt, OriginalBindingReceipt,
    PrecheckReceipt, ReceiptError, SessionError, StimulusReceipt,
};

use super::{
    AssessmentSession,
    support::{CanaryKey, receipt_is_new},
    validate_cleanup_reserve,
};

/// Ordered lifecycle phase of one on-path assessment
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AssessmentPhase {
    /// No precheck has been committed
    Created,
    /// A precheck has been committed
    Precheck,
    /// Every planned original binding has been recorded
    OriginalBindingRecorded,
    /// Every controlled endpoint has been armed
    EndpointsArmed,
    /// Every planned bounded stimulus has a committed transmit receipt
    StimuliCommitted,
    /// Every planned stimulus has a neighbor transition receipt
    TransitionsRecorded,
    /// Every planned canary has an authenticated traversal receipt
    CanariesRecorded,
    /// Endpoint restoration has begun and no more experiment receipts are accepted
    CleanupInProgress,
    /// Every controlled endpoint has a cleanup/restoration receipt
    CleanupRecorded,
}
impl AssessmentSession {
    /// Start a session in the precheck gate
    #[must_use]
    pub fn new(plan: &AssessmentPlan, timebase: BudgetTimebase) -> Self {
        Self {
            plan: plan.clone(),
            phase: AssessmentPhase::Created,
            precheck: None,
            originals: BTreeMap::new(),
            arms: BTreeMap::new(),
            stimuli: BTreeMap::new(),
            transitions: BTreeMap::new(),
            canaries: BTreeMap::new(),
            cleanup: BTreeMap::new(),
            controller_events: l2_segmentation::ControllerEventLedger::default(),
            timebase,
            budget_started_at: None,
            last_receipt_at: None,
            resource_usage: BTreeMap::new(),
        }
    }

    /// Return the immutable plan used by this session
    #[must_use]
    pub const fn plan(&self) -> &AssessmentPlan {
        &self.plan
    }

    /// Return the current ordered lifecycle phase
    #[must_use]
    pub const fn phase(&self) -> AssessmentPhase {
        self.phase
    }

    /// Commit the mandatory precheck result
    ///
    /// # Errors
    /// Returns [`SessionError`] when the session phase, run, or precheck is invalid
    pub fn record_precheck(
        &mut self,
        receipt: PrecheckReceipt,
        received_at: ClockStamp,
    ) -> Result<(), SessionError> {
        self.require_phase("record precheck", AssessmentPhase::Created)?;
        if receipt.run_id() != *self.plan.run_id() {
            return Err(ReceiptError::WrongRun.into());
        }
        if usize::from(receipt.endpoint_count()) != self.plan.endpoints().len() {
            return Err(SessionError::PrecheckIncomplete);
        }
        if !receipt.is_clean() {
            return Err(SessionError::PrecheckIncomplete);
        }
        if !self.plan.has_complete_cleanup_commitments() {
            return Err(SessionError::CleanupCommitmentsIncomplete);
        }
        validate_cleanup_reserve(&self.plan)?;
        self.validate_receipt_time(received_at, false)?;
        self.precheck = Some(receipt);
        self.phase = AssessmentPhase::Precheck;
        self.accept_receipt_time(received_at);
        Ok(())
    }

    /// Record one original binding before an endpoint is armed
    ///
    /// # Errors
    /// Returns [`SessionError`] when the phase, endpoint, run, or receipt is invalid
    pub fn record_original_binding(
        &mut self,
        receipt: OriginalBindingReceipt,
        received_at: ClockStamp,
    ) -> Result<(), SessionError> {
        self.require_one_of(
            "record original binding",
            &[
                AssessmentPhase::Precheck,
                AssessmentPhase::OriginalBindingRecorded,
            ],
        )?;
        self.check_run(receipt.run_id())?;
        let binding = receipt.binding();
        let key = (binding.endpoint(), binding.family());
        let Some(endpoint) = self.plan.endpoint(key.0, key.1) else {
            return Err(ReceiptError::UnknownEndpoint { endpoint: key.0 }.into());
        };
        if receipt.interface() != endpoint.interface() {
            return Err(ReceiptError::EndpointInterfaceMismatch {
                expected: endpoint.interface(),
                actual: receipt.interface(),
            }
            .into());
        }
        if endpoint.binding() != binding {
            return Err(ReceiptError::OriginalBindingMismatch.into());
        }
        if !receipt_is_new(&self.originals, &key, &receipt)? {
            return Ok(());
        }
        self.validate_receipt_time(received_at, false)?;
        self.originals.insert(key, receipt);
        if self.originals.len() == self.plan.endpoints().len() {
            self.phase = AssessmentPhase::OriginalBindingRecorded;
        }
        self.accept_receipt_time(received_at);
        Ok(())
    }

    /// Arm one endpoint after every original binding is recorded
    ///
    /// # Errors
    /// Returns [`SessionError`] when the phase, endpoint, run, or receipt is invalid
    pub fn arm_endpoint(
        &mut self,
        receipt: ArmReceipt,
        received_at: ClockStamp,
    ) -> Result<(), SessionError> {
        self.require_one_of(
            "arm endpoint",
            &[
                AssessmentPhase::OriginalBindingRecorded,
                AssessmentPhase::EndpointsArmed,
            ],
        )?;
        self.check_run(receipt.run_id())?;
        let key = (receipt.endpoint(), receipt.family());
        let Some(endpoint) = self.plan.endpoint(key.0, key.1) else {
            return Err(ReceiptError::UnknownEndpoint { endpoint: key.0 }.into());
        };
        if receipt.interface() != endpoint.interface() {
            return Err(ReceiptError::EndpointInterfaceMismatch {
                expected: endpoint.interface(),
                actual: receipt.interface(),
            }
            .into());
        }
        if !self.originals.contains_key(&key) {
            return Err(ReceiptError::MissingReceipt.into());
        }
        if !receipt_is_new(&self.arms, &key, &receipt)? {
            return Ok(());
        }
        self.validate_receipt_time(received_at, false)?;
        self.arms.insert(key, receipt);
        if self.arms.len() == self.plan.endpoints().len() {
            self.phase = AssessmentPhase::EndpointsArmed;
        }
        self.accept_receipt_time(received_at);
        Ok(())
    }

    /// Record a committed bounded stimulus using shared segmentation TX evidence
    ///
    /// # Errors
    /// Returns [`SessionError`] when the phase, stimulus, run, or receipt is invalid
    pub fn record_stimulus(
        &mut self,
        receipt: StimulusReceipt,
        received_at: ClockStamp,
    ) -> Result<(), SessionError> {
        self.require_one_of(
            "record committed stimulus",
            &[
                AssessmentPhase::EndpointsArmed,
                AssessmentPhase::StimuliCommitted,
            ],
        )?;
        self.check_run(receipt.run_id())?;
        let Some(stimulus) = self.plan.stimulus(receipt.stimulus()) else {
            return Err(ReceiptError::UnknownStimulus {
                id: receipt.stimulus(),
            }
            .into());
        };
        if receipt.sequence() != stimulus.sequence() {
            return Err(ReceiptError::WrongSequence {
                expected: stimulus.sequence(),
                actual: receipt.sequence(),
            }
            .into());
        }
        self.require_commitment(receipt.tx())?;
        let key = receipt.stimulus();
        if !receipt_is_new(&self.stimuli, &key, &receipt)? {
            return Ok(());
        }
        let commitment = self.plan.commitment(receipt.sequence()).ok_or_else(|| {
            ReceiptError::MissingCommitment {
                sequence: receipt.sequence(),
            }
        })?;
        let next_usage = self.next_tx_usage(stimulus.check(), commitment)?;
        self.validate_receipt_time(received_at, false)?;
        self.controller_events.reserve_transmit(receipt.tx())?;
        self.accept_tx_usage(stimulus.check(), next_usage);
        self.stimuli.insert(key, receipt);
        if self.stimuli.len() == self.plan.stimuli().len() {
            self.phase = AssessmentPhase::StimuliCommitted;
        }
        self.accept_receipt_time(received_at);
        Ok(())
    }

    /// Record the neighbor or switch transition after every stimulus commits
    ///
    /// # Errors
    /// Returns [`SessionError`] when the phase or transition does not match the plan
    pub fn record_transition(
        &mut self,
        receipt: NeighborTransitionReceipt,
        received_at: ClockStamp,
    ) -> Result<(), SessionError> {
        self.require_one_of(
            "record neighbor transition",
            &[
                AssessmentPhase::StimuliCommitted,
                AssessmentPhase::TransitionsRecorded,
            ],
        )?;
        self.check_run(receipt.run_id())?;
        let Some(stimulus) = self.plan.stimulus(receipt.stimulus()) else {
            return Err(ReceiptError::UnknownStimulus {
                id: receipt.stimulus(),
            }
            .into());
        };
        let Some(endpoint) = self.plan.endpoints().iter().find(|item| {
            item.id() == stimulus.endpoint() && stimulus.check().accepts_family(item.family())
        }) else {
            return Err(ReceiptError::UnknownEndpoint {
                endpoint: stimulus.endpoint(),
            }
            .into());
        };
        if receipt.family() != endpoint.family() {
            return Err(ReceiptError::WrongFamily {
                expected: endpoint.family(),
                actual: receipt.family(),
            }
            .into());
        }
        let window = receipt.window();
        if window.run_id() != *self.plan.run_id() {
            return Err(ReceiptError::WrongRun.into());
        }
        if window.sequence() != stimulus.sequence() {
            return Err(ReceiptError::WrongSequence {
                expected: stimulus.sequence(),
                actual: window.sequence(),
            }
            .into());
        }
        if window.receiver() != stimulus.endpoint() {
            return Err(ReceiptError::WrongReceiver.into());
        }
        if window.receiver_interface() != endpoint.interface() {
            return Err(ReceiptError::ObservationInterfaceMismatch.into());
        }
        let Some(transmit) = self.stimuli.get(&receipt.stimulus()).map(|item| item.tx()) else {
            return Err(ReceiptError::MissingReceipt.into());
        };
        if !window.causally_covers(transmit) {
            return Err(ReceiptError::CausalCoverageMissing.into());
        }
        Self::validate_transition(stimulus.check(), *endpoint, receipt.family(), &receipt)?;
        let key = receipt.stimulus();
        if !receipt_is_new(&self.transitions, &key, &receipt)? {
            return Ok(());
        }
        self.validate_receipt_time(received_at, false)?;
        self.controller_events.reserve_window(receipt.window())?;
        self.transitions.insert(key, receipt);
        if self.transitions.len() == self.plan.stimuli().len() {
            self.phase = AssessmentPhase::TransitionsRecorded;
        }
        self.accept_receipt_time(received_at);
        Ok(())
    }

    /// Record one authenticated canary traversal after all transitions exist
    ///
    /// # Errors
    /// Returns [`SessionError`] when the phase or authenticated receipt does not match the plan
    pub fn record_canary(
        &mut self,
        receipt: AuthenticatedCanaryReceipt,
        received_at: ClockStamp,
    ) -> Result<(), SessionError> {
        self.require_one_of(
            "record authenticated canary",
            &[
                AssessmentPhase::TransitionsRecorded,
                AssessmentPhase::CanariesRecorded,
            ],
        )?;
        let canary = receipt.canary();
        self.check_run(canary.run_id().into_bytes())?;
        let Some(expectation) = self.plan.canary(&canary) else {
            return Err(ReceiptError::UnknownCanary.into());
        };
        let Some(stimulus) = self.plan.stimulus(expectation.stimulus()) else {
            return Err(ReceiptError::UnknownStimulus {
                id: expectation.stimulus(),
            }
            .into());
        };
        let Some(destination) = self
            .plan
            .endpoint_for_check(canary.destination_agent_id(), stimulus.check())
        else {
            return Err(ReceiptError::UnknownEndpoint {
                endpoint: canary.destination_agent_id(),
            }
            .into());
        };
        if receipt.window().receiver_interface() != destination.interface() {
            return Err(ReceiptError::ObservationInterfaceMismatch.into());
        }
        self.require_commitment(receipt.transmit())?;
        let key = CanaryKey::from_canary(&canary);
        if !receipt_is_new(&self.canaries, &key, &receipt)? {
            return Ok(());
        }
        let commitment = self.plan.commitment(canary.sequence()).ok_or_else(|| {
            ReceiptError::MissingCommitment {
                sequence: canary.sequence(),
            }
        })?;
        let next_usage = self.next_tx_usage(stimulus.check(), commitment)?;
        self.validate_receipt_time(received_at, false)?;
        self.controller_events
            .reserve_transmit_and_window(receipt.transmit(), receipt.window())?;
        self.accept_tx_usage(stimulus.check(), next_usage);
        self.canaries.insert(key, receipt);
        if self.canaries.len() == self.plan.canaries().len() {
            self.phase = AssessmentPhase::CanariesRecorded;
        }
        self.accept_receipt_time(received_at);
        Ok(())
    }

    /// Verify a raw canary wire without retaining unauthenticated bytes or a key
    ///
    /// # Errors
    /// Returns [`SessionError`] when authentication, observation, or lifecycle validation fails
    pub fn record_canary_wire(
        &mut self,
        input: &[u8],
        key: &SessionKey,
        evidence: CanaryWireEvidence,
        received_at: ClockStamp,
    ) -> Result<(), SessionError> {
        let verified =
            l2_canary::verify(UnverifiedCanary::new(input), key).map_err(SessionError::Canary)?;
        // Arrival scope is validated before lifecycle state can change
        let arrival = l2_segmentation::CanaryArrivalReceipt::from_verified(
            verified,
            evidence.window(),
            evidence.observed_interface(),
            evidence.observed_at(),
            evidence.evidence_packet(),
        )?;
        let receipt = AuthenticatedCanaryReceipt::from_arrival(arrival, evidence.transmit())
            .map_err(SessionError::Model)?;
        self.record_canary(receipt, received_at)
    }

    /// Record a complete loss-free absence for a canary on a blocked path
    ///
    /// The verified payload must have been authenticated by the caller using a
    /// temporary session key. The key is never retained by this session.
    ///
    /// # Errors
    /// Returns [`SessionError`] when lifecycle or observation validation fails
    pub fn record_blocked_canary(
        &mut self,
        verified: l2_canary::VerifiedCanary,
        transmit: l2_segmentation::TxReceipt,
        window: ObservationWindowReceipt,
        evidence_packet: PacketReference,
        received_at: ClockStamp,
    ) -> Result<(), SessionError> {
        let receipt = AuthenticatedCanaryReceipt::from_verified_blocked(
            verified,
            transmit,
            window,
            evidence_packet,
        )
        .map_err(SessionError::Model)?;
        self.record_canary(receipt, received_at)
    }

    /// Verify a wire and record its complete loss-free absence on a blocked path
    ///
    /// Raw bytes and the supplied key are discarded after authentication.
    ///
    /// # Errors
    /// Returns [`SessionError`] when authentication, observation, or lifecycle validation fails
    pub fn record_blocked_canary_wire(
        &mut self,
        input: &[u8],
        key: &SessionKey,
        transmit: l2_segmentation::TxReceipt,
        window: ObservationWindowReceipt,
        evidence_packet: PacketReference,
        received_at: ClockStamp,
    ) -> Result<(), SessionError> {
        let verified =
            l2_canary::verify(UnverifiedCanary::new(input), key).map_err(SessionError::Canary)?;
        self.record_blocked_canary(verified, transmit, window, evidence_packet, received_at)
    }

    /// Record one cleanup and restoration receipt for a controlled endpoint
    ///
    /// The session copies the receipt only after validation and duplicate checks succeed
    ///
    /// # Errors
    /// Returns [`SessionError`] when the phase, endpoint, run, or restoration is invalid
    pub fn record_cleanup(
        &mut self,
        receipt: &CleanupReceipt,
        received_at: ClockStamp,
    ) -> Result<(), SessionError> {
        self.require_one_of(
            "record cleanup",
            &[
                AssessmentPhase::EndpointsArmed,
                AssessmentPhase::StimuliCommitted,
                AssessmentPhase::TransitionsRecorded,
                AssessmentPhase::CanariesRecorded,
                AssessmentPhase::CleanupInProgress,
                AssessmentPhase::CleanupRecorded,
            ],
        )?;
        let key = (receipt.endpoint(), receipt.family());
        self.validate_cleanup_receipt(receipt)?;
        if !receipt_is_new(&self.cleanup, &key, receipt)? {
            return Ok(());
        }
        self.validate_receipt_time(received_at, true)?;
        self.controller_events
            .reserve_transmit(receipt.transmit())?;
        // Keep accepted evidence independent of the caller's receipt
        self.cleanup.insert(key, *receipt);
        if self.cleanup.len() == self.plan.endpoints().len() {
            self.phase = AssessmentPhase::CleanupRecorded;
        } else {
            self.phase = AssessmentPhase::CleanupInProgress;
        }
        self.accept_receipt_time(received_at);
        Ok(())
    }

    fn validate_cleanup_receipt(&self, receipt: &CleanupReceipt) -> Result<(), SessionError> {
        self.check_run(receipt.run_id())?;
        let key = (receipt.endpoint(), receipt.family());
        let Some(endpoint) = self.plan.endpoint(key.0, key.1) else {
            return Err(ReceiptError::UnknownEndpoint { endpoint: key.0 }.into());
        };
        if receipt.interface() != endpoint.interface() {
            return Err(ReceiptError::EndpointInterfaceMismatch {
                expected: endpoint.interface(),
                actual: receipt.interface(),
            }
            .into());
        }
        Self::validate_cleanup_binding(receipt, endpoint)?;
        let Some(commitment) = self.plan.cleanup_commitment(key.0, key.1) else {
            return Err(SessionError::CleanupCommitmentsIncomplete);
        };
        if receipt.transmit().sequence() != commitment.sequence() {
            return Err(ReceiptError::WrongSequence {
                expected: commitment.sequence(),
                actual: receipt.transmit().sequence(),
            }
            .into());
        }
        self.require_commitment(receipt.transmit())
    }

    fn validate_cleanup_binding(
        receipt: &CleanupReceipt,
        endpoint: crate::ControlledEndpoint,
    ) -> Result<(), SessionError> {
        let observed = receipt.observed_binding();
        if observed.address() != endpoint.binding().address() {
            return Err(ReceiptError::CleanupBindingAddressMismatch {
                expected: endpoint.binding().address(),
                actual: observed.address(),
            }
            .into());
        }
        if receipt.restored() && observed != endpoint.binding() {
            return Err(ReceiptError::RestorationMismatch.into());
        }
        if !receipt.restored() && observed == endpoint.binding() {
            return Err(ReceiptError::UnrestoredBindingMatchesOriginal.into());
        }
        Ok(())
    }

    fn check_run(&self, run_id: [u8; 16]) -> Result<(), SessionError> {
        if run_id == *self.plan.run_id() {
            Ok(())
        } else {
            Err(ReceiptError::WrongRun.into())
        }
    }

    fn require_commitment(&self, transmit: l2_segmentation::TxReceipt) -> Result<(), SessionError> {
        self.check_run(transmit.run_id())?;
        let sequence = transmit.sequence();
        let Some(commitment) = self.plan.commitment(sequence) else {
            return Err(ReceiptError::MissingCommitment { sequence }.into());
        };
        if commitment.frame_hash() != transmit.frame_hash() {
            return Err(ReceiptError::CommitmentMismatch { sequence }.into());
        }
        if commitment.interface() != transmit.interface() {
            return Err(ReceiptError::InterfaceMismatch { sequence }.into());
        }
        Ok(())
    }

    fn validate_transition(
        check: crate::CheckKind,
        endpoint: crate::ControlledEndpoint,
        family: AddressFamily,
        receipt: &NeighborTransitionReceipt,
    ) -> Result<(), SessionError> {
        let disposition = receipt.disposition();
        if !check.accepts_disposition(disposition) {
            return Err(ReceiptError::IncompatibleDisposition { check, disposition }.into());
        }
        let Some(observed) = receipt.observed_binding() else {
            if disposition.requires_changed_binding() {
                return Err(ReceiptError::MissingChangedBinding { disposition }.into());
            }
            return Ok(());
        };
        if observed.endpoint() != endpoint.id() {
            return Err(ReceiptError::ObservedBindingEndpointMismatch {
                expected: endpoint.id(),
                actual: observed.endpoint(),
            }
            .into());
        }
        if observed.family() != family || observed.family() != endpoint.family() {
            return Err(ReceiptError::ObservedBindingFamilyMismatch {
                expected: endpoint.family(),
                actual: observed.family(),
            }
            .into());
        }
        if observed.address() != endpoint.binding().address() {
            return Err(ReceiptError::ObservedBindingAddressMismatch {
                expected: endpoint.binding().address(),
                actual: observed.address(),
            }
            .into());
        }
        let changed = observed != endpoint.binding();
        if disposition.requires_changed_binding() && !changed {
            return Err(ReceiptError::MissingChangedBinding { disposition }.into());
        }
        if !disposition.requires_changed_binding() && changed {
            return Err(ReceiptError::UnexpectedChangedBinding { disposition }.into());
        }
        Ok(())
    }

    fn require_phase(
        &self,
        operation: &'static str,
        expected: AssessmentPhase,
    ) -> Result<(), SessionError> {
        if self.phase == expected {
            Ok(())
        } else {
            Err(SessionError::WrongPhase {
                operation,
                phase: self.phase,
            })
        }
    }

    fn require_one_of(
        &self,
        operation: &'static str,
        expected: &[AssessmentPhase],
    ) -> Result<(), SessionError> {
        if expected.contains(&self.phase) {
            Ok(())
        } else {
            Err(SessionError::WrongPhase {
                operation,
                phase: self.phase,
            })
        }
    }
}
