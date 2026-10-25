//! Stateful evaluation of authenticated canary observations

mod support;
mod types;

pub use self::types::{
    AbsenceEvidence, ArrivalEvidence, CaptureQuality, EvaluationContext, EvaluationReport,
    EvaluationStatus, ObservationDisposition, ObservationRejection, RuleResult,
};

use std::collections::{BTreeMap, BTreeSet};

use l2_canary::{Canary, ReplayError, ReplayGuard, SessionKey, UnverifiedCanary};

use crate::{
    CanaryArrivalReceipt, ClockStamp, ControllerEventLedger, EvaluationError,
    InterfaceBindingRequest, ObservationWindowReceipt, Plan, Probe, ReceiptError, RuleExpectation,
    TxCommitment, TxReceipt,
};

use self::support::{
    ObservationIdentity, ObservationKey, ReceiptKey, append_context_limitations, receipt_is_new,
};

/// Stateful bounded evaluator for one immutable plan
#[derive(Clone, Debug)]
pub struct Evaluator {
    plan: Plan,
    replay: BTreeMap<ObservationIdentity, ReplayGuard>,
    accepted: BTreeMap<ObservationKey, ArrivalEvidence>,
    observed: BTreeSet<ObservationKey>,
    commitments: BTreeMap<ReceiptKey, TxCommitment>,
    tx_receipts: BTreeMap<ReceiptKey, TxReceipt>,
    windows: BTreeMap<ReceiptKey, ObservationWindowReceipt>,
    controller_events: ControllerEventLedger,
}

impl Evaluator {
    /// Construct an empty evaluator for a validated plan
    #[must_use]
    pub fn new(plan: &Plan) -> Self {
        Self {
            plan: plan.clone(),
            replay: BTreeMap::new(),
            accepted: BTreeMap::new(),
            observed: BTreeSet::new(),
            commitments: BTreeMap::new(),
            tx_receipts: BTreeMap::new(),
            windows: BTreeMap::new(),
            controller_events: ControllerEventLedger::default(),
        }
    }

    /// Return the plan being evaluated
    #[must_use]
    pub const fn plan(&self) -> &Plan {
        &self.plan
    }

    /// Record the expected frame hash for one planned transmission
    ///
    /// Commitments are bounded by the plan's probe keys and must be recorded
    /// before the corresponding transmit receipt
    ///
    /// # Errors
    ///
    /// Rejects commitments outside the plan, conflicting hashes, or changes
    /// made after the transmit receipt is recorded
    pub fn record_commitment(&mut self, commitment: TxCommitment) -> Result<(), ReceiptError> {
        let key = ReceiptKey::new(commitment.run_id(), commitment.sequence());
        let Some(probe) = self.probe_for_key(key) else {
            return Err(ReceiptError::UnknownProbe);
        };
        // Segmentation probes always commit the exact authenticated canary
        let expected = probe
            .canary()
            .map_err(|_| ReceiptError::CommitmentCanaryMismatch)?;
        if commitment.planned_canary() != Some(expected) {
            return Err(ReceiptError::CommitmentCanaryMismatch);
        }
        if commitment.interface() != probe.source_interface() {
            return Err(ReceiptError::SourceInterfaceMismatch);
        }
        // A receipt closes the commitment for this probe
        if self.tx_receipts.contains_key(&key) {
            return Err(ReceiptError::LateCommitment);
        }
        if let Some(existing) = self.commitments.get(&key) {
            return if *existing == commitment {
                Ok(())
            } else {
                Err(ReceiptError::ConflictingCommitment)
            };
        }
        // The plan key check above bounds this map to the immutable probe set
        self.commitments.insert(key, commitment);
        Ok(())
    }

    /// Record a caller claim that one planned transmission committed
    ///
    /// # Errors
    ///
    /// Rejects receipts outside the plan, missing commitments, hash mismatches,
    /// or evidence that changes after recording
    pub fn record_tx(&mut self, receipt: TxReceipt) -> Result<(), ReceiptError> {
        let key = ReceiptKey::new(receipt.run_id(), receipt.sequence());
        if !self.has_probe_key(key) {
            return Err(ReceiptError::UnknownProbe);
        }
        // A transmit receipt is meaningful only against predeclared frame material
        let Some(commitment) = self.commitments.get(&key) else {
            return Err(ReceiptError::MissingCommitment);
        };
        if commitment.interface() != receipt.interface() {
            return Err(ReceiptError::InterfaceMismatch);
        }
        if commitment.frame_hash() != receipt.frame_hash() {
            return Err(ReceiptError::CommitmentMismatch);
        }
        if !receipt_is_new(&self.tx_receipts, key, &receipt)? {
            return Ok(());
        }
        self.controller_events.reserve_transmit(receipt)?;
        self.tx_receipts.insert(key, receipt);
        Ok(())
    }

    /// Record a receiver's bounded observation-window claim
    ///
    /// # Errors
    ///
    /// Rejects receipts outside the plan, for the wrong receiver, or conflicting evidence
    pub fn record_window(&mut self, receipt: ObservationWindowReceipt) -> Result<(), ReceiptError> {
        let key = ReceiptKey::new(receipt.run_id(), receipt.sequence());
        let Some(probe) = self.probe_for_key(key) else {
            return Err(ReceiptError::UnknownProbe);
        };
        if receipt.receiver() != probe.destination_agent_id() {
            return Err(ReceiptError::WrongReceiver);
        }
        if receipt.receiver_interface() != probe.destination_interface() {
            return Err(ReceiptError::DestinationInterfaceMismatch);
        }
        if !receipt_is_new(&self.windows, key, &receipt)? {
            return Ok(());
        }
        self.controller_events.reserve_window(receipt)?;
        self.windows.insert(key, receipt);
        Ok(())
    }

    /// Verify and count one canary claimed at a concrete receiver observation point
    ///
    /// # Errors
    ///
    /// Returns an authentication error or rejects inconsistent receiver,
    /// interface, clock-domain, and local-window claims
    pub fn observe_wire(
        &mut self,
        input: &[u8],
        key: &SessionKey,
        window: ObservationWindowReceipt,
        observed_interface: InterfaceBindingRequest,
        observed_at: ClockStamp,
        evidence_packet: crate::PacketReference,
    ) -> Result<ObservationDisposition, EvaluationError> {
        let canary = l2_canary::verify(UnverifiedCanary::new(input), key)
            .map_err(EvaluationError::Verification)?;
        let fields = canary.as_canary();

        // Classify unrelated authenticated traffic before validating its claim
        let Some(probe) = self.matching_probe(fields) else {
            return Ok(ObservationDisposition::Ignored(
                self.classify_mismatch(fields),
            ));
        };
        if window.receiver() != fields.destination_agent_id() {
            return Ok(ObservationDisposition::Ignored(
                ObservationRejection::WrongObservationPoint,
            ));
        }
        if window.receiver_interface() != probe.destination_interface() {
            return Err(ReceiptError::DestinationInterfaceMismatch.into());
        }

        // Construct the complete claim before replay state can be mutated
        let arrival = CanaryArrivalReceipt::from_verified(
            canary,
            window,
            observed_interface,
            observed_at,
            evidence_packet,
        )?;
        let receipt_key = ReceiptKey::new(fields.run_id().into_bytes(), fields.sequence());
        let Some(transmit) = self.tx_receipts.get(&receipt_key).copied() else {
            return Err(ReceiptError::MissingTransmitReceipt.into());
        };
        let Some(commitment) = self.commitments.get(&receipt_key).copied() else {
            return Err(ReceiptError::MissingCommitment.into());
        };
        if !arrival.window().causally_covers(transmit) {
            return Err(ReceiptError::CausalCoverageMissing.into());
        }
        self.record_window(arrival.window())?;
        // Every valid destination arrival disproves absence, even when replay
        // classification later identifies the packet as stale or duplicate
        self.observed
            .insert(ObservationKey::from_canary(&arrival.canary()));
        Ok(self.observe_arrival(&ArrivalEvidence::new(&arrival, &commitment, &transmit)))
    }

    /// Build conservative results from all observations and collection facts
    #[must_use]
    pub fn evaluate(&self, context: &EvaluationContext) -> EvaluationReport {
        // Results follow the same stable rule order as the immutable plan
        let mut results = Vec::with_capacity(self.plan.rules().len());
        for rule in self.plan.rules() {
            results.push(self.evaluate_rule(*rule, *context));
        }
        EvaluationReport {
            plan: self.plan.clone(),
            results,
        }
    }

    fn observe_arrival(&mut self, evidence: &ArrivalEvidence) -> ObservationDisposition {
        let verified = evidence.arrival().verified();
        let canary = *verified.as_canary();
        let key = ObservationKey::from_canary(&canary);
        // A duplicate is reported separately from a stale sequence
        if self.accepted.contains_key(&key) {
            return ObservationDisposition::Ignored(ObservationRejection::Duplicate);
        }
        let identity = ObservationIdentity::from_canary(&canary);
        // One guard per identity keeps l2-canary's table bound local
        let replay = self.replay.entry(identity).or_default();
        match replay.accept(&verified) {
            Ok(()) => {
                self.accepted.insert(key, *evidence);
                ObservationDisposition::Accepted
            }
            Err(ReplayError::NonIncreasing { .. }) => {
                ObservationDisposition::Ignored(ObservationRejection::Stale)
            }
            Err(ReplayError::IdentityLimit { .. }) => {
                ObservationDisposition::Ignored(ObservationRejection::ReplayLimit)
            }
        }
    }

    fn matching_probe(&self, canary: &Canary) -> Option<Probe> {
        self.plan.probes().iter().copied().find(|probe| {
            probe.run_id.into_bytes() == canary.run_id().into_bytes()
                && probe.source_agent_id() == canary.source_agent_id()
                && probe.destination_agent_id() == canary.destination_agent_id()
                && probe.sequence == canary.sequence()
                && probe.nonce == canary.nonce()
        })
    }

    fn classify_mismatch(&self, canary: &Canary) -> ObservationRejection {
        if canary.run_id().into_bytes() != *self.plan.run_id() {
            return ObservationRejection::WrongRun;
        }
        let source_exists = self.plan.probes().iter().any(|probe| {
            probe.run_id.into_bytes() == canary.run_id().into_bytes()
                && probe.source_agent_id() == canary.source_agent_id()
        });
        if !source_exists {
            return ObservationRejection::WrongSource;
        }
        let destination_exists = self.plan.probes().iter().any(|probe| {
            probe.run_id.into_bytes() == canary.run_id().into_bytes()
                && probe.destination_agent_id() == canary.destination_agent_id()
        });
        if !destination_exists {
            return ObservationRejection::WrongDestination;
        }
        let direction_exists = self.plan.probes().iter().any(|probe| {
            probe.run_id.into_bytes() == canary.run_id().into_bytes()
                && probe.source_agent_id() == canary.source_agent_id()
                && probe.destination_agent_id() == canary.destination_agent_id()
        });
        if !direction_exists {
            return ObservationRejection::WrongDirection;
        }
        let sequence_exists = self.plan.probes().iter().any(|probe| {
            probe.run_id.into_bytes() == canary.run_id().into_bytes()
                && probe.source_agent_id() == canary.source_agent_id()
                && probe.destination_agent_id() == canary.destination_agent_id()
                && probe.sequence == canary.sequence()
        });
        if !sequence_exists {
            return ObservationRejection::WrongSequence;
        }
        ObservationRejection::WrongNonce
    }

    fn evaluate_rule(&self, rule: crate::DirectedRule, context: EvaluationContext) -> RuleResult {
        let planned_attempts = self
            .plan
            .probes()
            .iter()
            .filter(|probe| {
                probe.source_segment() == rule.source
                    && probe.destination_segment() == rule.destination
            })
            .count();
        let evidence: Vec<_> = self
            .plan
            .probes()
            .iter()
            .filter(|probe| {
                probe.source_segment() == rule.source
                    && probe.destination_segment() == rule.destination
            })
            .filter_map(|probe| {
                self.accepted
                    .get(&ObservationKey::from_probe(probe))
                    .copied()
            })
            .collect();
        let matching_receipts = evidence.len();
        // Accepted receipts are always a subset of the planned probes
        let missing_attempts = planned_attempts - matching_receipts;
        let absence_evidence = self.absence_evidence(rule);
        let mut limitations = Vec::new();
        let status = match rule.expectation {
            // Any destination-scoped arrival claim contradicts a deny rule
            RuleExpectation::Deny if matching_receipts > 0 => EvaluationStatus::Fail,
            // A validated plan always contains at least one probe per rule
            RuleExpectation::Deny
                if context.supports_absence_pass()
                    && absence_evidence.len() == planned_attempts =>
            {
                // Absence is meaningful only with healthy endpoints and capture
                limitations.push(String::from(
                    "only the tested canaries were assessed as blocked",
                ));
                EvaluationStatus::Pass
            }
            RuleExpectation::Deny => {
                append_context_limitations(&mut limitations, context);
                self.append_receipt_limitations(&mut limitations, rule);
                limitations.push(String::from(
                    "one or more planned deny attempts had no matching receipt",
                ));
                EvaluationStatus::Inconclusive
            }
            RuleExpectation::Allow if missing_attempts == 0 => {
                // Allow requires every planned attempt to arrive
                EvaluationStatus::Pass
            }
            RuleExpectation::Allow => {
                append_context_limitations(&mut limitations, context);
                limitations.push(String::from(
                    "one or more planned allow attempts had no matching receipt",
                ));
                EvaluationStatus::Inconclusive
            }
        };

        RuleResult {
            source: rule.source,
            destination: rule.destination,
            expectation: rule.expectation,
            status,
            planned_attempts,
            matching_receipts,
            missing_attempts,
            evidence,
            absence_evidence,
            limitations,
        }
    }

    fn has_probe_key(&self, key: ReceiptKey) -> bool {
        self.probe_for_key(key).is_some()
    }

    fn probe_for_key(&self, key: ReceiptKey) -> Option<&Probe> {
        self.plan
            .probes()
            .iter()
            .find(|probe| probe.run_id.into_bytes() == key.run_id && probe.sequence == key.sequence)
    }

    fn absence_evidence(&self, rule: crate::DirectedRule) -> Vec<AbsenceEvidence> {
        self.plan
            .probes()
            .iter()
            .filter(|probe| {
                probe.source_segment() == rule.source
                    && probe.destination_segment() == rule.destination
            })
            .filter_map(|probe| {
                let canary = probe.canary().ok()?;
                if self.observed.contains(&ObservationKey::from_probe(probe)) {
                    return None;
                }
                let key = ReceiptKey::from_probe(probe);
                let commitment = self.commitments.get(&key).copied()?;
                let transmit = self.tx_receipts.get(&key).copied()?;
                let window = self.windows.get(&key).copied()?;
                if commitment.planned_canary() != Some(canary)
                    || commitment.interface() != transmit.interface()
                    || commitment.frame_hash() != transmit.frame_hash()
                    || !window.proves_complete_absence_for(transmit)
                {
                    return None;
                }
                Some(AbsenceEvidence::new(canary, commitment, transmit, window))
            })
            .collect()
    }

    fn append_receipt_limitations(&self, limitations: &mut Vec<String>, rule: crate::DirectedRule) {
        let mut missing_tx = false;
        let mut missing_commitment = false;
        let mut mismatched_hash = false;
        let mut mismatched_interface = false;
        let mut incomplete_window = false;
        for probe in self.plan.probes().iter().filter(|probe| {
            probe.source_segment() == rule.source && probe.destination_segment() == rule.destination
        }) {
            let key = ReceiptKey::from_probe(probe);
            let commitment = self.commitments.get(&key);
            missing_commitment |= commitment.is_none();
            mismatched_hash |= match (commitment, self.tx_receipts.get(&key)) {
                (Some(expected), Some(transmit)) => expected.frame_hash() != transmit.frame_hash(),
                _ => false,
            };
            mismatched_interface |= match (commitment, self.tx_receipts.get(&key)) {
                (Some(expected), Some(transmit)) => expected.interface() != transmit.interface(),
                _ => false,
            };
            missing_tx |= !self.tx_receipts.contains_key(&key);
            incomplete_window |= match (self.tx_receipts.get(&key), self.windows.get(&key)) {
                (Some(transmit), Some(window)) => !window.proves_complete_absence_for(*transmit),
                _ => true,
            };
        }
        if missing_commitment {
            limitations.push(String::from(
                "one or more planned probes lack an expected transmit commitment",
            ));
        }
        if mismatched_hash {
            limitations.push(String::from(
                "one or more transmit receipts do not match their expected frame commitment",
            ));
        }
        if mismatched_interface {
            limitations.push(String::from(
                "one or more transmit receipts use a different interface than their commitment",
            ));
        }
        if missing_tx {
            limitations.push(String::from(
                "one or more planned probes lack a committed transmit receipt",
            ));
        }
        if incomplete_window {
            limitations.push(String::from(
                "one or more receiver windows lack complete loss-free coverage of the committed send",
            ));
        }
    }
}
