//! Immutable bounded assessment plan construction

use std::collections::BTreeMap;

use l2_canary::{AgentId, Canary, ID_LEN, RunId};
use l2_segmentation::TxCommitment;

use super::{
    AddressFamily, CanaryExpectation, CheckKind, ControlledEndpoint, MAX_CANARIES, MAX_COMMITMENTS,
    MAX_ENDPOINTS, MAX_STIMULI, Stimulus, StimulusId,
};
use crate::PlanError;

/// One immutable plan for a bounded on-path session
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssessmentPlan {
    run_id: [u8; ID_LEN],
    endpoints: Vec<ControlledEndpoint>,
    checks: Vec<CheckKind>,
    stimuli: Vec<Stimulus>,
    canaries: Vec<CanaryExpectation>,
    commitments: BTreeMap<u64, TxCommitment>,
    cleanup_commitments: BTreeMap<(AgentId, AddressFamily), TxCommitment>,
}

impl AssessmentPlan {
    /// Construct an empty plan from a checked recorded run identity
    ///
    /// # Errors
    /// Returns [`PlanError::InvalidRunId`] for the reserved all-zero identity
    pub fn for_replay(run_id: [u8; ID_LEN]) -> Result<Self, PlanError> {
        RunId::from_recorded(run_id).map_err(|_| PlanError::InvalidRunId)?;
        Ok(Self {
            run_id,
            endpoints: Vec::new(),
            checks: Vec::new(),
            stimuli: Vec::new(),
            canaries: Vec::new(),
            commitments: BTreeMap::new(),
            cleanup_commitments: BTreeMap::new(),
        })
    }

    /// Construct an empty plan with a fresh operating-system run identity
    ///
    /// # Errors
    /// Returns the entropy error when the operating system cannot provide an identity
    pub fn new() -> Result<Self, l2_canary::RunIdError> {
        RunId::generate().map(Self::from_run_id)
    }

    /// Construct a plan from the canary crate's checked run identity
    #[must_use]
    pub const fn from_run_id(run_id: RunId) -> Self {
        Self {
            run_id: run_id.into_bytes(),
            endpoints: Vec::new(),
            checks: Vec::new(),
            stimuli: Vec::new(),
            canaries: Vec::new(),
            commitments: BTreeMap::new(),
            cleanup_commitments: BTreeMap::new(),
        }
    }

    /// Return the run identity authenticated by all session evidence
    #[must_use]
    pub const fn run_id(&self) -> &[u8; ID_LEN] {
        &self.run_id
    }

    /// Return endpoints in insertion order
    #[must_use]
    pub fn endpoints(&self) -> &[ControlledEndpoint] {
        &self.endpoints
    }

    /// Return selected descriptor kinds
    #[must_use]
    pub fn checks(&self) -> &[CheckKind] {
        &self.checks
    }

    /// Return planned stimuli
    #[must_use]
    pub fn stimuli(&self) -> &[Stimulus] {
        &self.stimuli
    }

    /// Return planned authenticated canaries
    #[must_use]
    pub fn canaries(&self) -> &[CanaryExpectation] {
        &self.canaries
    }

    /// Return exact transmit commitments in deterministic sequence order
    pub fn commitments(&self) -> impl Iterator<Item = TxCommitment> + '_ {
        let mut commitments =
            Vec::with_capacity(self.commitments.len() + self.cleanup_commitments.len());
        commitments.extend(self.commitments.values().copied());
        commitments.extend(self.cleanup_commitments.values().copied());
        commitments.sort_unstable_by_key(|commitment| commitment.sequence());
        commitments.into_iter()
    }

    /// Return exact endpoint restoration commitments in endpoint order
    pub fn cleanup_commitments(&self) -> impl Iterator<Item = TxCommitment> + '_ {
        self.cleanup_commitments.values().copied()
    }

    /// Add one endpoint to the immutable plan
    ///
    /// # Errors
    /// Returns [`PlanError`] when the endpoint is repeated or the endpoint bound is full
    pub fn add_endpoint(&mut self, endpoint: ControlledEndpoint) -> Result<(), PlanError> {
        if self.endpoints.len() >= MAX_ENDPOINTS {
            return Err(PlanError::EndpointLimitExceeded {
                count: self.endpoints.len() + 1,
                maximum: MAX_ENDPOINTS,
            });
        }
        let key = (endpoint.id(), endpoint.family());
        if self
            .endpoints
            .iter()
            .any(|item| (item.id(), item.family()) == key)
        {
            return Err(PlanError::DuplicateEndpoint {
                endpoint: endpoint.id(),
                family: endpoint.family(),
            });
        }
        self.endpoints.push(endpoint);
        Ok(())
    }

    /// Select one catalog descriptor
    ///
    /// # Errors
    /// Returns [`PlanError`] when the check collection has reached its fixed bound or repeats
    pub fn add_check(&mut self, kind: CheckKind) -> Result<(), PlanError> {
        if self.checks.contains(&kind) {
            return Err(PlanError::DuplicateCheck { kind });
        }
        self.checks.push(kind);
        Ok(())
    }

    /// Add one bounded stimulus with a unique identity and sequence
    ///
    /// # Errors
    /// Returns [`PlanError`] when references or fixed bounds are invalid
    pub fn add_stimulus(&mut self, stimulus: Stimulus) -> Result<(), PlanError> {
        if self.stimuli.len() >= MAX_STIMULI {
            return Err(PlanError::StimulusLimitExceeded {
                count: self.stimuli.len() + 1,
                maximum: MAX_STIMULI,
            });
        }
        if !self.checks.contains(&stimulus.check()) {
            return Err(PlanError::UnknownCheck {
                kind: stimulus.check(),
            });
        }
        // A single controlled agent may carry both IPv4 and IPv6 bindings
        let Some(_endpoint) = self.endpoints.iter().find(|item| {
            item.id() == stimulus.endpoint() && stimulus.check().accepts_family(item.family())
        }) else {
            let Some(endpoint) = self
                .endpoints
                .iter()
                .find(|item| item.id() == stimulus.endpoint())
            else {
                return Err(PlanError::UnknownEndpoint {
                    endpoint: stimulus.endpoint(),
                });
            };
            return Err(PlanError::WrongFamily {
                check: stimulus.check(),
                family: endpoint.family(),
            });
        };
        if self.stimuli.iter().any(|item| item.id() == stimulus.id()) {
            return Err(PlanError::DuplicateStimulus { id: stimulus.id() });
        }
        if self
            .stimuli
            .iter()
            .any(|item| item.sequence() == stimulus.sequence())
        {
            return Err(PlanError::DuplicateStimulusSequence {
                sequence: stimulus.sequence(),
            });
        }
        if self
            .canaries
            .iter()
            .any(|item| item.canary().sequence() == stimulus.sequence())
        {
            return Err(PlanError::DuplicateTransmitSequence {
                sequence: stimulus.sequence(),
            });
        }
        self.stimuli.push(stimulus);
        Ok(())
    }

    /// Add one authenticated canary expectation tied to a planned stimulus
    ///
    /// # Errors
    /// Returns [`PlanError`] when references or fixed bounds are invalid
    pub fn add_canary(&mut self, canary: CanaryExpectation) -> Result<(), PlanError> {
        if self.canaries.len() >= MAX_CANARIES {
            return Err(PlanError::CanaryLimitExceeded {
                count: self.canaries.len() + 1,
                maximum: MAX_CANARIES,
            });
        }
        if !self
            .stimuli
            .iter()
            .any(|item| item.id() == canary.stimulus())
        {
            return Err(PlanError::UnknownStimulus {
                id: canary.stimulus(),
            });
        }
        let fields = canary.canary();
        if fields.run_id().into_bytes() != self.run_id {
            return Err(PlanError::WrongRun);
        }
        let Some(stimulus) = self.stimulus(canary.stimulus()) else {
            return Err(PlanError::UnknownStimulus {
                id: canary.stimulus(),
            });
        };
        if self
            .endpoint_for_check(fields.source_agent_id(), stimulus.check())
            .is_none()
        {
            return Err(PlanError::UnknownEndpoint {
                endpoint: fields.source_agent_id(),
            });
        }
        if fields.source_agent_id() != stimulus.endpoint() {
            return Err(PlanError::CanarySourceMismatch {
                expected: stimulus.endpoint(),
                actual: fields.source_agent_id(),
            });
        }
        if self
            .endpoint_for_check(fields.destination_agent_id(), stimulus.check())
            .is_none()
        {
            return Err(PlanError::UnknownEndpoint {
                endpoint: fields.destination_agent_id(),
            });
        }
        if self.canaries.iter().any(|item| item.matches(&fields)) {
            return Err(PlanError::DuplicateCanary);
        }
        if self
            .stimuli
            .iter()
            .any(|item| item.sequence() == fields.sequence())
            || self
                .canaries
                .iter()
                .any(|item| item.canary().sequence() == fields.sequence())
        {
            return Err(PlanError::DuplicateTransmitSequence {
                sequence: fields.sequence(),
            });
        }
        self.canaries.push(canary);
        Ok(())
    }

    /// Add one exact frame commitment for a planned stimulus or canary
    ///
    /// The commitment is the expected digest of the complete encoded frame.
    /// It fixes the exact bytes that a later transmit claim must match, but it
    /// does not prove kernel activity or physical delivery
    ///
    /// # Errors
    /// Returns [`PlanError`] when the run or sequence is not part of this
    /// plan, the bounded collection is full, or a sequence is repeated
    pub fn add_commitment(&mut self, commitment: TxCommitment) -> Result<(), PlanError> {
        if commitment.run_id() != self.run_id {
            return Err(PlanError::WrongRun);
        }
        let sequence = commitment.sequence();
        if self.commitments.len() + self.cleanup_commitments.len() >= MAX_COMMITMENTS {
            return Err(PlanError::CommitmentLimitExceeded {
                count: self.commitments.len() + self.cleanup_commitments.len() + 1,
                maximum: MAX_COMMITMENTS,
            });
        }
        let planned_stimulus = self
            .stimuli
            .iter()
            .find(|stimulus| stimulus.sequence() == sequence)
            .copied();
        let planned_canary = self
            .canaries
            .iter()
            .find(|canary| canary.canary().sequence() == sequence)
            .copied();
        if planned_stimulus.is_none() && planned_canary.is_none() {
            return Err(PlanError::UnknownCommitmentSequence { sequence });
        }

        // Canary commitments must preserve the authenticated payload identity
        if let Some(expectation) = planned_canary {
            let canary = expectation.canary();
            if commitment.planned_canary() != Some(canary) {
                return Err(PlanError::CommitmentCanaryMismatch { sequence });
            }
            let Some(stimulus) = self.stimulus(expectation.stimulus()) else {
                return Err(PlanError::UnknownStimulus {
                    id: expectation.stimulus(),
                });
            };
            let Some(source) = self.endpoint_for_check(canary.source_agent_id(), stimulus.check())
            else {
                return Err(PlanError::UnknownEndpoint {
                    endpoint: canary.source_agent_id(),
                });
            };
            if commitment.interface() != source.interface() {
                return Err(PlanError::CommitmentInterfaceMismatch { sequence });
            }
        } else if let Some(stimulus) = planned_stimulus {
            if commitment.planned_canary().is_some() {
                return Err(PlanError::UnexpectedCanaryCommitment { sequence });
            }
            let Some(endpoint) = self.endpoint_for_check(stimulus.endpoint(), stimulus.check())
            else {
                return Err(PlanError::UnknownEndpoint {
                    endpoint: stimulus.endpoint(),
                });
            };
            if commitment.interface() != endpoint.interface() {
                return Err(PlanError::CommitmentInterfaceMismatch { sequence });
            }
        }
        if let Some(existing) = self.commitments.get(&sequence) {
            return if *existing == commitment {
                Err(PlanError::DuplicateCommitment { sequence })
            } else {
                Err(PlanError::ConflictingCommitment { sequence })
            };
        }
        if self
            .cleanup_commitments
            .values()
            .any(|item| item.sequence() == sequence)
        {
            return Err(PlanError::DuplicateCommitment { sequence });
        }
        self.commitments.insert(sequence, commitment);
        Ok(())
    }

    /// Add one exact restoration frame commitment for a planned endpoint
    ///
    /// The frame digest and length reserve a concrete cleanup operation before
    /// any stimulus can consume the check budget
    ///
    /// # Errors
    /// Returns [`PlanError`] when the endpoint, run, interface, subject, or
    /// sequence does not match the immutable plan
    pub fn add_cleanup_commitment(
        &mut self,
        endpoint: AgentId,
        family: AddressFamily,
        commitment: TxCommitment,
    ) -> Result<(), PlanError> {
        if commitment.run_id() != self.run_id {
            return Err(PlanError::WrongRun);
        }
        let key = (endpoint, family);
        let Some(planned_endpoint) = self.endpoint(endpoint, family) else {
            return Err(PlanError::UnknownEndpoint { endpoint });
        };
        if commitment.interface() != planned_endpoint.interface() {
            return Err(PlanError::CommitmentInterfaceMismatch {
                sequence: commitment.sequence(),
            });
        }
        if commitment.planned_canary().is_some() {
            return Err(PlanError::UnexpectedCanaryCommitment {
                sequence: commitment.sequence(),
            });
        }
        let sequence = commitment.sequence();
        if self.stimuli.iter().any(|item| item.sequence() == sequence)
            || self
                .canaries
                .iter()
                .any(|item| item.canary().sequence() == sequence)
            || self.commitments.contains_key(&sequence)
            || self
                .cleanup_commitments
                .values()
                .any(|item| item.sequence() == sequence)
        {
            return Err(PlanError::DuplicateCommitment { sequence });
        }
        if self.cleanup_commitments.contains_key(&key) {
            return Err(PlanError::DuplicateCleanupCommitment { endpoint, family });
        }
        if self.commitments.len() + self.cleanup_commitments.len() >= MAX_COMMITMENTS {
            return Err(PlanError::CommitmentLimitExceeded {
                count: self.commitments.len() + self.cleanup_commitments.len() + 1,
                maximum: MAX_COMMITMENTS,
            });
        }
        self.cleanup_commitments.insert(key, commitment);
        Ok(())
    }

    /// Find the endpoint with one exact family and identity
    #[must_use]
    pub(crate) fn endpoint(
        &self,
        id: AgentId,
        family: AddressFamily,
    ) -> Option<ControlledEndpoint> {
        self.endpoints
            .iter()
            .copied()
            .find(|endpoint| endpoint.id() == id && endpoint.family() == family)
    }

    /// Find one endpoint that can participate in a selected check
    #[must_use]
    pub(crate) fn endpoint_for_check(
        &self,
        id: AgentId,
        check: CheckKind,
    ) -> Option<ControlledEndpoint> {
        self.endpoints
            .iter()
            .copied()
            .find(|endpoint| endpoint.id() == id && check.accepts_family(endpoint.family()))
    }

    /// Find one planned stimulus by its stable ID
    #[must_use]
    pub(crate) fn stimulus(&self, id: StimulusId) -> Option<Stimulus> {
        self.stimuli
            .iter()
            .copied()
            .find(|stimulus| stimulus.id() == id)
    }

    /// Find one canary expectation that exactly matches authenticated fields
    #[must_use]
    pub(crate) fn canary(&self, value: &Canary) -> Option<CanaryExpectation> {
        self.canaries
            .iter()
            .copied()
            .find(|item| item.matches(value))
    }

    /// Find an exact frame commitment for one planned sequence
    #[must_use]
    pub fn commitment(&self, sequence: u64) -> Option<TxCommitment> {
        self.commitments.get(&sequence).copied().or_else(|| {
            self.cleanup_commitments
                .values()
                .find(|commitment| commitment.sequence() == sequence)
                .copied()
        })
    }

    /// Return one exact cleanup commitment for a planned endpoint
    #[must_use]
    pub fn cleanup_commitment(
        &self,
        endpoint: AgentId,
        family: AddressFamily,
    ) -> Option<TxCommitment> {
        self.cleanup_commitments.get(&(endpoint, family)).copied()
    }

    /// Return whether every endpoint has one exact cleanup transmit reserve
    #[must_use]
    pub fn has_complete_cleanup_commitments(&self) -> bool {
        self.cleanup_commitments.len() == self.endpoints.len()
    }
}
