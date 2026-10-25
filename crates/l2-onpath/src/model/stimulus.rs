//! Bounded stimuli, path expectations, and canary plans

use l2_canary::{AgentId, Canary};

use super::CheckKind;
use crate::ModelError;

/// One-based identifier for a planned bounded stimulus
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StimulusId(u16);

impl StimulusId {
    /// Construct a nonzero stimulus identifier
    ///
    /// # Errors
    /// Returns [`ModelError::ZeroStimulusId`] for the reserved zero value
    pub const fn new(value: u16) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::ZeroStimulusId)
        } else {
            Ok(Self(value))
        }
    }

    /// Return the identifier value
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// One planned protocol stimulus; construction has no I/O side effects
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Stimulus {
    id: StimulusId,
    check: CheckKind,
    endpoint: AgentId,
    sequence: u64,
}

impl Stimulus {
    /// Construct one bounded stimulus identity
    ///
    /// # Errors
    /// Returns [`ModelError`] when the ID or sequence is zero
    pub const fn new(
        id: u16,
        check: CheckKind,
        endpoint: AgentId,
        sequence: u64,
    ) -> Result<Self, ModelError> {
        let Ok(id) = StimulusId::new(id) else {
            return Err(ModelError::ZeroStimulusId);
        };
        if sequence == 0 {
            return Err(ModelError::ZeroSequence);
        }
        Ok(Self {
            id,
            check,
            endpoint,
            sequence,
        })
    }

    /// Return the one-based stimulus ID
    #[must_use]
    pub const fn id(self) -> StimulusId {
        self.id
    }

    /// Return the descriptor kind exercised by the stimulus
    #[must_use]
    pub const fn check(self) -> CheckKind {
        self.check
    }

    /// Return the controlled endpoint targeted by the stimulus
    #[must_use]
    pub const fn endpoint(self) -> AgentId {
        self.endpoint
    }

    /// Return the unique sequence attached to committed transmit evidence
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// Whether an authenticated canary was expected to cross the tested path
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PathExpectation {
    /// A destination-scoped arrival claim contradicts the isolation boundary
    Blocked,
    /// A destination-scoped arrival claim is required for the allowed path
    Forwarded,
}

/// One canary tied to a bounded stimulus and a specific path expectation
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CanaryExpectation {
    canary: Canary,
    expectation: PathExpectation,
    stimulus: StimulusId,
}

impl CanaryExpectation {
    /// Construct a canary expectation from an already scoped canary
    ///
    /// # Errors
    /// Returns [`ModelError`] when the stimulus identifier is invalid
    pub const fn new(
        canary: Canary,
        expectation: PathExpectation,
        stimulus: u16,
    ) -> Result<Self, ModelError> {
        let Ok(stimulus) = StimulusId::new(stimulus) else {
            return Err(ModelError::ZeroStimulusId);
        };
        Ok(Self {
            canary,
            expectation,
            stimulus,
        })
    }

    /// Return the exact canary material that must be authenticated
    #[must_use]
    pub const fn canary(self) -> Canary {
        self.canary
    }

    /// Return the configured path expectation
    #[must_use]
    pub const fn expectation(self) -> PathExpectation {
        self.expectation
    }

    /// Return the stimulus associated with this canary
    #[must_use]
    pub const fn stimulus(self) -> StimulusId {
        self.stimulus
    }

    /// Return whether an authenticated canary matches this expectation
    #[must_use]
    pub fn matches(self, canary: &Canary) -> bool {
        self.canary == *canary
    }
}
