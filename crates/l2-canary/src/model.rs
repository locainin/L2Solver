use crate::{AgentIdError, CanaryError, CanaryIdentityError, ID_LEN, NONCE_LEN, RunId};

/// Stable identity for one controlled agent
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AgentId([u8; ID_LEN]);

impl AgentId {
    /// Construct a checked controlled-agent identity
    ///
    /// # Errors
    /// Returns [`AgentIdError::ReservedZero`] for the all-zero sentinel
    pub const fn new(bytes: [u8; ID_LEN]) -> Result<Self, AgentIdError> {
        if all_zero(&bytes) {
            Err(AgentIdError::ReservedZero)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Return the identity bytes for a canary field
    #[must_use]
    pub const fn bytes(self) -> [u8; ID_LEN] {
        self.0
    }

    /// Borrow the identity bytes without copying
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }
}

impl TryFrom<[u8; ID_LEN]> for AgentId {
    type Error = AgentIdError;

    fn try_from(bytes: [u8; ID_LEN]) -> Result<Self, Self::Error> {
        Self::new(bytes)
    }
}

impl From<AgentId> for [u8; ID_LEN] {
    fn from(identity: AgentId) -> Self {
        identity.bytes()
    }
}

/// Run/source/destination tuple that scopes sequence monotonicity
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CanaryIdentity {
    run_id: RunId,
    source: AgentId,
    destination: AgentId,
}

impl CanaryIdentity {
    /// Construct a checked directional identity tuple
    ///
    /// # Errors
    /// Returns [`CanaryIdentityError::SameAgent`] when both ends name one agent
    pub const fn new(
        run_id: RunId,
        source_agent_id: AgentId,
        destination_agent_id: AgentId,
    ) -> Result<Self, CanaryIdentityError> {
        if same_agent(source_agent_id, destination_agent_id) {
            return Err(CanaryIdentityError::SameAgent);
        }
        Ok(Self {
            run_id,
            source: source_agent_id,
            destination: destination_agent_id,
        })
    }

    /// Return the checked run identity
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    /// Return the checked sending-agent identity
    #[must_use]
    pub const fn source_agent_id(self) -> AgentId {
        self.source
    }

    /// Return the checked receiving-agent identity
    #[must_use]
    pub const fn destination_agent_id(self) -> AgentId {
        self.destination
    }
}

/// Authenticated canary fields carried by the fixed wire format
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Canary {
    identity: CanaryIdentity,
    sequence: u64,
    nonce: [u8; NONCE_LEN],
}

impl Canary {
    /// Construct a checked canary payload
    ///
    /// # Errors
    /// Returns [`CanaryError::ZeroSequence`] for the reserved zero sequence
    pub const fn new(
        identity: CanaryIdentity,
        sequence: u64,
        nonce: [u8; NONCE_LEN],
    ) -> Result<Self, CanaryError> {
        if sequence == 0 {
            return Err(CanaryError::ZeroSequence);
        }
        Ok(Self {
            identity,
            sequence,
            nonce,
        })
    }

    /// Return the checked run identity
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.identity.run_id()
    }

    /// Return the checked sending-agent identity
    #[must_use]
    pub const fn source_agent_id(self) -> AgentId {
        self.identity.source_agent_id()
    }

    /// Return the checked receiving-agent identity
    #[must_use]
    pub const fn destination_agent_id(self) -> AgentId {
        self.identity.destination_agent_id()
    }

    /// Return the checked identity tuple used by replay tracking and context checks
    #[must_use]
    pub const fn identity(self) -> CanaryIdentity {
        self.identity
    }

    /// Return the one-based sequence number
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Return the caller-provided freshness value
    #[must_use]
    pub const fn nonce(self) -> [u8; NONCE_LEN] {
        self.nonce
    }
}

const fn all_zero(bytes: &[u8; ID_LEN]) -> bool {
    u128::from_be_bytes(*bytes) == 0
}

const fn same_agent(source: AgentId, destination: AgentId) -> bool {
    u128::from_be_bytes(source.bytes()) == u128::from_be_bytes(destination.bytes())
}

/// Wire bytes that have not passed authentication
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnverifiedCanary<'a> {
    wire: &'a [u8],
}

impl<'a> UnverifiedCanary<'a> {
    /// Mark borrowed wire bytes as untrusted canary input
    #[must_use]
    pub const fn new(wire: &'a [u8]) -> Self {
        Self { wire }
    }

    pub(crate) const fn wire(self) -> &'a [u8] {
        self.wire
    }
}

/// Canary fields whose wire authentication has been verified
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VerifiedCanary {
    inner: Canary,
    wire_sha256: [u8; 32],
}

impl VerifiedCanary {
    pub(crate) const fn new(inner: Canary, wire_sha256: [u8; 32]) -> Self {
        Self { inner, wire_sha256 }
    }

    /// Borrow the authenticated fields
    #[must_use]
    pub const fn as_canary(&self) -> &Canary {
        &self.inner
    }

    /// Copy the authenticated fields out of the verification state
    #[must_use]
    pub const fn into_canary(self) -> Canary {
        self.inner
    }

    /// Return the authenticated replay identity
    #[must_use]
    pub const fn identity(self) -> CanaryIdentity {
        self.inner.identity()
    }

    /// Return the authenticated sequence number
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.inner.sequence()
    }

    /// Return the digest of the exact authenticated bytes that were verified
    #[must_use]
    pub const fn wire_sha256(self) -> [u8; 32] {
        self.wire_sha256
    }
}
