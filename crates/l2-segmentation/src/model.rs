//! Bounded identities, rules, plans, and probe material

use l2_canary::{
    AgentId, Canary, CanaryError, CanaryIdentity, ID_LEN, NONCE_LEN, RunId, RunIdError,
};

/// Stable bounded identifier for one logical Layer-2 segment
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SegmentId(u8);

impl SegmentId {
    /// Construct a segment identifier
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Return the numeric segment identifier
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl From<u8> for SegmentId {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

/// One controlled agent and the segment where it is attached
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Agent {
    id: AgentId,
    segment: SegmentId,
    interface: crate::InterfaceBindingRequest,
}

impl Agent {
    /// Associate one agent identity with its segment and exact interface
    #[must_use]
    pub const fn new(
        id: AgentId,
        segment: SegmentId,
        interface: crate::InterfaceBindingRequest,
    ) -> Self {
        Self {
            id,
            segment,
            interface,
        }
    }

    /// Return the agent identity
    #[must_use]
    pub const fn id(self) -> AgentId {
        self.id
    }

    /// Return the attached segment
    #[must_use]
    pub const fn segment(self) -> SegmentId {
        self.segment
    }

    /// Return the exact namespace and interface attachment for this agent
    #[must_use]
    pub const fn interface(self) -> crate::InterfaceBindingRequest {
        self.interface
    }
}

/// Whether one directed segment path is expected to forward a canary
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RuleExpectation {
    /// A matching canary should arrive at the destination agent
    Allow,
    /// Matching canaries should be blocked by the Layer-2 path
    Deny,
}

/// One explicit directed policy rule between two segments
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DirectedRule {
    /// Segment holding the sending agent
    pub source: SegmentId,
    /// Segment holding the receiving agent
    pub destination: SegmentId,
    /// Expected forwarding behavior for this direction
    pub expectation: RuleExpectation,
    /// Number of distinct probes to plan for every agent pair
    pub attempts: u8,
}

impl DirectedRule {
    /// Construct an explicit directed rule
    #[must_use]
    pub const fn new(
        source: SegmentId,
        destination: SegmentId,
        expectation: RuleExpectation,
        attempts: u8,
    ) -> Self {
        Self {
            source,
            destination,
            expectation,
            attempts,
        }
    }

    /// Return the source segment
    #[must_use]
    pub const fn source(self) -> SegmentId {
        self.source
    }

    /// Return the destination segment
    #[must_use]
    pub const fn destination(self) -> SegmentId {
        self.destination
    }

    /// Return the expected directed behavior
    #[must_use]
    pub const fn expectation(self) -> RuleExpectation {
        self.expectation
    }

    /// Return the configured attempts per source and destination agent pair
    #[must_use]
    pub const fn attempts(self) -> u8 {
        self.attempts
    }
}

/// Input facts used to construct a deterministic segmentation plan
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanInput {
    /// Run identity included in every planned canary
    run_id: RunId,
    /// Logical segments known to the caller
    pub segments: Vec<SegmentId>,
    /// Controlled agents and their segment assignments
    pub agents: Vec<Agent>,
    /// Explicit directed policy rules
    pub rules: Vec<DirectedRule>,
}

impl PlanInput {
    /// Construct empty planning input with a fresh operating-system run ID
    ///
    /// # Errors
    ///
    /// Returns an entropy error when a fresh run identity cannot be generated
    pub fn new() -> Result<Self, RunIdError> {
        RunId::generate().map(Self::from_run_id)
    }

    /// Reconstruct planning input from a checked recorded run ID
    ///
    /// # Errors
    ///
    /// Rejects the all-zero sentinel
    pub fn for_replay(run_id: [u8; ID_LEN]) -> Result<Self, RunIdError> {
        RunId::from_recorded(run_id).map(Self::from_run_id)
    }

    /// Construct planning input from an already checked run identity
    #[must_use]
    pub const fn from_run_id(run_id: RunId) -> Self {
        Self {
            run_id,
            segments: Vec::new(),
            agents: Vec::new(),
            rules: Vec::new(),
        }
    }

    /// Return the authenticated run identity
    #[must_use]
    pub const fn run_id(&self) -> &[u8; ID_LEN] {
        self.run_id.as_bytes()
    }

    pub(crate) const fn run_id_value(&self) -> RunId {
        self.run_id
    }

    /// Build a deterministic plan from this input
    ///
    /// # Errors
    ///
    /// Returns a bounded validation error when the input is not planable
    pub fn plan(&self) -> Result<Plan, crate::PlanError> {
        crate::plan(self)
    }
}

/// A fully validated deterministic segmentation plan
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    pub(crate) run_id: RunId,
    pub(crate) segments: Vec<SegmentId>,
    pub(crate) agents: Vec<Agent>,
    pub(crate) rules: Vec<DirectedRule>,
    pub(crate) probes: Vec<Probe>,
}

impl Plan {
    /// Return the assessment run identity
    #[must_use]
    pub const fn run_id(&self) -> &[u8; ID_LEN] {
        self.run_id.as_bytes()
    }

    /// Return segments in stable ascending order
    #[must_use]
    pub fn segments(&self) -> &[SegmentId] {
        &self.segments
    }

    /// Return agents in stable segment and identity order
    #[must_use]
    pub fn agents(&self) -> &[Agent] {
        &self.agents
    }

    /// Return explicit directed rules in stable source and destination order
    #[must_use]
    pub fn rules(&self) -> &[DirectedRule] {
        &self.rules
    }

    /// Return all planned probes in stable deterministic order
    #[must_use]
    pub fn probes(&self) -> &[Probe] {
        &self.probes
    }
}

/// One canary material item assigned to a source and destination agent pair
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Probe {
    pub(crate) run_id: RunId,
    pub(crate) source: Agent,
    pub(crate) destination: Agent,
    pub(crate) expectation: RuleExpectation,
    pub(crate) attempt: u8,
    pub(crate) sequence: u64,
    pub(crate) nonce: [u8; NONCE_LEN],
}

impl Probe {
    /// Return the segment where this probe starts
    #[must_use]
    pub const fn source_segment(self) -> SegmentId {
        self.source.segment()
    }

    /// Return the segment where this probe should arrive
    #[must_use]
    pub const fn destination_segment(self) -> SegmentId {
        self.destination.segment()
    }

    /// Return the sending agent identity
    #[must_use]
    pub const fn source_agent_id(self) -> AgentId {
        self.source.id()
    }

    /// Return the receiving agent identity
    #[must_use]
    pub const fn destination_agent_id(self) -> AgentId {
        self.destination.id()
    }

    /// Return the interface that must carry this probe's transmission
    #[must_use]
    pub const fn source_interface(self) -> crate::InterfaceBindingRequest {
        self.source.interface()
    }

    /// Return the interface that must observe this probe at its destination
    #[must_use]
    pub const fn destination_interface(self) -> crate::InterfaceBindingRequest {
        self.destination.interface()
    }

    /// Return the directed expectation attached to this probe
    #[must_use]
    pub const fn expectation(self) -> RuleExpectation {
        self.expectation
    }

    /// Return the one-based attempt number for this agent pair
    #[must_use]
    pub const fn attempt(self) -> u8 {
        self.attempt
    }

    /// Return the globally unique sequence material for this plan
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Return the deterministic nonce material for this plan
    #[must_use]
    pub const fn nonce(self) -> [u8; NONCE_LEN] {
        self.nonce
    }

    /// Return the authenticated canary that a caller may encode and transmit
    ///
    /// # Errors
    /// Returns [`CanaryError`] when the checked probe material cannot form a canary
    pub fn canary(self) -> Result<Canary, CanaryError> {
        let identity = CanaryIdentity::new(self.run_id, self.source.id(), self.destination.id())
            .map_err(CanaryError::from)?;
        Canary::new(identity, self.sequence, self.nonce)
    }
}
