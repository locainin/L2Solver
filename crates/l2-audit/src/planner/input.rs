//! Bounded facts supplied to the applicability planner

use super::types::{AssessmentProfile, Capability};
use crate::{DEFAULT_SOURCE, InterfaceObservation, PortRole};
use l2_capture::InterfaceId;
use l2_discovery::{FingerprintStatus, Protocol};
use std::{collections::BTreeSet, fmt};

use super::MAX_AGENT_COUNT;

/// Bounded input facts supplied to the applicability planner
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannerInput {
    pub(super) protocols: BTreeSet<Protocol>,
    pub(super) capabilities: BTreeSet<Capability>,
    pub(super) sources: BTreeSet<InterfaceId>,
    pub(super) agent_count: usize,
    pub(super) capture_available: bool,
    pub(super) stp_root_sources: BTreeSet<InterfaceId>,
    pub(super) profile: AssessmentProfile,
    pub(super) port_roles: BTreeSet<PortRole>,
}

impl Default for PlannerInput {
    fn default() -> Self {
        Self::new()
    }
}

impl PlannerInput {
    /// Construct an input with passive capture available and no active agents
    #[must_use]
    pub fn new() -> Self {
        let mut capabilities = BTreeSet::new();
        capabilities.insert(Capability::PassiveCapture);
        let sources = BTreeSet::from([InterfaceId {
            section: 0,
            index: 0,
        }]);
        Self {
            protocols: BTreeSet::new(),
            capabilities,
            sources,
            agent_count: 0,
            capture_available: true,
            stp_root_sources: BTreeSet::new(),
            profile: AssessmentProfile::Opportunistic,
            port_roles: BTreeSet::new(),
        }
    }

    /// Infer the protocol surfaces represented by the current inventory
    #[must_use]
    pub fn from_interfaces(interfaces: &[InterfaceObservation]) -> Self {
        let mut input = Self::new();
        input.sources.clear();
        for interface in interfaces {
            input.sources.insert(InterfaceId {
                section: interface.section,
                index: interface.index,
            });
            if !interface.neighbors.is_empty() {
                input.protocols.insert(Protocol::Lldp);
            }
            if interface.stp_frames > 0 || !interface.stp.is_empty() {
                input.protocols.insert(Protocol::Stp);
            }
            if !interface.stp.is_empty() {
                input.stp_root_sources.insert(InterfaceId {
                    section: interface.section,
                    index: interface.index,
                });
            }
            input.protocols.extend(
                interface
                    .protocols
                    .iter()
                    .filter(|observation| matches!(observation.status, FingerprintStatus::Observed))
                    .map(|observation| observation.protocol),
            );
            input
                .port_roles
                .insert(crate::infer_port_role(interface).role);
        }
        input
    }

    /// Select how passive evidence influences active-check applicability
    #[must_use]
    pub const fn with_profile(mut self, profile: AssessmentProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Add a port role supplied by inference or explicit operator context
    #[must_use]
    pub fn with_port_role(mut self, role: PortRole) -> Self {
        self.port_roles.insert(role);
        self
    }

    /// Add a protocol fingerprint while preserving deterministic set semantics
    #[must_use]
    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocols.insert(protocol);
        self
    }

    /// Add a local capability to the planner input
    #[must_use]
    pub fn with_capability(mut self, capability: Capability) -> Self {
        self.capabilities.insert(capability);
        self
    }

    /// Set the number of controlled agents within the planner bound
    /// # Errors
    /// Returns [`PlannerError::AgentCountExceeded`] when the requested count is too large
    pub fn with_agent_count(mut self, count: usize) -> Result<Self, PlannerError> {
        if count > MAX_AGENT_COUNT {
            return Err(PlannerError::AgentCountExceeded {
                count,
                maximum: MAX_AGENT_COUNT,
            });
        }
        self.agent_count = count;
        Ok(self)
    }

    /// Mark whether a usable capture scope exists
    #[must_use]
    pub const fn with_capture_available(mut self, available: bool) -> Self {
        self.capture_available = available;
        self
    }

    /// Add a usable root-bearing STP advertisement to synthetic planner input
    #[must_use]
    pub fn with_stp_root_advertisement(mut self) -> Self {
        self.protocols.insert(Protocol::Stp);
        self.stp_root_sources.insert(DEFAULT_SOURCE);
        self
    }

    /// Return the observed protocol fingerprints
    #[must_use]
    pub const fn protocols(&self) -> &BTreeSet<Protocol> {
        &self.protocols
    }

    /// Return the available local capabilities
    #[must_use]
    pub const fn capabilities(&self) -> &BTreeSet<Capability> {
        &self.capabilities
    }

    /// Return the capture interfaces that contributed observations
    #[must_use]
    pub const fn sources(&self) -> &BTreeSet<InterfaceId> {
        &self.sources
    }

    /// Return the number of controlled agents
    #[must_use]
    pub const fn agent_count(&self) -> usize {
        self.agent_count
    }

    /// Return whether a capture scope is available
    #[must_use]
    pub const fn capture_available(&self) -> bool {
        self.capture_available
    }

    /// Return whether the capture contains a root-bearing STP advertisement
    #[must_use]
    pub fn stp_root_advertisement(&self) -> bool {
        !self.stp_root_sources.is_empty()
    }

    /// Return whether one capture source supplied a root-bearing STP advertisement
    #[must_use]
    pub fn has_stp_root_advertisement(&self, source: InterfaceId) -> bool {
        self.stp_root_sources.contains(&source)
    }

    /// Return the selected assessment profile
    #[must_use]
    pub const fn profile(&self) -> AssessmentProfile {
        self.profile
    }

    /// Return inferred or explicitly supplied port roles
    #[must_use]
    pub const fn port_roles(&self) -> &BTreeSet<PortRole> {
        &self.port_roles
    }
}

/// Planner input exceeded a hard resource bound
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlannerError {
    AgentCountExceeded { count: usize, maximum: usize },
}

impl fmt::Display for PlannerError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AgentCountExceeded { count, maximum } => {
                write!(
                    output,
                    "agent count {count} exceeds planner maximum {maximum}"
                )
            }
        }
    }
}

impl std::error::Error for PlannerError {}
