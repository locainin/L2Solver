//! Neighbor-discovery inventory and policy checks

use super::super::types::{CheckCategory, CheckDescriptor, CleanupPolicy, RiskClass};
use super::requirements::{CDP_REQUIREMENTS, LLDP_POLICY_REQUIREMENTS, LLDP_REQUIREMENTS};
use std::time::Duration;

pub(super) const CDP_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "CDP-OBS-001",
    title: "CDP control-plane fingerprint inventory",
    category: CheckCategory::NeighborDiscovery,
    prerequisites: CDP_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const LLDP_001: CheckDescriptor = CheckDescriptor {
    id: "LLDP-001",
    title: "LLDP neighbor inventory",
    category: CheckCategory::NeighborDiscovery,
    prerequisites: LLDP_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const LLDP_002: CheckDescriptor = CheckDescriptor {
    id: "LLDP-002",
    title: "LLDP visibility policy comparison",
    category: CheckCategory::NeighborDiscovery,
    prerequisites: LLDP_POLICY_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};
