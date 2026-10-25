//! First-hop redundancy inventory checks

use super::super::types::{CheckCategory, CheckDescriptor, CleanupPolicy, RiskClass};
use super::requirements::{HSRP_REQUIREMENTS, VRRP_REQUIREMENTS};
use std::time::Duration;

pub(super) const HSRP_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "HSRP-OBS-001",
    title: "HSRP participant inventory",
    category: CheckCategory::FirstHopRedundancy,
    prerequisites: HSRP_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const VRRP_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "VRRP-OBS-001",
    title: "VRRP participant inventory",
    category: CheckCategory::FirstHopRedundancy,
    prerequisites: VRRP_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};
