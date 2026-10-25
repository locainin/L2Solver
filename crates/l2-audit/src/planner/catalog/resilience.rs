//! Resource and loop-resilience checks

use super::super::types::{CheckCategory, CheckDescriptor, CleanupPolicy, RiskClass};
use super::requirements::{LOOP_REQUIREMENTS, MAC_TABLE_REQUIREMENTS, STORM_REQUIREMENTS};
use std::time::Duration;

pub(super) const LOOP_001: CheckDescriptor = CheckDescriptor {
    id: "LOOP-001",
    title: "Loop-protection behavior validation",
    category: CheckCategory::Resilience,
    prerequisites: LOOP_REQUIREMENTS,
    risk: RiskClass::Disruptive,
    required_agents: 1,
    packet_budget: 128,
    byte_budget: 32_768,
    duration_budget: Duration::from_secs(20),
    cleanup: CleanupPolicy::Verified,
};

pub(super) const MACTABLE_001: CheckDescriptor = CheckDescriptor {
    id: "MACTABLE-001",
    title: "Forwarding-table resource validation",
    category: CheckCategory::Resilience,
    prerequisites: MAC_TABLE_REQUIREMENTS,
    risk: RiskClass::Disruptive,
    required_agents: 1,
    packet_budget: 256,
    byte_budget: 65_536,
    duration_budget: Duration::from_secs(30),
    cleanup: CleanupPolicy::Verified,
};

pub(super) const STORM_001: CheckDescriptor = CheckDescriptor {
    id: "STORM-001",
    title: "Storm-control behavior validation",
    category: CheckCategory::Resilience,
    prerequisites: STORM_REQUIREMENTS,
    risk: RiskClass::Disruptive,
    required_agents: 1,
    packet_budget: 256,
    byte_budget: 65_536,
    duration_budget: Duration::from_secs(30),
    cleanup: CleanupPolicy::Verified,
};
