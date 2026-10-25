//! Multicast control-plane and snooping checks

use super::super::types::{CheckCategory, CheckDescriptor, CleanupPolicy, RiskClass};
use super::requirements::{
    IGMP_REQUIREMENTS, IGMP_SNOOP_REQUIREMENTS, MLD_REQUIREMENTS, MLD_SNOOP_REQUIREMENTS,
};
use std::time::Duration;

pub(super) const IGMP_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "IGMP-OBS-001",
    title: "IGMP control-plane inventory",
    category: CheckCategory::Multicast,
    prerequisites: IGMP_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const IGMP_SNOOP_001: CheckDescriptor = CheckDescriptor {
    id: "IGMP-SNOOP-001",
    title: "IGMP snooping validation",
    category: CheckCategory::Multicast,
    prerequisites: IGMP_SNOOP_REQUIREMENTS,
    risk: RiskClass::SafeActive,
    required_agents: 2,
    packet_budget: 256,
    byte_budget: 65_536,
    duration_budget: Duration::from_secs(30),
    cleanup: CleanupPolicy::Verified,
};

pub(super) const MLD_001: CheckDescriptor = CheckDescriptor {
    id: "MLD-001",
    title: "MLD control-plane inventory",
    category: CheckCategory::Multicast,
    prerequisites: MLD_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const MLD_SNOOP_001: CheckDescriptor = CheckDescriptor {
    id: "MLD-SNOOP-001",
    title: "MLD snooping validation",
    category: CheckCategory::Multicast,
    prerequisites: MLD_SNOOP_REQUIREMENTS,
    risk: RiskClass::SafeActive,
    required_agents: 2,
    packet_budget: 256,
    byte_budget: 65_536,
    duration_budget: Duration::from_secs(30),
    cleanup: CleanupPolicy::Verified,
};
