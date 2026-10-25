//! Trunk negotiation and VLAN-management checks

use super::super::types::{CheckCategory, CheckDescriptor, CleanupPolicy, RiskClass};
use super::requirements::{DTP_OBSERVATION_REQUIREMENTS, DTP_REQUIREMENTS, VTP_REQUIREMENTS};
use std::time::Duration;

pub(super) const DTP_001: CheckDescriptor = CheckDescriptor {
    id: "DTP-001",
    title: "Trunk negotiation validation",
    category: CheckCategory::Trunking,
    prerequisites: DTP_REQUIREMENTS,
    risk: RiskClass::Stateful,
    required_agents: 1,
    packet_budget: 128,
    byte_budget: 32_768,
    duration_budget: Duration::from_secs(20),
    cleanup: CleanupPolicy::Verified,
};

pub(super) const DTP_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "DTP-OBS-001",
    title: "DTP exposure inventory",
    category: CheckCategory::Trunking,
    prerequisites: DTP_OBSERVATION_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const VTP_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "VTP-OBS-001",
    title: "VTP control-plane inventory",
    category: CheckCategory::Trunking,
    prerequisites: VTP_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};
