//! Spanning-tree observation and protection checks

use super::super::types::{CheckCategory, CheckDescriptor, CleanupPolicy, RiskClass};
use super::requirements::{
    PVST_REQUIREMENTS, STP_ENDPOINT_POLICY_REQUIREMENTS, STP_GUARD_REQUIREMENTS, STP_REQUIREMENTS,
    STP_ROOT_REQUIREMENTS,
};
use std::time::Duration;

pub(super) const PVST_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "PVST-OBS-001",
    title: "PVST+ control-plane inventory",
    category: CheckCategory::SpanningTree,
    prerequisites: PVST_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const STP_001: CheckDescriptor = CheckDescriptor {
    id: "STP-001",
    title: "STP topology inventory",
    category: CheckCategory::SpanningTree,
    prerequisites: STP_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const STP_002: CheckDescriptor = CheckDescriptor {
    id: "STP-002",
    title: "Expected STP root comparison",
    category: CheckCategory::SpanningTree,
    prerequisites: STP_ROOT_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const STP_003: CheckDescriptor = CheckDescriptor {
    id: "STP-003",
    title: "Endpoint STP visibility policy comparison",
    category: CheckCategory::SpanningTree,
    prerequisites: STP_ENDPOINT_POLICY_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const STP_CHANGE_001: CheckDescriptor = CheckDescriptor {
    id: "STP-CHANGE-001",
    title: "STP root advertisement change observation",
    category: CheckCategory::SpanningTree,
    prerequisites: STP_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const STP_GUARD_001: CheckDescriptor = CheckDescriptor {
    id: "STP-GUARD-001",
    title: "BPDU Guard and root protection validation",
    category: CheckCategory::SpanningTree,
    prerequisites: STP_GUARD_REQUIREMENTS,
    risk: RiskClass::Stateful,
    required_agents: 1,
    packet_budget: 256,
    byte_budget: 65_536,
    duration_budget: Duration::from_secs(30),
    cleanup: CleanupPolicy::Verified,
};
