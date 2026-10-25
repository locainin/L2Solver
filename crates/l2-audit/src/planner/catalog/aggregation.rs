//! Link aggregation checks

use super::super::types::{CheckCategory, CheckDescriptor, CleanupPolicy, RiskClass};
use super::requirements::{LACP_OBSERVATION_REQUIREMENTS, LACP_REQUIREMENTS, PAGP_REQUIREMENTS};
use std::time::Duration;

pub(super) const LACP_001: CheckDescriptor = CheckDescriptor {
    id: "LACP-001",
    title: "Link aggregation validation",
    category: CheckCategory::Aggregation,
    prerequisites: LACP_REQUIREMENTS,
    risk: RiskClass::Stateful,
    required_agents: 1,
    packet_budget: 128,
    byte_budget: 32_768,
    duration_budget: Duration::from_secs(20),
    cleanup: CleanupPolicy::Required,
};

pub(super) const LACP_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "LACP-OBS-001",
    title: "LACP control-plane fingerprint inventory",
    category: CheckCategory::Aggregation,
    prerequisites: LACP_OBSERVATION_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const PAGP_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "PAGP-OBS-001",
    title: "PAgP control-plane fingerprint inventory",
    category: CheckCategory::Aggregation,
    prerequisites: PAGP_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};
