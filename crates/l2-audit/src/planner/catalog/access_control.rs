//! Access-control and endpoint admission checks

use super::super::types::{CheckCategory, CheckDescriptor, CleanupPolicy, RiskClass};
use super::requirements::{
    CONTROL_POLICY_REQUIREMENTS, DOT1X_OBSERVATION_REQUIREMENTS, DOT1X_POLICY_REQUIREMENTS,
    DOT1X_REQUIREMENTS, PORT_SECURITY_REQUIREMENTS,
};
use std::time::Duration;

pub(super) const CTRL_POLICY_001: CheckDescriptor = CheckDescriptor {
    id: "CTRL-POLICY-001",
    title: "Control-protocol exposure policy comparison",
    category: CheckCategory::AccessControl,
    prerequisites: CONTROL_POLICY_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const DOT1X_001: CheckDescriptor = CheckDescriptor {
    id: "DOT1X-001",
    title: "802.1X enforcement validation",
    category: CheckCategory::AccessControl,
    prerequisites: DOT1X_REQUIREMENTS,
    risk: RiskClass::Stateful,
    required_agents: 1,
    packet_budget: 512,
    byte_budget: 131_072,
    duration_budget: Duration::from_mins(1),
    cleanup: CleanupPolicy::Verified,
};

pub(super) const DOT1X_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "DOT1X-OBS-001",
    title: "802.1X control-plane inventory",
    category: CheckCategory::AccessControl,
    prerequisites: DOT1X_OBSERVATION_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const DOT1X_POLICY_001: CheckDescriptor = CheckDescriptor {
    id: "DOT1X-POLICY-001",
    title: "Required 802.1X enforcement validation",
    category: CheckCategory::AccessControl,
    prerequisites: DOT1X_POLICY_REQUIREMENTS,
    risk: RiskClass::Stateful,
    required_agents: 1,
    packet_budget: 512,
    byte_budget: 131_072,
    duration_budget: Duration::from_mins(1),
    cleanup: CleanupPolicy::Verified,
};

pub(super) const PORTSEC_001: CheckDescriptor = CheckDescriptor {
    id: "PORTSEC-001",
    title: "Port-security threshold validation",
    category: CheckCategory::AccessControl,
    prerequisites: PORT_SECURITY_REQUIREMENTS,
    risk: RiskClass::Disruptive,
    required_agents: 1,
    packet_budget: 256,
    byte_budget: 65_536,
    duration_budget: Duration::from_secs(30),
    cleanup: CleanupPolicy::Verified,
};
