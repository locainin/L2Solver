//! Link-security checks

use super::super::types::{CheckCategory, CheckDescriptor, CleanupPolicy, RiskClass};
use super::requirements::{
    MACSEC_OBSERVATION_REQUIREMENTS, MACSEC_REQUIREMENTS, MKA_OBSERVATION_REQUIREMENTS,
};
use std::time::Duration;

pub(super) const MACSEC_001: CheckDescriptor = CheckDescriptor {
    id: "MACSEC-001",
    title: "MACsec policy validation",
    category: CheckCategory::LinkSecurity,
    prerequisites: MACSEC_REQUIREMENTS,
    risk: RiskClass::Stateful,
    required_agents: 1,
    packet_budget: 256,
    byte_budget: 65_536,
    duration_budget: Duration::from_secs(30),
    cleanup: CleanupPolicy::Verified,
};

pub(super) const MACSEC_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "MACSEC-OBS-001",
    title: "MACsec data-plane inventory",
    category: CheckCategory::LinkSecurity,
    prerequisites: MACSEC_OBSERVATION_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const MKA_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "MKA-OBS-001",
    title: "MACsec Key Agreement inventory",
    category: CheckCategory::LinkSecurity,
    prerequisites: MKA_OBSERVATION_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};
