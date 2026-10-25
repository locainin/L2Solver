//! Bounded passive survey and policy findings without transmission authority

#![forbid(unsafe_code)]

mod assessment;
mod checks;
mod distributed;
mod error;
mod exposures;
mod forensics;
mod inventory;
mod model;
mod network_model;
mod planner;
mod policy;
mod policy_schema;
mod role;
mod source;
mod survey;

// Flat policies describe the implicit interface used by classic PCAP captures
pub(crate) const DEFAULT_SOURCE: l2_capture::InterfaceId = l2_capture::InterfaceId {
    section: 0,
    index: 0,
};

pub use assessment::{
    AssessmentResult, CoverageEntry, CoverageMetric, CoverageStatus, Exposure, assess,
    assess_with_input, assess_with_input_and_source_labels, assess_with_source_labels,
};
pub use distributed::{
    DistributedAgent, DistributedAssessment, DistributedCanaryAbsenceEvidence,
    DistributedCanaryEvidence, DistributedClockStamp, DistributedInterfaceBinding,
    DistributedPathResult, DistributedPlan, DistributedPlanError, DistributedResultError,
    L2PathExpectation, assess_distributed, plan_distributed, plan_distributed_replay,
};
pub use error::AuditError;
pub use forensics::{
    ArpBindingChange, ArpObservation, DnsAddressUse, DnsObservation, DnsResponseMatch,
    ForensicReport, ForensicScope, ForensicTracker, IpCommunication, TrailingData,
    TrailingProtocol,
};
pub use l2_discovery::{FingerprintStatus, NetworkAddress, Protocol};
pub use model::{
    BridgeIdentity, EvidenceLocator, EvidenceRef, Finding, InterfaceObservation,
    LinuxInterfaceEvidence, Neighbor, NonZeroVid, PacketEvidence, ProtocolIdentityObservation,
    ProtocolObservation, Quality, Report, ResourceLimit, ResourceLimitStatus, Severity,
    StpObservation, Verdict, Vid, VlanObservation,
};
pub use network_model::{
    AddressConflict, InfrastructureGroup, NetworkModel, NetworkNode, build_network_model,
};
pub use planner::{
    AssessmentProfile, Capability, CheckCategory, CheckDescriptor, CheckPlan, CleanupPolicy,
    MAX_AGENT_COUNT, MAX_EXPOSURES, MAX_FINDINGS, MAX_PLAN_ENTRIES, MAX_RECOMMENDATIONS, PlanEntry,
    PlannerError, PlannerInput, PolicyRequirement, Recommendation, Requirement, RequirementKind,
    RiskClass, catalog, plan_passive, plan_passive_with_source_labels,
};
pub use policy::{
    Disposition, Policy, PortBinding, ResolvedExpectations, SegmentExpectations, StablePortBinding,
};
pub use role::{PortRole, PortRoleInference, infer_port_role, infer_port_roles};
pub use source::{
    MAX_SOURCE_LABEL_BYTES, MAX_SOURCE_LABELS, SourceLabelMap, SourceLabelMapError,
    StableSourceLabel, valid_source_label,
};
pub use survey::{Survey, SurveyLimits};
