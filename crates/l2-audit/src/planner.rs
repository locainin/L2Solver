//! Bounded applicability planning for passive and future active checks

mod catalog;
mod coverage;
mod input;
mod plan;
mod requirements;
mod types;

pub use input::{PlannerError, PlannerInput};
pub use plan::{catalog, plan_passive, plan_passive_with_source_labels};
pub use types::{
    AssessmentProfile, Capability, CheckCategory, CheckDescriptor, CheckPlan, CleanupPolicy,
    PlanEntry, PolicyRequirement, Recommendation, Requirement, RequirementKind, RiskClass,
};

/// Maximum number of controlled agents accepted by the planner
pub const MAX_AGENT_COUNT: usize = 64;

/// Maximum number of checks retained in one generated plan
pub const MAX_PLAN_ENTRIES: usize = 64;

/// Maximum number of recommendations retained in one generated plan
pub const MAX_RECOMMENDATIONS: usize = 32;

/// Maximum number of informational exposure rows retained by one assessment
pub const MAX_EXPOSURES: usize = 4_096;

/// Maximum number of policy findings retained by one assessment
pub const MAX_FINDINGS: usize = 10_000;
