//! Evidence-backed passive wireless policy assessment

#![forbid(unsafe_code)]

mod catalog;
mod error;
mod evaluate;
mod model;
mod policy;

pub use catalog::{RiskClass, WirelessCheckDescriptor, active_catalog};
pub use error::AuditError;
pub use evaluate::assess;
pub use model::{Assessment, Coverage, CoverageStatus, Exposure, Finding, Severity, Verdict};
pub use policy::{PmfRequirement, WirelessNetworkPolicy, WirelessPolicy};
