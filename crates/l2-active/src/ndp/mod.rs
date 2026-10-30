//! Bounded IPv6 neighbor discovery over an explicitly authorized active link

mod plan;
mod report;
mod session;
mod wire;

pub use plan::{NdpPlanError, NdpProbe};
pub use report::{NdpObservation, NdpReport, NdpStatus};
