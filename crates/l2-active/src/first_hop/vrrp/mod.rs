//! Bounded receive-only VRRPv3/IPv4 observation

mod report;
mod session;
mod wire;

pub use report::{
    VrrpAdvertisement, VrrpEvidence, VrrpMalformed, VrrpObservation, VrrpReport, VrrpStatus,
};
pub use session::VrrpMonitor;
