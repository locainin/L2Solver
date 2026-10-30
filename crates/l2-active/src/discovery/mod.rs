//! Bounded receive-only LLDP and CDP observation on an explicitly selected link

mod decode;
mod report;
mod session;

pub use report::{
    DiscoveryDisposition, DiscoveryIdentity, DiscoveryObservation, DiscoveryProtocol,
    DiscoveryReport, DiscoveryStatus, IdentityAssessment,
};
pub use session::{DiscoveryMonitor, MAX_OBSERVATIONS};
