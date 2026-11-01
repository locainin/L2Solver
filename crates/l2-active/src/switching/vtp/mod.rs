//! Receive-only VTP version 1 and 2 observations and advertised VLAN claims

mod report;
mod session;
mod wire;

pub use report::{
    VtpEvidence, VtpMalformed, VtpMessage, VtpMessageKind, VtpObservation, VtpReport, VtpVlan,
};
pub use session::VtpMonitor;
