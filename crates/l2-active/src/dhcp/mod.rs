//! Bounded active `DHCPv4` discovery over an explicitly selected link
//!
//! A discover asks for offers but does not request a lease or configure the host
//! Replies are untrusted network claims even when their transaction fields match

mod decode;
mod encode;
mod error;
mod options;
mod plan;
mod report;
mod session;

pub use error::DhcpError;
pub use plan::DhcpProbe;
pub use report::{DhcpObservation, DhcpReport, DhcpStatus};
