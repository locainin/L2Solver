//! Literal packet relationships and ordered ARP evidence without intent attribution

mod arp;
mod communications;
mod dns;
mod model;
mod tracker;
mod trailers;

pub use dns::{DnsAddressUse, DnsObservation, DnsResponseMatch};
pub use model::{
    ArpBindingChange, ArpObservation, ForensicReport, ForensicScope, IpCommunication, TrailingData,
    TrailingProtocol,
};
pub use tracker::ForensicTracker;
