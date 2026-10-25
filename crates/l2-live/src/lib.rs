//! Linux receive-only libpcap adapter with explicit packet and duration limits

#![forbid(unsafe_code)]

mod budget;
mod interface;
mod metadata;
mod packet;
mod receive;

pub use budget::StopReason;
pub use interface::LiveInterfaceIdentity;
pub use receive::{LiveLink, LiveStatistics};

/// List libpcap interfaces in stable name order
///
/// # Errors
/// Returns a libpcap error if interface enumeration fails
pub fn interfaces() -> Result<Vec<String>, pcap::Error> {
    let mut names: Vec<_> = pcap::Device::list()?
        .into_iter()
        .map(|device| device.name)
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}
