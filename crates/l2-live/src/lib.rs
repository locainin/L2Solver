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

/// List capture interfaces in stable name order
///
/// On Linux, only sources with a kernel interface index are listed
///
/// # Errors
/// Returns a libpcap error if interface enumeration fails
pub fn interfaces() -> Result<Vec<String>, pcap::Error> {
    let mut names: Vec<_> = pcap::Device::list()?
        .into_iter()
        .map(|device| device.name)
        .collect();
    // Capture opening requires a kernel interface rather than a libpcap pseudo-device
    #[cfg(target_os = "linux")]
    names.retain(|name| nix::net::if_::if_nametoindex(name.as_str()).is_ok());
    names.sort();
    names.dedup();
    Ok(names)
}
