//! Read-only Linux `nl80211` capability discovery

#![forbid(unsafe_code)]

mod discover;
mod error;
mod model;
mod normalize;

pub use discover::discover;
pub use error::DiscoveryError;
pub use model::{
    Band, BandKind, CapabilityState, ChannelCapability, InterfaceInfo, MAX_CHANNEL_RECORDS,
    MAX_UNIQUE_CHANNELS, PhyCapabilities, WirelessInventory, WirelessMode,
};
