//! Fundamental, allocation-aware Layer-2 frame types and codecs

#![forbid(unsafe_code)]

mod decode;
mod encode;
mod error;
mod ethernet;
mod vlan;

// Re-export the small public surface so callers do not depend on module layout
pub use decode::decode;
pub use encode::{encode, encoded_len};
pub use error::{DecodeContext, DecodeError, EncodeError};
pub use ethernet::{EthernetFrame, FrameField};
pub use vlan::VlanTag;

/// Maximum number of bytes accepted by the bounded frame decoder
pub const MAX_FRAME_LEN: usize = 65_535;

/// Maximum number of VLAN tags represented by the bounded Ethernet model
pub const MAX_VLAN_TAGS: usize = 4;

// IEEE 802.3 reserves values through 1500 for the length field
const LENGTH_FIELD_MAX: u16 = 1_500;

// The EtherType range starts at 1536 after the reserved gap
const ETHERTYPE_MIN: u16 = 1_536;

// Supported VLAN tag protocol identifiers
const TPID_8021Q: u16 = 0x8100;
const TPID_8021AD: u16 = 0x88a8;
