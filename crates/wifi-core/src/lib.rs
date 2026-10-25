//! Bounded IEEE 802.11 MAC framing
//!
//! This crate decodes raw 802.11 frames after any radiotap envelope has been
//! removed. It owns no radio, interface, timer, or transmit authority.

#![forbid(unsafe_code)]

mod decode;
mod error;
mod model;

pub use decode::decode;
pub use error::DecodeError;
pub use model::{
    ControlSubtype, DataSubtype, FrameControl, FrameKind, FrameType, MacAddress, ManagementSubtype,
    WifiFrame,
};
