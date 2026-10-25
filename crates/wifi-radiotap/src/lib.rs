//! Bounded radiotap framing for raw IEEE 802.11 captures
//!
//! The radiotap length remains authoritative even when a metadata field is not
//! understood. This keeps the following 802.11 frame correctly located without
//! guessing the size of an unknown field.

#![forbid(unsafe_code)]

mod decode;
mod encode;
mod error;
mod model;

pub use decode::decode;
pub use encode::encode;
pub use error::{DecodeError, EncodeError};
pub use model::{Channel, RadiotapFields, RadiotapFlags, RadiotapFrame};

/// Maximum chained presence words accepted from one header
pub const MAX_PRESENCE_WORDS: usize = 8;
