//! Bounded, borrowed decoding of selected CDP identity fields

mod decode;
mod error;
mod model;

pub use decode::decode_cdp;
pub use error::CdpError;
pub use model::{CdpField, CdpFrame, CdpLimits, MAX_CDP_BYTES};
