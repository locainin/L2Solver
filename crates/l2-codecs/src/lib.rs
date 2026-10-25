//! Passive Layer-2 protocol decoders
//!
//! This crate currently exposes a bounded decoder for an LLDP data unit. It
//! only borrows the supplied bytes and never opens an interface or transmits
//! anything

#![forbid(unsafe_code)]

mod decoder;
mod encoder;
mod error;
mod model;
mod semantic;
mod stp;
mod stp_error;
mod stp_model;

pub use decoder::decode_lldp;
pub use encoder::{encode_lldp, lldp_encoded_len};
pub use error::{DecodeError, EncodeError};
pub use model::{LldpFrame, MAX_FRAME_LEN, MAX_TLVS, Tlv, Validity};
pub use stp::decode_stp;
pub use stp_error::{StpContext, StpError};
pub use stp_model::{
    BridgeId, PortId, PortRole, StpBpduType, StpFlags, StpFrame, StpLlcHeader, StpTimers,
    StpVersion,
};
