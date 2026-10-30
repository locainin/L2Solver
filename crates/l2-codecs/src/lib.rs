//! Passive Layer-2 protocol decoders
//!
//! LLDP, CDP, and spanning-tree codecs borrow bounded input bytes and never
//! open an interface or transmit anything

#![forbid(unsafe_code)]

mod cdp;
mod decoder;
mod encoder;
mod error;
mod model;
mod semantic;
mod stp;
mod stp_error;
mod stp_model;

pub use cdp::{CdpError, CdpField, CdpFrame, CdpLimits, MAX_CDP_BYTES, decode_cdp};
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
