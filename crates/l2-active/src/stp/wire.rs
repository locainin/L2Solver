//! Recognize the supported untagged IEEE STP envelope

use l2_capture::CapturedFrame;
use l2_codecs::StpError;
use l2_core::FrameField;
use l2_onpath::MacAddress;

use super::{MalformedStp, StpEvidence};

const STP_DESTINATION: [u8; 6] = [0x01, 0x80, 0xc2, 0, 0, 0];
const STP_DSAP: u8 = 0x42;
const ETHERNET_HEADER: usize = 14;

pub fn classify(frame: &CapturedFrame) -> Option<StpEvidence> {
    let bytes = frame.bytes();
    if bytes.get(..STP_DESTINATION.len())? != STP_DESTINATION {
        return None;
    }
    let ethernet = match l2_core::decode(bytes) {
        Ok(ethernet) => ethernet,
        // A broken length still identifies a candidate when STP LLC is visible
        Err(error) if bytes.get(ETHERNET_HEADER) == Some(&STP_DSAP) => {
            return Some(StpEvidence::Malformed(MalformedStp::Ethernet(error)));
        }
        Err(_) => return None,
    };
    if !ethernet.vlan_tags.is_empty()
        || !matches!(ethernet.field, FrameField::Length(_))
        || ethernet.payload.first() != Some(&STP_DSAP)
    {
        return None;
    }
    if MacAddress::new(ethernet.source).is_err() {
        return Some(StpEvidence::Malformed(MalformedStp::SourceAddress));
    }
    // Keep unsupported versions distinct from structurally broken packets
    Some(match l2_codecs::decode_stp(ethernet.payload) {
        Ok(_) => StpEvidence::Decoded,
        Err(
            error @ (StpError::UnsupportedVersion { .. }
            | StpError::UnsupportedType { .. }
            | StpError::UnsupportedExtension { .. }),
        ) => StpEvidence::Unsupported(error),
        Err(error) => StpEvidence::Malformed(MalformedStp::Bpdu(error)),
    })
}

pub fn decoded(frame: &CapturedFrame) -> Option<l2_codecs::StpFrame<'_>> {
    let ethernet = l2_core::decode(frame.bytes()).ok()?;
    l2_codecs::decode_stp(ethernet.payload).ok()
}
