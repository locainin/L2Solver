//! Recognize scoped discovery frames and locate their semantic identity fields

use std::ops::Range;

use l2_core::FrameField;

use super::DiscoveryProtocol;

const ETHERNET_HEADER_BYTES: usize = 14;
const SNAP_HEADER_BYTES: usize = 8;
const LLDP_NEAREST: [u8; 6] = [1, 0x80, 0xc2, 0, 0, 14];
const LLDP_NON_TPMR: [u8; 6] = [1, 0x80, 0xc2, 0, 0, 3];
const LLDP_CUSTOMER: [u8; 6] = [1, 0x80, 0xc2, 0, 0, 0];
const CDP_DESTINATION: [u8; 6] = [1, 0, 0x0c, 0xcc, 0xcc, 0xcc];
const CDP_SNAP: [u8; SNAP_HEADER_BYTES] = [0xaa, 0xaa, 3, 0, 0, 0x0c, 0x20, 0];

#[derive(Debug)]
pub(super) struct IdentityFields {
    pub device: Range<usize>,
    pub port: Range<usize>,
    pub hold_seconds: u16,
}

#[derive(Debug)]
pub(super) struct Decoded {
    pub protocol: DiscoveryProtocol,
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub content: Content,
}

#[derive(Debug)]
pub(super) enum Content {
    Valid(IdentityFields),
    Malformed,
    LimitExceeded,
}

pub(super) fn decode(bytes: &[u8]) -> Option<Decoded> {
    let frame = l2_core::decode(bytes).ok()?;
    // Tagged discovery traffic is outside the selected untagged link scope
    if !frame.vlan_tags.is_empty() {
        return None;
    }
    let (protocol, content) = match (frame.field, frame.destination) {
        (FrameField::EtherType(0x88cc), LLDP_NEAREST | LLDP_NON_TPMR | LLDP_CUSTOMER) => {
            (DiscoveryProtocol::Lldp, decode_lldp(frame.payload))
        }
        (FrameField::Length(_), CDP_DESTINATION) => {
            let payload = frame.payload.strip_prefix(&CDP_SNAP)?;
            (DiscoveryProtocol::Cdp, decode_cdp(payload))
        }
        _ => return None,
    };
    let [first, ..] = frame.source;
    // Preserve recognizable frames with invalid senders as malformed evidence
    let content = if frame.source == [0; 6] || first & 1 != 0 {
        Content::Malformed
    } else {
        content
    };
    Some(Decoded {
        protocol,
        source_mac: frame.source,
        destination_mac: frame.destination,
        content,
    })
}

fn decode_lldp(payload: &[u8]) -> Content {
    match l2_codecs::decode_lldp(payload) {
        Ok(frame) => lldp_identity(&frame).map_or(Content::Malformed, Content::Valid),
        Err(
            l2_codecs::DecodeError::TooManyTlvs { .. }
            | l2_codecs::DecodeError::FrameTooLong { .. },
        ) => Content::LimitExceeded,
        Err(_) => Content::Malformed,
    }
}

fn lldp_identity(frame: &l2_codecs::LldpFrame<'_>) -> Option<IdentityFields> {
    if frame.validity != l2_codecs::Validity::Valid {
        return None;
    }
    let device = frame.tlvs.iter().find(|tlv| tlv.kind == 1)?;
    let port = frame.tlvs.iter().find(|tlv| tlv.kind == 2)?;
    let ttl: [u8; 2] = frame
        .tlvs
        .iter()
        .find(|tlv| tlv.kind == 3)?
        .value
        .try_into()
        .ok()?;
    Some(IdentityFields {
        device: field_range(ETHERNET_HEADER_BYTES, device.offset + 2, device.value.len())?,
        port: field_range(ETHERNET_HEADER_BYTES, port.offset + 2, port.value.len())?,
        hold_seconds: u16::from_be_bytes(ttl),
    })
}

fn decode_cdp(payload: &[u8]) -> Content {
    // Every possible Ethernet CDP value fits the codec's fixed byte budget
    let limits = l2_codecs::CdpLimits::new(l2_codecs::MAX_CDP_BYTES / 4, l2_codecs::MAX_CDP_BYTES);
    match l2_codecs::decode_cdp(payload, limits) {
        Ok(frame) => cdp_identity(&frame).map_or(Content::Malformed, Content::Valid),
        Err(l2_codecs::CdpError::FrameTooLong { .. } | l2_codecs::CdpError::TooManyTlvs { .. }) => {
            Content::LimitExceeded
        }
        Err(l2_codecs::CdpError::InvalidIdentity { length, max, .. }) if length > max => {
            Content::LimitExceeded
        }
        Err(_) => Content::Malformed,
    }
}

fn cdp_identity(frame: &l2_codecs::CdpFrame<'_>) -> Option<IdentityFields> {
    let base = ETHERNET_HEADER_BYTES + SNAP_HEADER_BYTES;
    Some(IdentityFields {
        device: field_range(base, frame.device.offset, frame.device.value.len())?,
        port: field_range(base, frame.port.offset, frame.port.value.len())?,
        hold_seconds: u16::from(frame.hold_seconds),
    })
}

fn field_range(base: usize, offset: usize, length: usize) -> Option<Range<usize>> {
    let start = base.checked_add(offset)?;
    Some(start..start.checked_add(length)?)
}
