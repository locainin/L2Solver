//! Fixed Start encoding and bounded EAPOL Request classification

use l2_core::{EthernetFrame, FrameField};
use l2_onpath::MacAddress;

use super::{Dot1xDestination, MalformedReason};

const PAE_GROUP: [u8; 6] = [0x01, 0x80, 0xc2, 0, 0, 0x03];
const EAPOL_ETHERTYPE: u16 = 0x888e;
pub(super) const START_LEN: usize = 60;

pub(super) fn start(source: MacAddress) -> Result<[u8; START_LEN], l2_core::EncodeError> {
    let frame = EthernetFrame {
        destination: PAE_GROUP,
        source: source.bytes(),
        vlan_tags: Vec::new(),
        field: FrameField::EtherType(EAPOL_ETHERTYPE),
        payload: &[2, 1, 0, 0],
        padding: &[0; 42],
    };
    let mut bytes = [0; START_LEN];
    l2_core::encode(&frame, &mut bytes)?;
    Ok(bytes)
}

#[derive(Debug)]
pub(super) struct Request {
    pub source: MacAddress,
    pub destination: Dot1xDestination,
    pub version: u8,
    pub identifier: u8,
    pub type_code: u8,
}

pub(super) enum Classification {
    Request(Request),
    Malformed(MalformedReason),
    Unrelated,
}

pub(super) fn classify(bytes: &[u8], selected: MacAddress) -> Classification {
    let Ok(frame) = l2_core::decode(bytes) else {
        return Classification::Unrelated;
    };
    if frame.field != FrameField::EtherType(EAPOL_ETHERTYPE) || !frame.vlan_tags.is_empty() {
        return Classification::Unrelated;
    }
    let destination = if frame.destination == selected.bytes() {
        Dot1xDestination::SelectedInterface
    } else if frame.destination == PAE_GROUP {
        Dot1xDestination::PaeGroup
    } else {
        return Classification::Unrelated;
    };
    if frame.source == selected.bytes() {
        return Classification::Unrelated;
    }
    let Ok(source) = MacAddress::new(frame.source) else {
        return Classification::Malformed(MalformedReason::SourceMac);
    };
    match request(frame.payload) {
        Ok(Some((version, identifier, request_type))) => Classification::Request(Request {
            source,
            destination,
            version,
            identifier,
            type_code: request_type,
        }),
        Ok(None) => Classification::Unrelated,
        Err(reason) => Classification::Malformed(reason),
    }
}

fn request(payload: &[u8]) -> Result<Option<(u8, u8, u8)>, MalformedReason> {
    let Some((version, body)) = eapol_packet(payload)? else {
        return Ok(None);
    };
    Ok(eap_request(body)?.map(|(identifier, request_type)| (version, identifier, request_type)))
}

fn eapol_packet(payload: &[u8]) -> Result<Option<(u8, &[u8])>, MalformedReason> {
    let (header, remaining) = payload
        .split_first_chunk::<4>()
        .ok_or(MalformedReason::EapolHeader)?;
    let [version, packet_type, high, low] = *header;
    if version == 0 {
        return Err(MalformedReason::EapolHeader);
    }
    if version > 3 {
        return Ok(None);
    }
    let body_len = usize::from(u16::from_be_bytes([high, low]));
    let body = remaining
        .get(..body_len)
        .ok_or(MalformedReason::EapolHeader)?;
    // Start and Logoff are empty even when no authentication packet follows
    if matches!(packet_type, 1 | 2) && body_len != 0 {
        return Err(MalformedReason::EapolHeader);
    }
    if packet_type != 0 {
        return Ok(None);
    }
    Ok(Some((version, body)))
}

fn eap_request(body: &[u8]) -> Result<Option<(u8, u8)>, MalformedReason> {
    let header = body.get(..4).ok_or(MalformedReason::EapHeader)?;
    let [code, identifier, high, low] =
        <[u8; 4]>::try_from(header).map_err(|_| MalformedReason::EapHeader)?;
    let length = usize::from(u16::from_be_bytes([high, low]));
    if length < 4 || length > body.len() {
        return Err(MalformedReason::EapHeader);
    }
    if code != 1 {
        return Ok(None);
    }
    let eap = body.get(..length).ok_or(MalformedReason::EapHeader)?;
    let request_type = *eap.get(4).ok_or(MalformedReason::EapHeader)?;
    if invalid_request_type(request_type, eap) {
        return Err(MalformedReason::RequestType);
    }
    Ok(Some((identifier, request_type)))
}

fn invalid_request_type(request_type: u8, eap: &[u8]) -> bool {
    match request_type {
        0 | 3 => true,
        2 => {
            let message = eap.get(5..).unwrap_or_default();
            message.is_empty() || message.contains(&0) || std::str::from_utf8(message).is_err()
        }
        254 => invalid_expanded_type(eap),
        _ => false,
    }
}

fn invalid_expanded_type(eap: &[u8]) -> bool {
    // The IETF Expanded Nak is a Response, never a Request
    let Some(vendor) = eap.get(5..12) else {
        return true;
    };
    vendor == [0, 0, 0, 0, 0, 0, 3]
}
