//! Decode supported VTP fields without treating them as authenticated state

use std::net::Ipv4Addr;

use super::{VtpEvidence, VtpMalformed, VtpMessage, VtpMessageKind, VtpVlan};
use crate::switching::wire::{self, Candidate};

const COMMON_BYTES: usize = 36;
const SUMMARY_BYTES: usize = 72;
const SUBSET_HEADER_BYTES: usize = 40;
const REQUEST_BYTES: usize = 38;
const VLAN_HEADER_BYTES: usize = 12;
const MAX_VLANS: usize = 64;
const MAX_TLVS: usize = 128;

#[derive(Clone, Copy)]
enum ParseError {
    Malformed,
    Limit,
}

pub(super) fn classify(frame: &[u8]) -> Option<VtpEvidence> {
    Some(match wire::classify(frame, 0x2003)? {
        Candidate::MalformedEnvelope => VtpEvidence::Malformed(VtpMalformed::Ethernet),
        Candidate::Payload { source, .. } if !wire::valid_source(source) => {
            VtpEvidence::Malformed(VtpMalformed::SourceMac)
        }
        Candidate::Payload { source, bytes } => decode(source, bytes),
    })
}

fn decode(source: [u8; 6], payload: &[u8]) -> VtpEvidence {
    let Some(&version) = payload.first() else {
        return VtpEvidence::Malformed(VtpMalformed::Protocol);
    };
    if !matches!(version, 1 | 2) {
        return VtpEvidence::UnsupportedVersion(version);
    }
    let Some(&code) = payload.get(1) else {
        return VtpEvidence::Malformed(VtpMalformed::Protocol);
    };
    if !matches!(code, 1..=3) {
        return VtpEvidence::UnsupportedMessage(code);
    }
    match message(source, version, code, payload) {
        Ok(message) => VtpEvidence::Message(message),
        Err(ParseError::Malformed) => VtpEvidence::Malformed(VtpMalformed::Protocol),
        Err(ParseError::Limit) => VtpEvidence::LimitExceeded,
    }
}

fn message(
    source: [u8; 6],
    version: u8,
    code: u8,
    payload: &[u8],
) -> Result<VtpMessage, ParseError> {
    let domain_len = usize::from(*payload.get(3).ok_or(ParseError::Malformed)?);
    if domain_len > 32 || payload.len() < COMMON_BYTES {
        return Err(ParseError::Malformed);
    }
    let domain = payload
        .get(4..4 + domain_len)
        .ok_or(ParseError::Malformed)?
        .to_vec();
    let field = *payload.get(2).ok_or(ParseError::Malformed)?;
    let kind = match code {
        1 => {
            // The fixed digest and timestamp must exist but are not validated or copied
            if payload.len() < SUMMARY_BYTES {
                return Err(ParseError::Malformed);
            }
            let revision = be32(payload, 36)?;
            let updater = Ipv4Addr::from(
                <[u8; 4]>::try_from(payload.get(40..44).ok_or(ParseError::Malformed)?)
                    .map_err(|_| ParseError::Malformed)?,
            );
            VtpMessageKind::Summary {
                revision,
                followers: field,
                updater,
            }
        }
        2 => {
            if payload.len() < SUBSET_HEADER_BYTES || field == 0 {
                return Err(ParseError::Malformed);
            }
            let revision = be32(payload, 36)?;
            let records = payload
                .get(SUBSET_HEADER_BYTES..)
                .ok_or(ParseError::Malformed)?;
            VtpMessageKind::Subset {
                revision,
                sequence: field,
                vlans: vlan_records(records)?,
            }
        }
        3 => {
            if payload.len() < REQUEST_BYTES {
                return Err(ParseError::Malformed);
            }
            VtpMessageKind::Request {
                start_value: be16(payload, 36)?,
            }
        }
        _ => return Err(ParseError::Malformed),
    };
    Ok(VtpMessage {
        source,
        version,
        domain,
        kind,
    })
}

fn vlan_records(mut remaining: &[u8]) -> Result<Vec<VtpVlan>, ParseError> {
    let mut result = Vec::new();
    let mut tlv_count = 0;
    while !remaining.is_empty() {
        if result.len() == MAX_VLANS {
            return Err(ParseError::Limit);
        }
        let length = usize::from(*remaining.first().ok_or(ParseError::Malformed)?);
        if length < VLAN_HEADER_BYTES {
            return Err(ParseError::Malformed);
        }
        let (record, next) = remaining
            .split_at_checked(length)
            .ok_or(ParseError::Malformed)?;
        result.push(vlan_record(record, &mut tlv_count)?);
        remaining = next;
    }
    Ok(result)
}

fn vlan_record(record: &[u8], tlv_count: &mut usize) -> Result<VtpVlan, ParseError> {
    let status = *record.get(1).ok_or(ParseError::Malformed)?;
    let vlan_type = *record.get(2).ok_or(ParseError::Malformed)?;
    let name_len = usize::from(*record.get(3).ok_or(ParseError::Malformed)?);
    let name_padded = (name_len + 3) & !3;
    let name = record
        .get(VLAN_HEADER_BYTES..VLAN_HEADER_BYTES + name_len)
        .ok_or(ParseError::Malformed)?
        .to_vec();
    let mut extensions = record
        .get(VLAN_HEADER_BYTES + name_padded..)
        .ok_or(ParseError::Malformed)?;
    // Nested VLAN TLV length counts 16-bit values rather than bytes
    while !extensions.is_empty() {
        if *tlv_count == MAX_TLVS {
            return Err(ParseError::Limit);
        }
        let ([_, words], body) = extensions
            .split_first_chunk::<2>()
            .ok_or(ParseError::Malformed)?;
        let (_, next) = body
            .split_at_checked(usize::from(*words) * 2)
            .ok_or(ParseError::Malformed)?;
        *tlv_count += 1;
        extensions = next;
    }
    Ok(VtpVlan {
        id: be16(record, 4)?,
        status,
        vlan_type,
        mtu: be16(record, 6)?,
        said: be32(record, 8)?,
        name,
    })
}

fn be16(input: &[u8], offset: usize) -> Result<u16, ParseError> {
    let bytes = <[u8; 2]>::try_from(input.get(offset..offset + 2).ok_or(ParseError::Malformed)?)
        .map_err(|_| ParseError::Malformed)?;
    Ok(u16::from_be_bytes(bytes))
}

fn be32(input: &[u8], offset: usize) -> Result<u32, ParseError> {
    let bytes = <[u8; 4]>::try_from(input.get(offset..offset + 4).ok_or(ParseError::Malformed)?)
        .map_err(|_| ParseError::Malformed)?;
    Ok(u32::from_be_bytes(bytes))
}
