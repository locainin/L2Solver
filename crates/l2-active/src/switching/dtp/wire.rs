//! Decode the version 1 DTP TLV profile with finite work

use super::{DtpAdvertisement, DtpEvidence, DtpMalformed, DtpStatus, DtpTrunkType};
use crate::switching::wire::{self, Candidate};

const MAX_TLVS: usize = 64;
const MAX_DOMAIN_BYTES: usize = 33;

pub(super) fn classify(frame: &[u8]) -> Option<DtpEvidence> {
    Some(match wire::classify(frame, 0x2004)? {
        Candidate::MalformedEnvelope => DtpEvidence::Malformed(DtpMalformed::Ethernet),
        Candidate::Payload { source, .. } if !wire::valid_source(source) => {
            DtpEvidence::Malformed(DtpMalformed::SourceMac)
        }
        Candidate::Payload { source, bytes } => decode(source, bytes),
    })
}

fn decode(source: [u8; 6], payload: &[u8]) -> DtpEvidence {
    let Some((&version, mut remaining)) = payload.split_first() else {
        return DtpEvidence::Malformed(DtpMalformed::Protocol);
    };
    if version != 1 {
        return DtpEvidence::UnsupportedVersion(version);
    }
    let mut claim = DtpAdvertisement {
        source,
        domain: None,
        status: None,
        trunk_type: None,
        sender_id: None,
    };
    let mut count = 0;
    while !remaining.is_empty() {
        if count == MAX_TLVS {
            return DtpEvidence::LimitExceeded;
        }
        let Some((header, body)) = remaining.split_first_chunk::<4>() else {
            return DtpEvidence::Malformed(DtpMalformed::Protocol);
        };
        let [type_hi, type_lo, length_hi, length_lo] = *header;
        let kind = u16::from_be_bytes([type_hi, type_lo]);
        let length = usize::from(u16::from_be_bytes([length_hi, length_lo]));
        let Some(value_len) = length.checked_sub(4) else {
            return DtpEvidence::Malformed(DtpMalformed::Protocol);
        };
        let Some((value, next)) = body.split_at_checked(value_len) else {
            return DtpEvidence::Malformed(DtpMalformed::Protocol);
        };
        // A duplicate known field has ambiguous meaning and is not a single claim
        match kind {
            1 if claim.domain.is_none() && (1..=MAX_DOMAIN_BYTES).contains(&value.len()) => {
                claim.domain = Some(value.to_vec());
            }
            2 if claim.status.is_none() => {
                let [status] = value else {
                    return DtpEvidence::Malformed(DtpMalformed::Protocol);
                };
                claim.status = Some(DtpStatus(*status));
            }
            3 if claim.trunk_type.is_none() => {
                let [trunk_type] = value else {
                    return DtpEvidence::Malformed(DtpMalformed::Protocol);
                };
                claim.trunk_type = Some(DtpTrunkType(*trunk_type));
            }
            4 if claim.sender_id.is_none() => {
                let Ok(id) = <[u8; 6]>::try_from(value) else {
                    return DtpEvidence::Malformed(DtpMalformed::Protocol);
                };
                claim.sender_id = Some(id);
            }
            1..=4 => return DtpEvidence::Malformed(DtpMalformed::Protocol),
            _ => {}
        }
        count += 1;
        remaining = next;
    }
    if count == 0 {
        DtpEvidence::Malformed(DtpMalformed::Protocol)
    } else {
        DtpEvidence::Advertisement(claim)
    }
}
