//! Bound a VRRPv3/IPv4 candidate and validate its advertised message

use std::num::NonZeroU8;

use l2_core::{EthernetFrame, FrameField};
use l2_discovery::{FingerprintStatus, Protocol};
use l2_onpath::MacAddress;
use smoltcp::wire::{Ipv4Packet, checksum};

use crate::validate_ipv4_target;

use super::{VrrpAdvertisement, VrrpEvidence, VrrpMalformed};

const DESTINATION_MAC: [u8; 6] = [1, 0, 0x5e, 0, 0, 0x12];
const DESTINATION_IP: [u8; 4] = [224, 0, 0, 18];
const ETHERNET_HEADER: usize = 14;
const VRRP_HEADER: usize = 8;

pub(super) fn classify(bytes: &[u8], selected: Option<NonZeroU8>) -> Option<VrrpEvidence> {
    let frame = l2_core::decode(bytes).ok()?;
    if !candidate(&frame, selected) {
        return None;
    }
    Some(match decode(&frame) {
        Ok(evidence) => evidence,
        Err(reason) => VrrpEvidence::Malformed(reason),
    })
}

fn candidate(frame: &EthernetFrame<'_>, selected: Option<NonZeroU8>) -> bool {
    // Restrict the scope before interpreting attacker-controlled protocol bytes
    if frame.field != FrameField::EtherType(0x0800)
        || !frame.vlan_tags.is_empty()
        || frame.destination != DESTINATION_MAC
        || frame.payload.get(9) != Some(&112)
        || frame.payload.get(16..20) != Some(&DESTINATION_IP)
    {
        return false;
    }
    if let Some(vrid) = selected {
        let Some(first) = frame.payload.first() else {
            return false;
        };
        let Some(length) = frame
            .payload
            .get(2..4)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        else {
            return false;
        };
        let header_len = usize::from(first & 0x0f) * 4;
        let total_len = usize::from(u16::from_be_bytes(length));
        // The selected identifier must belong to the declared IP packet, not padding
        return header_len >= 20
            && total_len >= header_len + 2
            && frame.payload.get(header_len + 1) == Some(&vrid.get());
    }
    true
}

fn decode(frame: &EthernetFrame<'_>) -> Result<VrrpEvidence, VrrpMalformed> {
    let source_mac = MacAddress::new(frame.source).map_err(|_| VrrpMalformed::SourceMac)?;
    let (ip, header_len) = ipv4(frame)?;
    advertisement(frame, &ip, header_len, source_mac)
}

fn ipv4<'a>(frame: &EthernetFrame<'a>) -> Result<(Ipv4Packet<&'a [u8]>, usize), VrrpMalformed> {
    let header = l2_discovery::ip_header(frame).ok_or(VrrpMalformed::Ipv4Header)?;
    if header.fragmented {
        return Err(VrrpMalformed::Fragmented);
    }
    // Exclude Ethernet padding before passing the packet to the IPv4 decoder
    let packet = frame
        .payload
        .get(..header.total_len)
        .ok_or(VrrpMalformed::Truncated)?;
    let ip = Ipv4Packet::new_checked(packet).map_err(|_| VrrpMalformed::Ipv4Header)?;
    if !ip.verify_checksum() {
        return Err(VrrpMalformed::Ipv4Checksum);
    }
    if ip.hop_limit() != 255 {
        return Err(VrrpMalformed::Ttl);
    }
    validate_ipv4_target(ip.src_addr()).map_err(|_| VrrpMalformed::SourceIp)?;
    Ok((ip, header.header_len))
}

fn advertisement(
    frame: &EthernetFrame<'_>,
    ip: &Ipv4Packet<&[u8]>,
    header_len: usize,
    source_mac: MacAddress,
) -> Result<VrrpEvidence, VrrpMalformed> {
    let body = ip.payload();
    let version = body.first().copied().ok_or(VrrpMalformed::Truncated)? >> 4;
    // Other versions can carry data with different interpretation and sensitivity
    if version != 3 {
        return Ok(VrrpEvidence::UnsupportedVersion(version));
    }
    validate_fingerprint(frame)?;
    let (fixed, _) = body
        .split_first_chunk::<VRRP_HEADER>()
        .ok_or(VrrpMalformed::Truncated)?;
    let [
        _,
        identifier,
        priority,
        count,
        interval_high,
        interval_low,
        _,
        _,
    ] = *fixed;
    let vrid = NonZeroU8::new(identifier).ok_or(VrrpMalformed::Header)?;
    let count = usize::from(count);
    let interval = u16::from_be_bytes([interval_high, interval_low]) & 0x0fff;
    let message_len = VRRP_HEADER + count * 4;
    let message = body.get(..message_len).ok_or(VrrpMalformed::Truncated)?;
    // RFC 9568 checks the VRRP message alone, without an IPv4 pseudo-header
    if checksum::data(message) != u16::MAX {
        return Err(VrrpMalformed::Checksum);
    }
    // The candidate scope excludes VLAN tags, so the Ethernet header is fixed
    let addresses_start = ETHERNET_HEADER + header_len + VRRP_HEADER;
    let addresses_end = addresses_start + count * 4;
    Ok(VrrpEvidence::Advertisement(VrrpAdvertisement {
        source_ip: ip.src_addr(),
        source_mac,
        vrid,
        priority,
        interval_centiseconds: interval,
        addresses: addresses_start..addresses_end,
        trailing_ip_bytes: body.len() - message_len,
    }))
}

fn validate_fingerprint(frame: &EthernetFrame<'_>) -> Result<(), VrrpMalformed> {
    match l2_discovery::fingerprint(frame) {
        Some(fingerprint) if fingerprint.protocol == Protocol::Vrrp => match fingerprint.status {
            FingerprintStatus::Observed => Ok(()),
            FingerprintStatus::Truncated => Err(VrrpMalformed::Truncated),
            FingerprintStatus::Malformed | FingerprintStatus::Unsupported => {
                Err(VrrpMalformed::Header)
            }
        },
        _ => Err(VrrpMalformed::Header),
    }
}
