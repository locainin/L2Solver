use crate::{
    Fingerprint, MAX_IPV6_EXTENSION_HEADERS, Protocol,
    bytes::{read_u8, read_u16, take},
    ip, mld, udp, vrrp,
};

const IPV6_HEADER_LEN: usize = 40;
const NEXT_HEADER_HOP_BY_HOP: u8 = 0;
const NEXT_HEADER_ROUTING: u8 = 43;
const NEXT_HEADER_FRAGMENT: u8 = 44;
const NEXT_HEADER_AH: u8 = 51;
const NEXT_HEADER_DESTINATION: u8 = 60;
const NEXT_HEADER_UDP: u8 = 17;
const NEXT_HEADER_ICMPV6: u8 = 58;
const NEXT_HEADER_VRRP: u8 = 112;

/// Fingerprint IPv6 control protocols after a bounded extension-header walk
pub fn fingerprint(packet: &[u8]) -> Option<Fingerprint> {
    let header = ip::ipv6_header(packet)?;
    let declared_end = header.total_len;
    let available_end = packet.len().min(declared_end);
    let mut next_header = header.protocol;
    let mut offset = IPV6_HEADER_LEN;
    let mut extension_count = 0;
    let mut fragmented = false;
    let capture_truncated = declared_end > packet.len();

    // Walk only the declared payload and stop at the configured header ceiling
    loop {
        match next_header {
            NEXT_HEADER_ICMPV6 => {
                return icmpv6_fingerprint(
                    packet,
                    offset,
                    available_end,
                    capture_truncated,
                    fragmented,
                );
            }
            NEXT_HEADER_UDP => {
                return udp_fingerprint(
                    packet,
                    offset,
                    available_end,
                    declared_end,
                    capture_truncated,
                    fragmented,
                );
            }
            NEXT_HEADER_VRRP => {
                // VRRP address width follows the enclosing IPv6 family
                if fragmented {
                    return None;
                }
                let body_len = available_end.checked_sub(offset)?;
                return Some(vrrp::fingerprint(
                    take(packet, offset, body_len)?,
                    vrrp::IpFamily::V6,
                    capture_truncated,
                ));
            }
            NEXT_HEADER_HOP_BY_HOP
            | NEXT_HEADER_ROUTING
            | NEXT_HEADER_FRAGMENT
            | NEXT_HEADER_AH
            | NEXT_HEADER_DESTINATION => {
                if extension_count >= MAX_IPV6_EXTENSION_HEADERS {
                    return None;
                }
                let (following, length, is_fragmented) =
                    extension_span(packet, next_header, offset, available_end)?;
                next_header = following;
                fragmented |= is_fragmented;
                offset = offset.checked_add(length)?;
                extension_count += 1;
            }
            // Encrypted ESP and all other unknown headers have no safe passive fingerprint
            _ => return None,
        }
    }
}

pub fn extension_span(
    packet: &[u8],
    kind: u8,
    offset: usize,
    limit: usize,
) -> Option<(u8, usize, bool)> {
    let following = read_u8(packet, offset)?;
    let length_field = read_u8(packet, offset.checked_add(1)?)?;
    let length = match kind {
        NEXT_HEADER_FRAGMENT => 8,
        NEXT_HEADER_AH => {
            if length_field == 0 {
                return None;
            }
            usize::from(length_field).checked_add(2)?.checked_mul(4)?
        }
        _ => usize::from(length_field).checked_add(1)?.checked_mul(8)?,
    };
    // Bound the extension against the declared IPv6 payload before reading its flags
    let _ = packet.get(offset..limit)?.get(..length)?;
    if kind == NEXT_HEADER_FRAGMENT {
        let flags_and_offset = read_u16(packet, offset.checked_add(2)?)?;
        // RFC 8200 ignores reserved fields on reception; only offset and M require reassembly
        let has_fragmentation = flags_and_offset & 0xfff9 != 0;
        return Some((following, length, has_fragmentation));
    }
    Some((following, length, false))
}

fn icmpv6_fingerprint(
    packet: &[u8],
    offset: usize,
    limit: usize,
    capture_truncated: bool,
    fragmented: bool,
) -> Option<Fingerprint> {
    // Classify the message before applying type-specific minimum sizes
    let payload = take(packet, offset, limit.checked_sub(offset)?)?;
    let message_type = read_u8(payload, 0)?;
    let protocol = match message_type {
        134 => Protocol::Ipv6Ra,
        133 | 135 | 136 | 137 => Protocol::Ipv6Nd,
        130 | 131 | 132 | 143 => Protocol::Mld,
        _ => return None,
    };
    let Some(code) = read_u8(payload, 1) else {
        return Some(Fingerprint::truncated(protocol));
    };
    if code != 0 {
        return Some(Fingerprint::malformed(protocol));
    }

    let minimum = match message_type {
        133 | 143 => 8,
        134 => 16,
        130..=132 | 135 | 136 => 24,
        137 => 40,
        _ => return None,
    };
    if payload.len() < minimum {
        return Some(Fingerprint::truncated(protocol));
    }
    // MLDv2 reports carry nested records that need their own bounded validation
    if message_type == 143 {
        let status = mld::report_status(payload);
        if status != crate::FingerprintStatus::Observed {
            return Some(Fingerprint { protocol, status });
        }
    }
    if fragmented || capture_truncated {
        return Some(Fingerprint::truncated(protocol));
    }
    Some(Fingerprint::observed(protocol))
}

fn udp_fingerprint(
    packet: &[u8],
    offset: usize,
    limit: usize,
    declared_end: usize,
    capture_truncated: bool,
    fragmented: bool,
) -> Option<Fingerprint> {
    // Reuse the shared UDP envelope checks with IPv6 address semantics
    let fingerprint = udp::fingerprint(
        packet,
        offset,
        limit,
        declared_end,
        capture_truncated,
        udp::AddressFamily::Ipv6,
    )?;
    if fragmented && fingerprint.status == crate::FingerprintStatus::Observed {
        return Some(Fingerprint::truncated(fingerprint.protocol));
    }
    Some(fingerprint)
}
