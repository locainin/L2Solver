use crate::{Fingerprint, Protocol, bytes::read_u8};

const VRRP_TYPE_ADVERTISEMENT: u8 = 1;
const VRRP_V2: u8 = 2;
const VRRP_V3: u8 = 3;
const VRRP_FIXED_HEADER_LEN: usize = 8;
const IPV4_ADDRESS_LEN: usize = 4;
const IPV6_ADDRESS_LEN: usize = 16;

/// Address family supplied by the enclosing IP packet
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpFamily {
    V4,
    V6,
}

/// Check the common VRRP advertisement header and its address-count bound
pub fn fingerprint(payload: &[u8], family: IpFamily, capture_truncated: bool) -> Fingerprint {
    if payload.len() < VRRP_FIXED_HEADER_LEN {
        return Fingerprint::truncated(Protocol::Vrrp);
    }
    let Some(version_and_type) = read_u8(payload, 0) else {
        return Fingerprint::truncated(Protocol::Vrrp);
    };
    let version = version_and_type >> 4;
    let message_type = version_and_type & 0x0f;
    if !matches!(version, VRRP_V2 | VRRP_V3) {
        return Fingerprint::unsupported(Protocol::Vrrp);
    }
    // VRRPv2 is defined only for IPv4
    if version == VRRP_V2 && family == IpFamily::V6 {
        return Fingerprint::unsupported(Protocol::Vrrp);
    }
    if message_type != VRRP_TYPE_ADVERTISEMENT {
        return Fingerprint::malformed(Protocol::Vrrp);
    }
    let Some(address_count) = read_u8(payload, 3).map(usize::from) else {
        return Fingerprint::truncated(Protocol::Vrrp);
    };
    if address_count == 0 {
        return Fingerprint::malformed(Protocol::Vrrp);
    }
    // VRRPv3 carries the same address family as its enclosing IP packet
    let address_len = match family {
        IpFamily::V4 => IPV4_ADDRESS_LEN,
        IpFamily::V6 => IPV6_ADDRESS_LEN,
    };
    let Some(required) = address_count
        .checked_mul(address_len)
        .and_then(|addresses| VRRP_FIXED_HEADER_LEN.checked_add(addresses))
    else {
        return Fingerprint::malformed(Protocol::Vrrp);
    };
    if payload.len() < required {
        return Fingerprint::truncated(Protocol::Vrrp);
    }
    if capture_truncated {
        return Fingerprint::truncated(Protocol::Vrrp);
    }
    Fingerprint::observed(Protocol::Vrrp)
}
