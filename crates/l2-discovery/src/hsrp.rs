use crate::{Fingerprint, Protocol, bytes::read_u8};

const HSRP_FIXED_HEADER_LEN: usize = 20;
const HSRP_MAX_OPCODE: u8 = 2;

/// Check the fixed HSRP header fields needed for a passive fingerprint
pub fn fingerprint(payload: &[u8]) -> Fingerprint {
    if payload.len() < HSRP_FIXED_HEADER_LEN {
        return Fingerprint::truncated(Protocol::Hsrp);
    }
    let Some(version) = read_u8(payload, 0) else {
        return Fingerprint::truncated(Protocol::Hsrp);
    };
    let Some(opcode) = read_u8(payload, 1) else {
        return Fingerprint::truncated(Protocol::Hsrp);
    };
    let Some(state) = read_u8(payload, 2) else {
        return Fingerprint::truncated(Protocol::Hsrp);
    };
    let Some(reserved) = read_u8(payload, 7) else {
        return Fingerprint::truncated(Protocol::Hsrp);
    };
    if version != 0 {
        return Fingerprint::unsupported(Protocol::Hsrp);
    }
    if opcode > HSRP_MAX_OPCODE || !matches!(state, 0 | 1 | 2 | 4 | 8 | 16) || reserved != 0 {
        return Fingerprint::malformed(Protocol::Hsrp);
    }
    Fingerprint::observed(Protocol::Hsrp)
}
