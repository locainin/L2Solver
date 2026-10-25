use crate::{Fingerprint, Protocol, bytes::read_u8};

const LACP_SUBTYPE: u8 = 1;

/// Recognize only the LACP subtype of the Slow Protocols `EtherType`
pub fn fingerprint(payload: &[u8]) -> Option<Fingerprint> {
    if read_u8(payload, 0) != Some(LACP_SUBTYPE) {
        return None;
    }
    let Some(version) = read_u8(payload, 1) else {
        return Some(Fingerprint::truncated(Protocol::Lacp));
    };
    if version == 0 {
        return Some(Fingerprint::malformed(Protocol::Lacp));
    }
    if version != 1 {
        return Some(Fingerprint::unsupported(Protocol::Lacp));
    }
    Some(Fingerprint::observed(Protocol::Lacp))
}
