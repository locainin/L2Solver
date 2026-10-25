use crate::{Fingerprint, Protocol, bytes::read_u16, mka};

const EAPOL_HEADER_LEN: usize = 4;
const MAX_SUPPORTED_VERSION: u8 = 3;
const MAX_SUPPORTED_PACKET_TYPE: u8 = 5;
const EAPOL_MKA: u8 = 5;

/// Check the EAPOL header and its declared body bound
pub fn fingerprint(payload: &[u8]) -> Fingerprint {
    let Some(header) = payload.get(..EAPOL_HEADER_LEN) else {
        return Fingerprint::truncated(Protocol::Eapol);
    };
    let Some(version) = header.first().copied() else {
        return Fingerprint::truncated(Protocol::Eapol);
    };
    if version == 0 {
        return Fingerprint::malformed(Protocol::Eapol);
    }
    if version > MAX_SUPPORTED_VERSION {
        return Fingerprint::unsupported(Protocol::Eapol);
    }
    let Some(packet_type) = header.get(1).copied() else {
        return Fingerprint::truncated(Protocol::Eapol);
    };
    if packet_type > MAX_SUPPORTED_PACKET_TYPE {
        return Fingerprint::unsupported(Protocol::Eapol);
    }

    let Some(declared_body) = read_u16(header, 2).map(usize::from) else {
        return Fingerprint::truncated(Protocol::Eapol);
    };
    let available_body = payload.len().saturating_sub(EAPOL_HEADER_LEN);
    if declared_body > available_body {
        return Fingerprint::truncated(Protocol::Eapol);
    }

    if packet_type == EAPOL_MKA {
        let Some(body) = payload.get(EAPOL_HEADER_LEN..EAPOL_HEADER_LEN + declared_body) else {
            return Fingerprint::truncated(Protocol::Mka);
        };
        return mka::fingerprint(body);
    }

    // Bytes beyond the EAPOL length can be Ethernet minimum-frame padding
    Fingerprint::observed(Protocol::Eapol)
}
