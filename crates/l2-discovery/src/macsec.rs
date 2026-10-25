use crate::{Fingerprint, Protocol};

const SECTAG_BASE_LEN: usize = 6;
const SECTAG_SCI_LEN: usize = 8;
const TCI_SC: u8 = 0x20;

/// Check the fixed `SecTAG` and optional SCI without attempting cryptographic validation
pub const fn fingerprint(payload: &[u8]) -> Fingerprint {
    if payload.len() < SECTAG_BASE_LEN {
        return Fingerprint::truncated(Protocol::Macsec);
    }
    let Some(&tci_an) = payload.first() else {
        return Fingerprint::truncated(Protocol::Macsec);
    };
    let required = if tci_an & TCI_SC == 0 {
        SECTAG_BASE_LEN
    } else {
        SECTAG_BASE_LEN + SECTAG_SCI_LEN
    };
    if payload.len() < required {
        return Fingerprint::truncated(Protocol::Macsec);
    }
    Fingerprint::observed(Protocol::Macsec)
}
