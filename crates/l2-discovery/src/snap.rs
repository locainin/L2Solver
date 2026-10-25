use crate::{Fingerprint, Protocol, bytes::read_u16};

const LLC_DSAP: u8 = 0xaa;
const LLC_SSAP: u8 = 0xaa;
const LLC_CONTROL: u8 = 0x03;
const CISCO_OUI: [u8; 3] = [0x00, 0x00, 0x0c];

/// Recognize Cisco control protocols carried in an 802.2 LLC/SNAP payload
pub fn fingerprint(payload: &[u8]) -> Option<Fingerprint> {
    if payload.get(..3) != Some(&[LLC_DSAP, LLC_SSAP, LLC_CONTROL]) {
        return None;
    }
    if payload.get(3..6) != Some(CISCO_OUI.as_slice()) {
        return None;
    }
    let Some(pid) = read_u16(payload, 6) else {
        return Some(Fingerprint::truncated(Protocol::CiscoSnap));
    };
    let protocol = match pid {
        0x2000 => Protocol::Cdp,
        0x2004 => Protocol::Dtp,
        0x2003 => Protocol::Vtp,
        0x0104 => Protocol::Pagp,
        0x010b => Protocol::PvstPlus,
        _ => return Some(Fingerprint::unsupported(Protocol::CiscoSnap)),
    };
    Some(Fingerprint::observed(protocol))
}
