use super::common::{AP, STATION};

// Keep malformed oversized fixture inputs non-panicking like the original builder
fn length_byte(length: usize) -> u8 {
    u8::try_from(length).unwrap_or(0)
}

// Build an RSN transition element with both PSK and SAE authentication suites
pub fn rsn_transition() -> Vec<u8> {
    let mut body = Vec::from(1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 4]);
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 4]);
    body.extend_from_slice(&2_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 2]);
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 8]);
    body.extend_from_slice(&0x00c0_u16.to_le_bytes());
    let mut ie = vec![48, length_byte(body.len())];
    ie.extend_from_slice(&body);
    ie
}

// Build a single-authentication RSN element and choose the pairwise cipher
pub fn rsn_psk(capabilities: u16, tkip: bool) -> Vec<u8> {
    let cipher = if tkip { 2 } else { 4 };
    let mut body = Vec::from(1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x0f, 0xac, cipher]);
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x0f, 0xac, cipher]);
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 2]);
    body.extend_from_slice(&capabilities.to_le_bytes());
    let mut ie = vec![48, length_byte(body.len())];
    ie.extend_from_slice(&body);
    ie
}

// Change only the group cipher while retaining the valid RSN structure
pub fn rsn_group_tkip() -> Vec<u8> {
    let mut ie = rsn_psk(0, false);
    if let Some(cipher) = ie.get_mut(7) {
        *cipher = 2;
    }
    ie
}

// Build an SAE-only RSN element with caller-selected PMF capabilities
pub fn rsn_sae_only(capabilities: u16) -> Vec<u8> {
    let mut body = Vec::from(1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 4]);
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 4]);
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 8]);
    body.extend_from_slice(&capabilities.to_le_bytes());
    let mut ie = vec![48, length_byte(body.len())];
    ie.extend_from_slice(&body);
    ie
}

// Build the legacy WPA vendor element used by mode classification tests
pub fn wpa() -> Vec<u8> {
    let mut body = vec![0x00, 0x50, 0xf2, 1];
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x50, 0xf2, 4]);
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x50, 0xf2, 4]);
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x50, 0xf2, 2]);
    let mut ie = vec![221, length_byte(body.len())];
    ie.extend_from_slice(&body);
    ie
}

// Build a management beacon while leaving information elements explicit at the call site
pub fn beacon_frame(
    bssid: [u8; 6],
    ssid: &[u8],
    capability: u16,
    channel: Option<u8>,
    elements: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::from(0x0080_u16.to_le_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&0_u64.to_le_bytes());
    frame.extend_from_slice(&100_u16.to_le_bytes());
    frame.extend_from_slice(&capability.to_le_bytes());
    frame.push(0);
    frame.push(length_byte(ssid.len()));
    frame.extend_from_slice(ssid);
    if let Some(channel) = channel {
        frame.extend_from_slice(&[3, 1, channel]);
    }
    frame.extend_from_slice(elements);
    frame
}

// Add the standard transition and WPS advertisements to a corporate beacon
pub fn beacon_with_ssid(ssid: &[u8]) -> Vec<u8> {
    let mut elements = vec![221, 4, 0x00, 0x50, 0xf2, 4];
    elements.extend_from_slice(&rsn_transition());
    beacon_frame(AP, ssid, 0x0010, Some(6), &elements)
}

pub fn beacon() -> Vec<u8> {
    beacon_with_ssid(b"Corp")
}

// Wrap a frame in the supported radiotap fields used by most observations
pub fn radiotap(frame: &[u8]) -> Vec<u8> {
    radiotap_at(frame, 2_437)
}

// Keep the frequency field configurable for channel mapping tests
pub fn radiotap_at(frame: &[u8], frequency: u16) -> Vec<u8> {
    let mut bytes = vec![0_u8, 0, 13, 0, 0x28, 0, 0, 0];
    bytes.extend_from_slice(&frequency.to_le_bytes());
    bytes.extend_from_slice(&0x00a0_u16.to_le_bytes());
    bytes.extend_from_slice(&(-40_i8).to_ne_bytes());
    bytes.extend_from_slice(frame);
    bytes
}

// Keep the radiotap flags field visible for FCS behavior tests
pub fn radiotap_with_flags(frame: &[u8], flags: u8) -> Vec<u8> {
    let mut bytes = vec![0_u8, 0, 15, 0, 0x2a, 0, 0, 0, flags, 0];
    bytes.extend_from_slice(&2_437_u16.to_le_bytes());
    bytes.extend_from_slice(&0x00a0_u16.to_le_bytes());
    bytes.extend_from_slice(&(-40_i8).to_ne_bytes());
    bytes.extend_from_slice(frame);
    bytes
}

// Build an association request whose transmitter is the station under test
pub fn association() -> Vec<u8> {
    let mut bytes = Vec::from(0x0000_u16.to_le_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&AP);
    bytes.extend_from_slice(&STATION);
    bytes.extend_from_slice(&AP);
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&[0x10, 0, 1, 0]);
    bytes
}
