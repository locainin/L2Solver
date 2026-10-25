// Shared BSSID values keep policy and observation fixtures aligned
pub const EXPECTED_AP: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
pub const ROGUE_AP: [u8; 6] = [0x02, 0, 0, 0, 0, 9];

// Keep malformed oversized fixture inputs non-panicking like the original builder
fn length_byte(length: usize) -> u8 {
    u8::try_from(length).ok().map_or(0, |value| value)
}

// Build the SAE RSN element with caller-selected PMF capabilities
pub fn rsn_sae_with(capabilities: u16) -> Vec<u8> {
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

pub fn rsn_sae() -> Vec<u8> {
    rsn_sae_with(0x00c0)
}

// Build a transition RSN element with PSK and SAE authentication suites
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

// Build a beacon with an explicit SSID, capability flags, and information elements
pub fn beacon_with(bssid: [u8; 6], ssid: &[u8], capability: u16, elements: &[u8]) -> Vec<u8> {
    beacon_on_channel(bssid, ssid, capability, 36, elements)
}

// Keep channel drift explicit when one BSSID changes advertisements
pub fn beacon_on_channel(
    bssid: [u8; 6],
    ssid: &[u8],
    capability: u16,
    channel: u8,
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
    frame.extend_from_slice(&[3, 1, channel]);
    frame.extend_from_slice(elements);
    frame
}

// Add optional WPS and SAE elements to a named beacon
pub fn beacon_named(bssid: [u8; 6], ssid: &[u8], secure: bool, wps: bool) -> Vec<u8> {
    let mut elements = Vec::new();
    if wps {
        elements.extend_from_slice(&[221, 4, 0x00, 0x50, 0xf2, 4]);
    }
    if secure {
        elements.extend_from_slice(&rsn_sae());
    }
    beacon_with(bssid, ssid, if secure { 0x0010 } else { 0 }, &elements)
}

pub fn beacon(bssid: [u8; 6], secure: bool, wps: bool) -> Vec<u8> {
    beacon_named(bssid, b"Corp", secure, wps)
}
