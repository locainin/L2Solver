use super::common::AP;

fn length_byte(length: usize) -> u8 {
    u8::try_from(length).ok().map_or(0, |value| value)
}

pub fn beacon() -> Vec<u8> {
    let mut elements = vec![221, 4, 0x00, 0x50, 0xf2, 4];
    elements.extend_from_slice(&[
        48, 24, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 2, 0, 0x00, 0x0f, 0xac, 2,
        0x00, 0x0f, 0xac, 8, 0xc0, 0,
    ]);
    beacon_frame(AP, b"Corp", 0x0010, Some(6), &elements)
}

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

pub fn radiotap_at(frame: &[u8], frequency: u16) -> Vec<u8> {
    let mut bytes = vec![0_u8, 0, 13, 0, 0x28, 0, 0, 0];
    bytes.extend_from_slice(&frequency.to_le_bytes());
    bytes.extend_from_slice(&0x00a0_u16.to_le_bytes());
    bytes.extend_from_slice(&(-40_i8).to_ne_bytes());
    bytes.extend_from_slice(frame);
    bytes
}

pub fn radiotap_with_flags(frame: &[u8], flags: u8) -> Vec<u8> {
    let mut bytes = vec![0_u8, 0, 15, 0, 0x2a, 0, 0, 0, flags, 0];
    bytes.extend_from_slice(&2_437_u16.to_le_bytes());
    bytes.extend_from_slice(&0x00a0_u16.to_le_bytes());
    bytes.extend_from_slice(&(-40_i8).to_ne_bytes());
    bytes.extend_from_slice(frame);
    bytes
}
