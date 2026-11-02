//! Build small protocol inputs from explicit fields instead of shipping capture files

const LOCAL_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const BRIDGE_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];

// All callers use fixed arrays whose field positions are checked at compile time
const fn put<const N: usize>(output: &mut [u8; N], offset: usize, value: &[u8]) {
    let (_, tail) = output.split_at_mut(offset);
    let (field, _) = tail.split_at_mut(value.len());
    field.copy_from_slice(value);
}

const fn header<const N: usize>(network: u32) -> [u8; N] {
    let mut output = [0; N];
    put(&mut output, 0, &0xa1b2_c3d4_u32.to_le_bytes());
    put(&mut output, 4, &2_u16.to_le_bytes());
    put(&mut output, 6, &4_u16.to_le_bytes());
    put(&mut output, 16, &65_535_u32.to_le_bytes());
    put(&mut output, 20, &network.to_le_bytes());
    output
}

const fn record<const N: usize>(output: &mut [u8; N], offset: usize, seconds: u32, length: u32) {
    put(output, offset, &seconds.to_le_bytes());
    put(output, offset + 8, &length.to_le_bytes());
    put(output, offset + 12, &length.to_le_bytes());
}

const fn lldp() -> [u8; 81] {
    let mut output = header(1);
    record(&mut output, 24, 1, 41);
    let mut frame = [0; 41];
    put(&mut frame, 0, &[1, 0x80, 0xc2, 0, 0, 0x0e]);
    put(&mut frame, 6, &LOCAL_MAC);
    put(&mut frame, 12, &0x88cc_u16.to_be_bytes());
    // Chassis MAC, interface name, TTL and system name are independent LLDP fields
    put(&mut frame, 14, &0x0207_u16.to_be_bytes());
    put(&mut frame, 16, &[4]);
    put(&mut frame, 17, &LOCAL_MAC);
    put(&mut frame, 23, &0x0402_u16.to_be_bytes());
    put(&mut frame, 25, &[5, b'p']);
    put(&mut frame, 27, &0x0602_u16.to_be_bytes());
    put(&mut frame, 29, &120_u16.to_be_bytes());
    put(&mut frame, 31, &0x0a06_u16.to_be_bytes());
    // Control characters exercise safe terminal rendering
    put(&mut frame, 33, b"core\x1b\x07");
    put(&mut output, 40, &frame);
    output
}

const fn stp() -> [u8; 92] {
    let mut output = header(1);
    record(&mut output, 24, 1, 52);
    let mut frame = [0; 52];
    put(&mut frame, 0, &[1, 0x80, 0xc2, 0, 0, 0]);
    put(&mut frame, 6, &BRIDGE_MAC);
    put(&mut frame, 12, &38_u16.to_be_bytes());
    put(&mut frame, 14, &[0x42, 0x42, 3]);
    // Root and bridge IDs use a fabricated local MAC with the default priority
    put(&mut frame, 22, &0x8000_u16.to_be_bytes());
    put(&mut frame, 24, &BRIDGE_MAC);
    put(&mut frame, 34, &0x8000_u16.to_be_bytes());
    put(&mut frame, 36, &BRIDGE_MAC);
    put(&mut frame, 42, &0x8001_u16.to_be_bytes());
    put(&mut frame, 46, &5_120_u16.to_be_bytes());
    put(&mut frame, 48, &512_u16.to_be_bytes());
    put(&mut frame, 50, &3_840_u16.to_be_bytes());
    put(&mut output, 40, &frame);
    output
}

const fn short() -> [u8; 41] {
    let mut output = header(1);
    record(&mut output, 24, 1, 1);
    output
}

const fn unsupported() -> [u8; 24] {
    let mut output = [0; 24];
    // A section marker with an invalid zero block length exercises rejection
    put(&mut output, 0, &0x0a0d_0d0a_u32.to_le_bytes());
    output
}

const fn beacon<const N: usize>(ssid: &[u8], ssid_length: u8, channel: u8) -> [u8; N] {
    let mut frame = [0; N];
    // Empty radiotap fields precede a management beacon with a local BSSID
    put(&mut frame, 2, &8_u16.to_le_bytes());
    put(&mut frame, 8, &0x0080_u16.to_le_bytes());
    put(&mut frame, 12, &[0xff; 6]);
    put(&mut frame, 18, &LOCAL_MAC);
    put(&mut frame, 24, &LOCAL_MAC);
    put(&mut frame, 40, &100_u16.to_le_bytes());
    put(&mut frame, 45, &[ssid_length]);
    put(&mut frame, 46, ssid);
    put(&mut frame, 46 + ssid.len(), &[3, 1, channel]);
    frame
}

const fn wifi_drift() -> [u8; 174] {
    let mut output = header(127);
    let first = beacon::<57>(b"CorpWiFi", 8, 6);
    let second = beacon::<61>(b"CorpWiFi-Lab", 12, 11);
    record(&mut output, 24, 1, 57);
    put(&mut output, 40, &first);
    record(&mut output, 97, 2, 61);
    put(&mut output, 113, &second);
    output
}

pub const LLDP: &[u8] = &lldp();
pub const LINUX_STP: &[u8] = &stp();
pub const SHORT: &[u8] = &short();
pub const UNSUPPORTED: &[u8] = &unsupported();
pub const WIFI_DRIFT: &[u8] = &wifi_drift();
