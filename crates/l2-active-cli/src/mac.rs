//! Format a checked Ethernet address for operator output

pub fn format_mac(bytes: [u8; 6]) -> String {
    let [first, second, third, fourth, fifth, sixth] = bytes;
    format!("{first:02x}:{second:02x}:{third:02x}:{fourth:02x}:{fifth:02x}:{sixth:02x}")
}
