use super::ipv4::ipv4;
use l2_capture::CapturedFrame;

pub fn tcp(
    reverse: bool,
    sequence: u32,
    flags: u8,
    payload: &[u8],
) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    tcp_ports(reverse, (40000, 9000), sequence, flags, payload)
}

pub fn tcp_ports(
    reverse: bool,
    ports: (u16, u16),
    sequence: u32,
    flags: u8,
    payload: &[u8],
) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    let mut body = Vec::new();
    let ports = if reverse { (ports.1, ports.0) } else { ports };
    body.extend_from_slice(&ports.0.to_be_bytes());
    body.extend_from_slice(&ports.1.to_be_bytes());
    // The fixed header leaves sequence and payload as the test-controlled evidence
    body.extend_from_slice(&sequence.to_be_bytes());
    body.extend_from_slice(&0_u32.to_be_bytes());
    body.extend_from_slice(&[0x50, flags, 0, 0, 0, 0, 0, 0]);
    body.extend_from_slice(payload);
    ipv4(0, 6, reverse, &body)
}
