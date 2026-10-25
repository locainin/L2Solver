use super::ipv4::ipv4;
use l2_capture::CapturedFrame;

pub fn fragment(flags: u16, body: &[u8]) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    ipv4(flags, 17, false, body)
}
