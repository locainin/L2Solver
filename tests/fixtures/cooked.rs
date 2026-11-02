//! Generate cooked capture frames around protocol bytes from Ethernet fixtures

use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId, LinkType};

pub fn cooked(
    input: &[u8],
    version: u16,
    interface: InterfaceId,
    ifindex: u32,
) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    let mut bytes = match version {
        113 => vec![0, 0, 0, 1, 0, 6, 2, 0, 0, 0, 0, 1, 0, 0, 8, 0],
        276 => {
            let mut header = vec![8, 0, 0, 0];
            header.extend_from_slice(&ifindex.to_be_bytes());
            header.extend_from_slice(&[0, 1, 0, 6, 2, 0, 0, 0, 0, 1, 0, 0]);
            header
        }
        _ => return Err("invalid cooked fixture version".into()),
    };
    let protocol = input.get(12..14).ok_or("short Ethernet fixture")?;
    let protocol_offset = if version == 113 { 14 } else { 0 };
    bytes
        .get_mut(protocol_offset..protocol_offset + 2)
        .ok_or("short cooked fixture")?
        .copy_from_slice(protocol);
    bytes.extend_from_slice(input.get(14..).ok_or("short Ethernet fixture")?);
    let metadata = CaptureMetadata::unknown(interface, u32::try_from(bytes.len())?)
        .with_link_type(LinkType::from_raw(version));
    Ok(CapturedFrame::new(bytes, metadata)?)
}
