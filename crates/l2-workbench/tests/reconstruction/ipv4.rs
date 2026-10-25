use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};

pub fn ipv4(
    flags: u16,
    protocol: u8,
    reverse: bool,
    body: &[u8],
) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    let mut bytes = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0, 0x45, 0];
    bytes.extend_from_slice(&u16::try_from(20 + body.len())?.to_be_bytes());
    bytes.extend_from_slice(&42_u16.to_be_bytes());
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes.extend_from_slice(&[64, protocol, 0, 0]);
    // Swapping endpoints keeps forward and reverse segments in one conversation
    let (source, destination) = if reverse {
        ([192, 0, 2, 2], [192, 0, 2, 1])
    } else {
        ([192, 0, 2, 1], [192, 0, 2, 2])
    };
    bytes.extend_from_slice(&source);
    bytes.extend_from_slice(&destination);
    bytes.extend_from_slice(body);
    let length = u32::try_from(bytes.len())?;
    Ok(CapturedFrame::new(
        bytes,
        CaptureMetadata::unknown(
            InterfaceId {
                section: 0,
                index: 0,
            },
            length,
        ),
    )?)
}
