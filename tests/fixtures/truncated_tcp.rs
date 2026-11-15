use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};
use std::error::Error;

pub fn tcp(
    sequence: u32,
    flags: u8,
    payload: &[u8],
    missing: usize,
) -> Result<CapturedFrame, Box<dyn Error>> {
    let source = [192, 0, 2, 1];
    let destination = [192, 0, 2, 2];
    let mut frame = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0];
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&u16::try_from(40 + payload.len() + missing)?.to_be_bytes());
    ip.extend_from_slice(&[0, 42, 0, 0, 64, 6, 0, 0]);
    ip.extend_from_slice(&source);
    ip.extend_from_slice(&destination);
    let ip_checksum = checksum(&ip);
    ip.get_mut(10..12)
        .ok_or("missing IP checksum")?
        .copy_from_slice(&ip_checksum.to_be_bytes());
    let mut transport = vec![];
    transport.extend_from_slice(&40_000_u16.to_be_bytes());
    transport.extend_from_slice(&9_000_u16.to_be_bytes());
    transport.extend_from_slice(&sequence.to_be_bytes());
    transport.extend_from_slice(&0_u32.to_be_bytes());
    transport.extend_from_slice(&[0x50, flags, 0, 0, 0, 0, 0, 0]);
    transport.extend_from_slice(payload);
    transport.resize(transport.len() + missing, 0);
    let mut pseudo = source.to_vec();
    pseudo.extend_from_slice(&destination);
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&u16::try_from(transport.len())?.to_be_bytes());
    pseudo.extend_from_slice(&transport);
    let transport_checksum = checksum(&pseudo);
    transport
        .get_mut(16..18)
        .ok_or("missing TCP checksum")?
        .copy_from_slice(&transport_checksum.to_be_bytes());
    transport.truncate(transport.len() - missing);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&transport);
    let original = u32::try_from(frame.len() + missing)?;
    Ok(CapturedFrame::new(
        frame,
        CaptureMetadata::unknown(
            InterfaceId {
                section: 0,
                index: 0,
            },
            original,
        ),
    )?)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|pair| {
            u32::from(pair.first().copied().unwrap_or(0)) * 256
                + u32::from(pair.get(1).copied().unwrap_or(0))
        })
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or_default()
}
