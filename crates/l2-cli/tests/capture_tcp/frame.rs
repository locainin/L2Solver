use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus, InterfaceId,
    TimestampSource,
};
use l2_core::{EthernetFrame, FrameField, VlanTag};
use l2_pcap::TimestampResolution;
use std::error::Error;

pub fn frame(
    sequence: u32,
    flags: u8,
    payload: &[u8],
    tags: Vec<VlanTag>,
    interface: u32,
) -> Result<CapturedFrame, Box<dyn Error>> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&40_000_u16.to_be_bytes());
    tcp.extend_from_slice(&40_001_u16.to_be_bytes());
    tcp.extend_from_slice(&sequence.to_be_bytes());
    tcp.extend_from_slice(&0_u32.to_be_bytes());
    tcp.extend_from_slice(&[0x60, flags, 0x20, 0, 0, 0, 0, 0, 1, 1, 1, 1]);
    tcp.extend_from_slice(payload);
    let mut ip = vec![0x46, 0];
    ip.extend_from_slice(&u16::try_from(24 + tcp.len())?.to_be_bytes());
    ip.extend_from_slice(&[
        0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 1, 1, 1, 1,
    ]);
    ip.extend_from_slice(&tcp);
    // Padding after the IP declaration must never become sequence payload
    ip.extend_from_slice(&[0xfa, 0xfb]);
    let ethernet = EthernetFrame {
        destination: [2, 0, 0, 0, 0, 2],
        source: [2, 0, 0, 0, 0, 1],
        vlan_tags: tags,
        payload: &ip,
        padding: &[],
        field: FrameField::EtherType(0x0800),
    };
    let mut bytes = vec![0; l2_core::encoded_len(&ethernet)?];
    l2_core::encode(&ethernet, &mut bytes)?;
    let length = u32::try_from(bytes.len())?;
    Ok(CapturedFrame::new(bytes, metadata(interface, length))?)
}

pub const fn metadata(interface: u32, length: u32) -> CaptureMetadata {
    CaptureMetadata::new(
        InterfaceId {
            section: 0,
            index: interface,
        },
        length,
        None,
        Some(CaptureTimestamp::new(
            0,
            TimestampResolution::MICROSECOND,
            0,
            TimestampSource::Unknown,
        )),
        Direction::Unknown,
        None,
        FcsStatus::Unknown,
    )
}
