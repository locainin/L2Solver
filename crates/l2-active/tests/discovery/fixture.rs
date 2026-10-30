use std::{error::Error, time::Duration};

use l2_active::{Limits, ReceiveEvent};
use l2_codecs::{LldpFrame, Tlv, Validity, encode_lldp, lldp_encoded_len};
use l2_core::{EthernetFrame, FrameField, encode, encoded_len};

use crate::support::{captured, identity};

pub const DEVICE: &[u8] = b"\x07switch-a";
pub const PORT: &[u8] = b"\x05Gi1/0/1";
// Scapy CDPv2 fixture with an independently checked odd-length checksum
pub const CDP: &[u8] = &[
    1, 0, 0x0c, 0xcc, 0xcc, 0xcc, 2, 0, 0, 0, 0, 1, 0, 0x23, 0xaa, 0xaa, 3, 0, 0, 0x0c, 0x20, 0, 2,
    0x78, 0xe6, 0xbe, 0, 1, 0, 0x0c, b's', b'w', b'i', b't', b'c', b'h', b'-', b'a', 0, 3, 0, 0x0b,
    b'G', b'i', b'1', b'/', b'0', b'/', b'1',
];

pub fn limits(packets: u32, bytes: u64) -> Result<Limits, Box<dyn Error>> {
    Ok(Limits::new(Duration::from_millis(20), packets, bytes)?)
}

pub fn event(bytes: Vec<u8>) -> Result<ReceiveEvent, Box<dyn Error>> {
    let original = u32::try_from(bytes.len())?;
    Ok(ReceiveEvent::Frame(captured(
        bytes,
        Some(identity()?),
        original,
    )?))
}

pub fn lldp(ttl: u16, scope: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    let ttl_bytes = ttl.to_be_bytes();
    let model = LldpFrame {
        tlvs: vec![
            Tlv {
                kind: 1,
                value: DEVICE,
                offset: 0,
            },
            Tlv {
                kind: 2,
                value: PORT,
                offset: 0,
            },
            Tlv {
                kind: 3,
                value: &ttl_bytes,
                offset: 0,
            },
        ],
        padding: &[],
        validity: Validity::Valid,
    };
    let mut payload = vec![0; lldp_encoded_len(&model)?];
    encode_lldp(&model, &mut payload)?;
    let frame = EthernetFrame {
        destination: [1, 0x80, 0xc2, 0, 0, scope],
        source: [2, 0, 0, 0, 0, 1],
        vlan_tags: Vec::new(),
        field: FrameField::EtherType(0x88cc),
        payload: &payload,
        padding: &[],
    };
    let mut bytes = vec![0; encoded_len(&frame)?];
    encode(&frame, &mut bytes)?;
    Ok(bytes)
}
