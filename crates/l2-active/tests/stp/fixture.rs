use std::{error::Error, time::Duration};

use l2_active::{Limits, ReceiveEvent};

use crate::support::{captured, identity};

pub const SOURCE: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
pub const ROOT: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
pub const BRIDGE: [u8; 6] = [0x02, 0x77, 0x88, 0x99, 0xaa, 0xbb];

pub fn limits(packets: u32, bytes: u64) -> Result<Limits, Box<dyn Error>> {
    Ok(Limits::new(Duration::from_millis(40), packets, bytes)?)
}

pub fn frame(source: [u8; 6], root: [u8; 6], rapid: bool) -> Vec<u8> {
    let mut result = vec![0x01, 0x80, 0xc2, 0, 0, 0];
    result.extend_from_slice(&source);
    result.extend_from_slice(&(if rapid { 39_u16 } else { 38_u16 }).to_be_bytes());
    result.extend_from_slice(&[0x42, 0x42, 0x03, 0, 0]);
    result.extend_from_slice(if rapid { &[2, 2, 0x7e] } else { &[0, 0, 0x81] });
    result.extend_from_slice(&0x8001_u16.to_be_bytes());
    result.extend_from_slice(&root);
    result.extend_from_slice(&16_u32.to_be_bytes());
    result.extend_from_slice(&0x9002_u16.to_be_bytes());
    result.extend_from_slice(&BRIDGE);
    result.extend_from_slice(&0x8001_u16.to_be_bytes());
    for timer in [0x0100_u16, 0x1400, 0x0200, 0x0f00] {
        result.extend_from_slice(&timer.to_be_bytes());
    }
    if rapid {
        result.push(0);
    }
    result.resize(60, 0);
    result
}

pub fn event(bytes: Vec<u8>) -> Result<ReceiveEvent, Box<dyn Error>> {
    let length = u32::try_from(bytes.len())?;
    Ok(ReceiveEvent::Frame(captured(
        bytes,
        Some(identity()?),
        length,
    )?))
}
