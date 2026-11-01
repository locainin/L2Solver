use std::{error::Error, time::Duration};

use l2_active::{Limits, ReceiveEvent};

use crate::support::{captured, identity};

pub const DTP: &[u8] = include_bytes!("fixtures/dtp.bin");
pub const SUMMARY: &[u8] = include_bytes!("fixtures/vtp-summary.bin");
pub const SUBSET: &[u8] = include_bytes!("fixtures/vtp-subset.bin");
pub const REQUEST: &[u8] = include_bytes!("fixtures/vtp-request.bin");

pub fn limits(packets: u32, bytes: u64) -> Result<Limits, Box<dyn Error>> {
    Ok(Limits::new(Duration::from_millis(25), packets, bytes)?)
}

pub fn event(bytes: &[u8]) -> Result<ReceiveEvent, Box<dyn Error>> {
    Ok(ReceiveEvent::Frame(captured(
        bytes.to_vec(),
        Some(identity()?),
        u32::try_from(bytes.len())?,
    )?))
}

pub fn frame(protocol: u16, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut frame = vec![1, 0, 0x0c, 0xcc, 0xcc, 0xcc, 2, 0, 0, 0, 0, 2];
    frame.extend_from_slice(&u16::try_from(8 + payload.len())?.to_be_bytes());
    frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0x0c]);
    frame.extend_from_slice(&protocol.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn change(bytes: &[u8], offset: usize, value: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut result = bytes.to_vec();
    *result.get_mut(offset).ok_or("fixture offset missing")? = value;
    Ok(result)
}
