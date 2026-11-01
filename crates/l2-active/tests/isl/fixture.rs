use std::{error::Error, time::Duration};

use l2_active::{Limits, ReceiveEvent};

use crate::support::{captured, identity};

pub const VALID: &[u8] = include_bytes!("fixtures/valid.bin");
pub const FOREIGN: &[u8] = include_bytes!("fixtures/other-prefix.bin");
pub const UNSUPPORTED_MEDIA: &[u8] = include_bytes!("fixtures/unsupported-media.bin");
pub const INVALID_LLC: &[u8] = include_bytes!("fixtures/malformed-llc.bin");
pub const UNSUPPORTED_LENGTH: &[u8] = include_bytes!("fixtures/unsupported-length.bin");

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

pub fn change(bytes: &[u8], offset: usize, value: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut result = bytes.to_vec();
    *result.get_mut(offset).ok_or("fixture offset missing")? = value;
    Ok(result)
}
