use std::{error::Error, time::Duration};

use l2_active::{Limits, dot1x::Dot1xProbe};
use l2_capture::CapturedFrame;
use l2_onpath::MacAddress;

use crate::support::{captured, identity};

pub const CLIENT: [u8; 6] = [2, 0, 0, 0, 0, 1];
pub const AUTHENTICATOR: [u8; 6] = [2, 0, 0, 0, 0, 2];
pub const START: &[u8] = include_bytes!("fixtures/start.bin");
pub const REQUEST: &[u8] = include_bytes!("fixtures/request.bin");
pub const GROUP: &[u8] = include_bytes!("fixtures/group.bin");

pub fn probe(packets: u32, bytes: u64) -> Result<Dot1xProbe, Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(20), packets, bytes)?;
    Ok(Dot1xProbe::new(MacAddress::new(CLIENT)?, limits)?)
}

pub fn capture(bytes: &[u8]) -> Result<CapturedFrame, Box<dyn Error>> {
    captured(
        bytes.to_vec(),
        Some(identity()?),
        u32::try_from(bytes.len())?,
    )
}
