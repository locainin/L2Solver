use std::{error::Error, time::Duration};

use l2_active::{Limits, mpls::MplsMonitor};
use l2_capture::CapturedFrame;

use crate::support::{captured, identity};

pub const DESTINATION: [u8; 6] = [2, 0, 0, 0, 0, 1];
pub const VALID: &[u8] = include_bytes!("fixtures/valid.bin");
pub const ZERO_TTL: &[u8] = include_bytes!("fixtures/zero-ttl.bin");
pub const MAX_DEPTH: &[u8] = include_bytes!("fixtures/max-depth.bin");
pub const OVER_DEPTH: &[u8] = include_bytes!("fixtures/over-depth.bin");
pub const SHORT: &[u8] = include_bytes!("fixtures/short.bin");
pub const NO_PAYLOAD: &[u8] = include_bytes!("fixtures/no-payload.bin");
pub const NULL_V4: &[u8] = include_bytes!("fixtures/null-v4.bin");
pub const NULL_V6: &[u8] = include_bytes!("fixtures/null-v6.bin");
pub const BAD_NULL: &[u8] = include_bytes!("fixtures/bad-null.bin");
pub const BAD_ALERT: &[u8] = include_bytes!("fixtures/bad-alert.bin");
pub const IMPLICIT_NULL: &[u8] = include_bytes!("fixtures/implicit-null.bin");
pub const MNA: &[u8] = include_bytes!("fixtures/mna.bin");
pub const ELI: &[u8] = include_bytes!("fixtures/eli.bin");
pub const EXTENSION: &[u8] = include_bytes!("fixtures/extension.bin");

pub fn monitor(
    expected: Option<u32>,
    packets: u32,
    bytes: u64,
) -> Result<MplsMonitor, Box<dyn Error>> {
    Ok(MplsMonitor::new(
        DESTINATION,
        expected,
        Limits::new(Duration::from_millis(20), packets, bytes)?,
    )?)
}

pub fn capture(bytes: &[u8]) -> Result<CapturedFrame, Box<dyn Error>> {
    captured(
        bytes.to_vec(),
        Some(identity()?),
        u32::try_from(bytes.len())?,
    )
}
