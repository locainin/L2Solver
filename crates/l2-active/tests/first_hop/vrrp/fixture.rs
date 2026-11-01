use std::{error::Error, num::NonZeroU8, time::Duration};

use l2_active::{Limits, first_hop::vrrp::VrrpMonitor};
use l2_capture::CapturedFrame;

use crate::support::{captured, identity};

pub const VALID: &[u8] = include_bytes!("fixtures/valid.bin");
pub const PSEUDO: &[u8] = include_bytes!("fixtures/pseudo.bin");
pub const OTHER_VRID: &[u8] = include_bytes!("fixtures/other-vrid.bin");
pub const ANOMALY: &[u8] = include_bytes!("fixtures/sender-anomaly.bin");
pub const RESERVED: &[u8] = include_bytes!("fixtures/reserved.bin");
pub const RELINQUISH: &[u8] = include_bytes!("fixtures/relinquish.bin");
pub const BAD_TTL: &[u8] = include_bytes!("fixtures/bad-ttl.bin");
pub const FRAGMENT: &[u8] = include_bytes!("fixtures/fragment.bin");
pub const BAD_SOURCE: &[u8] = include_bytes!("fixtures/bad-source.bin");
pub const ZERO_VRID: &[u8] = include_bytes!("fixtures/zero-vrid.bin");
pub const ZERO_COUNT: &[u8] = include_bytes!("fixtures/zero-count.bin");
pub const BAD_TYPE: &[u8] = include_bytes!("fixtures/bad-type.bin");
pub const EXTRA_IP: &[u8] = include_bytes!("fixtures/extra-ip.bin");
pub const OPTIONS: &[u8] = include_bytes!("fixtures/options.bin");
pub const SHORT_IP: &[u8] = include_bytes!("fixtures/short-ip.bin");
pub const MAXIMUM: &[u8] = include_bytes!("fixtures/maximum.bin");
pub const V2_AUTH: &[u8] = include_bytes!("fixtures/v2-auth.bin");

pub fn monitor(vrid: Option<u8>, packets: u32, bytes: u64) -> Result<VrrpMonitor, Box<dyn Error>> {
    let selection = vrid
        .map(|value| NonZeroU8::new(value).ok_or("invalid fixture VRID"))
        .transpose()?;
    Ok(VrrpMonitor::new(
        selection,
        Limits::new(Duration::from_millis(20), packets, bytes)?,
    ))
}

pub fn capture(bytes: &[u8]) -> Result<CapturedFrame, Box<dyn Error>> {
    captured(
        bytes.to_vec(),
        Some(identity()?),
        u32::try_from(bytes.len())?,
    )
}
