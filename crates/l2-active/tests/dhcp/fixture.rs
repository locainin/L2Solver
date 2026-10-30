use std::{error::Error, net::Ipv4Addr, num::NonZeroU32, time::Duration};

use l2_active::{Limits, dhcp::DhcpProbe};
use l2_capture::CapturedFrame;
use l2_onpath::MacAddress;

use crate::support::{captured, identity};

pub const CLIENT_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
pub const SERVER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
pub const TRANSACTION: u32 = 0x1234_5678;
pub const SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
pub const OFFERED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
pub const DISCOVER: &[u8] = include_bytes!("fixtures/discover.bin");
pub const OFFER: &[u8] = include_bytes!("fixtures/offer.bin");
pub const WRONG_XID: &[u8] = include_bytes!("fixtures/wrong-xid.bin");
pub const WRONG_CLIENT: &[u8] = include_bytes!("fixtures/wrong-client.bin");
pub const UNEXPECTED_SERVER: &[u8] = include_bytes!("fixtures/unexpected-server.bin");
pub const WRONG_PORT: &[u8] = include_bytes!("fixtures/wrong-port.bin");
pub const FRAGMENT: &[u8] = include_bytes!("fixtures/fragment.bin");
pub const DUPLICATE_SERVER: &[u8] = include_bytes!("fixtures/duplicate-server.bin");
pub const MISSING_END: &[u8] = include_bytes!("fixtures/missing-end.bin");
pub const TRUNCATED_OPTION: &[u8] = include_bytes!("fixtures/truncated-option.bin");

pub fn probe(
    allowed: Option<&[Ipv4Addr]>,
    packets: u32,
    bytes: u64,
) -> Result<DhcpProbe, Box<dyn Error>> {
    Ok(DhcpProbe::new(
        MacAddress::new(CLIENT_MAC)?,
        NonZeroU32::new(TRANSACTION).ok_or("fixture transaction must be nonzero")?,
        allowed,
        Limits::new(Duration::from_millis(100), packets, bytes)?,
    )?)
}

pub fn capture(bytes: &[u8]) -> Result<CapturedFrame, Box<dyn Error>> {
    captured(
        bytes.to_vec(),
        Some(identity()?),
        u32::try_from(bytes.len())?,
    )
}

pub const ZERO_UDP_CHECKSUM: &[u8] = include_bytes!("fixtures/zero-udp-checksum.bin");
pub const UNICAST_OFFER: &[u8] = include_bytes!("fixtures/unicast-offer.bin");
pub const OVERLOADED_OPTIONS: &[u8] = include_bytes!("fixtures/overloaded-options.bin");
pub const EXTRA_OPTIONS: &[u8] = include_bytes!("fixtures/extra-options.bin");
pub const BAD_HARDWARE_TYPE: &[u8] = include_bytes!("fixtures/bad-hardware-type.bin");
pub const BAD_HARDWARE_LENGTH: &[u8] = include_bytes!("fixtures/bad-hardware-length.bin");
pub const INVALID_OFFERED_IP: &[u8] = include_bytes!("fixtures/invalid-offered-ip.bin");
pub const MISSING_SERVER: &[u8] = include_bytes!("fixtures/missing-server.bin");
pub const MISSING_LEASE: &[u8] = include_bytes!("fixtures/missing-lease.bin");

pub const RELAY_OFFER: &[u8] = include_bytes!("fixtures/relay-offer.bin");
pub const BAD_COOKIE: &[u8] = include_bytes!("fixtures/bad-cookie.bin");
pub const BAD_OPCODE: &[u8] = include_bytes!("fixtures/bad-opcode.bin");
pub const DUPLICATE_TYPE: &[u8] = include_bytes!("fixtures/duplicate-type.bin");
pub const OVERLOAD_DUPLICATE: &[u8] = include_bytes!("fixtures/overload-duplicate.bin");
pub const BAD_OVERLOAD: &[u8] = include_bytes!("fixtures/bad-overload.bin");

pub const FILE_OVERLOAD: &[u8] = include_bytes!("fixtures/file-overload.bin");
pub const ZERO_OVERLOAD: &[u8] = include_bytes!("fixtures/zero-overload.bin");
