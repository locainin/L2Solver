use std::{error::Error, net::Ipv4Addr};

use l2_active::{ArpProbe, Limits};
use l2_onpath::MacAddress;

pub use crate::support::{Link, captured, identity};

pub const LOCAL_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
pub const REMOTE_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
pub const OTHER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 3];
pub const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
pub const TARGET_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);

pub fn probe(
    expected: Option<[u8; 6]>,
    packets: u32,
    bytes: u64,
) -> Result<ArpProbe, Box<dyn Error>> {
    let expected = expected.map(MacAddress::new).transpose()?;
    Ok(ArpProbe::new(
        MacAddress::new(LOCAL_MAC)?,
        LOCAL_IP,
        TARGET_IP,
        expected,
        Limits::new(std::time::Duration::from_millis(20), packets, bytes)?,
    )?)
}

pub fn reply(mac: [u8; 6], sender: Ipv4Addr, target: Ipv4Addr) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&LOCAL_MAC);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 2]);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&sender.octets());
    frame.extend_from_slice(&LOCAL_MAC);
    frame.extend_from_slice(&target.octets());
    frame.resize(60, 0);
    frame
}
