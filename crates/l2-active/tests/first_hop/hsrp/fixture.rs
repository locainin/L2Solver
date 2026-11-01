use std::{error::Error, net::Ipv4Addr, time::Duration};

use l2_active::{Limits, ReceiveEvent};
use smoltcp::wire::{IpAddress, Ipv4Packet, UdpPacket};

use crate::support::{captured, identity};

// The independent Scapy frame contains a unique authentication and padding marker
pub const ADVERTISEMENT: &[u8] = include_bytes!("fixtures/advertisement.bin");
pub const IP_OPTIONS: &[u8] = include_bytes!("fixtures/ip-options.bin");
pub const MAX_IP_OPTIONS: &[u8] = include_bytes!("fixtures/max-ip-options.bin");
pub const EXTENSION: &[u8] = include_bytes!("fixtures/extension.bin");
pub const VERSION_TWO: &[u8] = include_bytes!("fixtures/hsrp-v2.bin");
pub const AUTH_MARKER: &str = "AuthP@ss";
pub const PAD_MARKER: &str = "PAD-SECRET";

pub fn limits() -> Result<Limits, Box<dyn Error>> {
    Ok(Limits::new(Duration::from_millis(20), 128, 16_384)?)
}

pub fn event(bytes: Vec<u8>) -> Result<ReceiveEvent, Box<dyn Error>> {
    let length = u32::try_from(bytes.len())?;
    Ok(ReceiveEvent::Frame(captured(
        bytes,
        Some(identity()?),
        length,
    )?))
}

pub fn fix_checksums(bytes: &mut [u8]) -> Result<(), Box<dyn Error>> {
    let ip = bytes.get_mut(14..).ok_or("short Ethernet frame")?;
    let mut packet = Ipv4Packet::new_checked(ip).map_err(|_| "invalid IPv4 fixture")?;
    let source = packet.src_addr();
    let destination = packet.dst_addr();
    packet.fill_checksum();
    let mut udp =
        UdpPacket::new_checked(packet.payload_mut()).map_err(|_| "invalid UDP fixture")?;
    udp.fill_checksum(&IpAddress::Ipv4(source), &IpAddress::Ipv4(destination));
    Ok(())
}

pub fn mutate(offset: usize, value: u8, fix: bool) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = ADVERTISEMENT.to_vec();
    *bytes.get_mut(offset).ok_or("missing fixture byte")? = value;
    if fix {
        fix_checksums(&mut bytes)?;
    }
    Ok(bytes)
}

pub const fn target() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 1)
}
