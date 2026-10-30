use std::{error::Error, net::Ipv6Addr, time::Duration};

use l2_active::{Limits, NdpProbe, ReceiveEvent};
use l2_onpath::MacAddress;
use smoltcp::wire::Icmpv6Packet;

use crate::support::{captured, identity};

pub const LOCAL_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
pub const REMOTE_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
pub const OTHER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 3];

// Complete NA with an independently calculated ICMPv6 checksum
pub const RESPONSE: [u8; 86] = *include_bytes!("fixtures/advertisement.bin");

pub fn probe(
    expected: Option<[u8; 6]>,
    packets: u32,
    bytes: u64,
) -> Result<NdpProbe, Box<dyn Error>> {
    Ok(NdpProbe::new(
        MacAddress::new(LOCAL_MAC)?,
        "fe80::1".parse()?,
        64,
        "fe80::2".parse()?,
        expected.map(MacAddress::new).transpose()?,
        Limits::new(Duration::from_millis(20), packets, bytes)?,
    )?)
}

pub fn event(bytes: Vec<u8>) -> Result<ReceiveEvent, Box<dyn Error>> {
    let original = u32::try_from(bytes.len())?;
    Ok(ReceiveEvent::Frame(captured(
        bytes,
        Some(identity()?),
        original,
    )?))
}

pub fn with_mac(mac: [u8; 6]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut frame = RESPONSE.to_vec();
    frame
        .get_mut(6..12)
        .ok_or("missing Ethernet source")?
        .copy_from_slice(&mac);
    frame
        .get_mut(80..86)
        .ok_or("missing target option")?
        .copy_from_slice(&mac);
    fix_checksum(&mut frame)?;
    Ok(frame)
}

pub fn fix_checksum(frame: &mut [u8]) -> Result<(), Box<dyn Error>> {
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(
        frame.get(22..38).ok_or("missing source")?,
    )?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(
        frame.get(38..54).ok_or("missing destination")?,
    )?);
    let payload = frame.get_mut(54..).ok_or("missing ICMPv6")?;
    let mut packet = Icmpv6Packet::new_checked(payload).map_err(|_| "invalid ICMPv6 fixture")?;
    packet.fill_checksum(&source, &destination);
    Ok(())
}
