//! IPv6 solicitation encoding and scoped advertisement validation

use std::net::Ipv6Addr;

use l2_core::{EthernetFrame, FrameField};
use l2_onpath::MacAddress;
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{
        Icmpv6Message, Icmpv6Packet, Icmpv6Repr, IpProtocol, Ipv6Packet, Ipv6Repr,
        NdiscNeighborFlags, NdiscOption, NdiscOptionType, NdiscRepr, RawHardwareAddress,
    },
};

use super::{NdpPlanError, NdpProbe, plan::usable_unicast};

const IPV6_LEN: usize = 40;
const SOLICIT_LEN: usize = 32;
pub(super) const REQUEST_LEN: usize = 14 + IPV6_LEN + SOLICIT_LEN;

pub(super) fn solicitation(
    source_mac: MacAddress,
    source_ip: Ipv6Addr,
    target: Ipv6Addr,
) -> Result<[u8; REQUEST_LEN], NdpPlanError> {
    let [_, _, _, _, _, _, _, _, _, _, _, _, _, a, b, c] = target.octets();
    let destination = Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        0xff00 | u16::from(a),
        u16::from_be_bytes([b, c]),
    );
    let message = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
        target_addr: target,
        lladdr: Some(RawHardwareAddress::from_bytes(source_mac.as_bytes())),
    });
    let header = Ipv6Repr {
        src_addr: source_ip,
        dst_addr: destination,
        next_header: IpProtocol::Icmpv6,
        payload_len: SOLICIT_LEN,
        hop_limit: 255,
    };
    let mut payload = [0_u8; IPV6_LEN + SOLICIT_LEN];
    // The fixed buffers have exactly the lengths required by smoltcp's emitters
    let mut ipv6 = Ipv6Packet::new_unchecked(&mut payload[..]);
    header.emit(&mut ipv6);
    let mut icmp = Icmpv6Packet::new_unchecked(ipv6.payload_mut());
    message.emit(
        &source_ip,
        &destination,
        &mut icmp,
        &ChecksumCapabilities::default(),
    );
    let ethernet = EthernetFrame {
        destination: [0x33, 0x33, 0xff, a, b, c],
        source: source_mac.bytes(),
        vlan_tags: Vec::new(),
        field: FrameField::EtherType(0x86dd),
        payload: &payload,
        padding: &[],
    };
    let mut frame = [0; REQUEST_LEN];
    l2_core::encode(&ethernet, &mut frame).map_err(NdpPlanError::Encode)?;
    Ok(frame)
}

pub(super) fn advertisement(probe: &NdpProbe, bytes: &[u8]) -> Option<(MacAddress, Ipv6Addr)> {
    let ethernet = scoped_ethernet(probe, bytes)?;
    let ip = scoped_ipv6(probe, ethernet.payload)?;
    let icmp = scoped_advertisement(probe, &ip)?;
    let mac = target_mac(icmp.payload())?;
    (mac.bytes() == ethernet.source).then_some((mac, ip.src_addr()))
}

fn scoped_ethernet<'a>(probe: &NdpProbe, bytes: &'a [u8]) -> Option<EthernetFrame<'a>> {
    let ethernet = l2_core::decode(bytes).ok()?;
    if !ethernet.vlan_tags.is_empty()
        || ethernet.field != FrameField::EtherType(0x86dd)
        || ethernet.destination != probe.source_mac.bytes()
    {
        return None;
    }
    Some(ethernet)
}

fn scoped_ipv6<'a>(probe: &NdpProbe, bytes: &'a [u8]) -> Option<Ipv6Packet<&'a [u8]>> {
    let ip = Ipv6Packet::new_checked(bytes).ok()?;
    if ip.version() != 6
        || ip.next_header() != IpProtocol::Icmpv6
        || ip.hop_limit() != 255
        || ip.dst_addr() != probe.source_ip
        || !usable_unicast(ip.src_addr())
    {
        return None;
    }
    Some(ip)
}

fn scoped_advertisement<'a>(
    probe: &NdpProbe,
    ip: &Ipv6Packet<&'a [u8]>,
) -> Option<Icmpv6Packet<&'a [u8]>> {
    let icmp = Icmpv6Packet::new_checked(ip.payload()).ok()?;
    if icmp.msg_type() != Icmpv6Message::NeighborAdvert
        || icmp.msg_code() != 0
        || !icmp.verify_checksum(&ip.src_addr(), &ip.dst_addr())
        || icmp.target_addr() != probe.target
        || !icmp
            .neighbor_flags()
            .contains(NdiscNeighborFlags::SOLICITED)
    {
        return None;
    }
    Some(icmp)
}

fn target_mac(mut options: &[u8]) -> Option<MacAddress> {
    let mut found = None;
    while !options.is_empty() {
        // The checked option rejects zero lengths and incomplete option bytes
        let option = NdiscOption::new_checked(options).ok()?;
        let length = usize::from(option.data_len()) * 8;
        if option.option_type() == NdiscOptionType::TargetLinkLayerAddr {
            if option.data_len() != 1 || found.is_some() {
                return None;
            }
            let address = option.link_layer_addr();
            let bytes: [u8; 6] = address.as_bytes().try_into().ok()?;
            found = Some(MacAddress::new(bytes).ok()?);
        }
        options = options.get(length..)?;
    }
    found
}
