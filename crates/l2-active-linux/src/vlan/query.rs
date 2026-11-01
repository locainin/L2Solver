//! Read one fixed interface record from the kernel

use std::{io, sync::atomic::AtomicBool, time::Instant};

use netlink_packet_core::{NLM_F_REQUEST, NetlinkMessage};
use netlink_packet_route::{RouteNetlinkMessage, link::LinkMessage};

use super::{VlanData, decode};

const MAX_REPLY_BYTES: usize = 65_536;

pub(super) fn lookup(
    index: u32,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<Option<VlanData>> {
    let bytes =
        crate::netlink::exchange(deadline, cancelled, MAX_REPLY_BYTES, |sequence, port| {
            request(index, sequence, port)
        })?;
    decode::decode_link(&bytes, index)
}

pub(super) fn request(index: u32, sequence: u32, port: u32) -> NetlinkMessage<RouteNetlinkMessage> {
    let mut link = LinkMessage::default();
    link.header.index = index;
    let mut packet = NetlinkMessage::from(RouteNetlinkMessage::GetLink(link));
    packet.header.flags = NLM_F_REQUEST;
    packet.header.sequence_number = sequence;
    packet.header.port_number = port;
    packet.finalize();
    packet
}
