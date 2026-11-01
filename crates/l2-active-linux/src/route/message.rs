//! Construct the one route query and reject ambiguous netlink replies

use std::io;

use netlink_packet_core::{NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    route::{RouteAddress, RouteAttribute, RouteMessage},
};

use super::{RouteQuery, policy};

pub(super) fn request(
    query: RouteQuery,
    sequence: u32,
    port: u32,
) -> NetlinkMessage<RouteNetlinkMessage> {
    let mut route = RouteMessage::default();
    route.header.address_family = AddressFamily::Inet6;
    route.header.destination_prefix_length = 128;
    route.header.source_prefix_length = 128;
    route.attributes = vec![
        RouteAttribute::Destination(RouteAddress::Inet6(query.target)),
        RouteAttribute::Source(RouteAddress::Inet6(query.source)),
        RouteAttribute::Oif(query.ifindex),
    ];
    let mut packet = NetlinkMessage::from(RouteNetlinkMessage::GetRoute(route));
    packet.header.flags = NLM_F_REQUEST;
    packet.header.sequence_number = sequence;
    packet.header.port_number = port;
    packet.finalize();
    packet
}

pub(super) fn parse_reply(bytes: &[u8], query: RouteQuery) -> io::Result<()> {
    let packet = NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes).map_err(invalid)?;
    match packet.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)) => {
            policy::validate_route(&route, query)
        }
        _ => Err(invalid("unexpected route reply type")),
    }
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
