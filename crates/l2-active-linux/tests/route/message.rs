use std::{error::Error, io, net::Ipv6Addr, num::NonZeroI32};

use netlink_packet_core::{ErrorMessage, NLM_F_MULTIPART, NetlinkMessage, NetlinkPayload};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType},
};
use netlink_sys::SocketAddr;

use super::RouteQuery;

fn parse_reply(
    bytes: &[u8],
    peer: SocketAddr,
    sequence: u32,
    port: u32,
    query: RouteQuery,
) -> io::Result<()> {
    crate::netlink::validate_reply(bytes, peer, sequence, port)?;
    super::message::parse_reply(bytes, query)
}

fn response(query: RouteQuery, sequence: u32, port: u32) -> Vec<u8> {
    let mut route = RouteMessage::default();
    route.header.address_family = AddressFamily::Inet6;
    route.header.destination_prefix_length = 128;
    route.header.protocol = RouteProtocol::Kernel;
    route.header.scope = RouteScope::Universe;
    route.header.kind = RouteType::Unicast;
    route.attributes = vec![
        RouteAttribute::Destination(RouteAddress::Inet6(query.target)),
        RouteAttribute::Oif(query.ifindex),
    ];
    let mut packet = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(route));
    packet.header.sequence_number = sequence;
    packet.header.port_number = port;
    packet.finalize();
    let mut bytes = vec![0; packet.buffer_len()];
    packet.serialize(&mut bytes);
    bytes
}

#[test]
fn accepts_one_matching_kernel_route_response() -> Result<(), Box<dyn Error>> {
    let query = RouteQuery {
        source: "2001:db8:1::1".parse::<Ipv6Addr>()?,
        target: "2001:db8:1::2".parse()?,
        ifindex: 2,
    };
    let bytes = response(query, 7, 11);
    assert!(parse_reply(&bytes, SocketAddr::new(0, 0), 7, 11, query).is_ok());
    Ok(())
}

#[test]
fn rejects_wrong_peer_sequence_port_truncation_and_extra_data() -> Result<(), Box<dyn Error>> {
    let query = RouteQuery {
        source: "2001:db8:1::1".parse()?,
        target: "2001:db8:1::2".parse()?,
        ifindex: 2,
    };
    let bytes = response(query, 7, 11);
    assert!(parse_reply(&bytes, SocketAddr::new(8, 0), 7, 11, query).is_err());
    assert!(parse_reply(&bytes, SocketAddr::new(0, 1), 7, 11, query).is_err());
    assert!(parse_reply(&bytes, SocketAddr::new(0, 0), 8, 11, query).is_err());
    assert!(parse_reply(&bytes, SocketAddr::new(0, 0), 7, 12, query).is_err());
    for end in 0..bytes.len() {
        assert!(
            parse_reply(
                bytes.get(..end).ok_or("missing prefix")?,
                SocketAddr::new(0, 0),
                7,
                11,
                query
            )
            .is_err(),
            "truncated at {end}"
        );
    }
    let mut extra = bytes;
    extra.push(0);
    assert!(parse_reply(&extra, SocketAddr::new(0, 0), 7, 11, query).is_err());
    Ok(())
}

#[test]
fn rejects_multipart_and_non_route_messages() -> Result<(), Box<dyn Error>> {
    let query = RouteQuery {
        source: "2001:db8:1::1".parse()?,
        target: "2001:db8:1::2".parse()?,
        ifindex: 2,
    };
    let bytes = response(query, 7, 11);
    let mut packet = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&bytes)?;
    packet.header.flags = NLM_F_MULTIPART;
    packet.finalize();
    let mut encoded = vec![0; packet.buffer_len()];
    packet.serialize(&mut encoded);
    assert!(parse_reply(&encoded, SocketAddr::new(0, 0), 7, 11, query).is_err());
    packet.payload = NetlinkPayload::Noop;
    packet.finalize();
    encoded.resize(packet.buffer_len(), 0);
    packet.serialize(&mut encoded);
    assert!(parse_reply(&encoded, SocketAddr::new(0, 0), 7, 11, query).is_err());
    Ok(())
}

#[test]
fn rejects_invalid_netlink_error_codes_and_preserves_kernel_errno() -> Result<(), Box<dyn Error>> {
    let query = RouteQuery {
        source: "2001:db8:1::1".parse()?,
        target: "2001:db8:1::2".parse()?,
        ifindex: 2,
    };
    let mut packet = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&response(query, 7, 11))?;
    for code in [0, 1, i32::MIN, -nix::libc::ENETUNREACH] {
        let mut error = ErrorMessage::default();
        error.code = NonZeroI32::new(code);
        packet.payload = NetlinkPayload::Error(error);
        packet.finalize();
        let mut encoded = vec![0; packet.buffer_len()];
        packet.serialize(&mut encoded);
        let error = parse_reply(&encoded, SocketAddr::new(0, 0), 7, 11, query)
            .err()
            .ok_or("error reply was accepted")?;
        if code == -nix::libc::ENETUNREACH {
            assert_eq!(error.raw_os_error(), Some(nix::libc::ENETUNREACH));
        } else {
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }
    Ok(())
}

#[test]
fn request_names_exact_source_target_and_output_interface() -> Result<(), Box<dyn Error>> {
    let query = RouteQuery {
        source: "2001:db8:1::1".parse()?,
        target: "2001:db8:1::2".parse()?,
        ifindex: 7,
    };
    let packet = super::message::request(query, 23, 31);
    assert_eq!(packet.header.sequence_number, 23);
    assert_eq!(packet.header.port_number, 31);
    let NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetRoute(route)) = packet.payload else {
        return Err("not a route query".into());
    };
    assert_eq!(route.header.address_family, AddressFamily::Inet6);
    assert_eq!(route.header.destination_prefix_length, 128);
    assert_eq!(route.header.source_prefix_length, 128);
    assert_eq!(
        route.attributes,
        [
            RouteAttribute::Destination(RouteAddress::Inet6(query.target)),
            RouteAttribute::Source(RouteAddress::Inet6(query.source)),
            RouteAttribute::Oif(query.ifindex),
        ]
    );
    Ok(())
}
