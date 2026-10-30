use std::{error::Error, io, net::Ipv6Addr};

use super::{RouteQuery, policy::validate_route};
use netlink_packet_route::{
    AddressFamily,
    route::{
        RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteProtocol, RouteScope,
        RouteType,
    },
};

fn query() -> Result<RouteQuery, Box<dyn Error>> {
    Ok(RouteQuery {
        source: "2001:db8:1::1".parse()?,
        target: "2001:db8:1::2".parse()?,
        ifindex: 2,
    })
}

fn direct(query: RouteQuery) -> RouteMessage {
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
    route
}

#[test]
fn accepts_a_direct_ipv6_route_for_the_exact_target_and_interface() -> Result<(), Box<dyn Error>> {
    let query = query()?;
    let mut route = direct(query);
    assert!(validate_route(&route, query).is_ok());
    route
        .attributes
        .push(RouteAttribute::Source(RouteAddress::Inet6(query.source)));
    route.header.flags = RouteFlags::Cloned;
    assert!(validate_route(&route, query).is_ok());
    Ok(())
}

#[test]
fn rejects_gateway_indirect_multipath_and_non_unicast_routes() -> Result<(), Box<dyn Error>> {
    let query = query()?;
    let mut gateway = direct(query);
    gateway
        .attributes
        .push(RouteAttribute::Gateway(RouteAddress::Inet6(
            "fe80::1".parse()?,
        )));
    let mut multipath = direct(query);
    multipath
        .attributes
        .push(RouteAttribute::MultiPath(Vec::new()));
    let mut next_hop = direct(query);
    next_hop.attributes.push(RouteAttribute::NhId(7));
    let mut local = direct(query);
    local.header.kind = RouteType::Local;
    let mut reject = direct(query);
    reject.header.kind = RouteType::BlackHole;
    for route in [&gateway, &multipath, &next_hop, &local, &reject] {
        assert_eq!(
            validate_route(route, query).err().map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported)
        );
    }
    Ok(())
}

#[test]
fn rejects_wrong_missing_or_ambiguous_target_source_and_interface() -> Result<(), Box<dyn Error>> {
    let query = query()?;
    let mut other_interface = direct(query);
    other_interface.attributes.push(RouteAttribute::Oif(3));
    let mut missing_interface = direct(query);
    missing_interface
        .attributes
        .retain(|attribute| !matches!(attribute, RouteAttribute::Oif(_)));
    let mut wrong_destination = direct(query);
    wrong_destination
        .attributes
        .retain(|attribute| !matches!(attribute, RouteAttribute::Destination(_)));
    wrong_destination
        .attributes
        .push(RouteAttribute::Destination(RouteAddress::Inet6(
            "2001:db8:2::1".parse::<Ipv6Addr>()?,
        )));
    let mut wrong_source = direct(query);
    wrong_source
        .attributes
        .push(RouteAttribute::Source(RouteAddress::Inet6(
            "2001:db8:1::99".parse()?,
        )));
    let mut absent_source = direct(query);
    absent_source.header.source_prefix_length = 128;
    let mut invalid_source_prefix = direct(query);
    invalid_source_prefix.header.source_prefix_length = 129;
    for route in [
        &other_interface,
        &missing_interface,
        &wrong_destination,
        &wrong_source,
        &absent_source,
        &invalid_source_prefix,
    ] {
        assert!(validate_route(route, query).is_err());
    }
    Ok(())
}

#[test]
fn rejects_unusable_route_state_and_unknown_attributes() -> Result<(), Box<dyn Error>> {
    let query = query()?;
    let mut dead = direct(query);
    dead.header.flags = RouteFlags::Dead;
    let mut host = direct(query);
    host.header.scope = RouteScope::Host;
    let mut unknown = direct(query);
    unknown
        .attributes
        .push(RouteAttribute::Other(netlink_packet_core::DefaultNla::new(
            0xff,
            vec![1, 2, 3, 4],
        )));
    for route in [&dead, &host, &unknown] {
        assert_eq!(
            validate_route(route, query).err().map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported)
        );
    }
    Ok(())
}
