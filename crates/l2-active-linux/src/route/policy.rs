//! Conservative interpretation of a resolved kernel route

use std::io;

use netlink_packet_route::{
    AddressFamily,
    route::{
        RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteProtocol, RouteScope,
        RouteType,
    },
};

use super::RouteQuery;

pub(super) fn validate_route(route: &RouteMessage, query: RouteQuery) -> io::Result<()> {
    if route.header.address_family != AddressFamily::Inet6
        || route.header.destination_prefix_length != 128
        || route.header.source_prefix_length > 128
        || route.header.kind != RouteType::Unicast
        || !matches!(route.header.scope, RouteScope::Universe | RouteScope::Link)
        || matches!(route.header.protocol, RouteProtocol::Other(_))
    {
        return Err(unsupported(
            "resolved route is not a supported IPv6 unicast route",
        ));
    }
    let allowed = RouteFlags::Cloned
        | RouteFlags::LookupTable
        | RouteFlags::Onlink
        | RouteFlags::Offload
        | RouteFlags::RtOffload;
    if !(route.header.flags - allowed).is_empty() {
        return Err(unsupported(
            "resolved route has unsupported or unusable flags",
        ));
    }
    let mut destination = None;
    let mut output = None;
    let mut source = None;
    for attribute in &route.attributes {
        match attribute {
            RouteAttribute::Destination(RouteAddress::Inet6(address))
                if destination.replace(*address).is_none() => {}
            RouteAttribute::Source(RouteAddress::Inet6(address))
                if source.replace(*address).is_none() => {}
            RouteAttribute::Oif(index) if output.replace(*index).is_none() => {}
            RouteAttribute::PrefSource(RouteAddress::Inet6(_))
            | RouteAttribute::CacheInfo(_)
            | RouteAttribute::Priority(_)
            | RouteAttribute::Table(_)
            | RouteAttribute::Preference(_)
            | RouteAttribute::Expires(_)
            | RouteAttribute::Uid(_)
            | RouteAttribute::Metrics(_) => {}
            // Gateways, next-hop objects, encapsulation and unknown attributes are not direct proof
            _ => {
                return Err(unsupported(
                    "resolved route contains indirect, duplicate, or unsupported attributes",
                ));
            }
        }
    }
    if destination != Some(query.target)
        || output != Some(query.ifindex)
        || (route.header.source_prefix_length != 0 && source.is_none())
        || source.is_some_and(|address| address != query.source)
    {
        return Err(unsupported(
            "resolved route does not match the requested source, target, and interface",
        ));
    }
    Ok(())
}

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
