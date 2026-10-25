use crate::{
    Fingerprint, Protocol,
    bytes::{read_u16, take},
};

pub const UDP_HEADER_LEN: usize = 8;

const MDNS_PORT: u16 = 5353;
const SSDP_PORT: u16 = 1900;
const NETBIOS_NAME_PORT: u16 = 137;
const NETBIOS_DATAGRAM_PORT: u16 = 138;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;
const DHCPV6_CLIENT_PORT: u16 = 546;
const DHCPV6_SERVER_PORT: u16 = 547;
const HSRP_PORT_ONE: u16 = 1985;
const HSRP_PORT_TWO: u16 = 2029;

#[derive(Clone, Copy)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

/// Select only the registered UDP service ports in scope for this crate
pub const fn protocol_for_ports(
    source: u16,
    destination: u16,
    family: AddressFamily,
) -> Option<Protocol> {
    if matches!(family, AddressFamily::Ipv4)
        && ((source == DHCP_CLIENT_PORT && destination == DHCP_SERVER_PORT)
            || (source == DHCP_SERVER_PORT && destination == DHCP_CLIENT_PORT))
    {
        return Some(Protocol::Dhcp);
    }
    if matches!(family, AddressFamily::Ipv4) && is_hsrp_port(source) && is_hsrp_port(destination) {
        return Some(Protocol::Hsrp);
    }
    if matches!(family, AddressFamily::Ipv6)
        && ((source == DHCPV6_CLIENT_PORT && destination == DHCPV6_SERVER_PORT)
            || (source == DHCPV6_SERVER_PORT && destination == DHCPV6_CLIENT_PORT))
    {
        return Some(Protocol::Dhcpv6);
    }
    if source == MDNS_PORT || destination == MDNS_PORT {
        return Some(Protocol::Mdns);
    }
    if source == SSDP_PORT || destination == SSDP_PORT {
        return Some(Protocol::Ssdp);
    }
    if matches!(family, AddressFamily::Ipv4)
        && (matches!(source, NETBIOS_NAME_PORT | NETBIOS_DATAGRAM_PORT)
            || matches!(destination, NETBIOS_NAME_PORT | NETBIOS_DATAGRAM_PORT))
    {
        return Some(Protocol::Netbios);
    }
    None
}

const fn is_hsrp_port(port: u16) -> bool {
    matches!(port, HSRP_PORT_ONE | HSRP_PORT_TWO)
}

/// Check a UDP envelope while leaving service payload bytes opaque
pub fn fingerprint(
    packet: &[u8],
    offset: usize,
    available_end: usize,
    declared_end: usize,
    capture_truncated: bool,
    family: AddressFamily,
) -> Option<Fingerprint> {
    let payload = take(packet, offset, available_end.checked_sub(offset)?)?;
    // The port prefix can still identify a malformed short IP payload when
    // the capture includes the bytes that follow its invalid declaration.
    let captured = packet.get(offset..)?;
    let source = read_u16(captured, 0)?;
    let destination = read_u16(captured, 2)?;
    let protocol = protocol_for_ports(source, destination, family)?;
    let declared_payload_len = declared_end.checked_sub(offset)?;

    // A recognized port pair turns an undersized IP payload into a precise
    // malformed result once both port fields were available.
    if declared_payload_len < UDP_HEADER_LEN {
        return Some(Fingerprint::malformed(protocol));
    }

    let Some(declared_udp_len) = read_u16(captured, 4).map(usize::from) else {
        return Some(Fingerprint::truncated(protocol));
    };
    if declared_udp_len < UDP_HEADER_LEN {
        return Some(Fingerprint::malformed(protocol));
    }
    if declared_udp_len > payload.len() {
        return Some(Fingerprint::truncated(protocol));
    }
    if declared_udp_len < payload.len() {
        return Some(Fingerprint::malformed(protocol));
    }
    // Equal captured and declared UDP lengths still leave the outer IP packet incomplete
    if capture_truncated {
        return Some(Fingerprint::truncated(protocol));
    }
    Some(Fingerprint::observed(protocol))
}
