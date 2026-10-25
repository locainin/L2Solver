use l2_core::{EthernetFrame, FrameField, VlanTag};
use l2_discovery::{FingerprintStatus, IdentityRole, NetworkAddress, Protocol, discover};

const OUTER_SOURCE: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

const fn ethernet(field: FrameField, payload: &[u8]) -> EthernetFrame<'_> {
    EthernetFrame {
        destination: [0xff; 6],
        source: OUTER_SOURCE,
        vlan_tags: Vec::<VlanTag>::new(),
        payload,
        padding: &[],
        field,
    }
}

fn ipv4_udp(source_port: u16, destination_port: u16, body: &[u8]) -> Vec<u8> {
    let udp_length = u16::try_from(8 + body.len()).unwrap_or(u16::MAX);
    let total_length = 20_u16.saturating_add(udp_length);
    let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0];
    packet.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
    if let Some(field) = packet.get_mut(2..4) {
        field.copy_from_slice(&total_length.to_be_bytes());
    }
    packet.extend_from_slice(&source_port.to_be_bytes());
    packet.extend_from_slice(&destination_port.to_be_bytes());
    packet.extend_from_slice(&udp_length.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(body);
    packet
}

fn dhcp_payload() -> Vec<u8> {
    let mut payload = vec![0; 236];
    payload.extend_from_slice(&[0x63, 0x82, 0x53, 0x63, 53, 1, 2, 255]);
    payload
}

#[test]
fn separates_arp_source_and_claim() -> Result<(), Box<dyn std::error::Error>> {
    let mut payload = vec![0, 1, 0x08, 0, 6, 4, 0, 2];
    payload.extend_from_slice(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    payload.extend_from_slice(&[192, 0, 2, 7]);
    payload.extend_from_slice(&[0; 6]);
    payload.extend_from_slice(&[192, 0, 2, 1]);

    let result = discover(&ethernet(FrameField::EtherType(0x0806), &payload))
        .ok_or("missing ARP discovery")?;
    let identity = result.identity.ok_or("missing ARP identity")?;

    assert_eq!(result.fingerprint.protocol, Protocol::Arp);
    assert_eq!(identity.role, IdentityRole::AddressClaim);
    assert_eq!(identity.source_mac, OUTER_SOURCE);
    assert_eq!(
        identity.claimed_mac,
        Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
    );
    assert_eq!(identity.address, Some(NetworkAddress::Ipv4([192, 0, 2, 7])));
    Ok(())
}

#[test]
fn arp_probe_without_zero_address() -> Result<(), Box<dyn std::error::Error>> {
    let mut payload = vec![0, 1, 0x08, 0, 6, 4, 0, 1];
    payload.extend_from_slice(&OUTER_SOURCE);
    payload.extend_from_slice(&[0; 4]);
    payload.extend_from_slice(&[0; 6]);
    payload.extend_from_slice(&[192, 0, 2, 7]);
    let result = discover(&ethernet(FrameField::EtherType(0x0806), &payload))
        .ok_or("missing ARP discovery")?;
    let identity = result.identity.ok_or("missing probe identity")?;
    assert_eq!(identity.role, IdentityRole::AddressProbe);
    assert_eq!(identity.claimed_mac, Some(OUTER_SOURCE));
    assert_eq!(identity.address, None);
    Ok(())
}

#[test]
fn arp_identity_fixed_header_field() -> Result<(), Box<dyn std::error::Error>> {
    let mut valid = vec![0, 1, 0x08, 0, 6, 4, 0, 2];
    valid.extend_from_slice(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    valid.extend_from_slice(&[192, 0, 2, 7]);
    valid.extend_from_slice(&[0; 6]);
    valid.extend_from_slice(&[192, 0, 2, 1]);

    // Change exactly one ARP identity field at a time
    for (offset, value) in [(1, 2), (2, 0x86), (4, 5), (5, 3), (7, 3)] {
        let mut changed = valid.clone();
        if let Some(byte) = changed.get_mut(offset) {
            *byte = value;
        }
        let result = discover(&ethernet(FrameField::EtherType(0x0806), &changed))
            .ok_or("the ARP envelope lost its structural fingerprint")?;
        assert_eq!(result.fingerprint.status, FingerprintStatus::Observed);
        assert_eq!(result.identity, None);
    }
    Ok(())
}

#[test]
fn dhcp_server_ipv4_source_retained() -> Result<(), Box<dyn std::error::Error>> {
    let packet = ipv4_udp(67, 68, &dhcp_payload());
    let result = discover(&ethernet(FrameField::EtherType(0x0800), &packet))
        .ok_or("missing DHCP discovery")?;
    let identity = result.identity.ok_or("missing DHCP identity")?;

    assert_eq!(identity.role, IdentityRole::DhcpServer);
    assert_eq!(identity.address, Some(NetworkAddress::Ipv4([192, 0, 2, 1])));

    // The client port maps to the complementary DHCP identity role
    let packet = ipv4_udp(68, 67, &dhcp_payload());
    let result = discover(&ethernet(FrameField::EtherType(0x0800), &packet))
        .ok_or("missing DHCP client discovery")?;
    let identity = result.identity.ok_or("missing DHCP client identity")?;
    assert_eq!(identity.role, IdentityRole::DhcpClient);
    Ok(())
}

#[test]
fn retains_router_advertisement_source() -> Result<(), Box<dyn std::error::Error>> {
    let mut packet = vec![0x60, 0, 0, 0, 0, 16, 58, 255];
    packet.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    packet.extend_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    packet.extend_from_slice(&[134, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    let result = discover(&ethernet(FrameField::EtherType(0x86dd), &packet))
        .ok_or("missing RA discovery")?;
    let identity = result.identity.ok_or("missing router identity")?;

    assert_eq!(identity.role, IdentityRole::Ipv6Router);
    assert_eq!(
        identity.address,
        Some(NetworkAddress::Ipv6([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]))
    );
    Ok(())
}

#[test]
fn uses_observed_outer_source() -> Result<(), Box<dyn std::error::Error>> {
    let payload = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x04];
    let result =
        discover(&ethernet(FrameField::Length(8), &payload)).ok_or("missing DTP discovery")?;
    let identity = result.identity.ok_or("missing control identity")?;

    assert_eq!(identity.role, IdentityRole::ControlPlaneParticipant);
    assert_eq!(identity.source_mac, OUTER_SOURCE);
    assert_eq!(identity.claimed_mac, None);
    assert_eq!(identity.address, None);
    Ok(())
}

#[test]
fn malformed_protocols_produce_no_identity() -> Result<(), Box<dyn std::error::Error>> {
    for payload in [&[0_u8; 0][..], &[2, 0, 0, 4, 1][..]] {
        let result = discover(&ethernet(FrameField::EtherType(0x888e), payload))
            .ok_or("missing EAPOL fingerprint")?;
        assert!(matches!(
            result.fingerprint.status,
            FingerprintStatus::Malformed | FingerprintStatus::Truncated
        ));
        assert_eq!(result.identity, None);
    }
    Ok(())
}
