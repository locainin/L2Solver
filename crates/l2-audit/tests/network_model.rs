use l2_audit::{
    FingerprintStatus, InterfaceObservation, Policy, ProtocolIdentityObservation,
    ProtocolObservation, Quality, Severity, assess, build_network_model, catalog,
};
use l2_discovery::{IdentityRole, NetworkAddress, Protocol};

const fn interface(section: u32, index: u32) -> InterfaceObservation {
    InterfaceObservation {
        section,
        index,
        frames: 10,
        macs: Vec::new(),
        vlans: Vec::new(),
        untagged_packet: None,
        neighbors: Vec::new(),
        protocols: Vec::new(),
        identities: Vec::new(),
        stp_frames: 0,
        stp_packet: None,
        stp: Vec::new(),
    }
}

fn identity(
    protocol: Protocol,
    role: IdentityRole,
    source_mac: &str,
    claimed_mac: Option<&str>,
    address: Option<NetworkAddress>,
    vlan_tags: Vec<(u16, u16)>,
    packet: u64,
) -> ProtocolIdentityObservation {
    ProtocolIdentityObservation {
        protocol,
        role,
        source_mac: source_mac.into(),
        claimed_mac: claimed_mac.map(str::to_owned),
        address,
        vlan_tags,
        vlan_aux: None,
        frames: 1,
        packet,
    }
}

#[test]
fn network_nodes_merge_within_interface() {
    let mut first = interface(0, 1);
    first.identities.extend([
        identity(
            Protocol::Eapol,
            IdentityRole::AccessControlParticipant,
            "02:00:00:00:00:01",
            None,
            None,
            Vec::new(),
            2,
        ),
        identity(
            Protocol::Dhcp,
            IdentityRole::DhcpClient,
            "02:00:00:00:00:01",
            None,
            Some(NetworkAddress::Ipv4([0, 0, 0, 0])),
            Vec::new(),
            3,
        ),
    ]);
    let mut second = interface(0, 2);
    second.identities.push(identity(
        Protocol::Eapol,
        IdentityRole::AccessControlParticipant,
        "02:00:00:00:00:01",
        None,
        None,
        Vec::new(),
        4,
    ));

    let model = build_network_model(&[second, first]);

    assert_eq!(model.nodes.len(), 2);
    let first_node = model.nodes.first().ok_or("missing first node");
    assert!(first_node.is_ok());
    if let Ok(first_node) = first_node {
        assert_eq!((first_node.section, first_node.interface), (0, 1));
        assert_eq!(first_node.protocols, vec![Protocol::Eapol, Protocol::Dhcp]);
        assert_eq!(first_node.evidence_packets, vec![2, 3]);
    }
}

#[test]
fn arp_conflicts_require_matching_context() {
    let address = NetworkAddress::Ipv4([192, 0, 2, 1]);
    let mut observed = interface(3, 7);
    observed.identities.extend([
        identity(
            Protocol::Arp,
            IdentityRole::AddressClaim,
            "02:00:00:00:00:01",
            Some("00:11:22:33:44:55"),
            Some(address),
            vec![(0x8100, 20)],
            10,
        ),
        identity(
            Protocol::Arp,
            IdentityRole::AddressClaim,
            "02:00:00:00:00:02",
            Some("00:11:22:33:44:66"),
            Some(address),
            vec![(0x8100, 20)],
            11,
        ),
        identity(
            Protocol::Arp,
            IdentityRole::AddressClaim,
            "02:00:00:00:00:03",
            Some("00:11:22:33:44:77"),
            Some(address),
            vec![(0x8100, 30)],
            12,
        ),
    ]);

    let model = build_network_model(&[observed]);

    assert_eq!(model.address_conflicts.len(), 1);
    let conflict = model.address_conflicts.first().ok_or("missing conflict");
    assert!(conflict.is_ok());
    if let Ok(conflict) = conflict {
        assert_eq!(conflict.address, address);
        assert_eq!(conflict.vlan_tags, vec![(0x8100, 20)]);
        assert_eq!(
            conflict.claimed_macs,
            vec!["00:11:22:33:44:55", "00:11:22:33:44:66"]
        );
        assert_eq!(conflict.evidence_packets, vec![10, 11]);
    }
}

#[test]
fn arp_conflicts_per_vid() {
    let mut observed = interface(0, 0);
    for (mac, tags, packet) in [
        ("02:00:00:00:00:01", vec![(0x8100, 20)], 1),
        ("02:00:00:00:00:02", vec![(0x8100, 0xb014)], 2),
    ] {
        observed.identities.push(identity(
            Protocol::Arp,
            IdentityRole::AddressClaim,
            mac,
            Some(mac),
            Some(NetworkAddress::Ipv4([192, 0, 2, 1])),
            tags,
            packet,
        ));
    }
    let model = build_network_model(&[observed]);
    assert_eq!(model.address_conflicts.len(), 1);
    assert_eq!(
        model
            .address_conflicts
            .first()
            .map(|conflict| conflict.evidence_packets.as_slice()),
        Some([1, 2].as_slice())
    );
}

#[test]
fn reports_arp_and_dhcp_exposures() -> Result<(), Box<dyn std::error::Error>> {
    let mut observed = interface(0, 0);
    let address = NetworkAddress::Ipv4([192, 0, 2, 1]);
    observed.identities.extend([
        identity(
            Protocol::Arp,
            IdentityRole::AddressClaim,
            "02:00:00:00:00:01",
            Some("00:11:22:33:44:55"),
            Some(address),
            Vec::new(),
            1,
        ),
        identity(
            Protocol::Arp,
            IdentityRole::AddressClaim,
            "02:00:00:00:00:02",
            Some("00:11:22:33:44:66"),
            Some(address),
            Vec::new(),
            2,
        ),
        identity(
            Protocol::Dhcp,
            IdentityRole::DhcpServer,
            "02:00:00:00:00:03",
            None,
            Some(NetworkAddress::Ipv4([192, 0, 2, 2])),
            Vec::new(),
            3,
        ),
        identity(
            Protocol::Dhcp,
            IdentityRole::DhcpServer,
            "02:00:00:00:00:04",
            None,
            Some(NetworkAddress::Ipv4([192, 0, 2, 3])),
            Vec::new(),
            4,
        ),
    ]);
    observed.protocols.extend([
        ProtocolObservation {
            protocol: Protocol::Arp,
            status: FingerprintStatus::Observed,
            frames: 2,
            packet: 1,
        },
        ProtocolObservation {
            protocol: Protocol::Dhcp,
            status: FingerprintStatus::Observed,
            frames: 2,
            packet: 3,
        },
    ]);

    let assessment = assess(&[observed], &Policy::default(), &Quality::default())?;

    assert!(assessment.findings.is_empty());
    assert!(assessment.exposures.iter().any(|exposure| {
        exposure.check_id == "ARP-CONFLICT-001"
            && exposure.severity == Severity::Medium
            && exposure.evidence_packets == [1, 2]
    }));
    assert!(assessment.exposures.iter().any(|exposure| {
        exposure.check_id == "DHCP-MULTIPLE-001"
            && exposure.severity == Severity::Low
            && exposure.evidence_packets == [3, 4]
    }));
    for exposure in assessment.exposures {
        assert!(
            catalog()
                .iter()
                .any(|descriptor| descriptor.id == exposure.check_id),
            "unregistered exposure identifier {}",
            exposure.check_id
        );
    }
    Ok(())
}
