use l2_audit::{InterfaceObservation, ProtocolIdentityObservation, build_network_model};
use l2_discovery::{IdentityRole, NetworkAddress, Protocol};

fn interface(identities: Vec<ProtocolIdentityObservation>) -> InterfaceObservation {
    InterfaceObservation {
        section: 0,
        index: 0,
        frames: u64::try_from(identities.len()).unwrap_or(u64::MAX),
        macs: Vec::new(),
        vlans: Vec::new(),
        untagged_packet: None,
        neighbors: Vec::new(),
        protocols: Vec::new(),
        identities,
        stp_frames: 0,
        stp_packet: None,
        stp: Vec::new(),
    }
}

const fn identity(
    protocol: Protocol,
    role: IdentityRole,
    source_mac: String,
    claimed_mac: Option<String>,
    address: Option<NetworkAddress>,
    vlan_tags: Vec<(u16, u16)>,
    packet: u64,
) -> ProtocolIdentityObservation {
    ProtocolIdentityObservation {
        protocol,
        role,
        source_mac,
        claimed_mac,
        address,
        vlan_tags,
        vlan_aux: None,
        frames: 1,
        packet,
    }
}

fn node_identities(kind: &str, count: usize) -> Vec<ProtocolIdentityObservation> {
    (0_u8..)
        .take(count)
        .map(|index| {
            let address = match kind {
                "addresses" => Some(NetworkAddress::Ipv4([192, 0, 2, index + 1])),
                _ => Some(NetworkAddress::Ipv4([192, 0, 2, 1])),
            };
            let claimed_mac = match kind {
                "claimed" => Some(format!("00:11:22:33:44:{index:02x}")),
                _ => None,
            };
            let vlan_tags = match kind {
                "vlans" => vec![(0x8100, u16::from(index) + 1)],
                _ => Vec::new(),
            };
            let packet = if kind == "evidence" {
                u64::from(index) + 1
            } else {
                1
            };
            identity(
                if matches!(kind, "vlans" | "evidence") {
                    Protocol::Eapol
                } else {
                    Protocol::Arp
                },
                if matches!(kind, "vlans" | "evidence") {
                    IdentityRole::AccessControlParticipant
                } else {
                    IdentityRole::AddressClaim
                },
                String::from("02:00:00:00:00:01"),
                claimed_mac,
                address,
                vlan_tags,
                packet,
            )
        })
        .collect()
}

#[test]
fn node_summary_marks_value_truncation() -> Result<(), Box<dyn std::error::Error>> {
    for kind in ["addresses", "claimed", "vlans", "evidence"] {
        let model = build_network_model(&[interface(node_identities(kind, 65))]);
        let node = model.nodes.first().ok_or("missing network node")?;
        assert!(node.truncated, "{kind} should mark the node truncated");
        assert!(model.truncated, "{kind} should mark the model truncated");
    }
    Ok(())
}

#[test]
fn bounded_values_capacity_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let exact = build_network_model(&[interface(node_identities("addresses", 64))]);
    assert!(!exact.nodes.first().ok_or("missing exact node")?.truncated);
    assert!(!exact.truncated);

    let over = build_network_model(&[interface(node_identities("addresses", 65))]);
    assert!(
        over.nodes
            .first()
            .ok_or("missing over-limit node")?
            .truncated
    );
    assert!(over.truncated);
    Ok(())
}

#[test]
fn arp_conflicts_require_protocol_role() {
    let address = NetworkAddress::Ipv4([192, 0, 2, 1]);
    let valid = identity(
        Protocol::Arp,
        IdentityRole::AddressClaim,
        String::from("02:00:00:00:00:01"),
        Some(String::from("00:11:22:33:44:55")),
        Some(address),
        Vec::new(),
        1,
    );
    let wrong_role = identity(
        Protocol::Arp,
        IdentityRole::DhcpClient,
        String::from("02:00:00:00:00:02"),
        Some(String::from("00:11:22:33:44:66")),
        Some(address),
        Vec::new(),
        2,
    );
    let wrong_protocol = identity(
        Protocol::Eapol,
        IdentityRole::AddressClaim,
        String::from("02:00:00:00:00:03"),
        Some(String::from("00:11:22:33:44:77")),
        Some(address),
        Vec::new(),
        3,
    );
    assert!(
        build_network_model(&[interface(vec![valid.clone(), wrong_role])])
            .address_conflicts
            .is_empty()
    );
    assert!(
        build_network_model(&[interface(vec![valid, wrong_protocol])])
            .address_conflicts
            .is_empty()
    );
}

fn infrastructure_identities(kind: &str, count: usize) -> Vec<ProtocolIdentityObservation> {
    (0_u8..)
        .take(count)
        .map(|index| {
            let source_mac = if kind == "sources" {
                format!("02:00:00:00:00:{index:02x}")
            } else {
                String::from("02:00:00:00:00:01")
            };
            let address = if kind == "addresses" {
                Some(NetworkAddress::Ipv4([198, 51, 100, index + 1]))
            } else {
                None
            };
            let packet = if kind == "evidence" {
                u64::from(index) + 1
            } else {
                1
            };
            identity(
                Protocol::Dhcp,
                IdentityRole::DhcpServer,
                source_mac,
                None,
                address,
                Vec::new(),
                packet,
            )
        })
        .collect()
}

#[test]
fn infrastructure_summary_marks_limits() -> Result<(), Box<dyn std::error::Error>> {
    for kind in ["sources", "addresses", "evidence"] {
        let model = build_network_model(&[interface(infrastructure_identities(kind, 65))]);
        let group = model
            .infrastructure
            .first()
            .ok_or("missing infrastructure group")?;
        assert!(group.truncated, "{kind} should mark the group truncated");
        assert!(model.truncated, "{kind} should mark the model truncated");
    }
    Ok(())
}

fn conflict_identities(kind: &str, count: usize) -> Vec<ProtocolIdentityObservation> {
    (0_u8..)
        .take(count)
        .map(|index| {
            let claimed_mac = if kind == "claims" {
                format!("00:11:22:33:44:{index:02x}")
            } else if index % 2 == 0 {
                String::from("00:11:22:33:44:01")
            } else {
                String::from("00:11:22:33:44:02")
            };
            identity(
                Protocol::Arp,
                IdentityRole::AddressClaim,
                format!("02:00:00:00:00:{index:02x}"),
                Some(claimed_mac),
                Some(NetworkAddress::Ipv4([203, 0, 113, 1])),
                Vec::new(),
                u64::from(index) + 1,
            )
        })
        .collect()
}

#[test]
fn conflict_summary_marks_claim_limits() -> Result<(), Box<dyn std::error::Error>> {
    for kind in ["claims", "evidence"] {
        let model = build_network_model(&[interface(conflict_identities(kind, 65))]);
        let conflict = model
            .address_conflicts
            .first()
            .ok_or("missing address conflict")?;
        assert!(
            conflict.truncated,
            "{kind} should mark the conflict truncated"
        );
        assert!(model.truncated, "{kind} should mark the model truncated");
    }
    Ok(())
}
