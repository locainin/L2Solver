use l2_audit::{
    BridgeIdentity, FingerprintStatus, InterfaceObservation, Policy, Protocol, ProtocolObservation,
    Quality, Severity, StpObservation, assess, catalog,
};
use std::error::Error;

fn interface() -> InterfaceObservation {
    InterfaceObservation {
        section: 2,
        index: 7,
        frames: 8,
        macs: vec!["00:11:22:33:44:55".into()],
        vlans: Vec::new(),
        untagged_packet: Some(1),
        neighbors: Vec::new(),
        protocols: Vec::new(),
        identities: Vec::new(),
        stp_frames: 0,
        stp_packet: None,
        stp: Vec::new(),
    }
}

const fn protocol(
    protocol: Protocol,
    status: FingerprintStatus,
    frames: u64,
    packet: u64,
) -> ProtocolObservation {
    ProtocolObservation {
        protocol,
        status,
        frames,
        packet,
    }
}

fn bridge(mac: &str) -> BridgeIdentity {
    BridgeIdentity {
        priority: 32_768,
        system_id_extension: 20,
        mac: mac.into(),
    }
}

#[test]
fn valid_protocols_become_exposures() -> Result<(), Box<dyn Error>> {
    let mut observed = interface();
    observed.protocols.extend([
        protocol(Protocol::Dtp, FingerprintStatus::Observed, 3, 2),
        protocol(Protocol::Eapol, FingerprintStatus::Observed, 2, 3),
        protocol(Protocol::Lacp, FingerprintStatus::Observed, 1, 4),
        protocol(Protocol::Ipv6Ra, FingerprintStatus::Observed, 2, 5),
    ]);

    let assessment = assess(&[observed], &Policy::default(), &Quality::default())?;

    assert!(assessment.findings.is_empty());
    for check_id in [
        "DTP-OBS-001",
        "DOT1X-OBS-001",
        "LACP-OBS-001",
        "IPV6-RA-OBS-001",
    ] {
        let exposure = assessment
            .exposures
            .iter()
            .find(|exposure| exposure.check_id == check_id);
        assert!(exposure.is_some(), "missing exposure {check_id}");
    }
    let dtp = assessment
        .exposures
        .iter()
        .find(|exposure| exposure.check_id == "DTP-OBS-001");
    assert!(dtp.is_some_and(|exposure| {
        exposure.severity == Severity::Low
            && exposure.evidence_packets == [2]
            && exposure.source_interfaces == ["2:7"]
    }));
    Ok(())
}

#[test]
fn malformed_fingerprints_remain_diagnostics() -> Result<(), Box<dyn Error>> {
    let mut observed = interface();
    observed.protocols.extend([
        protocol(Protocol::Dtp, FingerprintStatus::Malformed, 1, 2),
        protocol(Protocol::Eapol, FingerprintStatus::Truncated, 1, 3),
    ]);

    let assessment = assess(&[observed], &Policy::default(), &Quality::default())?;

    assert_eq!(assessment.exposures, [] as [l2_audit::Exposure; 0]);
    assert!(assessment.findings.is_empty());
    Ok(())
}

#[test]
fn protocol_exposures_use_canonical_ids() -> Result<(), Box<dyn Error>> {
    let mut observed = interface();
    let protocols = [
        Protocol::Eapol,
        Protocol::Lacp,
        Protocol::Macsec,
        Protocol::Hsrp,
        Protocol::Vrrp,
        Protocol::Ipv6Ra,
        Protocol::Dhcpv6,
        Protocol::Igmp,
        Protocol::Mdns,
        Protocol::Ssdp,
        Protocol::Netbios,
        Protocol::Cdp,
        Protocol::Dtp,
        Protocol::Vtp,
        Protocol::Pagp,
        Protocol::PvstPlus,
    ];
    observed.protocols = protocols
        .into_iter()
        .zip(1_u64..)
        .map(|(kind, packet)| protocol(kind, FingerprintStatus::Observed, 1, packet))
        .collect();

    let assessment = assess(&[observed], &Policy::default(), &Quality::default())?;
    assert_eq!(assessment.exposures.len(), protocols.len());
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

#[test]
fn stp_root_movement_bounded_evidence() -> Result<(), Box<dyn Error>> {
    let mut observed = interface();
    observed.stp_frames = 7;
    observed.stp_packet = Some(2);
    observed.stp.extend([
        StpObservation {
            root: bridge("00:11:22:33:44:55"),
            version: "Rstp".into(),
            packet: 2,
            frames: 4,
        },
        StpObservation {
            root: bridge("00:11:22:33:44:66"),
            version: "Rstp".into(),
            packet: 6,
            frames: 2,
        },
        StpObservation {
            root: bridge("00:11:22:33:44:55"),
            version: "Rstp".into(),
            packet: 8,
            frames: 1,
        },
    ]);

    let assessment = assess(&[observed], &Policy::default(), &Quality::default())?;
    let movement = assessment
        .exposures
        .iter()
        .find(|exposure| exposure.check_id == "STP-CHANGE-001");

    assert!(movement.is_some_and(|exposure| {
        exposure.severity == Severity::Medium
            && exposure.evidence_packets == [2, 8]
            && exposure.observed.contains("3 root advertisement states")
    }));
    assert!(assessment.findings.is_empty());
    Ok(())
}

#[test]
fn bounds_stp_change_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let mut observed = interface();
    observed.stp_frames = 2;
    observed.stp_packet = Some(4);
    observed.stp.extend([
        StpObservation {
            root: bridge("00:11:22:33:44:55"),
            version: "Rstp".into(),
            packet: 4,
            frames: 1,
        },
        StpObservation {
            root: bridge("00:11:22:33:44:66"),
            version: "Rstp".into(),
            packet: 4,
            frames: 1,
        },
    ]);
    let assessment = assess(&[observed], &Policy::default(), &Quality::default())?;
    let movement = assessment
        .exposures
        .iter()
        .find(|exposure| exposure.check_id == "STP-CHANGE-001");
    let Some(movement) = movement else {
        return Err(
            std::io::Error::other("two STP states should produce a change exposure").into(),
        );
    };
    assert_eq!(movement.evidence_packets, [4]);
    Ok(())
}

#[test]
fn deduplicates_infrastructure_identity() -> Result<(), Box<dyn Error>> {
    let mut observed = interface();
    observed
        .identities
        .push(l2_audit::ProtocolIdentityObservation {
            protocol: Protocol::Dhcp,
            role: l2_discovery::IdentityRole::DhcpServer,
            source_mac: String::from("02:00:00:00:00:01"),
            claimed_mac: None,
            address: Some(l2_discovery::NetworkAddress::Ipv4([192, 0, 2, 1])),
            vlan_tags: Vec::new(),
            vlan_aux: None,
            frames: 1,
            packet: 7,
        });
    observed
        .identities
        .push(l2_audit::ProtocolIdentityObservation {
            protocol: Protocol::Ipv6Ra,
            role: l2_discovery::IdentityRole::Ipv6Router,
            source_mac: String::from("02:00:00:00:00:02"),
            claimed_mac: None,
            address: Some(l2_discovery::NetworkAddress::Ipv6([0; 16])),
            vlan_tags: Vec::new(),
            vlan_aux: None,
            frames: 1,
            packet: 8,
        });
    observed
        .identities
        .push(l2_audit::ProtocolIdentityObservation {
            protocol: Protocol::Ipv6Ra,
            role: l2_discovery::IdentityRole::Ipv6Router,
            source_mac: String::from("02:00:00:00:00:03"),
            claimed_mac: None,
            address: Some(l2_discovery::NetworkAddress::Ipv6([1; 16])),
            vlan_tags: Vec::new(),
            vlan_aux: None,
            frames: 1,
            packet: 9,
        });
    let assessment = assess(&[observed], &Policy::default(), &Quality::default())?;
    assert!(
        assessment
            .exposures
            .iter()
            .all(|exposure| exposure.check_id != "DHCP-MULTIPLE-001")
    );
    assert!(
        assessment
            .exposures
            .iter()
            .any(|exposure| exposure.check_id == "IPV6-RA-MULTIPLE-001")
    );
    Ok(())
}

#[test]
fn ipv6_router_deduplication() -> Result<(), Box<dyn Error>> {
    let mut observed = interface();
    observed
        .identities
        .push(l2_audit::ProtocolIdentityObservation {
            protocol: Protocol::Ipv6Ra,
            role: l2_discovery::IdentityRole::Ipv6Router,
            source_mac: String::from("02:00:00:00:00:01"),
            claimed_mac: None,
            address: Some(l2_discovery::NetworkAddress::Ipv6([0; 16])),
            vlan_tags: Vec::new(),
            vlan_aux: None,
            frames: 1,
            packet: 7,
        });

    let assessment = assess(&[observed], &Policy::default(), &Quality::default())?;

    assert!(
        assessment
            .exposures
            .iter()
            .all(|exposure| exposure.check_id != "IPV6-RA-MULTIPLE-001")
    );
    Ok(())
}
