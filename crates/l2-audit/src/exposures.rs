//! Passive surfaces and anomalies remain separate from asserted policy findings

use crate::{
    Exposure, FingerprintStatus, InterfaceObservation, NetworkModel, Protocol, Severity,
    planner::MAX_EXPOSURES,
};
use l2_discovery::IdentityRole;

struct ProtocolExposure {
    check_id: &'static str,
    title: &'static str,
    severity: Severity,
}

/// Build stable, bounded informational rows from validated passive observations
pub fn build_exposures(
    interfaces: &[InterfaceObservation],
    network_model: &NetworkModel,
) -> Vec<Exposure> {
    let mut ordered: Vec<_> = interfaces.iter().collect();
    // Capture-local ordering is normalized before bounded rows are emitted
    ordered.sort_by_key(|interface| (interface.section, interface.index));
    let mut result = Vec::new();
    for interface in ordered {
        if result.len() == MAX_EXPOSURES {
            break;
        }
        append_lldp(&mut result, interface);
        append_stp(&mut result, interface);
        append_protocols(&mut result, interface);
    }
    append_model_exposures(&mut result, network_model);
    result
}

fn append_lldp(result: &mut Vec<Exposure>, interface: &InterfaceObservation) {
    let source = format!("{}:{}", interface.section, interface.index);
    for neighbor in &interface.neighbors {
        // Capacity is checked before cloning any network-controlled identity bytes
        if result.len() == MAX_EXPOSURES {
            return;
        }
        result.push(Exposure {
            check_id: "LLDP-001".into(),
            severity: Severity::Info,
            title: "LLDP neighbor metadata is visible".into(),
            observed: format!(
                "LLDP neighbor advertised chassis {:?}, port {:?}, and system name {:?}",
                neighbor.chassis_id, neighbor.port_id, neighbor.system_name
            ),
            evidence_packets: vec![neighbor.packet],
            source_interfaces: vec![source.clone()],
            limitations: vec![
                "LLDP identity fields are unauthenticated control-plane claims".into(),
            ],
        });
    }
}

fn append_stp(result: &mut Vec<Exposure>, interface: &InterfaceObservation) {
    if result.len() == MAX_EXPOSURES {
        return;
    }
    let source = format!("{}:{}", interface.section, interface.index);
    if let Some(packet) = interface.stp_packet {
        result.push(Exposure {
            check_id: "STP-001".into(),
            severity: Severity::Info,
            title: "STP control-plane traffic is visible".into(),
            observed: format!("{} STP frame(s) observed", interface.stp_frames),
            evidence_packets: vec![packet],
            source_interfaces: vec![source.clone()],
            limitations: vec!["Passive STP visibility does not establish root protection".into()],
        });
    }
    // Root change exposure needs two retained source-scoped advertisements
    if interface.stp.len() < 2 || result.len() == MAX_EXPOSURES {
        return;
    }
    let first_packet = interface.stp.first().map(|state| state.packet);
    let last_packet = interface.stp.last().map(|state| state.packet);
    let evidence_packets = match (first_packet, last_packet) {
        (Some(first), Some(last)) if first != last => vec![first, last],
        (Some(packet), Some(_) | None) | (None, Some(packet)) => vec![packet],
        (None, None) => Vec::new(),
    };
    result.push(Exposure {
        check_id: "STP-CHANGE-001".into(),
        severity: Severity::Medium,
        title: "STP root advertisements changed during the sample".into(),
        observed: format!(
            "{} root advertisement states were observed",
            interface.stp.len()
        ),
        evidence_packets,
        source_interfaces: vec![source],
        limitations: vec![
            "Root changes can be planned maintenance; compare timestamps and topology policy"
                .into(),
        ],
    });
}

fn append_protocols(result: &mut Vec<Exposure>, interface: &InterfaceObservation) {
    let source = format!("{}:{}", interface.section, interface.index);
    for observation in &interface.protocols {
        if result.len() == MAX_EXPOSURES {
            return;
        }
        // Malformed and unsupported traffic remains a quality diagnostic
        if observation.status != FingerprintStatus::Observed {
            continue;
        }
        let Some(descriptor) = protocol_exposure(observation.protocol) else {
            continue;
        };
        result.push(Exposure {
            check_id: descriptor.check_id.into(),
            severity: descriptor.severity,
            title: descriptor.title.into(),
            observed: format!(
                "{} valid {} frame(s) were observed",
                observation.frames, observation.protocol
            ),
            evidence_packets: vec![observation.packet],
            source_interfaces: vec![source.clone()],
            limitations: vec![
                "Protocol visibility alone does not establish that an active protection is absent"
                    .into(),
            ],
        });
    }
}

const fn protocol_exposure(protocol: Protocol) -> Option<ProtocolExposure> {
    // Domain helpers keep the catalog readable without changing lookup order
    if let Some(exposure) = link_protocol_exposure(protocol) {
        return Some(exposure);
    }
    if let Some(exposure) = network_protocol_exposure(protocol) {
        return Some(exposure);
    }
    vendor_protocol_exposure(protocol)
}

const fn link_protocol_exposure(protocol: Protocol) -> Option<ProtocolExposure> {
    let (check_id, title, severity) = match protocol {
        Protocol::Eapol => (
            "DOT1X-OBS-001",
            "802.1X access-control traffic is visible",
            Severity::Info,
        ),
        Protocol::Lacp => (
            "LACP-OBS-001",
            "LACP aggregation traffic is visible",
            Severity::Info,
        ),
        Protocol::Macsec => (
            "MACSEC-OBS-001",
            "MACsec data-plane traffic is visible",
            Severity::Info,
        ),
        Protocol::Mka => (
            "MKA-OBS-001",
            "MACsec Key Agreement traffic is visible",
            Severity::Info,
        ),
        _ => return None,
    };
    Some(ProtocolExposure {
        check_id,
        title,
        severity,
    })
}

const fn network_protocol_exposure(protocol: Protocol) -> Option<ProtocolExposure> {
    let (check_id, title, severity) = match protocol {
        Protocol::Hsrp => (
            "HSRP-OBS-001",
            "HSRP first-hop redundancy traffic is visible",
            Severity::Info,
        ),
        Protocol::Vrrp => (
            "VRRP-OBS-001",
            "VRRP first-hop redundancy traffic is visible",
            Severity::Info,
        ),
        Protocol::Ipv6Ra => (
            "IPV6-RA-OBS-001",
            "IPv6 router advertisements are visible",
            Severity::Info,
        ),
        Protocol::Dhcpv6 => (
            "DHCPV6-OBS-001",
            "DHCPv6 control traffic is visible",
            Severity::Info,
        ),
        Protocol::Igmp => (
            "IGMP-OBS-001",
            "IGMP multicast control traffic is visible",
            Severity::Info,
        ),
        Protocol::Mdns => (
            "MDNS-OBS-001",
            "mDNS service-discovery traffic is visible",
            Severity::Info,
        ),
        Protocol::Ssdp => (
            "SSDP-OBS-001",
            "SSDP service-discovery traffic is visible",
            Severity::Info,
        ),
        Protocol::Netbios => (
            "NETBIOS-OBS-001",
            "NetBIOS broadcast traffic is visible",
            Severity::Low,
        ),
        _ => return None,
    };
    Some(ProtocolExposure {
        check_id,
        title,
        severity,
    })
}

const fn vendor_protocol_exposure(protocol: Protocol) -> Option<ProtocolExposure> {
    let (check_id, title, severity) = match protocol {
        Protocol::Cdp => (
            "CDP-OBS-001",
            "Cisco Discovery Protocol metadata is visible",
            Severity::Info,
        ),
        Protocol::Dtp => (
            "DTP-OBS-001",
            "Dynamic trunk negotiation traffic is visible",
            Severity::Low,
        ),
        Protocol::Vtp => (
            "VTP-OBS-001",
            "VLAN Trunking Protocol traffic is visible",
            Severity::Low,
        ),
        Protocol::Pagp => (
            "PAGP-OBS-001",
            "PAgP aggregation traffic is visible",
            Severity::Info,
        ),
        Protocol::PvstPlus => (
            "PVST-OBS-001",
            "PVST+ control-plane traffic is visible",
            Severity::Info,
        ),
        _ => return None,
    };
    Some(ProtocolExposure {
        check_id,
        title,
        severity,
    })
}

fn append_model_exposures(result: &mut Vec<Exposure>, model: &NetworkModel) {
    // Correlated conflicts are appended only after direct interface observations
    for conflict in &model.address_conflicts {
        if result.len() == MAX_EXPOSURES {
            return;
        }
        result.push(Exposure {
            check_id: "ARP-CONFLICT-001".into(),
            severity: Severity::Medium,
            title: "Conflicting ARP address claims were observed".into(),
            observed: format!(
                "{} was claimed by {} within VLAN context {:?}",
                conflict.address,
                conflict.claimed_macs.join(", "),
                conflict.vlan_tags
            ),
            evidence_packets: conflict.evidence_packets.clone(),
            source_interfaces: vec![format!("{}:{}", conflict.section, conflict.interface)],
            limitations: vec![
                "Passive claims may reflect legitimate redundancy or address movement and require investigation"
                    .into(),
            ],
        });
    }
    // Multiple infrastructure identities remain potential exposures until policy confirms risk
    for group in &model.infrastructure {
        if result.len() == MAX_EXPOSURES {
            return;
        }
        let descriptor = match group.role {
            IdentityRole::DhcpServer if group.source_macs.len() > 1 => Some((
                "DHCP-MULTIPLE-001",
                "Multiple DHCP server identities were observed",
                "DHCP server",
                Severity::Low,
            )),
            IdentityRole::Ipv6Router if group.source_macs.len() > 1 => Some((
                "IPV6-RA-MULTIPLE-001",
                "Multiple IPv6 router identities were observed",
                "IPv6 router",
                Severity::Low,
            )),
            IdentityRole::DhcpServer
            | IdentityRole::Ipv6Router
            | IdentityRole::FirstHopRouter
            | IdentityRole::AccessControlParticipant
            | IdentityRole::AddressClaim
            | IdentityRole::AddressProbe
            | IdentityRole::AggregationParticipant
            | IdentityRole::ControlPlaneParticipant
            | IdentityRole::DhcpClient
            | IdentityRole::Dhcpv6Participant
            | IdentityRole::Ipv6Neighbor
            | IdentityRole::LinkSecurityParticipant
            | IdentityRole::MulticastParticipant => None,
        };
        let Some((check_id, title, identity_name, severity)) = descriptor else {
            continue;
        };
        result.push(Exposure {
            check_id: check_id.into(),
            severity,
            title: title.into(),
            observed: format!(
                "{} {} source MACs were observed within VLAN context {:?}",
                group.source_macs.len(),
                identity_name,
                group.vlan_tags
            ),
            evidence_packets: group.evidence_packets.clone(),
            source_interfaces: vec![format!("{}:{}", group.section, group.interface)],
            limitations: vec![format!(
                "Multiple {identity_name} identities can be intentional; compare them with network policy"
            )],
        });
    }
}
