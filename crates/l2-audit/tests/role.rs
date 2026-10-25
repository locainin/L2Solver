use l2_audit::{
    FingerprintStatus, InterfaceObservation, PortRole, Protocol, ProtocolObservation, Quality,
    StpObservation, VlanObservation, assess, infer_port_role,
};

const fn interface() -> InterfaceObservation {
    InterfaceObservation {
        section: 2,
        index: 7,
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

const fn protocol(
    protocol: Protocol,
    status: FingerprintStatus,
    packet: u64,
) -> ProtocolObservation {
    ProtocolObservation {
        protocol,
        status,
        frames: 1,
        packet,
    }
}

fn vlan(id: u16, packet: u64) -> VlanObservation {
    VlanObservation {
        tags: vec![(0x8100, id)],
        packet,
    }
}

#[test]
fn lacp_marks_aggregated_link() {
    let mut observed = interface();
    observed
        .protocols
        .push(protocol(Protocol::Lacp, FingerprintStatus::Observed, 41));

    let role = infer_port_role(&observed);

    assert_eq!(role.role, PortRole::AggregatedLink);
    assert_eq!(role.evidence_packets, vec![41]);
    assert!(role.reasons.iter().any(|reason| reason.contains("LACP")));
}

#[test]
fn malformed_control_cannot_infer_infrastructure() {
    let mut observed = interface();
    observed
        .protocols
        .push(protocol(Protocol::Dtp, FingerprintStatus::Malformed, 18));
    observed
        .protocols
        .push(protocol(Protocol::Vtp, FingerprintStatus::Truncated, 19));
    observed.untagged_packet = Some(20);
    observed.macs.push("02:00:00:00:00:01".into());

    let role = infer_port_role(&observed);

    assert_eq!(role.role, PortRole::EndpointAccess);
    assert_eq!(role.evidence_packets, vec![20]);
}

#[test]
fn switch_uplink_control_vlan_breadth() {
    let mut observed = interface();
    observed
        .protocols
        .push(protocol(Protocol::Dtp, FingerprintStatus::Observed, 7));
    observed
        .protocols
        .push(protocol(Protocol::Vtp, FingerprintStatus::Observed, 8));
    observed.stp_frames = 2;
    observed.stp_packet = Some(6);
    observed.vlans.extend([vlan(10, 10), vlan(20, 11)]);

    let role = infer_port_role(&observed);

    assert_eq!(role.role, PortRole::SwitchUplink);
    assert_eq!(role.evidence_packets, vec![6, 7, 8, 10, 11]);
}

#[test]
fn tagged_trunk_without_control_protocols() {
    let mut observed = interface();
    observed
        .vlans
        .extend([vlan(30, 3), vlan(10, 1), vlan(20, 2)]);

    let role = infer_port_role(&observed);

    assert_eq!(role.role, PortRole::TaggedTrunk);
    assert_eq!(role.evidence_packets, vec![1, 2, 3]);
    assert!(
        role.reasons
            .iter()
            .any(|reason| reason.contains("3 ordinary VLAN identifiers"))
    );
}

#[test]
fn multiple_source_macs_infer_endpoints() {
    let mut observed = interface();
    observed.untagged_packet = Some(50);
    for suffix in 1..=8 {
        observed.macs.push(format!("02:00:00:00:00:{suffix:02x}"));
    }

    let role = infer_port_role(&observed);

    assert_eq!(role.role, PortRole::MultiEndpoint);
    assert_eq!(role.evidence_packets, vec![50]);
}

#[test]
fn inference_is_order_independent() {
    let mut first = interface();
    first.protocols.extend([
        protocol(Protocol::Vtp, FingerprintStatus::Observed, 4),
        protocol(Protocol::Dtp, FingerprintStatus::Observed, 3),
    ]);
    first.stp_frames = 1;
    first.stp_packet = Some(2);
    first.vlans.extend([vlan(20, 6), vlan(10, 5)]);

    let mut second = interface();
    second.protocols.extend([
        protocol(Protocol::Dtp, FingerprintStatus::Observed, 3),
        protocol(Protocol::Vtp, FingerprintStatus::Observed, 4),
    ]);
    second.stp_frames = 1;
    second.stp_packet = Some(2);
    second.vlans.extend([vlan(10, 5), vlan(20, 6)]);

    assert_eq!(infer_port_role(&first), infer_port_role(&second));
}

#[test]
fn assessment_separates_roles_and_findings() -> Result<(), Box<dyn std::error::Error>> {
    let mut observed = interface();
    observed
        .protocols
        .push(protocol(Protocol::Lacp, FingerprintStatus::Observed, 91));

    let assessment = assess(
        &[observed],
        &l2_audit::Policy::default(),
        &Quality::default(),
    )?;

    assert_eq!(assessment.port_roles.len(), 1);
    assert_eq!(
        assessment.port_roles.first().map(|role| role.role),
        Some(PortRole::AggregatedLink)
    );
    assert!(assessment.findings.is_empty());
    Ok(())
}

#[test]
fn port_role_display_names_stable() {
    for (role, name) in [
        (PortRole::Unknown, "unknown"),
        (PortRole::EndpointAccess, "endpoint access candidate"),
        (PortRole::MultiEndpoint, "multi-endpoint candidate"),
        (PortRole::TaggedTrunk, "tagged trunk candidate"),
        (PortRole::SwitchUplink, "switch uplink candidate"),
        (PortRole::AggregatedLink, "aggregated link candidate"),
    ] {
        assert_eq!(role.to_string(), name);
    }
}

#[test]
fn nested_tags_explain_trunk_role() {
    let mut single = interface();
    single.untagged_packet = Some(1);
    single.macs.push(String::from("02:00:00:00:00:01"));
    single.vlans.push(vlan(10, 2));
    assert_eq!(infer_port_role(&single).role, PortRole::EndpointAccess);

    let mut nested = single;
    assert!(nested.vlans.first_mut().is_some_and(|vlan| {
        vlan.tags.push((0x88a8, 20));
        true
    }));
    let role = infer_port_role(&nested);
    assert_eq!(role.role, PortRole::TaggedTrunk);
    assert!(
        role.reasons
            .iter()
            .any(|reason| reason.contains("stacked VLAN"))
    );
}

fn infrastructure_interface() -> InterfaceObservation {
    let mut observed = interface();
    observed
        .protocols
        .push(protocol(Protocol::Dtp, FingerprintStatus::Observed, 7));
    observed.vlans.extend([vlan(10, 10), vlan(20, 11)]);
    observed
}

#[test]
fn infrastructure_roles_require_evidence() {
    let without_supporting_evidence = infer_port_role(&infrastructure_interface());
    assert_ne!(without_supporting_evidence.role, PortRole::SwitchUplink);

    let mut stp_frames = infrastructure_interface();
    stp_frames.stp_frames = 1;
    stp_frames.stp_packet = Some(6);
    assert_eq!(infer_port_role(&stp_frames).role, PortRole::SwitchUplink);

    let mut stp_history = infrastructure_interface();
    stp_history.stp.push(StpObservation {
        root: l2_audit::BridgeIdentity {
            priority: 0,
            system_id_extension: 0,
            mac: String::from("00:11:22:33:44:55"),
        },
        version: String::from("Stp"),
        packet: 6,
        frames: 1,
    });
    assert_eq!(infer_port_role(&stp_history).role, PortRole::SwitchUplink);

    let mut neighbor = infrastructure_interface();
    neighbor.neighbors.push(l2_audit::Neighbor {
        chassis_id: vec![1],
        port_id: vec![2],
        system_name: vec![3],
        packet: 12,
    });
    assert_eq!(infer_port_role(&neighbor).role, PortRole::SwitchUplink);
}

#[test]
fn endpoint_requires_small_scope_fact() {
    let mut no_untagged = interface();
    no_untagged.macs.push(String::from("02:00:00:00:00:01"));
    assert_eq!(infer_port_role(&no_untagged).role, PortRole::Unknown);

    let mut no_macs = interface();
    no_macs.untagged_packet = Some(1);
    assert_eq!(infer_port_role(&no_macs).role, PortRole::Unknown);

    let mut many_vlans = interface();
    many_vlans.untagged_packet = Some(1);
    many_vlans.macs.push(String::from("02:00:00:00:00:01"));
    many_vlans.vlans.extend([vlan(10, 2), vlan(20, 3)]);
    assert_eq!(infer_port_role(&many_vlans).role, PortRole::Unknown);

    let mut infrastructure = interface();
    infrastructure.untagged_packet = Some(1);
    infrastructure.macs.push(String::from("02:00:00:00:00:01"));
    infrastructure
        .protocols
        .push(protocol(Protocol::Dtp, FingerprintStatus::Observed, 2));
    assert_eq!(infer_port_role(&infrastructure).role, PortRole::Unknown);
}

#[test]
fn protocol_evidence_non_observed_statuses() {
    let mut observed = interface();
    observed.protocols.extend([
        protocol(Protocol::Lacp, FingerprintStatus::Observed, 41),
        protocol(Protocol::Lacp, FingerprintStatus::Malformed, 42),
    ]);

    let role = infer_port_role(&observed);
    assert_eq!(role.role, PortRole::AggregatedLink);
    assert_eq!(role.evidence_packets, vec![41]);
}
