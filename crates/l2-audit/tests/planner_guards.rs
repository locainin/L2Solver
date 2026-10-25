use l2_audit::{
    BridgeIdentity, Capability, CheckCategory, FingerprintStatus, InterfaceObservation,
    MAX_AGENT_COUNT, Neighbor, PlannerError, PlannerInput, Policy, Protocol, ProtocolObservation,
    StpObservation, plan_passive,
};
use l2_capture::InterfaceId;

fn interface_with_protocol_facts() -> InterfaceObservation {
    InterfaceObservation {
        section: 1,
        index: 2,
        frames: 3,
        macs: Vec::new(),
        vlans: Vec::new(),
        untagged_packet: None,
        neighbors: vec![Neighbor {
            chassis_id: vec![1],
            port_id: vec![2],
            system_name: vec![3],
            packet: 10,
        }],
        protocols: vec![
            ProtocolObservation {
                protocol: Protocol::Arp,
                status: FingerprintStatus::Observed,
                frames: 1,
                packet: 11,
            },
            ProtocolObservation {
                protocol: Protocol::Cdp,
                status: FingerprintStatus::Unsupported,
                frames: 1,
                packet: 12,
            },
            ProtocolObservation {
                protocol: Protocol::Vrrp,
                status: FingerprintStatus::Malformed,
                frames: 1,
                packet: 13,
            },
        ],
        identities: Vec::new(),
        stp_frames: 1,
        stp_packet: Some(14),
        stp: Vec::new(),
    }
}

#[test]
fn planner_input_usable_protocol_statuses() {
    let input = PlannerInput::from_interfaces(&[interface_with_protocol_facts()]);

    assert!(input.protocols().contains(&Protocol::Arp));
    assert!(!input.protocols().contains(&Protocol::Cdp));
    assert!(input.protocols().contains(&Protocol::Lldp));
    assert!(input.protocols().contains(&Protocol::Stp));
    assert!(!input.protocols().contains(&Protocol::Vrrp));
    assert!(input.capabilities().contains(&Capability::PassiveCapture));
    assert_eq!(input.agent_count(), 0);
    assert!(input.capture_available());
    assert!(!input.stp_root_advertisement());

    let mut no_stp = interface_with_protocol_facts();
    no_stp.neighbors.clear();
    no_stp.stp_frames = 0;
    assert!(
        !PlannerInput::from_interfaces(&[no_stp])
            .protocols()
            .contains(&Protocol::Stp)
    );

    let mut stp_history = interface_with_protocol_facts();
    stp_history.neighbors.clear();
    stp_history.stp_frames = 0;
    stp_history.stp.push(StpObservation {
        root: BridgeIdentity {
            priority: 0,
            system_id_extension: 0,
            mac: String::from("00:11:22:33:44:55"),
        },
        version: String::from("Stp"),
        packet: 15,
        frames: 1,
    });
    let history_input = PlannerInput::from_interfaces(&[stp_history]);
    assert!(history_input.protocols().contains(&Protocol::Stp));
    assert!(history_input.stp_root_advertisement());
    assert!(history_input.has_stp_root_advertisement(InterfaceId {
        section: 1,
        index: 2,
    }));
    assert!(!history_input.has_stp_root_advertisement(InterfaceId {
        section: 1,
        index: 3,
    }));
}

#[test]
fn planner_input_preserves_state() -> Result<(), PlannerError> {
    let input = PlannerInput::new()
        .with_protocol(Protocol::Arp)
        .with_capability(Capability::ActiveTransmit)
        .with_capture_available(false)
        .with_agent_count(MAX_AGENT_COUNT)?;

    assert!(input.protocols().contains(&Protocol::Arp));
    assert!(input.capabilities().contains(&Capability::ActiveTransmit));
    assert_eq!(input.agent_count(), MAX_AGENT_COUNT);
    assert!(!input.capture_available());
    let root_input = PlannerInput::new().with_stp_root_advertisement();
    assert!(root_input.protocols().contains(&Protocol::Stp));
    assert!(root_input.stp_root_advertisement());
    assert!(matches!(
        PlannerInput::new().with_agent_count(MAX_AGENT_COUNT + 1),
        Err(PlannerError::AgentCountExceeded { count, maximum })
            if count == MAX_AGENT_COUNT + 1 && maximum == MAX_AGENT_COUNT
    ));
    let error = PlannerInput::new()
        .with_agent_count(MAX_AGENT_COUNT + 1)
        .err()
        .map(|error| error.to_string());
    assert_eq!(
        error.as_deref(),
        Some("agent count 65 exceeds planner maximum 64")
    );
    Ok(())
}

#[test]
fn check_names_plan_lookup_stable() {
    let categories = [
        (CheckCategory::AccessControl, "Access control"),
        (CheckCategory::Aggregation, "Link aggregation"),
        (CheckCategory::ArpProtection, "ARP protections"),
        (CheckCategory::BroadcastHygiene, "Broadcast hygiene"),
        (CheckCategory::DhcpProtection, "DHCP protections"),
        (CheckCategory::FirstHopRedundancy, "First-hop redundancy"),
        (CheckCategory::Ipv6Protection, "IPv6 protections"),
        (CheckCategory::LinkSecurity, "Link security"),
        (CheckCategory::Multicast, "Multicast controls"),
        (CheckCategory::NeighborDiscovery, "Neighbor discovery"),
        (CheckCategory::Resilience, "Resource controls"),
        (CheckCategory::Segmentation, "Segmentation"),
        (CheckCategory::SpanningTree, "Spanning tree"),
        (CheckCategory::Trunking, "Trunking"),
        (CheckCategory::Vlan, "VLAN policy"),
    ];
    for (category, name) in categories {
        assert_eq!(category.as_str(), name);
        assert_eq!(category.to_string(), name);
    }

    let plan = plan_passive(&PlannerInput::new(), &Policy::default());
    assert_eq!(
        plan.entries
            .first()
            .and_then(|first| plan.entry(&first.check_id)),
        plan.entries.first()
    );
    assert!(plan.entry("missing-check").is_none());
}
