use l2_codecs::{BridgeId, PortId, PortRole, StpFlags};

#[test]
fn preserves_bridge_identity_fields() {
    let bridge = BridgeId::from_wire(0xa123, [1, 2, 3, 4, 5, 6]);

    assert_eq!(bridge.priority, 0xa000);
    assert_eq!(bridge.system_id_extension, 0x0123);
    assert_eq!(bridge.wire_priority_and_extension(), 0xa123);
    assert_eq!(bridge.mac, [1, 2, 3, 4, 5, 6]);
}

#[test]
fn bridge_id_reconstruction_preserves_fields() {
    let bridge = BridgeId {
        priority: 0x0f00,
        system_id_extension: 0x0ff0,
        mac: [0; 6],
    };

    assert_eq!(bridge.wire_priority_and_extension(), 0x0ff0);
}

#[test]
fn port_id_extract_wire_field() {
    let port = PortId::from_wire(0xa123);

    assert_eq!(port.raw, 0xa123);
    assert_eq!(port.priority(), 0x0a);
    assert_eq!(port.number(), 0x0123);
}

#[test]
fn rstp_flag_getter_bit() {
    let no_flags = StpFlags::from_wire(0);
    assert!(!no_flags.topology_change());
    assert!(!no_flags.proposal());
    assert!(!no_flags.learning());
    assert!(!no_flags.forwarding());
    assert!(!no_flags.agreement());
    assert!(!no_flags.topology_change_ack());

    let all_flags = StpFlags::from_wire(0xff);
    assert!(all_flags.topology_change());
    assert!(all_flags.proposal());
    assert!(all_flags.learning());
    assert!(all_flags.forwarding());
    assert!(all_flags.agreement());
    assert!(all_flags.topology_change_ack());
}

#[test]
fn decodes_all_rstp_port_roles() {
    assert_eq!(
        StpFlags::from_wire(0x04).port_role(),
        PortRole::AlternateBackup
    );
    assert_eq!(StpFlags::from_wire(0x08).port_role(), PortRole::Root);
    assert_eq!(StpFlags::from_wire(0x0c).port_role(), PortRole::Designated);
    assert_eq!(StpFlags::from_wire(0x00).port_role(), PortRole::Unknown);
}
