use std::error::Error;

use l2_active_linux::VlanProtocol;
use l2_capture::LinuxInterfaceIdentity;

use super::{IdentityView, InterfaceView, VlanView, protocol_name};

#[test]
fn vlan_scope_renders_its_immediate_parent_and_sampled_validation() -> Result<(), Box<dyn Error>> {
    let selected = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let parent = LinuxInterfaceIdentity::new(1, 2, 6, 7, 8)?;
    let view = InterfaceView {
        interface: "vlan37",
        identity: IdentityView::new(selected),
        vlan: Some(VlanView {
            id: 37,
            protocol: protocol_name(VlanProtocol::Ieee8021Ad),
            parent: IdentityView::new(parent),
            reorders_headers: true,
        }),
        scope_validation: "sampled",
    };
    let value = serde_json::to_value(&view)?;
    assert_eq!(
        value,
        serde_json::json!({
            "interface": "vlan37", "ifindex": 5, "namespace_device": 1,
            "namespace_inode": 2, "interface_device": 3, "interface_inode": 4,
            "vlan": {
                "id": 37, "protocol": "802.1ad", "reorders_headers": true,
                "parent": { "ifindex": 8, "namespace_device": 1, "namespace_inode": 2,
                    "interface_device": 6, "interface_inode": 7 },
            },
            "scope_validation": "sampled",
        })
    );
    let mut text = Vec::new();
    view.write_text(&mut text)?;
    let text = String::from_utf8(text)?;
    assert!(text.contains("VLAN: ID 37  protocol 802.1ad  parent index 8"));
    assert!(text.contains("Scope validation: sampled"));
    assert_eq!(protocol_name(VlanProtocol::Ieee8021Q), "802.1Q");
    Ok(())
}

#[test]
fn non_vlan_scope_does_not_derive_topology_from_its_name() -> Result<(), Box<dyn Error>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let view = InterfaceView::new("eth0.37", identity, None);
    let value = serde_json::to_value(&view)?;
    assert_eq!(value.get("vlan"), Some(&serde_json::Value::Null));
    assert_eq!(
        value
            .get("scope_validation")
            .and_then(serde_json::Value::as_str),
        Some("sampled")
    );
    let mut text = Vec::new();
    view.write_text(&mut text)?;
    assert!(String::from_utf8(text)?.contains("VLAN: none on selected interface"));
    Ok(())
}
