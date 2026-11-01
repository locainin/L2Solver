//! A common, sampled interface scope for active reports

use std::io::Write;

use l2_active_linux::{VlanInfo, VlanProtocol};
use l2_capture::LinuxInterfaceIdentity;
use serde::Serialize;

use super::Error;

#[cfg(test)]
#[path = "../tests/interface_view/mod.rs"]
mod tests;

#[derive(Debug, Serialize)]
pub struct InterfaceView<'a> {
    interface: &'a str,
    #[serde(flatten)]
    identity: IdentityView,
    vlan: Option<VlanView>,
    scope_validation: &'static str,
}

impl<'a> InterfaceView<'a> {
    pub fn new(name: &'a str, identity: LinuxInterfaceIdentity, vlan: Option<VlanInfo>) -> Self {
        Self {
            interface: name,
            identity: IdentityView::new(identity),
            vlan: vlan.map(VlanView::new),
            scope_validation: "sampled",
        }
    }

    #[cfg(target_os = "linux")]
    pub const fn name(&self) -> &str {
        self.interface
    }

    pub fn write_text(&self, output: &mut impl Write) -> Result<(), Error> {
        match &self.vlan {
            Some(vlan) => writeln!(
                output,
                "VLAN: ID {}  protocol {}  parent index {}  reorder headers: {}",
                vlan.id, vlan.protocol, vlan.parent.ifindex, vlan.reorders_headers
            ),
            None => writeln!(output, "VLAN: none on selected interface"),
        }
        .map_err(Error::Output)?;
        writeln!(output, "Scope validation: sampled (not continuous)").map_err(Error::Output)
    }
}

#[derive(Debug, Serialize)]
struct IdentityView {
    ifindex: u32,
    namespace_device: u64,
    namespace_inode: u64,
    interface_device: u64,
    interface_inode: u64,
}

impl IdentityView {
    const fn new(identity: LinuxInterfaceIdentity) -> Self {
        Self {
            ifindex: identity.ifindex(),
            namespace_device: identity.namespace_device(),
            namespace_inode: identity.namespace_inode(),
            interface_device: identity.interface_device(),
            interface_inode: identity.interface_inode(),
        }
    }
}

#[derive(Debug, Serialize)]
struct VlanView {
    id: u16,
    protocol: &'static str,
    parent: IdentityView,
    reorders_headers: bool,
}

impl VlanView {
    const fn new(vlan: VlanInfo) -> Self {
        Self {
            id: vlan.id(),
            protocol: protocol_name(vlan.protocol()),
            parent: IdentityView::new(vlan.parent_identity()),
            reorders_headers: vlan.reorders_headers(),
        }
    }
}

const fn protocol_name(protocol: VlanProtocol) -> &'static str {
    match protocol {
        VlanProtocol::Ieee8021Q => "802.1Q",
        VlanProtocol::Ieee8021Ad => "802.1ad",
    }
}
