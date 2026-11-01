//! Kernel-reported scope of a selected Linux VLAN interface

#[cfg(target_os = "linux")]
mod decode;
#[cfg(target_os = "linux")]
mod pin;
#[cfg(target_os = "linux")]
mod query;

#[cfg(target_os = "linux")]
pub use pin::{VlanPin, check_unscoped, pin};

#[cfg(all(test, target_os = "linux"))]
#[path = "../../tests/vlan/metadata.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "../../tests/vlan/pin.rs"]
mod pin_tests;

/// The encapsulation used by one Linux VLAN interface
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VlanProtocol {
    /// IEEE 802.1Q, `EtherType` 0x8100
    Ieee8021Q,
    /// IEEE 802.1ad, `EtherType` 0x88a8
    Ieee8021Ad,
}

/// A fresh kernel snapshot no longer matches the admitted VLAN scope
#[derive(Debug)]
pub struct VlanScopeChanged;

impl std::fmt::Display for VlanScopeChanged {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("selected VLAN scope changed")
    }
}

impl std::error::Error for VlanScopeChanged {}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct UnsupportedVlan(&'static str);

#[cfg(target_os = "linux")]
impl std::fmt::Display for UnsupportedVlan {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(self.0)
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for UnsupportedVlan {}

#[cfg(target_os = "linux")]
fn unsupported(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Unsupported, UnsupportedVlan(message))
}

/// One VLAN layer and its immediate parent in the current network namespace
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VlanInfo {
    pub(crate) id: u16,
    pub(crate) protocol: VlanProtocol,
    pub(crate) parent: l2_capture::LinuxInterfaceIdentity,
    pub(crate) reorders_headers: bool,
}

impl VlanInfo {
    /// Return the configured VLAN identifier
    #[must_use]
    pub const fn id(self) -> u16 {
        self.id
    }

    /// Return the configured tag protocol
    #[must_use]
    pub const fn protocol(self) -> VlanProtocol {
        self.protocol
    }

    /// Return the pinned identity of the immediate parent
    #[must_use]
    pub const fn parent_identity(self) -> l2_capture::LinuxInterfaceIdentity {
        self.parent
    }

    /// Return whether Linux removes the VLAN header on logical-device receive
    #[must_use]
    pub const fn reorders_headers(self) -> bool {
        self.reorders_headers
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VlanData {
    id: u16,
    protocol: VlanProtocol,
    parent_ifindex: u32,
    reorders_headers: bool,
}
