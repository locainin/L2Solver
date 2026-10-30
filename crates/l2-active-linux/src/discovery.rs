use crate::InterfaceSelector;
use l2_capture::LinuxInterfaceIdentity;
use std::{io, net::Ipv4Addr};

/// One IPv4 address and its interface-reported network mask
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ipv4Assignment {
    pub(crate) address: Ipv4Addr,
    pub(crate) netmask: Ipv4Addr,
}

impl Ipv4Assignment {
    /// Return the address assigned to the selected interface
    #[must_use]
    pub const fn address(self) -> Ipv4Addr {
        self.address
    }

    /// Return the kernel-reported mask for this address
    #[must_use]
    pub const fn netmask(self) -> Ipv4Addr {
        self.netmask
    }
}

/// A read-only snapshot of one explicitly selected interface
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceInfo {
    pub(crate) name: String,
    pub(crate) identity: LinuxInterfaceIdentity,
    pub(crate) mac: [u8; 6],
    pub(crate) mtu: u32,
    pub(crate) flags: u32,
    pub(crate) hardware_type: u16,
    pub(crate) assignments: Vec<Ipv4Assignment>,
}

impl InterfaceInfo {
    /// Return the selected kernel interface name
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the namespace and kernel object identity observed during discovery
    #[must_use]
    pub const fn identity(&self) -> LinuxInterfaceIdentity {
        self.identity
    }

    /// Return the interface's six-byte hardware address
    #[must_use]
    pub const fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Return the maximum transmission unit reported by the interface
    #[must_use]
    pub const fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Return the Linux interface flags as observed during discovery
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Return the Linux hardware type reported by the interface
    #[must_use]
    pub const fn hardware_type(&self) -> u16 {
        self.hardware_type
    }

    /// Return whether the kernel marks this interface administratively up
    #[must_use]
    pub const fn is_up(&self) -> bool {
        self.flags & 1 != 0
    }

    /// Return whether the kernel reports an Ethernet-compatible link layout
    #[must_use]
    pub const fn is_ethernet(&self) -> bool {
        self.hardware_type == 1
    }

    /// Return address and mask pairs for scope validation
    #[must_use]
    pub fn ipv4_assignments(&self) -> &[Ipv4Assignment] {
        &self.assignments
    }
}

/// Read the identity, addresses and link properties of the selected interface
///
/// Discovery does not create a packet socket or transmit traffic
///
/// # Errors
/// Returns an operating-system error when identity or properties cannot be
/// established, and `Unsupported` when the platform is not Linux
#[cfg(target_os = "linux")]
pub fn discover(selector: &InterfaceSelector) -> io::Result<InterfaceInfo> {
    crate::pin::discover(selector)
}

/// Read the identity and properties of an explicitly selected interface
///
/// # Errors
/// Returns `Unsupported` because this backend requires Linux
#[cfg(not(target_os = "linux"))]
pub fn discover(_selector: &InterfaceSelector) -> io::Result<InterfaceInfo> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Linux is required",
    ))
}
