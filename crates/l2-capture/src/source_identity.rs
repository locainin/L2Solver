//! Checked operating-system capture source identities

use core::{
    fmt,
    num::{NonZeroU32, NonZeroU64},
};

/// Component rejected while constructing a Linux interface identity
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LinuxInterfaceIdentityField {
    /// Device number containing the network namespace object
    NamespaceDevice,
    /// Inode number of the network namespace object
    NamespaceInode,
    /// Device number containing the sysfs interface object
    InterfaceDevice,
    /// Inode number of the sysfs interface object
    InterfaceInode,
    /// Kernel interface index bound to the capture socket
    InterfaceIndex,
}

/// Failure to construct a Linux interface identity from a zero component
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LinuxInterfaceIdentityError {
    field: LinuxInterfaceIdentityField,
}

impl LinuxInterfaceIdentityError {
    /// Return the component that contained the reserved zero value
    #[must_use]
    pub const fn field(self) -> LinuxInterfaceIdentityField {
        self.field
    }
}

impl fmt::Display for LinuxInterfaceIdentityError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "Linux interface identity has a zero {:?} component",
            self.field
        )
    }
}

impl std::error::Error for LinuxInterfaceIdentityError {}

/// Exact Linux namespace and interface object supplying captured bytes
///
/// The values are structural provenance. Their authority depends on the
/// backend checking the retained kernel descriptors around frame acquisition
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LinuxInterfaceIdentity {
    namespace_device: NonZeroU64,
    namespace_inode: NonZeroU64,
    interface_device: NonZeroU64,
    interface_inode: NonZeroU64,
    ifindex: NonZeroU32,
}

impl LinuxInterfaceIdentity {
    /// Construct one identity after rejecting every reserved zero component
    ///
    /// # Errors
    /// Returns the first component whose value is zero
    pub const fn new(
        namespace_device: u64,
        namespace_inode: u64,
        interface_device: u64,
        interface_inode: u64,
        ifindex: u32,
    ) -> Result<Self, LinuxInterfaceIdentityError> {
        let Some(namespace_device) = NonZeroU64::new(namespace_device) else {
            return Err(LinuxInterfaceIdentityError {
                field: LinuxInterfaceIdentityField::NamespaceDevice,
            });
        };
        let Some(namespace_inode) = NonZeroU64::new(namespace_inode) else {
            return Err(LinuxInterfaceIdentityError {
                field: LinuxInterfaceIdentityField::NamespaceInode,
            });
        };
        let Some(interface_device) = NonZeroU64::new(interface_device) else {
            return Err(LinuxInterfaceIdentityError {
                field: LinuxInterfaceIdentityField::InterfaceDevice,
            });
        };
        let Some(interface_inode) = NonZeroU64::new(interface_inode) else {
            return Err(LinuxInterfaceIdentityError {
                field: LinuxInterfaceIdentityField::InterfaceInode,
            });
        };
        let Some(ifindex) = NonZeroU32::new(ifindex) else {
            return Err(LinuxInterfaceIdentityError {
                field: LinuxInterfaceIdentityField::InterfaceIndex,
            });
        };
        Ok(Self {
            namespace_device,
            namespace_inode,
            interface_device,
            interface_inode,
            ifindex,
        })
    }

    /// Return the device number containing the network namespace object
    #[must_use]
    pub const fn namespace_device(self) -> u64 {
        self.namespace_device.get()
    }

    /// Return the inode number of the network namespace object
    #[must_use]
    pub const fn namespace_inode(self) -> u64 {
        self.namespace_inode.get()
    }

    /// Return the device number containing the sysfs interface object
    #[must_use]
    pub const fn interface_device(self) -> u64 {
        self.interface_device.get()
    }

    /// Return the inode number of the sysfs interface object
    #[must_use]
    pub const fn interface_inode(self) -> u64 {
        self.interface_inode.get()
    }

    /// Return the kernel interface index
    #[must_use]
    pub const fn ifindex(self) -> u32 {
        self.ifindex.get()
    }
}
