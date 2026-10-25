//! Kernel identity checks for an activated live capture

use std::io;

/// Stable Linux namespace, interface, and data-link identity for one live handle
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveInterfaceIdentity {
    source: l2_capture::LinuxInterfaceIdentity,
    datalink: u32,
}

impl LiveInterfaceIdentity {
    fn new(
        namespace_device: u64,
        namespace_inode: u64,
        interface_device: u64,
        interface_inode: u64,
        ifindex: u32,
        datalink: u32,
    ) -> io::Result<Self> {
        if datalink == 0 {
            return Err(io::Error::other(
                "live interface identity contains a zero component",
            ));
        }
        let source = l2_capture::LinuxInterfaceIdentity::new(
            namespace_device,
            namespace_inode,
            interface_device,
            interface_inode,
            ifindex,
        )
        .map_err(io::Error::other)?;
        Ok(Self { source, datalink })
    }

    /// Return the device number of the held network namespace
    #[must_use]
    pub const fn namespace_device(self) -> u64 {
        self.source.namespace_device()
    }

    /// Return the inode number of the held network namespace
    #[must_use]
    pub const fn namespace_inode(self) -> u64 {
        self.source.namespace_inode()
    }

    /// Return the device number containing the held interface object
    #[must_use]
    pub const fn interface_device(self) -> u64 {
        self.source.interface_device()
    }

    /// Return the inode number of the held interface object
    #[must_use]
    pub const fn interface_inode(self) -> u64 {
        self.source.interface_inode()
    }

    /// Return the kernel interface index bound to the capture socket
    #[must_use]
    pub const fn ifindex(self) -> u32 {
        self.source.ifindex()
    }

    /// Return the exact data-link value reported by libpcap
    #[must_use]
    pub const fn datalink(self) -> u32 {
        self.datalink
    }

    /// Return the source identity attached to every frame from this handle
    #[must_use]
    pub const fn source(self) -> l2_capture::LinuxInterfaceIdentity {
        self.source
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceSnapshot {
    namespace_device: u64,
    namespace_inode: u64,
    interface_device: u64,
    interface_inode: u64,
    ifindex: u32,
}

/// Descriptors that keep the original namespace and interface object alive
#[cfg(target_os = "linux")]
pub struct PinnedInterface {
    namespace: rustix::fd::OwnedFd,
    interface: rustix::fd::OwnedFd,
    identity: InterfaceSnapshot,
}

#[cfg(target_os = "linux")]
impl PinnedInterface {
    const fn identity(&self) -> InterfaceSnapshot {
        self.identity
    }
}

#[cfg(not(target_os = "linux"))]
pub struct PinnedInterface;

#[cfg(target_os = "linux")]
pub fn pin(interface: &str) -> io::Result<PinnedInterface> {
    use nix::net::if_::if_nametoindex;
    use rustix::fs::{self, CWD, Mode, OFlags};
    use std::path::Path;

    const NSFS_MAGIC: u64 = 0x6e73_6673;
    const SYSFS_MAGIC: u64 = 0x6265_6572;

    let namespace = fs::openat(
        CWD,
        Path::new("/proc/self/ns/net"),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let namespace_metadata = fs::fstat(&namespace)?;
    let namespace_filesystem = fs::fstatfs(&namespace)?;
    if u64::try_from(namespace_filesystem.f_type).ok() != Some(NSFS_MAGIC) {
        return Err(io::Error::other(
            "network namespace descriptor is not backed by nsfs",
        ));
    }
    let ifindex = if_nametoindex(interface).map_err(io::Error::other)?;
    if ifindex == 0 {
        return Err(io::Error::other("capture interface has no kernel index"));
    }
    let interface_path = Path::new("/sys/class/net").join(interface);
    let interface_fd = fs::openat(
        CWD,
        &interface_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let interface_filesystem = fs::fstatfs(&interface_fd)?;
    if u64::try_from(interface_filesystem.f_type).ok() != Some(SYSFS_MAGIC) {
        return Err(io::Error::other(
            "capture interface object is not backed by sysfs",
        ));
    }
    let interface_metadata = fs::fstat(&interface_fd)?;
    Ok(PinnedInterface {
        namespace,
        interface: interface_fd,
        identity: InterfaceSnapshot {
            namespace_device: namespace_metadata.st_dev,
            namespace_inode: namespace_metadata.st_ino,
            interface_device: interface_metadata.st_dev,
            interface_inode: interface_metadata.st_ino,
            ifindex,
        },
    })
}

#[cfg(target_os = "linux")]
pub fn snapshot(interface: &str) -> io::Result<InterfaceSnapshot> {
    pin(interface).map(|pinned| pinned.identity())
}

#[cfg(not(target_os = "linux"))]
pub fn snapshot(_interface: &str) -> io::Result<InterfaceSnapshot> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable live interface binding requires Linux AF_PACKET",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn pin(_interface: &str) -> io::Result<PinnedInterface> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable live interface binding requires Linux AF_PACKET",
    ))
}

#[cfg(target_os = "linux")]
pub fn validate_capture(
    capture: &pcap::Capture<pcap::Active>,
    interface: &str,
    pinned: &PinnedInterface,
    datalink: u32,
) -> io::Result<LiveInterfaceIdentity> {
    let bound_ifindex = capture_socket_ifindex(capture)?;
    let after = snapshot(interface)?;
    validate_pinned_descriptors(pinned)?;
    validate_bound_identity(pinned.identity(), bound_ifindex, after, datalink)
}

/// Revalidate a live descriptor immediately around frame acquisition
#[cfg(target_os = "linux")]
pub fn revalidate_capture(
    capture: &pcap::Capture<pcap::Active>,
    interface: &str,
    expected: LiveInterfaceIdentity,
    pinned: &PinnedInterface,
) -> io::Result<()> {
    let before = snapshot(interface)?;
    let bound_ifindex = capture_socket_ifindex(capture)?;
    let datalink = u32::try_from(capture.get_datalink().0)
        .map_err(|_| io::Error::other("capture data-link identity is out of range"))?;
    let after = snapshot(interface)?;
    validate_pinned_descriptors(pinned)?;
    if pinned.identity() != before {
        return Err(io::Error::other(
            "capture interface identity changed before descriptor validation",
        ));
    }
    validate_current_identity(expected, before, bound_ifindex, after, datalink)
}

#[cfg(target_os = "linux")]
fn capture_socket_ifindex(capture: &pcap::Capture<pcap::Active>) -> io::Result<u32> {
    use nix::sys::socket::{SockaddrStorage, getsockname};
    use std::os::fd::AsRawFd;

    // AF_PACKET returns offsetof(sll_addr) plus sll_halen, after the full ifindex field
    // SockaddrStorage accepts that populated prefix where LinkAddr requires the full struct
    let address: SockaddrStorage = getsockname(capture.as_raw_fd()).map_err(io::Error::other)?;
    packet_socket_ifindex(&address)
}

#[cfg(target_os = "linux")]
fn packet_socket_ifindex(address: &nix::sys::socket::SockaddrStorage) -> io::Result<u32> {
    let Some(link_address) = address.as_link_addr() else {
        return Err(io::Error::other(
            "capture socket address is not an AF_PACKET interface",
        ));
    };
    u32::try_from(link_address.ifindex())
        .map_err(|_| io::Error::other("capture socket interface index is out of range"))
}

#[cfg(not(target_os = "linux"))]
pub fn validate_capture(
    _capture: &pcap::Capture<pcap::Active>,
    _interface: &str,
    _pinned: &PinnedInterface,
    _datalink: u32,
) -> io::Result<LiveInterfaceIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable live interface binding requires Linux AF_PACKET",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn revalidate_capture(
    _capture: &pcap::Capture<pcap::Active>,
    _interface: &str,
    _expected: LiveInterfaceIdentity,
    _pinned: &PinnedInterface,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable live interface binding requires Linux AF_PACKET",
    ))
}

#[cfg(target_os = "linux")]
fn validate_pinned_descriptors(pinned: &PinnedInterface) -> io::Result<()> {
    use rustix::fs;

    let namespace = fs::fstat(&pinned.namespace)?;
    let interface = fs::fstat(&pinned.interface)?;
    let expected = pinned.identity();
    if namespace.st_dev != expected.namespace_device
        || namespace.st_ino != expected.namespace_inode
        || interface.st_dev != expected.interface_device
        || interface.st_ino != expected.interface_inode
    {
        return Err(io::Error::other(
            "held live interface descriptors changed identity",
        ));
    }
    Ok(())
}

fn validate_bound_identity(
    before: InterfaceSnapshot,
    bound_ifindex: u32,
    after: InterfaceSnapshot,
    datalink: u32,
) -> io::Result<LiveInterfaceIdentity> {
    if before != after {
        return Err(io::Error::other(
            "capture interface identity changed while libpcap opened",
        ));
    }
    if bound_ifindex == 0 || bound_ifindex != before.ifindex {
        return Err(io::Error::other(
            "libpcap capture socket is not bound to the requested interface",
        ));
    }
    LiveInterfaceIdentity::new(
        after.namespace_device,
        after.namespace_inode,
        after.interface_device,
        after.interface_inode,
        bound_ifindex,
        datalink,
    )
}

fn validate_current_identity(
    expected: LiveInterfaceIdentity,
    before: InterfaceSnapshot,
    bound_ifindex: u32,
    after: InterfaceSnapshot,
    datalink: u32,
) -> io::Result<()> {
    let current = validate_bound_identity(before, bound_ifindex, after, datalink)?;
    if current != expected {
        return Err(io::Error::other(
            "live capture interface identity changed after open",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/interface/internal.rs"]
mod tests;
