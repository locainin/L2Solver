use crate::{InterfaceInfo, InterfaceSelector, Ipv4Assignment};
use nix::{errno::Errno, ifaddrs::getifaddrs, net::if_::if_nametoindex};
use rustix::{
    fd::OwnedFd,
    fs::{self, CWD, Mode, OFlags},
};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

const NSFS_MAGIC: u64 = 0x6e73_6673;
const SYSFS_MAGIC: u64 = 0x6265_6572;
const MAX_IPV4_ASSIGNMENTS: usize = 256;

// The held descriptors prevent their identities from being recycled mid-session
pub struct PinnedInterface {
    pub namespace: OwnedFd,
    pub interface: OwnedFd,
    pub identity: l2_capture::LinuxInterfaceIdentity,
}

impl PinnedInterface {
    pub fn is_up(&self) -> io::Result<bool> {
        Ok(read_flags(&self.interface)? & 1 != 0)
    }

    pub fn open(selector: &InterfaceSelector) -> io::Result<Self> {
        let namespace = fs::openat(
            CWD,
            Path::new("/proc/thread-self/ns/net"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        require_filesystem(&namespace, NSFS_MAGIC)?;
        let namespace_metadata = fs::fstat(&namespace)?;
        let ifindex = interface_index(selector)?;
        let interface = fs::openat(
            CWD,
            Path::new("/sys/class/net").join(selector.name()),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        require_filesystem(&interface, SYSFS_MAGIC)?;
        let interface_metadata = fs::fstat(&interface)?;
        let reported_ifindex = read_property(&interface, "ifindex")?
            .parse::<u32>()
            .map_err(invalid_data)?;
        if ifindex != reported_ifindex || ifindex != interface_index(selector)? {
            return Err(io::Error::other("selected interface changed while pinning"));
        }
        let identity = l2_capture::LinuxInterfaceIdentity::new(
            namespace_metadata.st_dev,
            namespace_metadata.st_ino,
            interface_metadata.st_dev,
            interface_metadata.st_ino,
            ifindex,
        )
        .map_err(invalid_data)?;
        Ok(Self {
            namespace,
            interface,
            identity,
        })
    }

    pub fn revalidate(&self, selector: &InterfaceSelector) -> io::Result<()> {
        let current = Self::open(selector)?;
        let namespace = fs::fstat(&self.namespace)?;
        let interface = fs::fstat(&self.interface)?;
        if self.identity != current.identity
            || namespace.st_dev != self.identity.namespace_device()
            || namespace.st_ino != self.identity.namespace_inode()
            || interface.st_dev != self.identity.interface_device()
            || interface.st_ino != self.identity.interface_inode()
        {
            return Err(io::Error::other("selected interface identity changed"));
        }
        Ok(())
    }
}

pub fn discover(selector: &InterfaceSelector) -> io::Result<InterfaceInfo> {
    let pinned = PinnedInterface::open(selector)?;
    let mac = parse_mac(&read_property(&pinned.interface, "address")?)?;
    let mtu = read_property(&pinned.interface, "mtu")?
        .parse()
        .map_err(invalid_data)?;
    let hardware_type = read_property(&pinned.interface, "type")?
        .parse()
        .map_err(invalid_data)?;
    let flags = read_flags(&pinned.interface)?;
    let mut assignments = ipv4_assignments(selector)?;
    assignments.sort_by_key(|assignment| (assignment.address, assignment.netmask));
    assignments.dedup();
    // Reopen both names after reading to detect replacement during discovery
    pinned.revalidate(selector)?;
    Ok(InterfaceInfo {
        name: selector.name().to_owned(),
        identity: pinned.identity,
        mac,
        mtu,
        flags,
        hardware_type,
        assignments,
    })
}

fn read_flags(interface: &OwnedFd) -> io::Result<u32> {
    let text = read_property(interface, "flags")?;
    u32::from_str_radix(text.trim_start_matches("0x"), 16).map_err(invalid_data)
}

fn interface_index(selector: &InterfaceSelector) -> io::Result<u32> {
    if_nametoindex(selector.name()).map_err(|error| match error {
        Errno::ENODEV | Errno::ENXIO => io::Error::new(io::ErrorKind::NotFound, error),
        other => io::Error::from_raw_os_error(other as i32),
    })
}

fn require_filesystem(fd: &OwnedFd, expected: u64) -> io::Result<()> {
    if u64::try_from(fs::fstatfs(fd)?.f_type).ok() != Some(expected) {
        return Err(io::Error::other(
            "interface identity is on an unexpected filesystem",
        ));
    }
    Ok(())
}

fn read_property(directory: &OwnedFd, name: &str) -> io::Result<String> {
    let fd = fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let mut contents = String::new();
    File::from(fd).take(128).read_to_string(&mut contents)?;
    if contents.len() == 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized interface property",
        ));
    }
    Ok(contents.trim().to_owned())
}

fn parse_mac(value: &str) -> io::Result<[u8; 6]> {
    let parsed: Result<Vec<_>, _> = value
        .split(':')
        .map(|part| u8::from_str_radix(part, 16))
        .collect();
    parsed.map_err(invalid_data)?.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "interface does not have a six-byte hardware address",
        )
    })
}

fn ipv4_assignments(selector: &InterfaceSelector) -> io::Result<Vec<Ipv4Assignment>> {
    let mut assignments = Vec::new();
    for entry in getifaddrs().map_err(|error| io::Error::from_raw_os_error(error as i32))? {
        if entry.interface_name != selector.name() {
            continue;
        }
        let address = entry.address.and_then(|address| {
            address
                .as_sockaddr_in()
                .map(nix::sys::socket::SockaddrIn::ip)
        });
        let netmask = entry.netmask.and_then(|netmask| {
            netmask
                .as_sockaddr_in()
                .map(nix::sys::socket::SockaddrIn::ip)
        });
        if let (Some(address), Some(netmask)) = (address, netmask) {
            if assignments.len() == MAX_IPV4_ASSIGNMENTS {
                return Err(io::Error::other(
                    "selected interface has too many IPv4 assignments",
                ));
            }
            assignments.try_reserve(1).map_err(io::Error::other)?;
            assignments.push(Ipv4Assignment { address, netmask });
        }
    }
    Ok(assignments)
}

fn invalid_data(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
