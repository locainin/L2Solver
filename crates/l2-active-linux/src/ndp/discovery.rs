use std::{
    io,
    net::Ipv6Addr,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use crate::{InterfaceInfo, InterfaceSelector};

/// One IPv6 address and the kernel metadata observed for the selected link
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ipv6Assignment {
    pub(super) address: Ipv6Addr,
    pub(super) prefix_len: u8,
    pub(super) scope: u8,
    pub(super) flags: u8,
}

impl Ipv6Assignment {
    /// Return the assigned IPv6 address
    #[must_use]
    pub const fn address(self) -> Ipv6Addr {
        self.address
    }

    /// Return the kernel-reported prefix length
    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    /// Return the Linux address scope
    #[must_use]
    pub const fn scope(self) -> u8 {
        self.scope
    }

    /// Return the low eight bits of the Linux address flags
    #[must_use]
    pub const fn flags(self) -> u8 {
        self.flags
    }
}

/// Interface properties and IPv6 assignments observed during one discovery
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NdpInterfaceInfo {
    pub(super) interface: InterfaceInfo,
    pub(super) assignments: Vec<Ipv6Assignment>,
}

impl NdpInterfaceInfo {
    /// Return the selected interface and its pinned identity
    #[must_use]
    pub const fn interface(&self) -> &InterfaceInfo {
        &self.interface
    }

    /// Return the kernel-reported IPv6 assignments for this interface
    #[must_use]
    pub fn assignments(&self) -> &[Ipv6Assignment] {
        &self.assignments
    }
}

/// Read IPv6 addresses for an explicitly selected Linux interface
///
/// Interface identity and address records are checked again before returning
/// The resulting snapshot is read-only and must be refreshed immediately
/// before a privileged worker sends a frame
///
/// # Errors
/// Returns `Unsupported` if Linux IPv6 information is unavailable
/// Malformed, excessive, changing or inaccessible interface data is rejected
pub fn discover(selector: &InterfaceSelector) -> io::Result<NdpInterfaceInfo> {
    discover_until(
        selector,
        Instant::now() + Duration::from_secs(2),
        &AtomicBool::new(false),
    )
}

/// Read IPv6 assignments while honoring a caller's deadline and cancellation
///
/// # Errors
/// Returns an operating-system error, `Interrupted` on cancellation, or
/// `TimedOut` when the deadline expires
pub fn discover_until(
    selector: &InterfaceSelector,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<NdpInterfaceInfo> {
    crate::netlink::check_control(deadline, cancelled)?;
    let pinned = crate::pin::PinnedInterface::open(selector)?;
    let (first, first_vlan) =
        crate::pin::discover_with_pin(selector, &pinned, deadline, cancelled)?;
    let first_assignments = read_snapshot(selector.name(), pinned.identity.ifindex())?;
    crate::pin::revalidate_scope(selector, &pinned, first_vlan.as_ref(), deadline, cancelled)?;

    // Compare separate observations while the original interface remains held
    let (second, second_vlan) =
        crate::pin::discover_with_pin(selector, &pinned, deadline, cancelled)?;
    let second_assignments = read_snapshot(selector.name(), pinned.identity.ifindex())?;
    crate::pin::revalidate_scope(selector, &pinned, second_vlan.as_ref(), deadline, cancelled)?;
    if first.vlan() != second.vlan() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            crate::VlanScopeChanged,
        ));
    }
    if first != second || first_assignments != second_assignments {
        return Err(io::Error::other(
            "interface properties changed during IPv6 discovery",
        ));
    }
    Ok(NdpInterfaceInfo {
        interface: second,
        assignments: second_assignments,
    })
}

fn read_snapshot(name: &str, ifindex: u32) -> io::Result<Vec<Ipv6Assignment>> {
    use rustix::fs::{self, CWD, Mode, OFlags};
    use std::{fs::File, io::Read};

    const PROC_SUPER_MAGIC: u64 = 0x9fa0;
    const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;

    // Open the calling thread's namespace view and verify it is procfs
    let fd = fs::openat(
        CWD,
        "/proc/thread-self/net/if_inet6",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "Linux IPv6 address information is unavailable",
            )
        } else {
            io::Error::from(error)
        }
    })?;
    if u64::try_from(fs::fstatfs(&fd)?.f_type).ok() != Some(PROC_SUPER_MAGIC) {
        return Err(io::Error::other("IPv6 address data is not on procfs"));
    }
    let mut bytes = Vec::new();
    // One extra byte makes an oversized kernel snapshot detectable
    bytes
        .try_reserve_exact(MAX_SNAPSHOT_BYTES + 1)
        .map_err(io::Error::other)?;
    File::from(fd)
        .take((MAX_SNAPSHOT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(invalid_data("IPv6 address data exceeds the snapshot limit"));
    }
    let text = std::str::from_utf8(&bytes).map_err(invalid_data)?;
    parse_snapshot(text, name, ifindex)
}

pub(super) fn parse_snapshot(
    text: &str,
    name: &str,
    ifindex: u32,
) -> io::Result<Vec<Ipv6Assignment>> {
    const MAX_ASSIGNMENTS: usize = 256;

    // A missing final newline can indicate that the read stopped mid-record
    if !text.is_empty() && !text.ends_with('\n') {
        return Err(invalid_data("incomplete IPv6 address record"));
    }
    let mut assignments = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let address = fields
            .next()
            .ok_or_else(|| invalid_data("missing IPv6 address"))?;
        if address.len() != 32 || !address.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid_data("invalid IPv6 address"));
        }
        let address = Ipv6Addr::from(u128::from_str_radix(address, 16).map_err(invalid_data)?);
        let index = hex_field(fields.next(), 2, 8)?;
        if index == 0 {
            return Err(invalid_data("invalid IPv6 interface index"));
        }
        let prefix = hex_field(fields.next(), 2, 2)?;
        if prefix > 128 {
            return Err(invalid_data("invalid IPv6 prefix length"));
        }
        let scope = hex_field(fields.next(), 2, 2)?;
        let flags = hex_field(fields.next(), 2, 2)?;
        let observed_name = fields
            .next()
            .ok_or_else(|| invalid_data("missing IPv6 interface name"))?;
        if fields.next().is_some() {
            return Err(invalid_data("extra IPv6 address fields"));
        }
        // Name and index must both refer to the same held interface
        let matches_name = observed_name == name;
        let matches_index = index == ifindex;
        if matches_name != matches_index {
            return Err(invalid_data("IPv6 interface name and index disagree"));
        }
        if !matches_name {
            continue;
        }
        if assignments.len() == MAX_ASSIGNMENTS {
            return Err(invalid_data(
                "too many IPv6 assignments on the selected interface",
            ));
        }
        assignments.try_reserve(1).map_err(io::Error::other)?;
        assignments.push(Ipv6Assignment {
            address,
            prefix_len: u8::try_from(prefix).map_err(invalid_data)?,
            scope: u8::try_from(scope).map_err(invalid_data)?,
            flags: u8::try_from(flags).map_err(invalid_data)?,
        });
    }
    // Stable ordering keeps repeated snapshots independent of kernel record order
    assignments.sort_unstable();
    assignments.dedup();
    Ok(assignments)
}

fn hex_field(field: Option<&str>, min: usize, max: usize) -> io::Result<u32> {
    let field = field.ok_or_else(|| invalid_data("missing IPv6 address field"))?;
    if !(min..=max).contains(&field.len()) || !field.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_data("invalid IPv6 address field"));
    }
    u32::from_str_radix(field, 16).map_err(invalid_data)
}

fn invalid_data(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
