//! Scoped multicast membership for an owned, already-bound packet socket

use std::{fmt, io, os::fd::AsRawFd};

use nix::sys::socket::{SockaddrStorage, getsockname, setsockopt};
use nix::{libc, setsockopt_impl, sockopt_impl};
use rscap::linux::l2::L2Socket;

#[cfg(test)]
#[path = "../../tests/listen/membership.rs"]
mod tests;

const STP_GROUP: [u8; 6] = [1, 0x80, 0xc2, 0, 0, 0];
const PAE_GROUP: [u8; 6] = [1, 0x80, 0xc2, 0, 0, 3];
const VRRP_GROUP: [u8; 6] = [1, 0, 0x5e, 0, 0, 0x12];
const HSRP_GROUP: [u8; 6] = [1, 0, 0x5e, 0, 0, 2];
const CISCO_GROUP: [u8; 6] = [1, 0, 0x0c, 0xcc, 0xcc, 0xcc];
const DISCOVERY_GROUPS: [[u8; 6]; 4] =
    [[1, 0x80, 0xc2, 0, 0, 14], PAE_GROUP, STP_GROUP, CISCO_GROUP];

fn isl_groups() -> impl Iterator<Item = [u8; 6]> {
    (0_u8..16).flat_map(|user| [[1, 0, 0x0c, 0, 0, user], [3, 0, 0x0c, 0, 0, user]])
}

// The nix wrapper passes a fully initialized packet_mreq to Linux setsockopt
nix::sockopt_impl!(
    PacketAddMembership,
    SetOnly,
    nix::libc::SOL_PACKET,
    nix::libc::PACKET_ADD_MEMBERSHIP,
    nix::libc::packet_mreq
);

/// A bound socket could not join every selected protocol multicast group
#[derive(Debug)]
pub(super) enum MembershipError {
    /// The supplied interface index or socket binding was invalid
    Binding(io::Error),
    /// A membership call failed after the reported number of earlier joins
    Join {
        joined: usize,
        address: [u8; 6],
        source: io::Error,
    },
}

impl fmt::Display for MembershipError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binding(source) => write!(output, "invalid listen socket binding: {source}"),
            Self::Join {
                joined,
                address,
                source,
            } => write!(
                output,
                "multicast join {address:02x?} failed after {joined} successful joins: {source}"
            ),
        }
    }
}

impl std::error::Error for MembershipError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Binding(source) | Self::Join { source, .. } => Some(source),
        }
    }
}

/// Join the fixed groups on the verified socket, closing it on any failure
pub(super) fn join_discovery(socket: L2Socket, ifindex: u32) -> Result<L2Socket, MembershipError> {
    join_fixed(socket, ifindex, DISCOVERY_GROUPS)
}

/// Join only the fixed STP group, closing the socket on any failure
pub(super) fn join_stp(socket: L2Socket, ifindex: u32) -> Result<L2Socket, MembershipError> {
    join_fixed(socket, ifindex, [STP_GROUP])
}

/// Join only the fixed PAE group, closing the socket on any failure
pub(super) fn join_pae(socket: L2Socket, ifindex: u32) -> Result<L2Socket, MembershipError> {
    join_fixed(socket, ifindex, [PAE_GROUP])
}

/// Join only the VRRP multicast group
pub(super) fn join_vrrp(socket: L2Socket, ifindex: u32) -> Result<L2Socket, MembershipError> {
    join_fixed(socket, ifindex, [VRRP_GROUP])
}

/// Join only the `HSRPv1` multicast group
pub(super) fn join_hsrp(socket: L2Socket, ifindex: u32) -> Result<L2Socket, MembershipError> {
    join_fixed(socket, ifindex, [HSRP_GROUP])
}

/// Join only the Cisco DTP and VTP multicast group
pub(super) fn join_cisco(socket: L2Socket, ifindex: u32) -> Result<L2Socket, MembershipError> {
    join_fixed(socket, ifindex, [CISCO_GROUP])
}

/// Join the fixed Ethernet ISL multicast destinations
pub(super) fn join_isl(socket: L2Socket, ifindex: u32) -> Result<L2Socket, MembershipError> {
    join_fixed(socket, ifindex, isl_groups())
}

fn join_fixed(
    socket: L2Socket,
    ifindex: u32,
    groups: impl IntoIterator<Item = [u8; 6]>,
) -> Result<L2Socket, MembershipError> {
    let index = verify_binding(&socket, ifindex).map_err(MembershipError::Binding)?;
    let multicast = u16::try_from(libc::PACKET_MR_MULTICAST)
        .map_err(io::Error::other)
        .map_err(MembershipError::Binding)?;
    join_groups(groups, |address| {
        let [first, second, third, fourth, fifth, sixth] = address;
        let request = libc::packet_mreq {
            mr_ifindex: index,
            mr_type: multicast,
            mr_alen: 6,
            mr_address: [first, second, third, fourth, fifth, sixth, 0, 0],
        };
        setsockopt(&socket, PacketAddMembership, &request).map_err(io::Error::from)
    })?;
    // Ownership reaches the caller only after every fixed group succeeded
    Ok(socket)
}

fn verify_binding(socket: &L2Socket, ifindex: u32) -> io::Result<i32> {
    let index = checked_ifindex(ifindex)?;
    let address: SockaddrStorage = getsockname(socket.as_raw_fd()).map_err(io::Error::from)?;
    let bound = address
        .as_link_addr()
        .and_then(|value| u32::try_from(value.ifindex()).ok());
    if bound != Some(ifindex) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet socket is bound to a different interface",
        ));
    }
    Ok(index)
}

fn checked_ifindex(ifindex: u32) -> io::Result<i32> {
    i32::try_from(ifindex)
        .ok()
        .filter(|index| *index > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface index"))
}

fn join_groups(
    groups: impl IntoIterator<Item = [u8; 6]>,
    mut join: impl FnMut([u8; 6]) -> io::Result<()>,
) -> Result<(), MembershipError> {
    for (joined, address) in groups.into_iter().enumerate() {
        if let Err(source) = join(address) {
            return Err(MembershipError::Join {
                joined,
                address,
                source,
            });
        }
    }
    Ok(())
}
