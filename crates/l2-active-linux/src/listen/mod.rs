//! Fixed multicast memberships for scoped capture operations

mod membership;

use rscap::linux::l2::L2Socket;
use std::io;

use crate::intent::ListenKind;

pub fn join(socket: L2Socket, ifindex: u32, kind: ListenKind) -> io::Result<L2Socket> {
    let joined = match kind {
        ListenKind::Discovery => membership::join_discovery(socket, ifindex),
        ListenKind::Stp => membership::join_stp(socket, ifindex),
        ListenKind::Vrrp { .. } => membership::join_vrrp(socket, ifindex),
        ListenKind::Hsrp { .. } => membership::join_hsrp(socket, ifindex),
        ListenKind::Dtp | ListenKind::Vtp => membership::join_cisco(socket, ifindex),
        ListenKind::Isl => membership::join_isl(socket, ifindex),
        ListenKind::Mpls => Ok(socket),
    };
    joined.map_err(membership_error)
}

pub fn join_pae(socket: L2Socket, ifindex: u32) -> io::Result<L2Socket> {
    membership::join_pae(socket, ifindex).map_err(membership_error)
}

fn membership_error(error: membership::MembershipError) -> io::Error {
    let kind = match &error {
        membership::MembershipError::Binding(source)
        | membership::MembershipError::Join { source, .. } => source.kind(),
    };
    io::Error::new(kind, error)
}
