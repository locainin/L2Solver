use l2_capture::{
    CaptureMetadata, CapturedFrame, Direction, FcsStatus, InterfaceId, LinuxInterfaceIdentity,
    VlanAuxData,
};
use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};
use nix::{libc, setsockopt_impl, sockopt_impl};
use rscap::linux::l2::L2Socket;
use std::{
    io::{self, IoSliceMut},
    os::fd::AsRawFd,
};

#[cfg(test)]
#[path = "../tests/packet/auxiliary.rs"]
mod tests;

pub const PACKET_AUXDATA: nix::libc::c_int = 8;
const TP_STATUS_VLAN_VALID: u32 = 1 << 4;
const TP_STATUS_VLAN_TPID_VALID: u32 = 1 << 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Auxiliary {
    Unavailable,
    Untagged,
    Tagged(VlanAuxData),
}

// Linux supplies one auxiliary record for every packet after this option is set
nix::sockopt_impl!(
    PacketAuxdata,
    SetOnly,
    nix::libc::SOL_PACKET,
    PACKET_AUXDATA,
    bool
);

pub fn read_frame(
    socket: &L2Socket,
    identity: LinuxInterfaceIdentity,
    max_bytes: usize,
    charge: impl FnOnce(usize) -> io::Result<()>,
) -> io::Result<CapturedFrame> {
    let retained_limit = max_bytes.min(l2_capture::MAX_FRAME_LENGTH);
    let mut bytes = crate::buffer::zeroed(retained_limit)?;
    let mut iov = [IoSliceMut::new(&mut bytes)];
    let mut ancillary = crate::buffer::zeroed(nix::sys::socket::cmsg_space::<[u8; 20]>())?;
    let message = recvmsg::<SockaddrStorage>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut ancillary),
        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
    )
    .map_err(errno)?;
    // The socket consumed this record even if later metadata checks fail
    charge(message.bytes.min(retained_limit))?;
    let original_len = u32::try_from(message.bytes).map_err(invalid_data)?;
    let address = message
        .address
        .and_then(|value| value.as_link_addr().copied());
    let source_matches = address
        .is_some_and(|value| u32::try_from(value.ifindex()).ok() == Some(identity.ifindex()));
    let direction = match address
        .filter(|_| source_matches)
        .map(|value| value.pkttype())
    {
        Some(0..=3) => Direction::Inbound,
        Some(4) => Direction::Outbound,
        _ => Direction::Unknown,
    };
    let auxiliary = read_auxiliary(&message);
    let (direction, vlan) = qualify_auxiliary(direction, auxiliary);
    bytes.truncate(
        usize::try_from(original_len)
            .unwrap_or(usize::MAX)
            .min(max_bytes),
    );
    let mut metadata = CaptureMetadata::new(
        InterfaceId {
            section: 0,
            index: identity.ifindex(),
        },
        original_len,
        None,
        None,
        direction,
        vlan,
        FcsStatus::Unknown,
    );
    if source_matches {
        metadata = metadata.with_linux_interface(identity);
    }
    CapturedFrame::new(bytes, metadata).map_err(invalid_data)
}

fn read_auxiliary(message: &nix::sys::socket::RecvMsg<'_, '_, SockaddrStorage>) -> Auxiliary {
    let mut auxiliary = None;
    let Ok(messages) = message.cmsgs() else {
        return Auxiliary::Unavailable;
    };
    for message in messages {
        if let ControlMessageOwned::Unknown(item) = message
            && item.cmsg_header.cmsg_level == nix::libc::SOL_PACKET
            && item.cmsg_header.cmsg_type == PACKET_AUXDATA
        {
            if auxiliary.is_some() {
                return Auxiliary::Unavailable;
            }
            auxiliary = match parse_auxiliary(&item.data_bytes) {
                Ok(Some(vlan)) => Some(Auxiliary::Tagged(vlan)),
                Ok(None) => Some(Auxiliary::Untagged),
                Err(_) => return Auxiliary::Unavailable,
            };
        }
    }
    auxiliary.unwrap_or(Auxiliary::Unavailable)
}

const fn qualify_auxiliary(
    direction: Direction,
    auxiliary: Auxiliary,
) -> (Direction, Option<VlanAuxData>) {
    match auxiliary {
        Auxiliary::Tagged(vlan) => (direction, Some(vlan)),
        Auxiliary::Untagged => (direction, None),
        Auxiliary::Unavailable => (Direction::Unknown, None),
    }
}

fn parse_auxiliary(bytes: &[u8]) -> io::Result<Option<VlanAuxData>> {
    let status = u32::from_ne_bytes(read_array(bytes, 0)?);
    if bytes.len() < 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short packet auxiliary data",
        ));
    }
    if status & TP_STATUS_VLAN_VALID == 0 {
        return Ok(None);
    }
    let tci = u16::from_ne_bytes(read_array(bytes, 16)?);
    let tpid = if status & TP_STATUS_VLAN_TPID_VALID == 0 {
        0x8100
    } else {
        u16::from_ne_bytes(read_array(bytes, 18)?)
    };
    Ok(Some(VlanAuxData { tpid, tci }))
}

fn read_array<const SIZE: usize>(bytes: &[u8], offset: usize) -> io::Result<[u8; SIZE]> {
    let end = offset
        .checked_add(SIZE)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid auxiliary offset"))?;
    bytes
        .get(offset..end)
        .and_then(|part| part.try_into().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short packet auxiliary data"))
}

pub fn errno(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

fn invalid_data(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
