use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use nix::errno::Errno;
use nix::sys::socket::{
    AddressFamily, MsgFlags, SockFlag, SockType, getsockopt, recv, send, socketpair,
    sockopt::{PeerCredentials, SockType as SockTypeOption},
};
use nix::unistd::geteuid;
use nix::{getsockopt_impl, libc, sockopt_impl};

use crate::{MAX_IPC_BYTES, TransportError};

// Linux assigns one stable cookie to each socket object, including all duped descriptors
nix::sockopt_impl!(
    SocketCookie,
    GetOnly,
    nix::libc::SOL_SOCKET,
    nix::libc::SO_COOKIE,
    u64
);

/// The only socket type accepted by the helper transport
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketType {
    /// Linux `SOCK_SEQPACKET`
    SeqPacket,
    /// Any other kernel socket type
    Other,
}

/// Kernel UID/PID identity of a connected local peer
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    uid: u32,
    pid: u32,
}

impl PeerIdentity {
    /// Construct a peer identity from trusted launcher state
    #[must_use]
    pub const fn new(uid: u32, pid: u32) -> Self {
        Self { uid, pid }
    }

    /// Return the identity a socketpair-based launcher expects at pair creation
    #[must_use]
    pub fn current() -> Self {
        Self {
            // The launcher records these values before creating and handing off each pair
            uid: geteuid().as_raw(),
            pid: std::process::id(),
        }
    }

    /// Return the kernel UID
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    /// Return the kernel PID
    #[must_use]
    pub const fn pid(self) -> u32 {
        self.pid
    }
}

impl std::fmt::Display for PeerIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "uid={} pid={}", self.uid, self.pid)
    }
}

/// One owned local `SOCK_SEQPACKET` endpoint
#[derive(Debug)]
pub struct SeqPacketSocket {
    fd: OwnedFd,
}

impl SeqPacketSocket {
    fn from_owned_fd(fd: OwnedFd) -> Result<Self, TransportError> {
        let socket_type = getsockopt(&fd, SockTypeOption).map_err(errno)?;
        if socket_type != SockType::SeqPacket {
            return Err(TransportError::WrongSocketType(match socket_type {
                SockType::SeqPacket => SocketType::SeqPacket,
                _ => SocketType::Other,
            }));
        }
        Ok(Self { fd })
    }

    fn try_clone(&self) -> Result<Self, TransportError> {
        // OwnedFd duplicates atomically with close-on-exec, including controller clones
        Self::from_owned_fd(self.fd.try_clone().map_err(TransportError::Io)?)
    }

    fn peer_identity(&self) -> Result<PeerIdentity, TransportError> {
        let credentials = getsockopt(&self.fd, PeerCredentials).map_err(errno)?;
        let pid = u32::try_from(credentials.pid()).map_err(|_| {
            TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer PID was not a positive value",
            ))
        })?;
        let uid = credentials.uid();
        Ok(PeerIdentity::new(uid, pid))
    }

    fn socket_cookie(&self) -> Result<u64, TransportError> {
        getsockopt(&self.fd, SocketCookie).map_err(errno)
    }

    fn socket_type(&self) -> Result<SocketType, TransportError> {
        let socket_type = getsockopt(&self.fd, SockTypeOption).map_err(errno)?;
        Ok(match socket_type {
            SockType::SeqPacket => SocketType::SeqPacket,
            _ => SocketType::Other,
        })
    }

    pub(crate) fn try_send(&self, bytes: &[u8]) -> Result<(), TransportError> {
        if bytes.len() > MAX_IPC_BYTES {
            return Err(TransportError::MessageTooLarge {
                length: bytes.len(),
                maximum: MAX_IPC_BYTES,
            });
        }
        let sent = send(
            self.fd.as_raw_fd(),
            bytes,
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
        )
        .map_err(map_send_errno)?;
        if sent != bytes.len() {
            return Err(TransportError::PartialSend {
                sent,
                expected: bytes.len(),
            });
        }
        Ok(())
    }

    pub(crate) fn try_recv(&self) -> Result<Vec<u8>, TransportError> {
        let mut buffer = vec![0_u8; MAX_IPC_BYTES];
        let received = self.try_recv_into(&mut buffer)?;
        buffer.truncate(received);
        Ok(buffer)
    }

    pub(crate) fn try_recv_into(&self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        let received = recv(
            self.fd.as_raw_fd(),
            buffer,
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
        )
        .map_err(map_recv_errno)?;
        if received == 0 {
            // Protocol records are never empty; zero means the peer closed the socket
            return Err(TransportError::PeerClosed);
        }
        if received > buffer.len() || received > MAX_IPC_BYTES {
            return Err(TransportError::MessageTooLarge {
                length: received,
                maximum: buffer.len().min(MAX_IPC_BYTES),
            });
        }
        Ok(received)
    }
}

/// Frontend side of the credential-checked data/control transport
#[derive(Debug)]
pub struct FrontendTransport {
    data: SeqPacketSocket,
    control: SeqPacketSocket,
}

impl FrontendTransport {
    /// Build a frontend transport from two already connected owned seqpacket
    /// descriptors
    ///
    /// This constructor is the safe handoff point for a trusted process
    /// launcher. It does not accept raw descriptor integers.
    ///
    /// # Errors
    /// Returns an error when either descriptor is not `SOCK_SEQPACKET`, the
    /// channels alias one socket, or their peer credentials differ
    pub fn from_owned_fds(data: OwnedFd, control: OwnedFd) -> Result<Self, TransportError> {
        let data = SeqPacketSocket::from_owned_fd(data)?;
        let control = SeqPacketSocket::from_owned_fd(control)?;
        validate_channel_pair(&data, &control)?;
        Ok(Self { data, control })
    }

    /// Return the peer identity recorded when the socket pair was created
    ///
    /// # Errors
    /// Returns an operating-system error when peer credentials cannot be read
    pub fn peer_identity(&self) -> Result<PeerIdentity, TransportError> {
        self.data.peer_identity()
    }

    /// Return the data channel socket type
    ///
    /// # Errors
    /// Returns an operating-system error when the socket type cannot be read
    pub fn peer_socket_type(&self) -> Result<SocketType, TransportError> {
        self.data.socket_type()
    }

    /// Send one already encoded request on the ordinary data channel
    ///
    /// # Errors
    /// Returns an error for oversized records, a full queue, or peer closure
    pub fn try_send(&self, bytes: &[u8]) -> Result<(), TransportError> {
        self.data.try_send(bytes)
    }

    /// Receive one reply from the ordinary data channel without blocking
    ///
    /// # Errors
    /// Returns an error for a full record, a full receive buffer, or peer closure
    pub fn try_recv(&self) -> Result<Vec<u8>, TransportError> {
        self.data.try_recv()
    }

    /// Send one already encoded cancellation request on the dedicated control channel
    ///
    /// # Errors
    /// Returns an error for oversized records, a full queue, or peer closure
    pub fn try_send_cancel(&self, bytes: &[u8]) -> Result<(), TransportError> {
        self.control.try_send(bytes)
    }

    /// Receive one cancellation reply without blocking
    ///
    /// # Errors
    /// Returns an error for a full record, a full receive buffer, or peer closure
    pub fn try_recv_cancel(&self) -> Result<Vec<u8>, TransportError> {
        self.control.try_recv()
    }

    pub(crate) fn try_recv_into(
        &self,
        control: bool,
        buffer: &mut [u8],
    ) -> Result<usize, TransportError> {
        if control {
            self.control.try_recv_into(buffer)
        } else {
            self.data.try_recv_into(buffer)
        }
    }

    /// Clone both channels while retaining the same peer credentials
    ///
    /// # Errors
    /// Returns an operating-system error when either descriptor cannot be duplicated
    pub fn try_clone(&self) -> Result<Self, TransportError> {
        Self::from_owned_fds(self.data.try_clone()?.fd, self.control.try_clone()?.fd)
    }
}

/// Helper side of the credential-checked data/control transport
#[derive(Debug)]
pub struct HelperTransport {
    pub(crate) data: SeqPacketSocket,
    pub(crate) control: SeqPacketSocket,
}

impl HelperTransport {
    /// Build a helper transport from two already connected owned seqpacket
    /// descriptors
    ///
    /// # Errors
    /// Returns an error when either descriptor is not `SOCK_SEQPACKET`, the
    /// channels alias one socket, or their peer credentials differ
    pub fn from_owned_fds(data: OwnedFd, control: OwnedFd) -> Result<Self, TransportError> {
        let data = SeqPacketSocket::from_owned_fd(data)?;
        let control = SeqPacketSocket::from_owned_fd(control)?;
        validate_channel_pair(&data, &control)?;
        Ok(Self { data, control })
    }

    /// Return the peer identity recorded when the socket pair was created
    ///
    /// # Errors
    /// Returns an operating-system error when peer credentials cannot be read
    pub fn peer_identity(&self) -> Result<PeerIdentity, TransportError> {
        self.data.peer_identity()
    }

    /// Return the data channel socket type
    ///
    /// # Errors
    /// Returns an operating-system error when the socket type cannot be read
    pub fn peer_socket_type(&self) -> Result<SocketType, TransportError> {
        self.data.socket_type()
    }

    pub(crate) fn clone_control(&self) -> Result<SeqPacketSocket, TransportError> {
        self.control.try_clone()
    }

    pub(crate) fn try_send_data(&self, bytes: &[u8]) -> Result<(), TransportError> {
        self.data.try_send(bytes)
    }

    pub(crate) fn try_recv_data_into(&self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        self.data.try_recv_into(buffer)
    }
}

/// Create two private local seqpacket channels for one frontend/helper pair
///
/// The returned endpoints are suitable for passing to separate threads or
/// processes by a trusted launcher. The descriptors are close-on-exec, so a
/// launcher that execs a helper must arrange an explicit, trusted descriptor
/// handoff before starting it. No pathname is created and no interface or
/// packet capability is inherited by the frontend endpoint.
///
/// # Errors
/// Returns an operating-system error if either socketpair cannot be created
pub fn local_transport_pair() -> Result<(FrontendTransport, HelperTransport), TransportError> {
    let flags = SockFlag::SOCK_CLOEXEC;
    let (frontend_data, helper_data) =
        socketpair(AddressFamily::Unix, SockType::SeqPacket, None, flags).map_err(errno)?;
    let (frontend_control, helper_control) =
        socketpair(AddressFamily::Unix, SockType::SeqPacket, None, flags).map_err(errno)?;
    let frontend = FrontendTransport::from_owned_fds(frontend_data, frontend_control)?;
    let helper = HelperTransport::from_owned_fds(helper_data, helper_control)?;
    Ok((frontend, helper))
}

fn validate_channel_pair(
    data: &SeqPacketSocket,
    control: &SeqPacketSocket,
) -> Result<(), TransportError> {
    // Descriptor numbers can differ while SO_COOKIE still identifies one socket object
    if data.socket_cookie()? == control.socket_cookie()? {
        return Err(TransportError::AliasedChannels);
    }
    // Distinct socket objects must still be connected to the same launch peer
    if data.peer_identity()? != control.peer_identity()? {
        return Err(TransportError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper channels have different peers",
        )));
    }
    Ok(())
}

fn errno(error: Errno) -> TransportError {
    TransportError::Io(io::Error::from_raw_os_error(error as i32))
}

fn map_send_errno(error: Errno) -> TransportError {
    match error {
        Errno::EAGAIN => TransportError::WouldBlock,
        Errno::EPIPE | Errno::ECONNRESET => TransportError::PeerClosed,
        other => errno(other),
    }
}

fn map_recv_errno(error: Errno) -> TransportError {
    match error {
        Errno::EAGAIN => TransportError::WouldBlock,
        Errno::ECONNRESET => TransportError::PeerClosed,
        other => errno(other),
    }
}

#[cfg(test)]
#[path = "../tests/transport/internal.rs"]
mod tests;
