//! One bounded kernel netlink request and validated single reply

use std::{
    io,
    os::fd::AsFd,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use netlink_packet_core::{NLMSG_ERROR, NetlinkBuffer, NetlinkMessage, NetlinkPayload};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use nix::poll::{PollFd, PollFlags, poll};

const MAX_LOOKUP_TIME: Duration = Duration::from_secs(1);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
// Each request uses a new socket, so one sequence value is sufficient
const SEQUENCE: u32 = 1;

pub fn exchange(
    deadline: Instant,
    cancelled: &AtomicBool,
    reply_limit: usize,
    request: impl FnOnce(u32, u32) -> NetlinkMessage<RouteNetlinkMessage>,
) -> io::Result<Vec<u8>> {
    let ceiling = Instant::now()
        .checked_add(MAX_LOOKUP_TIME)
        .ok_or_else(|| io::Error::other("netlink deadline overflow"))?;
    let deadline = deadline.min(ceiling);
    check_control(deadline, cancelled)?;
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.set_non_blocking(true)?;
    let port = socket.bind_auto()?.port_number();
    let packet = request(SEQUENCE, port);
    let mut bytes = [0; 128];
    let output = bytes
        .get_mut(..packet.buffer_len())
        .ok_or_else(|| io::Error::other("netlink request exceeds fixed buffer"))?;
    packet.serialize(output);
    send(&socket, output, deadline, cancelled)?;
    receive(&socket, reply_limit, SEQUENCE, port, deadline, cancelled)
}

pub fn receive(
    socket: &Socket,
    reply_limit: usize,
    sequence: u32,
    port: u32,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<Vec<u8>> {
    // A fixed ceiling also detects datagrams larger than the receive buffer
    let mut reply = Vec::new();
    reply
        .try_reserve_exact(reply_limit)
        .map_err(io::Error::other)?;
    reply.resize(reply_limit, 0);
    loop {
        check_control(deadline, cancelled)?;
        match socket.recv_from(&mut reply.as_mut_slice(), nix::libc::MSG_TRUNC) {
            Ok((length, peer)) => {
                check_control(deadline, cancelled)?;
                if length > reply.len() {
                    return Err(invalid("netlink reply exceeded fixed buffer"));
                }
                reply.truncate(length);
                // Accept only the matching reply from the kernel
                validate_reply(&reply, peer, sequence, port)?;
                return Ok(reply);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                wait(socket, PollFlags::POLLIN, deadline, cancelled)?;
            }
            Err(error) => return Err(error),
        }
    }
}

pub fn validate_reply(bytes: &[u8], peer: SocketAddr, sequence: u32, port: u32) -> io::Result<()> {
    if peer != SocketAddr::new(0, 0) {
        return Err(invalid("netlink reply did not come from the kernel"));
    }
    let buffer = NetlinkBuffer::new_checked(bytes).map_err(invalid)?;
    if usize::try_from(buffer.length()).ok() != Some(bytes.len())
        || buffer.sequence_number() != sequence
        || buffer.port_number() != port
        || buffer.flags() != 0
    {
        return Err(invalid(
            "netlink reply has an unexpected length, sequence, port, or flags",
        ));
    }
    if buffer.message_type() == NLMSG_ERROR {
        let packet = NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes).map_err(invalid)?;
        let NetlinkPayload::Error(error) = packet.payload else {
            return Err(invalid("invalid netlink error reply"));
        };
        // Kernel errors use negative errno values, while zero is an ACK
        let code = error
            .code
            .and_then(|code| code.get().checked_neg())
            .filter(|code| *code > 0)
            .ok_or_else(|| invalid("invalid netlink error code"))?;
        return Err(io::Error::from_raw_os_error(code));
    }
    Ok(())
}

pub fn send(
    socket: &Socket,
    bytes: &[u8],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<()> {
    loop {
        check_control(deadline, cancelled)?;
        match socket.send_to(bytes, &SocketAddr::new(0, 0), 0) {
            Ok(length) if length == bytes.len() => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial netlink request",
                ));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                wait(socket, PollFlags::POLLOUT, deadline, cancelled)?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn wait(
    socket: &Socket,
    interest: PollFlags,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<()> {
    check_control(deadline, cancelled)?;
    // Wake periodically so cancellation is observed during a quiet socket
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .min(POLL_INTERVAL);
    let milliseconds = u16::try_from(remaining.as_millis().max(1)).map_err(io::Error::other)?;
    let mut descriptors = [PollFd::new(socket.as_fd(), interest)];
    match poll(&mut descriptors, milliseconds) {
        Ok(_) | Err(nix::errno::Errno::EINTR) => {}
        Err(error) => return Err(io::Error::from(error)),
    }
    let events = descriptors
        .first()
        .and_then(PollFd::revents)
        .ok_or_else(|| io::Error::other("netlink socket readiness unavailable"))?;
    if events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
        return Err(io::Error::other(
            "netlink socket readiness reported an error",
        ));
    }
    Ok(())
}

pub fn check_control(deadline: Instant, cancelled: &AtomicBool) -> io::Result<()> {
    if cancelled.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "netlink lookup cancelled",
        ));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "netlink lookup deadline elapsed",
        ));
    }
    Ok(())
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
