//! One bounded nonblocking `NETLINK_ROUTE` request and response

use std::{
    io,
    os::fd::AsFd,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use nix::poll::{PollFd, PollFlags, poll};

use super::{RouteQuery, message};

const MAX_LOOKUP_TIME: Duration = Duration::from_secs(1);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const MAX_REPLY_BYTES: usize = 8_192;
const SEQUENCE: u32 = 1;

pub(super) fn lookup(
    query: RouteQuery,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<()> {
    let bounded = Instant::now()
        .checked_add(MAX_LOOKUP_TIME)
        .ok_or_else(|| io::Error::other("route deadline overflow"))?;
    let deadline = deadline.min(bounded);
    check_control(deadline, cancelled)?;
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.set_non_blocking(true)?;
    let local = socket.bind_auto()?;
    let packet = message::request(query, SEQUENCE, local.port_number());
    let mut bytes = [0; 128];
    let output = bytes
        .get_mut(..packet.buffer_len())
        .ok_or_else(|| io::Error::other("route request exceeds fixed buffer"))?;
    packet.serialize(output);
    send(&socket, output, deadline, cancelled)?;
    let mut reply = [0; MAX_REPLY_BYTES];
    loop {
        check_control(deadline, cancelled)?;
        let result = socket.recv_from(&mut reply.as_mut_slice(), nix::libc::MSG_TRUNC);
        match result {
            Ok((length, peer)) => {
                check_control(deadline, cancelled)?;
                let frame = reply.get(..length).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "route reply exceeded fixed buffer",
                    )
                })?;
                return message::parse_reply(frame, peer, SEQUENCE, local.port_number(), query);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                wait(&socket, PollFlags::POLLIN, deadline, cancelled)?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn send(
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
                    "partial route request",
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
        .ok_or_else(|| io::Error::other("route socket readiness unavailable"))?;
    if events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
        return Err(io::Error::other("route socket readiness reported an error"));
    }
    Ok(())
}

pub(super) fn check_control(deadline: Instant, cancelled: &AtomicBool) -> io::Result<()> {
    if cancelled.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "route lookup cancelled",
        ));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "route lookup deadline elapsed",
        ));
    }
    Ok(())
}
