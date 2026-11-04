use crate::{packet::errno, wire};
use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, poll},
    sys::socket::{
        AddressFamily, ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixCredentials, send,
        setsockopt, socketpair, sockopt::PassCred,
    },
};

#[cfg(not(test))]
use nix::sys::socket::recvmsg;

#[cfg(test)]
#[path = "../tests/channel/fault.rs"]
pub mod fault;

#[cfg(test)]
use fault::recvmsg;

use std::{
    io::{self, IoSliceMut},
    os::fd::{AsFd, AsRawFd, OwnedFd},
    time::{Duration, Instant},
};

// Return to the caller regularly so it can observe cancellation
const CONTROL_SLICE: Duration = Duration::from_millis(20);

#[cfg(test)]
#[path = "../tests/channel/rights.rs"]
mod tests;

#[derive(Clone, Copy)]
pub struct Peer {
    pub pid: u32,
    pub uid: u32,
}

impl Peer {
    fn matches(self, credential: &UnixCredentials) -> bool {
        self.pid != 0
            && u32::try_from(credential.pid()).ok() == Some(self.pid)
            && credential.uid() == self.uid
    }
}

pub struct Channel {
    fd: OwnedFd,
    peer: Peer,
}

impl Channel {
    pub fn pair(peer: Peer) -> io::Result<(Self, OwnedFd)> {
        let (parent, child) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        )
        .map_err(errno)?;
        setsockopt(&parent, PassCred, &true).map_err(errno)?;
        setsockopt(&child, PassCred, &true).map_err(errno)?;
        Ok((Self { fd: parent, peer }, child))
    }

    pub fn from_owned(fd: OwnedFd, peer: Peer) -> io::Result<Self> {
        let kind = nix::sys::socket::getsockopt(&fd, nix::sys::socket::sockopt::SockType)
            .map_err(errno)?;
        if kind != SockType::SeqPacket {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "helper channel is not a seqpacket socket",
            ));
        }
        setsockopt(&fd, PassCred, &true).map_err(errno)?;
        Ok(Self { fd, peer })
    }

    pub const fn set_peer(&mut self, peer: Peer) {
        self.peer = peer;
    }

    pub fn send(&self, record: &[u8], deadline: Instant) -> io::Result<()> {
        if record.is_empty() || record.len() > wire::MAX_RECORD {
            return Err(wire::invalid_record());
        }
        loop {
            match retry_interrupted(deadline, || {
                send(
                    self.fd.as_raw_fd(),
                    record,
                    MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
                )
            }) {
                Ok(length) if length == record.len() => return Ok(()),
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial helper record",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait(PollFlags::POLLOUT, deadline)?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn try_receive(&self, deadline: Instant) -> io::Result<Option<Vec<u8>>> {
        // Avoid allocating receive buffers when the deadline already passed
        crate::deadline::ensure_before(deadline)?;
        let mut bytes = crate::buffer::zeroed(wire::MAX_RECORD)?;
        let mut iov = [IoSliceMut::new(&mut bytes)];
        // Linux emits credentials first and closes descriptors that do not fit
        let space = nix::sys::socket::cmsg_space::<nix::libc::ucred>();
        let mut ancillary = crate::buffer::zeroed(space)?;
        let retry_deadline = deadline.min(Instant::now() + CONTROL_SLICE);
        let received = retry_interrupted(retry_deadline, || {
            recvmsg::<()>(
                self.fd.as_raw_fd(),
                &mut iov,
                Some(&mut ancillary),
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC | MsgFlags::MSG_CMSG_CLOEXEC,
            )
            .map(|message| check_message(&message, self.peer))
        });
        let count = match received {
            Ok(result) => result?,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            // A retry slice may end before the operation's actual deadline
            Err(error) if error.kind() == io::ErrorKind::TimedOut && Instant::now() < deadline => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        bytes.truncate(count);
        Ok(Some(bytes))
    }

    pub fn wait(&self, event: PollFlags, deadline: Instant) -> io::Result<()> {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "active helper deadline elapsed",
            ));
        }
        let millis = u16::try_from(
            deadline
                .saturating_duration_since(now)
                .min(CONTROL_SLICE)
                .as_millis()
                .max(1),
        )
        .unwrap_or(20);
        let mut descriptors = [PollFd::new(self.fd.as_fd(), event)];
        match poll(&mut descriptors, millis) {
            Ok(_) | Err(Errno::EINTR) => Ok(()),
            Err(error) => Err(errno(error)),
        }
    }

    pub fn receive(&self, deadline: Instant) -> io::Result<Vec<u8>> {
        loop {
            if let Some(record) = self.try_receive(deadline)? {
                return Ok(record);
            }
            self.wait(PollFlags::POLLIN, deadline)?;
        }
    }
}

fn check_message(message: &nix::sys::socket::RecvMsg<'_, '_, ()>, peer: Peer) -> io::Result<usize> {
    let count = message.bytes;
    let truncated = message.flags.contains(MsgFlags::MSG_CTRUNC);
    let mut verified = false;
    let mut extra = false;
    let mut wrong_peer = false;
    let mut close_error = None;
    if !truncated {
        for control in message.cmsgs().map_err(errno)? {
            match control {
                ControlMessageOwned::ScmCredentials(credential) => {
                    wrong_peer |= verified || !peer.matches(&credential);
                    verified = true;
                }
                ControlMessageOwned::ScmRights(fds) => {
                    // A helper record never transfers authority via descriptors
                    for fd in fds {
                        if let Err(error) = nix::unistd::close(fd) {
                            close_error.get_or_insert_with(|| errno(error));
                        }
                    }
                    extra = true;
                }
                _ => extra = true,
            }
        }
    }
    if let Some(error) = close_error {
        return Err(error);
    }
    if count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "active helper closed its channel",
        ));
    }
    if wrong_peer {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unexpected helper peer credentials",
        ));
    }
    if truncated || !verified || extra || count > wire::MAX_RECORD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid helper record or ancillary data",
        ));
    }
    Ok(count)
}

fn retry_interrupted<T>(
    deadline: Instant,
    mut attempt: impl FnMut() -> nix::Result<T>,
) -> io::Result<T> {
    loop {
        // Require a fresh, strictly early clock sample before each attempt
        // Scheduling can delay the syscall or its completion past the deadline
        crate::deadline::ensure_before(deadline)?;
        match attempt() {
            Err(Errno::EINTR) => {}
            result => return result.map_err(errno),
        }
    }
}
