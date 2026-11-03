use nix::{
    errno::Errno,
    sys::socket::{self, MsgFlags, RecvMsg, SockaddrLike},
};
use std::{cell::Cell, io::IoSliceMut, os::fd::RawFd, time::Duration};

#[derive(Clone, Copy)]
struct Fault {
    remaining: Option<usize>,
    attempts: usize,
    delay: Duration,
}

thread_local! {
    static RECEIVE_FAULT: Cell<Option<Fault>> = const { Cell::new(None) };
}

pub struct InterruptedReceive;

impl InterruptedReceive {
    pub(crate) fn once() -> Self {
        Self::install(Some(1), Duration::ZERO)
    }

    pub(crate) fn repeated(delay: Duration) -> Self {
        Self::install(None, delay)
    }

    fn install(remaining: Option<usize>, delay: Duration) -> Self {
        RECEIVE_FAULT.set(Some(Fault {
            remaining,
            attempts: 0,
            delay,
        }));
        Self
    }

    pub(crate) fn attempts() -> usize {
        RECEIVE_FAULT.get().map_or(0, |fault| fault.attempts)
    }
}

impl Drop for InterruptedReceive {
    fn drop(&mut self) {
        RECEIVE_FAULT.set(None);
    }
}

pub(super) fn recvmsg<'a, 'outer, 'inner, S: SockaddrLike + 'a>(
    fd: RawFd,
    iov: &'outer mut [IoSliceMut<'inner>],
    ancillary: Option<&'a mut [u8]>,
    flags: MsgFlags,
) -> nix::Result<RecvMsg<'a, 'outer, S>>
where
    'inner: 'outer,
{
    let injected = RECEIVE_FAULT.with(|slot| {
        let mut fault = slot.get()?;
        fault.attempts += 1;
        let interrupted = match fault.remaining {
            Some(0) => false,
            Some(remaining) => {
                fault.remaining = Some(remaining - 1);
                true
            }
            None => true,
        };
        slot.set(Some(fault));
        interrupted.then_some(fault.delay)
    });
    if let Some(delay) = injected {
        std::thread::sleep(delay);
        return Err(Errno::EINTR);
    }
    socket::recvmsg(fd, iov, ancillary, flags)
}
