use crate::{
    InterfaceSelector, discover,
    intent::{Intent, IntentKind},
    packet::{self, PacketAuxdata},
    pin::PinnedInterface,
};
use l2_active::{ActiveLink, PreSendUsage, ReceiveEvent};
use l2_capture::LinuxInterfaceIdentity;
use nix::{
    poll::{PollFd, PollFlags, poll},
    sys::socket::{SockaddrStorage, getsockname, setsockopt},
};
use rscap::{
    Interface,
    linux::{addr::L2Protocol, l2::L2Socket},
};
use std::{
    io,
    os::fd::{AsFd, AsRawFd},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const DRAIN_PACKET_LIMIT: usize = 64;
const DRAIN_BYTE_LIMIT: u64 = 1_048_576;
const POLL_INTERVAL: Duration = Duration::from_millis(20);

// This type is reachable only from the fixed-operation worker
pub struct DirectLink {
    selector: InterfaceSelector,
    pinned: PinnedInterface,
    socket: L2Socket,
    intent: Intent,
    deadline: Instant,
    sent: bool,
    attempted: bool,
    pre_send: PreSendUsage,
    received_packets: u32,
    received_bytes: u64,
    drops: u64,
}

impl DirectLink {
    pub fn request_frame(&self) -> &[u8] {
        self.intent.frame()
    }

    pub const fn request_tag(&self) -> u8 {
        self.intent.tag()
    }

    pub fn deadline_elapsed(&self) -> bool {
        Instant::now() >= self.deadline
    }

    pub fn open(
        selector: &InterfaceSelector,
        expected: LinuxInterfaceIdentity,
        intent: Intent,
        deadline: Instant,
    ) -> io::Result<Self> {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "operation deadline elapsed",
            ));
        }
        // Admit the one typed operation before requesting a raw packet socket
        let pinned = PinnedInterface::open(selector)?;
        let info = discover(selector)?;
        if pinned.identity != info.identity() || pinned.identity != expected {
            return Err(io::Error::other(
                "selected interface changed during admission",
            ));
        }
        intent.validate(&info, selector)?;
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "operation deadline elapsed",
            ));
        }
        let socket = L2Socket::new()?;
        // Protocol zero receives nothing until the locked profile is installed
        crate::filter::attach(&socket, &intent)?;
        rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::CLOEXEC)?;
        socket.set_nonblocking(true)?;
        setsockopt(&socket, PacketAuxdata, &true).map_err(packet::errno)?;
        // rscap passes this field through unchanged while Linux requires network byte order
        let all_protocols = u16::try_from(nix::libc::ETH_P_ALL)
            .map_err(io::Error::other)?
            .to_be();
        socket.bind(
            Interface::new(selector.name())?,
            L2Protocol::Other(all_protocols),
        )?;
        let socket = if let Some(kind) = intent.listen_kind() {
            // Join only the fixed multicast groups before the worker reports readiness
            crate::listen::join(socket, pinned.identity.ifindex(), kind)?
        } else if matches!(intent.kind(), IntentKind::Dot1x) {
            crate::listen::join_pae(socket, pinned.identity.ifindex())?
        } else {
            socket
        };
        let link = Self {
            selector: selector.clone(),
            pinned,
            socket,
            intent,
            deadline,
            sent: false,
            attempted: false,
            pre_send: PreSendUsage::new(0, 0),
            received_packets: 0,
            received_bytes: 0,
            drops: 0,
        };
        link.revalidate()?;
        Ok(link)
    }

    fn revalidate(&self) -> io::Result<()> {
        self.pinned.revalidate(&self.selector)?;
        let address: SockaddrStorage =
            getsockname(self.socket.as_raw_fd()).map_err(packet::errno)?;
        let index = address
            .as_link_addr()
            .and_then(|value| u32::try_from(value.ifindex()).ok());
        if index != Some(self.pinned.identity.ifindex()) {
            return Err(io::Error::other(
                "packet socket is bound to a different interface",
            ));
        }
        Ok(())
    }

    fn check_time(&self, deadline: Instant, cancelled: &AtomicBool) -> io::Result<()> {
        if cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "operation cancelled",
            ));
        }
        if Instant::now() >= deadline.min(self.deadline) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "operation deadline elapsed",
            ));
        }
        Ok(())
    }

    fn drain(&mut self, deadline: Instant, cancelled: &AtomicBool) -> io::Result<()> {
        for _ in 0..DRAIN_PACKET_LIMIT {
            self.check_time(deadline, cancelled)?;
            let limits = self.intent.limits();
            if self.received_packets >= limits.max_received_packets()
                || self.received_bytes >= limits.max_received_bytes()
                || self.pre_send.bytes() >= DRAIN_BYTE_LIMIT
            {
                return Err(io::Error::other(
                    "pre-send capture drain exhausted its budget",
                ));
            }
            let remaining = (limits.max_received_bytes() - self.received_bytes)
                .min(DRAIN_BYTE_LIMIT - self.pre_send.bytes())
                .min(l2_capture::MAX_FRAME_LENGTH as u64);
            let max_bytes = usize::try_from(remaining).map_err(io::Error::other)?;
            match packet::read_frame(&self.socket, self.pinned.identity, max_bytes, |length| {
                let bytes = u64::try_from(length).map_err(io::Error::other)?;
                self.received_packets += 1;
                self.received_bytes += bytes;
                self.pre_send =
                    PreSendUsage::new(self.pre_send.packets() + 1, self.pre_send.bytes() + bytes);
                Ok(())
            }) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::other(
            "pre-send capture drain exceeded its packet limit",
        ))
    }
}

impl ActiveLink for DirectLink {
    fn interface(&self) -> LinuxInterfaceIdentity {
        self.pinned.identity
    }

    fn pre_send_usage(&mut self) -> io::Result<Option<PreSendUsage>> {
        Ok(Some(self.pre_send))
    }

    fn send(&mut self, frame: &[u8], deadline: Instant, cancelled: &AtomicBool) -> io::Result<()> {
        if self.intent.listen_kind().is_some() || self.attempted || frame != self.intent.frame() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "frame is not the admitted request",
            ));
        }
        self.check_time(deadline, cancelled)?;
        self.drain(deadline, cancelled)?;
        self.revalidate()?;
        let current = discover(&self.selector)?;
        if current.identity() != self.pinned.identity {
            return Err(io::Error::other("interface changed before transmission"));
        }
        self.intent.validate(&current, &self.selector)?;
        self.check_time(deadline, cancelled)?;
        self.attempted = true;
        let sent = self.socket.send(frame)?;
        if sent != frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "packet socket accepted a partial frame",
            ));
        }
        self.sent = true;
        Ok(())
    }

    fn receive(
        &mut self,
        deadline: Instant,
        cancelled: &AtomicBool,
        max_bytes: usize,
    ) -> io::Result<ReceiveEvent> {
        if (!self.sent && self.intent.listen_kind().is_none()) || max_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "receive requires an admitted operation and nonzero byte limit",
            ));
        }
        let limits = self.intent.limits();
        if self.received_packets >= limits.max_received_packets()
            || self.received_bytes >= limits.max_received_bytes()
        {
            return Err(io::Error::other("receive budget exhausted"));
        }
        let remaining = usize::try_from(limits.max_received_bytes() - self.received_bytes)
            .unwrap_or(usize::MAX);
        let max_bytes = max_bytes.min(remaining).min(l2_capture::MAX_FRAME_LENGTH);
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Ok(ReceiveEvent::Cancelled);
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(ReceiveEvent::TimedOut);
            }
            if now >= self.deadline {
                return Ok(ReceiveEvent::BackendTimedOut);
            }
            if !self.pinned.is_up()? {
                return Ok(ReceiveEvent::InterfaceDown);
            }
            if let Err(error) = self.revalidate() {
                if error.raw_os_error() == Some(nix::libc::ENETDOWN) {
                    return Ok(ReceiveEvent::InterfaceDown);
                }
                return Err(error);
            }
            if cancelled.load(Ordering::Acquire) {
                return Ok(ReceiveEvent::Cancelled);
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(ReceiveEvent::TimedOut);
            }
            if now >= self.deadline {
                return Ok(ReceiveEvent::BackendTimedOut);
            }
            match packet::read_frame(&self.socket, self.pinned.identity, max_bytes, |length| {
                self.received_packets += 1;
                self.received_bytes += u64::try_from(length).map_err(io::Error::other)?;
                Ok(())
            }) {
                Ok(frame) => {
                    self.revalidate()?;
                    // A delayed read cannot be attributed to an elapsed window
                    crate::deadline::ensure_before(self.deadline)?;
                    return Ok(ReceiveEvent::Frame(frame));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let timeout = deadline
                        .min(self.deadline)
                        .saturating_duration_since(now)
                        .min(POLL_INTERVAL);
                    let millis = u16::try_from(timeout.as_millis().max(1)).unwrap_or(20);
                    let mut descriptors = [PollFd::new(self.socket.as_fd(), PollFlags::POLLIN)];
                    match poll(&mut descriptors, millis) {
                        Ok(_) | Err(nix::errno::Errno::EINTR) => {}
                        Err(error) => return Err(packet::errno(error)),
                    }
                }
                Err(error) if error.raw_os_error() == Some(nix::libc::ENETDOWN) => {
                    return Ok(ReceiveEvent::InterfaceDown);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn capture_loss(&mut self) -> io::Result<Option<u64>> {
        // PACKET_STATISTICS resets each read, so retain its cumulative total
        self.drops += u64::from(self.socket.packet_stats()?.dropped());
        Ok(Some(self.drops))
    }

    fn capture_backlog(&mut self) -> io::Result<Option<bool>> {
        self.revalidate()?;
        let mut descriptors = [PollFd::new(self.socket.as_fd(), PollFlags::POLLIN)];
        poll(&mut descriptors, 0_u16).map_err(packet::errno)?;
        let events = descriptors
            .first()
            .and_then(PollFd::revents)
            .ok_or_else(|| io::Error::other("packet socket readiness was unavailable"))?;
        if events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
            return Err(io::Error::other(
                "packet socket readiness reported an error",
            ));
        }
        Ok(Some(events.contains(PollFlags::POLLIN)))
    }
}
