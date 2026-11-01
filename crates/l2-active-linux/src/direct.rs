use crate::{
    InterfaceInfo, InterfaceSelector, VlanInfo,
    intent::{Intent, IntentKind},
    packet::{self, PacketAuxdata},
    pin::{self, PinnedInterface},
    vlan::VlanPin,
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
const FINAL_SCOPE_TIMEOUT: Duration = Duration::from_millis(500);

#[cfg(test)]
#[path = "../tests/receive/post_read.rs"]
mod post_read_tests;

// This type is reachable only from the fixed-operation worker
pub struct DirectLink {
    selector: InterfaceSelector,
    pinned: PinnedInterface,
    vlan: Option<VlanPin>,
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

    pub fn request_profile(&self) -> u16 {
        self.intent.profile()
    }

    pub fn deadline_elapsed(&self) -> bool {
        Instant::now() >= self.deadline
    }

    pub fn open(
        selector: &InterfaceSelector,
        expected: LinuxInterfaceIdentity,
        expected_vlan: Option<VlanInfo>,
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
        let cancelled = AtomicBool::new(false);
        let (info, vlan) = pin::discover_with_pin(selector, &pinned, deadline, &cancelled)?;
        if pinned.identity != expected {
            return Err(io::Error::other(
                "selected interface changed during admission",
            ));
        }
        if info.vlan() != expected_vlan {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                crate::VlanScopeChanged,
            ));
        }
        verify_admission(&intent, &info, selector, deadline, &cancelled)?;
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
            vlan,
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
        link.revalidate(deadline, &cancelled)?;
        Ok(link)
    }

    fn revalidate(&self, deadline: Instant, cancelled: &AtomicBool) -> io::Result<()> {
        pin::revalidate_scope(
            &self.selector,
            &self.pinned,
            self.vlan.as_ref(),
            deadline,
            cancelled,
        )?;
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

    fn receive_status(
        &self,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> io::Result<Option<ReceiveEvent>> {
        if let Some(status) = self.terminal_status(deadline, cancelled) {
            return Ok(Some(status));
        }
        if let Err(error) = self.revalidate(deadline.min(self.deadline), cancelled) {
            if error.raw_os_error() == Some(nix::libc::ENETDOWN) {
                return Ok(Some(ReceiveEvent::InterfaceDown));
            }
            if matches!(error.get_ref(), Some(source) if source.is::<crate::VlanScopeChanged>()) {
                return Err(error);
            }
            if cancelled.load(Ordering::Acquire) {
                return Ok(Some(ReceiveEvent::Cancelled));
            }
            if error.kind() == io::ErrorKind::TimedOut {
                if Instant::now() >= self.deadline {
                    return Ok(Some(ReceiveEvent::BackendTimedOut));
                }
                if Instant::now() >= deadline {
                    return Ok(Some(ReceiveEvent::TimedOut));
                }
            }
            return Err(error);
        }
        if !self.pinned.is_up()? {
            return Ok(Some(ReceiveEvent::InterfaceDown));
        }
        Ok(self.terminal_status(deadline, cancelled))
    }

    fn terminal_status(&self, deadline: Instant, cancelled: &AtomicBool) -> Option<ReceiveEvent> {
        if cancelled.load(Ordering::Acquire) {
            Some(ReceiveEvent::Cancelled)
        } else if Instant::now() >= deadline {
            Some(ReceiveEvent::TimedOut)
        } else if Instant::now() >= self.deadline {
            Some(ReceiveEvent::BackendTimedOut)
        } else {
            None
        }
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
        let deadline = deadline.min(self.deadline);
        self.revalidate(deadline, cancelled)?;
        // Refresh mutable properties against the original retained scope
        let current = pin::snapshot_with_pin(
            &self.selector,
            &self.pinned,
            self.vlan.as_ref(),
            deadline,
            cancelled,
        )?;
        verify_admission(&self.intent, &current, &self.selector, deadline, cancelled)?;
        self.revalidate(deadline, cancelled)?;
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
            if let Some(status) = self.receive_status(deadline, cancelled)? {
                return Ok(status);
            }
            match packet::read_frame(&self.socket, self.pinned.identity, max_bytes, |length| {
                self.received_packets += 1;
                self.received_bytes += u64::try_from(length).map_err(io::Error::other)?;
                Ok(())
            }) {
                Ok(frame) => {
                    // A consumed frame must be checked against the operation deadline,
                    // not the shorter idle polling slice
                    let validation = self.revalidate(self.deadline, cancelled);
                    if let Some(status) = post_read_result(validation, self.deadline)? {
                        return Ok(status);
                    }
                    return Ok(ReceiveEvent::Frame(frame));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let timeout = deadline
                        .min(self.deadline)
                        .saturating_duration_since(Instant::now())
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
        // Collection may already have ended, so use a separate bounded final sample
        self.revalidate(
            Instant::now() + FINAL_SCOPE_TIMEOUT,
            &AtomicBool::new(false),
        )?;
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

fn post_read_result(
    validation: io::Result<()>,
    deadline: Instant,
) -> io::Result<Option<ReceiveEvent>> {
    match validation {
        Err(error) if error.kind() == io::ErrorKind::TimedOut && Instant::now() >= deadline => {
            Ok(Some(ReceiveEvent::BackendTimedOut))
        }
        Err(error) => Err(error),
        Ok(()) if Instant::now() >= deadline => Ok(Some(ReceiveEvent::BackendTimedOut)),
        Ok(()) => Ok(None),
    }
}

fn verify_admission(
    intent: &Intent,
    info: &InterfaceInfo,
    selector: &InterfaceSelector,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<()> {
    intent.validate(info)?;
    if let IntentKind::Ndp {
        source,
        target,
        prefix_len,
    } = intent.kind()
    {
        let current = crate::ndp::discover_until(selector, deadline, cancelled)?;
        if current.interface().identity() != info.identity() {
            return Err(io::Error::other("interface changed during IPv6 admission"));
        }
        if current.interface().vlan() != info.vlan() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                crate::VlanScopeChanged,
            ));
        }
        let prepared =
            crate::ndp::prepare(&current, Some(*source), *target, None, intent.limits())?;
        if prepared.source_mac() != intent.source_mac()
            || prepared.prefix_len() != *prefix_len
            || prepared.frame() != intent.frame()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NDP request does not match the selected IPv6 assignment",
            ));
        }
        if !source.is_unicast_link_local() {
            // A configured prefix alone cannot establish a global on-link target
            crate::route::verify_on_link(
                selector,
                info.identity(),
                *source,
                *target,
                deadline,
                cancelled,
            )?;
        }
    }
    Ok(())
}
