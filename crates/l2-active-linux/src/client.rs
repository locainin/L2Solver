use crate::{
    InterfaceInfo, InterfaceSelector,
    channel::{Channel, Peer},
    intent::{Intent, IntentKind, ListenKind},
    packet::errno,
    wire::{self, Reader, Writer},
};
use l2_active::{
    ActiveLink, ArpProbe, Limits, NdpProbe, PreSendUsage, ReceiveEvent, dhcp::DhcpProbe,
    dot1x::Dot1xProbe,
};
use l2_capture::{
    CaptureMetadata, CapturedFrame, Direction, FcsStatus, InterfaceId, LinuxInterfaceIdentity,
    VlanAuxData,
};
use l2_onpath::MacAddress;
use nix::{fcntl::OFlag, poll::PollFlags, unistd::pipe2};
use std::{
    io,
    os::fd::OwnedFd,
    os::unix::process::CommandExt,
    path::Path,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

#[cfg(test)]
#[path = "../tests/client/process.rs"]
mod tests;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_RESERVE: Duration = Duration::from_secs(2);
const RECEIVE_SLICE: Duration = Duration::from_millis(40);

/// One explicitly admitted operation executed by the active helper
pub struct HelperLink {
    channel: Channel,
    control: Option<OwnedFd>,
    child: Option<Child>,
    lease: Option<crate::reaper::Lease>,
    intent: Intent,
    identity: LinuxInterfaceIdentity,
    deadline: Instant,
    poisoned: bool,
    signalled: bool,
}

impl std::fmt::Debug for HelperLink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HelperLink")
            .field("identity", &self.identity)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl HelperLink {
    /// Launch a helper for a fixed probe and the previously discovered interface
    ///
    /// The helper executable must be a trusted installation of the matching
    /// version; it needs Linux `CAP_NET_RAW` to open its own packet socket
    ///
    /// # Errors
    /// Returns launch, credential, admission, or capability errors
    pub fn open(
        executable: &Path,
        selector: &InterfaceSelector,
        expected: &InterfaceInfo,
        probe: &ArpProbe,
        requested_deadline: Instant,
        cancelled: &AtomicBool,
    ) -> io::Result<Self> {
        Self::open_intent(
            executable,
            selector,
            expected,
            Intent::arp(probe)?,
            requested_deadline,
            cancelled,
        )
    }

    /// Launch one helper for a fixed DHCP Discover on the selected interface
    ///
    /// The worker reconstructs the request from its own checked MAC and XID
    ///
    /// # Errors
    /// Returns launch, credential, admission, encoding, or capability errors
    pub fn open_dhcp(
        executable: &Path,
        selector: &InterfaceSelector,
        expected: &InterfaceInfo,
        probe: &DhcpProbe,
        requested_deadline: Instant,
        cancelled: &AtomicBool,
    ) -> io::Result<Self> {
        Self::open_intent(
            executable,
            selector,
            expected,
            Intent::dhcp(probe)?,
            requested_deadline,
            cancelled,
        )
    }

    /// Launch one helper for a fixed NDP solicitation on the selected interface
    ///
    /// The worker rechecks the assigned IPv6 source and target scope before send
    ///
    /// # Errors
    /// Returns launch, credential, admission, or capability errors
    pub fn open_ndp(
        executable: &Path,
        selector: &InterfaceSelector,
        expected: &crate::ndp::NdpInterfaceInfo,
        probe: &NdpProbe,
        requested_deadline: Instant,
        cancelled: &AtomicBool,
    ) -> io::Result<Self> {
        Self::open_intent(
            executable,
            selector,
            expected.interface(),
            Intent::ndp(probe)?,
            requested_deadline,
            cancelled,
        )
    }

    /// Launch one fixed 802.1X Start on an explicitly dedicated interface
    ///
    /// The operator must acknowledge that the selected interface is dedicated;
    /// a Start can affect another supplicant using the same interface
    ///
    /// # Errors
    /// Returns `PermissionDenied` without acknowledgement, or launch,
    /// credential, admission, multicast membership, or capability errors
    pub fn open_dot1x(
        executable: &Path,
        selector: &InterfaceSelector,
        expected: &InterfaceInfo,
        probe: &Dot1xProbe,
        dedicated_interface_ack: bool,
        requested_deadline: Instant,
        cancelled: &AtomicBool,
    ) -> io::Result<Self> {
        if !dedicated_interface_ack {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "802.1X requires explicit dedicated-interface acknowledgement",
            ));
        }
        Self::open_intent(
            executable,
            selector,
            expected,
            Intent::dot1x(probe)?,
            requested_deadline,
            cancelled,
        )
    }

    /// Launch a receive-only helper for fixed LLDP and CDP multicast scopes
    ///
    /// No promiscuous mode is requested, and no send is permitted
    ///
    /// # Errors
    /// Returns launch, credential, multicast membership, or capability errors
    pub fn open_discovery(
        executable: &Path,
        selector: &InterfaceSelector,
        expected: &InterfaceInfo,
        limits: Limits,
        requested_deadline: Instant,
        cancelled: &AtomicBool,
    ) -> io::Result<Self> {
        Self::open_listen(
            executable,
            selector,
            expected,
            limits,
            requested_deadline,
            cancelled,
            ListenKind::Discovery,
        )
    }

    /// Launch a receive-only helper for the fixed STP multicast destination
    ///
    /// No promiscuous mode is requested, and no send is permitted
    ///
    /// # Errors
    /// Returns launch, credential, multicast membership, or capability errors
    pub fn open_stp(
        executable: &Path,
        selector: &InterfaceSelector,
        expected: &InterfaceInfo,
        limits: Limits,
        requested_deadline: Instant,
        cancelled: &AtomicBool,
    ) -> io::Result<Self> {
        Self::open_listen(
            executable,
            selector,
            expected,
            limits,
            requested_deadline,
            cancelled,
            ListenKind::Stp,
        )
    }

    fn open_listen(
        executable: &Path,
        selector: &InterfaceSelector,
        expected: &InterfaceInfo,
        limits: Limits,
        requested_deadline: Instant,
        cancelled: &AtomicBool,
        kind: ListenKind,
    ) -> io::Result<Self> {
        let mac = MacAddress::new(expected.mac())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Self::open_intent(
            executable,
            selector,
            expected,
            Intent::listen(mac, limits, kind),
            requested_deadline,
            cancelled,
        )
    }

    fn open_intent(
        executable: &Path,
        selector: &InterfaceSelector,
        expected: &InterfaceInfo,
        intent: Intent,
        requested_deadline: Instant,
        cancelled: &AtomicBool,
    ) -> io::Result<Self> {
        if cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "operation cancelled",
            ));
        }
        let encoded_deadline =
            crate::deadline::encode_deadline(requested_deadline, intent.limits().timeout())?;
        let admitted_deadline = crate::deadline::admitted_deadline(encoded_deadline)?;
        if expected.name() != selector.name() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface snapshot does not match the selection",
            ));
        }
        let lease = crate::reaper::reserve()?;
        let uid = nix::unistd::getuid().as_raw();
        let (mut channel, child_channel) = Channel::pair(Peer { pid: 0, uid })?;
        let (control_read, control_write) =
            pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).map_err(errno)?;
        let child = helper_command(executable)
            .stdin(Stdio::from(child_channel))
            .stdout(Stdio::from(control_read))
            .stderr(Stdio::null())
            .spawn()?;
        channel.set_peer(Peer {
            pid: child.id(),
            uid,
        });
        let mut link = Self {
            channel,
            control: Some(control_write),
            child: Some(child),
            lease: Some(lease),
            intent,
            identity: expected.identity(),
            deadline: admitted_deadline,
            poisoned: false,
            signalled: false,
        };
        let request = open_record(
            selector,
            expected.identity(),
            &link.intent,
            encoded_deadline,
        )?;
        let startup_deadline = admitted_deadline.min(Instant::now() + STARTUP_TIMEOUT);
        let response = link.exchange(&request, startup_deadline, Some(cancelled))?;
        expect_open(&response, link.intent.tag(), link.intent.frame())?;
        if cancelled.load(Ordering::Acquire) {
            link.cancel();
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "operation cancelled",
            ));
        }
        Ok(link)
    }

    /// Return the admitted deadline shared by startup and protocol collection
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Close the worker's packet socket and wait for successful process exit
    ///
    /// # Errors
    /// Returns an error when closure or worker termination cannot be confirmed
    pub fn close(mut self) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "helper closure was not confirmed after a channel failure",
            ));
        }
        let deadline = Instant::now() + RESPONSE_RESERVE;
        self.channel
            .send(&Writer::new(wire::CLOSE).finish(), deadline)?;
        let response = self.channel.receive(deadline)?;
        expect_ok(&response)?;
        drop(self.control.take());
        loop {
            let Some(child) = self.child.as_mut() else {
                return Err(io::Error::other("helper process is missing"));
            };
            if let Some(status) = child.try_wait()? {
                self.child.take();
                if status.success() {
                    return Ok(());
                }
                return Err(io::Error::other("active helper exited unsuccessfully"));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "helper termination was not confirmed",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn cancel(&mut self) {
        if !self.signalled {
            if let Some(control) = &self.control {
                let _ignored = nix::unistd::write(control, b"c");
            }
            self.signalled = true;
        }
    }

    fn exchange(
        &mut self,
        request: &[u8],
        deadline: Instant,
        cancelled: Option<&AtomicBool>,
    ) -> io::Result<Vec<u8>> {
        if self.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "active helper channel is unusable",
            ));
        }
        if cancelled.is_some_and(|token| token.load(Ordering::Acquire)) {
            self.cancel();
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "operation cancelled",
            ));
        }
        if let Err(error) = self.channel.send(request, deadline) {
            self.poisoned = true;
            return Err(error);
        }
        loop {
            if cancelled.is_some_and(|token| token.load(Ordering::Acquire)) {
                self.cancel();
                if request.first() == Some(&wire::OPEN) {
                    self.poisoned = true;
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "operation cancelled",
                    ));
                }
            }
            match self.channel.try_receive() {
                Ok(Some(record)) => return Ok(record),
                Ok(None) => {}
                Err(error) => {
                    self.poisoned = true;
                    return Err(error);
                }
            }
            if let Err(error) = self.channel.wait(PollFlags::POLLIN, deadline) {
                self.cancel();
                self.poisoned = true;
                return Err(error);
            }
        }
    }
}

fn helper_command(executable: &Path) -> Command {
    let mut command = Command::new(executable);
    // Terminal signals reach the frontend; cancellation reaches the helper by pipe
    command.env_clear().process_group(0);
    command
}

fn receive_deadline(deadline: Instant) -> io::Result<Option<u64>> {
    match crate::deadline::encode_deadline(deadline, RECEIVE_SLICE) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::TimedOut => Ok(None),
        Err(error) => Err(error),
    }
}

impl ActiveLink for HelperLink {
    fn interface(&self) -> LinuxInterfaceIdentity {
        self.identity
    }

    fn pre_send_usage(&mut self) -> io::Result<Option<PreSendUsage>> {
        let response = self.exchange(
            &Writer::new(wire::PRE_SEND).finish(),
            Instant::now() + RESPONSE_RESERVE,
            None,
        )?;
        let mut reader = Reader::new(&response);
        match reader.u8()? {
            wire::ERROR => Err(wire::read_error(&mut reader)?),
            wire::USAGE => {
                let usage = match reader.u8()? {
                    0 => None,
                    1 => Some(PreSendUsage::new(reader.u32()?, reader.u64()?)),
                    _ => return Err(wire::invalid_record()),
                };
                reader.finish()?;
                Ok(usage)
            }
            _ => Err(wire::invalid_record()),
        }
    }

    fn send(&mut self, frame: &[u8], deadline: Instant, cancelled: &AtomicBool) -> io::Result<()> {
        if self.intent.listen_kind().is_some() || frame != self.intent.frame() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "frame differs from the admitted request",
            ));
        }
        let mut request = Writer::new(wire::SEND);
        request.u64(crate::deadline::encode_deadline(
            deadline,
            l2_active::MAX_TIMEOUT,
        )?);
        let response = self.exchange(
            &request.finish(),
            deadline + RESPONSE_RESERVE,
            Some(cancelled),
        )?;
        expect_ok(&response)
    }

    fn receive(
        &mut self,
        deadline: Instant,
        cancelled: &AtomicBool,
        max_bytes: usize,
    ) -> io::Result<ReceiveEvent> {
        if max_bytes == 0 || max_bytes > l2_capture::MAX_FRAME_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid capture byte allowance",
            ));
        }
        loop {
            if cancelled.load(Ordering::Acquire) {
                self.cancel();
                return Ok(ReceiveEvent::Cancelled);
            }
            if Instant::now() >= deadline {
                return Ok(ReceiveEvent::TimedOut);
            }
            let mut request = Writer::new(wire::RECEIVE);
            let Some(encoded) = receive_deadline(deadline)? else {
                return Ok(ReceiveEvent::TimedOut);
            };
            request.u64(encoded);
            request.u32(u32::try_from(max_bytes).map_err(io::Error::other)?);
            let response = self.exchange(
                &request.finish(),
                deadline + RESPONSE_RESERVE,
                Some(cancelled),
            )?;
            let mut reader = Reader::new(&response);
            match reader.u8()? {
                wire::FRAME => {
                    // IPC scheduling cannot turn a late read into timely evidence
                    crate::deadline::ensure_before(deadline)?;
                    return decode_frame(&mut reader, self.identity, max_bytes)
                        .map(ReceiveEvent::Frame);
                }
                wire::TIMEOUT => reader.finish()?,
                wire::FINAL_TIMEOUT => {
                    reader.finish()?;
                    return Ok(ReceiveEvent::BackendTimedOut);
                }
                wire::CANCELLED => {
                    reader.finish()?;
                    return Ok(ReceiveEvent::Cancelled);
                }
                wire::DOWN => {
                    reader.finish()?;
                    return Ok(ReceiveEvent::InterfaceDown);
                }
                wire::ERROR => return Err(wire::read_error(&mut reader)?),
                _ => return Err(wire::invalid_record()),
            }
        }
    }

    fn capture_loss(&mut self) -> io::Result<Option<u64>> {
        let response = self.exchange(
            &Writer::new(wire::LOSS).finish(),
            Instant::now() + RESPONSE_RESERVE,
            None,
        )?;
        let mut reader = Reader::new(&response);
        match reader.u8()? {
            wire::ERROR => Err(wire::read_error(&mut reader)?),
            wire::STATS => {
                let loss = match reader.u8()? {
                    0 => None,
                    1 => Some(reader.u64()?),
                    _ => return Err(wire::invalid_record()),
                };
                reader.finish()?;
                Ok(loss)
            }
            _ => Err(wire::invalid_record()),
        }
    }

    fn capture_backlog(&mut self) -> io::Result<Option<bool>> {
        let response = self.exchange(
            &Writer::new(wire::BACKLOG).finish(),
            Instant::now() + RESPONSE_RESERVE,
            None,
        )?;
        let mut reader = Reader::new(&response);
        match reader.u8()? {
            wire::ERROR => Err(wire::read_error(&mut reader)?),
            wire::BACKLOG_RESULT => {
                let result = match reader.u8()? {
                    0 => None,
                    1 => Some(false),
                    2 => Some(true),
                    _ => return Err(wire::invalid_record()),
                };
                reader.finish()?;
                Ok(result)
            }
            _ => Err(wire::invalid_record()),
        }
    }
}

impl Drop for HelperLink {
    fn drop(&mut self) {
        self.cancel();
        if let Some(mut child) = self.child.take()
            && !matches!(child.try_wait(), Ok(Some(_)))
        {
            let _ignored = child.kill();
            // A single bounded reaper keeps the slot until exit is observed
            if let Some(lease) = self.lease.take() {
                crate::reaper::submit(child, lease);
            }
        }
    }
}

fn open_record(
    selector: &InterfaceSelector,
    identity: LinuxInterfaceIdentity,
    intent: &Intent,
    deadline: u64,
) -> io::Result<Vec<u8>> {
    let mut writer = Writer::new(wire::OPEN);
    writer.u8(wire::VERSION);
    writer.u8(intent.tag());
    writer.u8(u8::try_from(selector.name().len()).map_err(io::Error::other)?);
    writer.bytes(selector.name().as_bytes());
    wire::write_identity(&mut writer, identity);
    writer.bytes(&intent.source_mac().bytes());
    match intent.kind() {
        IntentKind::Arp { source, target } => {
            writer.bytes(&source.octets());
            writer.bytes(&target.octets());
        }
        IntentKind::Dhcp { transaction } => writer.u32(transaction.get()),
        IntentKind::Ndp {
            source,
            prefix_len,
            target,
        } => {
            writer.bytes(&source.octets());
            writer.u8(*prefix_len);
            writer.bytes(&target.octets());
        }
        IntentKind::Listen(_) => {}
        IntentKind::Dot1x => writer.u8(1),
    }
    writer.u32(u32::try_from(intent.limits().timeout().as_millis()).map_err(io::Error::other)?);
    writer.u32(intent.limits().max_received_packets());
    writer.u64(intent.limits().max_received_bytes());
    writer.u64(deadline);
    Ok(writer.finish())
}

fn expect_ok(record: &[u8]) -> io::Result<()> {
    let mut reader = Reader::new(record);
    match reader.u8()? {
        wire::OK => reader.finish(),
        wire::ERROR => Err(wire::read_error(&mut reader)?),
        _ => Err(wire::invalid_record()),
    }
}

fn expect_open(record: &[u8], expected_tag: u8, expected: &[u8]) -> io::Result<()> {
    let mut reader = Reader::new(record);
    match reader.u8()? {
        wire::OK => {
            if reader.u8()? != expected_tag {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "helper admitted a different operation",
                ));
            }
            let length = usize::from(reader.u16()?);
            let actual = reader.take(length)?;
            if actual != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "helper reconstructed a different request",
                ));
            }
            reader.finish()
        }
        wire::ERROR => Err(wire::read_error(&mut reader)?),
        _ => Err(wire::invalid_record()),
    }
}

fn decode_frame(
    reader: &mut Reader<'_>,
    identity: LinuxInterfaceIdentity,
    max_bytes: usize,
) -> io::Result<CapturedFrame> {
    let source_matches = match reader.u8()? {
        0 => false,
        1 => true,
        _ => return Err(wire::invalid_record()),
    };
    let direction = match reader.u8()? {
        0 => Direction::Unknown,
        1 => Direction::Inbound,
        2 => Direction::Outbound,
        _ => return Err(wire::invalid_record()),
    };
    let vlan = match reader.u8()? {
        0 => None,
        1 => Some(VlanAuxData {
            tpid: reader.u16()?,
            tci: reader.u16()?,
        }),
        _ => return Err(wire::invalid_record()),
    };
    let original_len = reader.u32()?;
    let bytes = reader.rest()?;
    if bytes.len() > max_bytes {
        return Err(wire::invalid_record());
    }
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
    CapturedFrame::new(crate::buffer::copy(bytes)?, metadata)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}
