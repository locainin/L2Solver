use std::{collections::VecDeque, error::Error, io, sync::atomic::AtomicBool, time::Instant};

use l2_active::{ActiveLink, PreSendUsage, ReceiveEvent};
use l2_capture::{
    CaptureMetadata, CapturedFrame, Direction, FcsStatus, InterfaceId, LinuxInterfaceIdentity,
};

/// Construct a fixed checked interface identity for isolated tests
///
/// # Errors
/// Returns the underlying identity validation error
pub fn identity() -> Result<LinuxInterfaceIdentity, Box<dyn Error>> {
    Ok(LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?)
}

/// Build one bounded captured frame with explicit test provenance
///
/// # Errors
/// Returns an error for inconsistent captured and original lengths
pub fn captured(
    bytes: Vec<u8>,
    source: Option<LinuxInterfaceIdentity>,
    original_len: u32,
) -> Result<CapturedFrame, Box<dyn Error>> {
    captured_with_direction(bytes, source, original_len, Direction::Inbound)
}

/// Build one bounded capture with an explicit packet direction
///
/// # Errors
/// Returns an error for inconsistent captured and original lengths
pub fn captured_with_direction(
    bytes: Vec<u8>,
    source: Option<LinuxInterfaceIdentity>,
    original_len: u32,
    direction: Direction,
) -> Result<CapturedFrame, Box<dyn Error>> {
    let mut metadata = CaptureMetadata::new(
        InterfaceId {
            section: 0,
            index: 5,
        },
        original_len,
        None,
        None,
        direction,
        None,
        FcsStatus::Absent,
    );
    if let Some(source) = source {
        metadata = metadata.with_linux_interface(source);
    }
    Ok(CapturedFrame::new(bytes, metadata)?)
}

#[derive(Debug)]
pub struct Link {
    pub sent: Vec<Vec<u8>>,
    pub events: VecDeque<ReceiveEvent>,
    pub loss: Option<u64>,
    pub source: LinuxInterfaceIdentity,
    pub cancel_during_send: bool,
    pub timeout_during_send: bool,
    pub ignore_receive_capacity: bool,
    pub send_error: Option<io::ErrorKind>,
    pub receive_error: Option<io::ErrorKind>,
    pub loss_error: Option<io::ErrorKind>,
    pub backlog: Option<bool>,
    pub backlog_error: Option<io::ErrorKind>,
    pub pre_send: Option<PreSendUsage>,
    pub pre_send_error: Option<io::ErrorKind>,
    pub receive_delay: std::time::Duration,
    pub sent_deadline: Option<Instant>,
    pub sent_at: Option<Instant>,
}

impl Link {
    /// Create a scripted transport bound to the fixture interface
    ///
    /// # Errors
    /// Returns the underlying identity validation error
    pub fn new(events: Vec<ReceiveEvent>, loss: Option<u64>) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            sent: Vec::new(),
            events: events.into(),
            loss,
            source: identity()?,
            cancel_during_send: false,
            timeout_during_send: false,
            ignore_receive_capacity: false,
            send_error: None,
            receive_error: None,
            loss_error: None,
            backlog: Some(false),
            backlog_error: None,
            pre_send: Some(PreSendUsage::new(0, 0)),
            pre_send_error: None,
            receive_delay: std::time::Duration::ZERO,
            sent_deadline: None,
            sent_at: None,
        })
    }
}

impl ActiveLink for Link {
    fn interface(&self) -> LinuxInterfaceIdentity {
        self.source
    }
    fn send(&mut self, frame: &[u8], deadline: Instant, cancelled: &AtomicBool) -> io::Result<()> {
        self.sent_deadline = Some(deadline);
        self.sent_at = Some(Instant::now());
        if self.cancel_during_send {
            cancelled.store(true, std::sync::atomic::Ordering::Release);
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        if self.timeout_during_send {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        if let Some(error) = self.send_error {
            return Err(io::Error::from(error));
        }
        self.sent.push(frame.to_vec());
        Ok(())
    }
    fn receive(
        &mut self,
        deadline: Instant,
        _cancelled: &AtomicBool,
        max_bytes: usize,
    ) -> io::Result<ReceiveEvent> {
        if let Some(error) = self.receive_error {
            return Err(io::Error::from(error));
        }
        let event = self.events.pop_front().unwrap_or_else(|| {
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            ReceiveEvent::TimedOut
        });
        if !self.receive_delay.is_zero() {
            std::thread::sleep(self.receive_delay);
        }
        if let ReceiveEvent::Frame(frame) = &event
            && !self.ignore_receive_capacity
            && frame.captured_len() > max_bytes
        {
            return Err(io::Error::other("fixture exceeded receive allowance"));
        }
        Ok(event)
    }
    fn pre_send_usage(&mut self) -> io::Result<Option<PreSendUsage>> {
        if let Some(error) = self.pre_send_error {
            return Err(io::Error::from(error));
        }
        Ok(self.pre_send)
    }
    fn capture_loss(&mut self) -> io::Result<Option<u64>> {
        if let Some(error) = self.loss_error {
            return Err(io::Error::from(error));
        }
        Ok(self.loss)
    }

    fn capture_backlog(&mut self) -> io::Result<Option<bool>> {
        if let Some(error) = self.backlog_error {
            return Err(io::Error::from(error));
        }
        Ok(self.backlog)
    }
}
