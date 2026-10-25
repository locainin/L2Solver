use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use l2_helper_protocol::{ControlAction, Message, MessageKind, PeerState, SessionId, decode};

use crate::{
    BindingError, CancellationToken, HelperError, HelperReply, HelperReplyKind, HelperTransport,
    InterfaceBindingRequest, ReceiveSocket, ReplyErrorCode, SessionBudget, SessionLimits,
    TransportError, encode_reply,
};

const POLL_DELAY: Duration = Duration::from_millis(2);

/// Trusted launch configuration for one receive-only helper session
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelperConfig {
    session: SessionId,
    expected_peer: crate::PeerIdentity,
    limits: SessionLimits,
}

impl HelperConfig {
    /// Create a helper configuration with an already allocated session identity
    /// and the expected socketpair-time peer credentials
    #[must_use]
    pub const fn new(
        session: SessionId,
        expected_peer: crate::PeerIdentity,
        limits: SessionLimits,
    ) -> Self {
        // SessionLimits is validated before it reaches the helper authority boundary
        Self {
            session,
            expected_peer,
            limits,
        }
    }

    /// Return the session identity
    #[must_use]
    pub const fn session(self) -> SessionId {
        self.session
    }

    /// Return the expected frontend kernel identity
    #[must_use]
    pub const fn expected_peer(self) -> crate::PeerIdentity {
        self.expected_peer
    }

    /// Return the helper-owned limits
    #[must_use]
    pub const fn limits(self) -> SessionLimits {
        self.limits
    }
}

/// Terminal reason for a helper session
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStop {
    /// Frontend sent a valid close request
    Closed,
    /// Frontend cancellation was accepted on the control channel
    Cancelled,
}

/// Bounded counters and terminal state returned after a normal helper stop
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionReport {
    stop: SessionStop,
    frames: u32,
    bytes: u64,
}

impl SessionReport {
    /// Return the terminal state
    #[must_use]
    pub const fn stop(self) -> SessionStop {
        self.stop
    }

    /// Return the number of frame replies emitted
    #[must_use]
    pub const fn frames(self) -> u32 {
        self.frames
    }

    /// Return the number of frame bytes emitted
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}

/// Receive-only helper authority bound to one pre-opened receive source
#[derive(Debug)]
pub struct HelperServer<S> {
    config: HelperConfig,
    transport: HelperTransport,
    held_binding: InterfaceBindingRequest,
    receiver: S,
}

impl<S: ReceiveSocket> HelperServer<S> {
    /// Check the socketpair-time peer and retain the already-bound receive source
    ///
    /// # Errors
    /// Returns an error before any request is accepted when the credential
    /// snapshot, socket channels, or source binding cannot be validated
    pub fn new(
        config: HelperConfig,
        transport: HelperTransport,
        receiver: S,
    ) -> Result<Self, HelperError> {
        let actual = transport.peer_identity()?;
        if actual != config.expected_peer {
            return Err(HelperError::UnauthorizedPeer {
                expected: config.expected_peer,
                actual,
            });
        }
        let held = receiver.binding();
        receiver.revalidate().map_err(HelperError::Binding)?;
        Ok(Self {
            config,
            transport,
            held_binding: held,
            receiver,
        })
    }

    /// Run one bounded receive session until close, cancellation, or a fail-closed error
    ///
    /// The ordinary channel is polled without blocking. A separate controller
    /// thread polls the control channel and sets cancellation before the receive
    /// loop can process another workload message.
    ///
    /// # Errors
    /// Returns an error for malformed IPC, peer closure, identity loss, budget
    /// exhaustion, backend failure, or queue saturation
    pub fn run(mut self) -> Result<SessionReport, HelperError> {
        let started = Instant::now();
        let limits = self.config.limits;
        let budget = SessionBudget::start_at(limits, started)?;
        let deadline = started + limits.duration();
        let shared = Arc::new(SharedState::new(self.config.session, deadline));
        let control = self.transport.clone_control()?;
        let controller_shared = Arc::clone(&shared);
        let controller = thread::Builder::new()
            .name("l2-helper-control".to_owned())
            .spawn(move || control_loop(&control, &controller_shared))
            .map_err(|_| HelperError::WorkerPanicked)?;
        let result = self.run_data_loop(&shared, budget);
        // An accepted cancellation finishes its acknowledgement within the current iteration
        shared.shutdown.store(true, Ordering::Release);
        shared.cancel.cancel();
        let controller_result = controller.join().map_err(|_| HelperError::WorkerPanicked)?;
        match controller_result {
            // Preserve the controller's original failure instead of replacing it with a
            // cancellation report observed by the data worker
            Err(error) => Err(error),
            Ok(()) => result,
        }
    }

    fn run_data_loop(
        &mut self,
        shared: &Arc<SharedState>,
        mut budget: SessionBudget,
    ) -> Result<SessionReport, HelperError> {
        let mut opened = false;
        let mut buffer = vec![0_u8; crate::MAX_IPC_BYTES];
        loop {
            if let Some(report) = Self::control_stop(shared, &budget)? {
                return Ok(report);
            }
            let Some(length) = self.receive_message(shared, &mut buffer)? else {
                if let Some(report) = Self::control_stop(shared, &budget)? {
                    return Ok(report);
                }
                return Err(HelperError::ControlChannelClosed);
            };
            // A request may have been dequeued just before the control worker
            // observed cancellation. Give the dedicated stop path priority.
            if let Some(report) = Self::control_stop(shared, &budget)? {
                return Ok(report);
            }
            let bytes = buffer.get(..length).ok_or(HelperError::Transport(
                TransportError::MessageTooLarge {
                    length,
                    maximum: buffer.len(),
                },
            ))?;
            let message = self.decode_message(bytes)?;
            if let Some(report) = self.handle_message(shared, &mut budget, &mut opened, &message)? {
                return Ok(report);
            }
        }
    }

    fn control_stop(
        shared: &SharedState,
        budget: &SessionBudget,
    ) -> Result<Option<SessionReport>, HelperError> {
        match shared.refresh_terminal_cause()? {
            TerminalCause::CancelAccepted => Ok(Some(SessionReport {
                stop: SessionStop::Cancelled,
                frames: budget.frames(),
                bytes: budget.bytes(),
            })),
            TerminalCause::Deadline => Err(HelperError::Budget(crate::BudgetError::Deadline)),
            TerminalCause::Running if shared.cancel.is_cancelled() => {
                // A controller failure also interrupts the backend, while the
                // controller thread retains the authoritative error result
                Ok(Some(SessionReport {
                    stop: SessionStop::Cancelled,
                    frames: budget.frames(),
                    bytes: budget.bytes(),
                }))
            }
            TerminalCause::CloseAccepted | TerminalCause::Running => Ok(None),
        }
    }

    fn receive_message(
        &self,
        shared: &SharedState,
        buffer: &mut [u8],
    ) -> Result<Option<usize>, HelperError> {
        let length = loop {
            if Self::receive_interrupted(shared)? {
                return Ok(None);
            }
            match self.transport.try_recv_data_into(buffer) {
                Ok(length) => break length,
                Err(TransportError::WouldBlock) => thread::sleep(POLL_DELAY),
                Err(TransportError::PeerClosed) => {
                    // A controller acknowledgement can close the frontend while this poll is in flight
                    if Self::receive_interrupted(shared)? {
                        return Ok(None);
                    }
                    return Err(HelperError::FrontendClosed);
                }
                Err(error) => return Err(HelperError::Transport(error)),
            }
        };
        Ok(Some(length))
    }

    fn receive_interrupted(shared: &SharedState) -> Result<bool, HelperError> {
        match shared.refresh_terminal_cause()? {
            TerminalCause::Deadline => Err(HelperError::Budget(crate::BudgetError::Deadline)),
            TerminalCause::CancelAccepted | TerminalCause::CloseAccepted => Ok(true),
            TerminalCause::Running => Ok(shared.cancel.is_cancelled()),
        }
    }

    fn decode_message<'a>(&self, bytes: &'a [u8]) -> Result<Message<'a>, HelperError> {
        let message = decode(bytes).map_err(HelperError::MalformedIpc)?;
        if message.kind() == MessageKind::Cancel {
            self.report_error(message.sequence(), ReplyErrorCode::ControlChannelRequired);
            return Err(HelperError::CancellationRequiresControlChannel);
        }
        Ok(message)
    }

    fn handle_message(
        &mut self,
        shared: &SharedState,
        budget: &mut SessionBudget,
        opened: &mut bool,
        message: &Message<'_>,
    ) -> Result<Option<SessionReport>, HelperError> {
        if let Some(report) = Self::control_stop(shared, budget)? {
            return Ok(Some(report));
        }
        let action = {
            let mut state = shared
                .state
                .lock()
                .map_err(|_| HelperError::WorkerPanicked)?;
            let action = state.accept(message);
            // Publish a validated close while the peer state lock still excludes
            // a controller cancellation from becoming a late protocol failure
            if matches!(action, Ok(ControlAction::Close))
                && shared.accept_terminal(TerminalCause::CloseAccepted)?
            {
                shared.shutdown.store(true, Ordering::Release);
            }
            drop(state);
            action
        };
        let action = match action {
            Ok(action) => action,
            Err(_) if shared.cancel.is_cancelled() => {
                return Self::control_stop(shared, budget);
            }
            Err(error) => {
                self.report_error(message.sequence(), ReplyErrorCode::Protocol);
                return Err(HelperError::Protocol(error));
            }
        };
        if let Some(report) = Self::control_stop(shared, budget)? {
            return Ok(Some(report));
        }
        match action {
            ControlAction::HandshakeAccepted => self.handle_handshake(message.sequence())?,
            ControlAction::OpenReceive(binding) => {
                if let Some(report) =
                    self.handle_open(shared, budget, *opened, binding, message.sequence())?
                {
                    return Ok(Some(report));
                }
                *opened = true;
            }
            ControlAction::ReceiveNext => {
                return self.handle_receive(shared, budget, *opened, message.sequence());
            }
            ControlAction::Cancel => {
                self.report_error(message.sequence(), ReplyErrorCode::ControlChannelRequired);
                return Err(HelperError::CancellationRequiresControlChannel);
            }
            ControlAction::Close => {
                return Ok(Some(self.handle_close(message.sequence(), budget)?));
            }
        }
        Ok(None)
    }

    fn handle_handshake(&self, sequence: u64) -> Result<(), HelperError> {
        self.send_reply(HelperReply::empty(
            HelperReplyKind::Ready,
            self.config.session,
            sequence,
        )?)
    }

    fn handle_open(
        &self,
        shared: &SharedState,
        budget: &SessionBudget,
        opened: bool,
        requested: InterfaceBindingRequest,
        sequence: u64,
    ) -> Result<Option<SessionReport>, HelperError> {
        if opened {
            self.report_error(sequence, ReplyErrorCode::Protocol);
            return Err(HelperError::InvalidRequest("receive source already opened"));
        }
        let held = self.held_binding;
        if requested != held {
            let error = BindingError::Mismatch { requested, held };
            self.report_error(sequence, ReplyErrorCode::BindingMismatch);
            return Err(HelperError::Binding(error));
        }
        if let Err(error) = self.validate_held_binding() {
            return self.stop_before_error(
                shared,
                budget,
                sequence,
                ReplyErrorCode::BindingMismatch,
                HelperError::Binding(error),
            );
        }
        // Do not publish a successful open after a stop was accepted
        if let Some(report) = Self::control_stop(shared, budget)? {
            return Ok(Some(report));
        }
        self.send_reply(HelperReply::empty(
            HelperReplyKind::Ready,
            self.config.session,
            sequence,
        )?)?;
        Ok(None)
    }

    fn handle_receive(
        &mut self,
        shared: &SharedState,
        budget: &mut SessionBudget,
        opened: bool,
        sequence: u64,
    ) -> Result<Option<SessionReport>, HelperError> {
        if !opened {
            self.report_error(sequence, ReplyErrorCode::ReceiveNotOpen);
            return Err(HelperError::ReceiveNotOpen);
        }
        if let Err(error) = budget.reserve(0) {
            self.report_error(sequence, ReplyErrorCode::Budget);
            return Err(HelperError::Budget(error));
        }
        if let Err(error) = self.validate_held_binding() {
            return self.stop_before_error(
                shared,
                budget,
                sequence,
                ReplyErrorCode::BindingMismatch,
                HelperError::Binding(error),
            );
        }
        let frame = match self.receiver.receive(&shared.cancel) {
            Ok(frame) => frame,
            Err(error) => {
                return self.stop_before_error(
                    shared,
                    budget,
                    sequence,
                    ReplyErrorCode::Backend,
                    error,
                );
            }
        };
        if let Some(report) = Self::control_stop(shared, budget)? {
            return Ok(Some(report));
        }
        // A link can be replaced while the backend waits. Revalidate again
        // before exposing the returned record to the frontend.
        if let Err(error) = self.validate_held_binding() {
            return self.stop_before_error(
                shared,
                budget,
                sequence,
                ReplyErrorCode::BindingMismatch,
                HelperError::Binding(error),
            );
        }
        // Recheck after backend validation so a late stop cannot become an Empty reply
        if let Some(report) = Self::control_stop(shared, budget)? {
            return Ok(Some(report));
        }
        let Some(frame) = frame else {
            self.send_reply(HelperReply::empty(
                HelperReplyKind::Empty,
                self.config.session,
                sequence,
            )?)?;
            return Ok(None);
        };
        self.send_frame_reply(budget, sequence, &frame)
    }

    fn validate_held_binding(&self) -> Result<(), BindingError> {
        if self.receiver.binding() != self.held_binding {
            return Err(BindingError::IdentityLost);
        }
        self.receiver.revalidate()
    }

    fn stop_before_error(
        &self,
        shared: &SharedState,
        budget: &SessionBudget,
        sequence: u64,
        code: ReplyErrorCode,
        error: HelperError,
    ) -> Result<Option<SessionReport>, HelperError> {
        // Work can finish after cancellation or deadline; terminal state wins
        if let Some(report) = Self::control_stop(shared, budget)? {
            return Ok(Some(report));
        }
        self.report_error(sequence, code);
        Err(error)
    }

    fn send_frame_reply(
        &self,
        budget: &mut SessionBudget,
        sequence: u64,
        frame: &[u8],
    ) -> Result<Option<SessionReport>, HelperError> {
        if frame.len() > crate::MAX_FRAME_BYTES {
            self.report_error(sequence, ReplyErrorCode::Backend);
            return Err(HelperError::InvalidRequest(
                "backend returned an oversized frame",
            ));
        }
        if let Err(error) = budget.reserve(frame.len()) {
            self.report_error(sequence, ReplyErrorCode::Budget);
            return Err(HelperError::Budget(error));
        }
        let reply = HelperReply::frame(self.config.session, sequence, frame)?;
        self.send_reply(reply)?;
        // Accounting follows the successful nonblocking enqueue. A failed
        // transport operation therefore cannot consume session budget.
        budget.commit_reserved(frame.len())?;
        Ok(None)
    }

    fn handle_close(
        &self,
        sequence: u64,
        budget: &SessionBudget,
    ) -> Result<SessionReport, HelperError> {
        self.send_reply(HelperReply::empty(
            HelperReplyKind::Closed,
            self.config.session,
            sequence,
        )?)?;
        Ok(SessionReport {
            stop: SessionStop::Closed,
            frames: budget.frames(),
            bytes: budget.bytes(),
        })
    }

    fn send_reply(&self, reply: HelperReply<'_>) -> Result<(), HelperError> {
        let mut encoded = vec![0_u8; crate::MAX_IPC_BYTES];
        let length = encode_reply(&reply, &mut encoded)?;
        self.transport.try_send_data(
            encoded
                .get(..length)
                .ok_or(HelperError::Reply(crate::ReplyError::LengthOverflow))?,
        )?;
        Ok(())
    }

    fn report_error(&self, sequence: u64, code: ReplyErrorCode) {
        // Reporting is best effort after terminal rejection; retain the original cause
        if let Ok(reply) = HelperReply::error(self.config.session, sequence, code) {
            let _ = self.send_reply(reply);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum TerminalCause {
    Running = 0,
    CloseAccepted = 1,
    CancelAccepted = 2,
    Deadline = 3,
}

struct SharedState {
    state: Mutex<PeerState>,
    cancel: CancellationToken,
    shutdown: AtomicBool,
    terminal: Mutex<TerminalCause>,
    deadline: Instant,
}

impl SharedState {
    fn new(session: SessionId, deadline: Instant) -> Self {
        Self {
            state: Mutex::new(PeerState::new(session)),
            cancel: CancellationToken::new(),
            shutdown: AtomicBool::new(false),
            terminal: Mutex::new(TerminalCause::Running),
            deadline,
        }
    }

    fn refresh_terminal_cause(&self) -> Result<TerminalCause, HelperError> {
        let mut terminal = self
            .terminal
            .lock()
            .map_err(|_| HelperError::WorkerPanicked)?;
        if Instant::now() >= self.deadline && *terminal == TerminalCause::Running {
            *terminal = TerminalCause::Deadline;
            // Wake a cooperative backend only when the deadline wins the race
            self.cancel.cancel();
        }
        Ok(*terminal)
    }

    fn accept_terminal(&self, cause: TerminalCause) -> Result<bool, HelperError> {
        debug_assert!(matches!(
            cause,
            TerminalCause::CloseAccepted | TerminalCause::CancelAccepted
        ));
        let mut terminal = self
            .terminal
            .lock()
            .map_err(|_| HelperError::WorkerPanicked)?;
        if Instant::now() >= self.deadline && *terminal == TerminalCause::Running {
            // Deadline arbitration shares this lock with close and cancellation
            *terminal = TerminalCause::Deadline;
            self.cancel.cancel();
        }
        if *terminal != TerminalCause::Running {
            return Ok(false);
        }
        *terminal = cause;
        drop(terminal);
        if cause == TerminalCause::CancelAccepted {
            self.cancel.cancel();
        }
        Ok(true)
    }
}

fn control_loop(
    control: &crate::transport::SeqPacketSocket,
    shared: &SharedState,
) -> Result<(), HelperError> {
    let mut buffer = vec![0_u8; crate::MAX_IPC_BYTES];
    while !shared.shutdown.load(Ordering::Acquire) {
        if shared.refresh_terminal_cause()? != TerminalCause::Running {
            return Ok(());
        }
        let Some(length) = poll_control(control, shared, &mut buffer)? else {
            if !shared.shutdown.load(Ordering::Acquire) {
                thread::sleep(POLL_DELAY);
            }
            continue;
        };
        let bytes = buffer.get(..length).ok_or(HelperError::Transport(
            TransportError::MessageTooLarge {
                length,
                maximum: buffer.len(),
            },
        ))?;
        let message = match decode(bytes) {
            Ok(message) => message,
            Err(error) => {
                // Hold the peer-state lock while deciding whether a data close won
                // the terminal race against this malformed control record
                let _state = shared
                    .state
                    .lock()
                    .map_err(|_| HelperError::WorkerPanicked)?;
                if shared.shutdown.load(Ordering::Acquire) {
                    return Ok(());
                }
                return control_failure(shared, HelperError::MalformedIpc(error));
            }
        };
        if !accept_control(&message, shared)? {
            // A validated data close won the terminal arbitration
            return Ok(());
        }
        if let Err(error) = send_control_reply(control, &message) {
            // Cancellation remains effective even when a peer has saturated its reply queue
            return control_failure(shared, error);
        }
        // A successful cancellation acknowledgement is the controller's terminal exchange
        return Ok(());
    }
    Ok(())
}

fn poll_control(
    control: &crate::transport::SeqPacketSocket,
    shared: &SharedState,
    buffer: &mut [u8],
) -> Result<Option<usize>, HelperError> {
    match control.try_recv_into(buffer) {
        Ok(length) => Ok(Some(length)),
        Err(TransportError::WouldBlock) => Ok(None),
        Err(TransportError::PeerClosed) if shared.shutdown.load(Ordering::Acquire) => Ok(None),
        Err(TransportError::PeerClosed) => {
            control_failure(shared, HelperError::ControlChannelClosed)
        }
        Err(error) => control_failure(shared, HelperError::Transport(error)),
    }
}

fn accept_control(
    message: &l2_helper_protocol::Message<'_>,
    shared: &SharedState,
) -> Result<bool, HelperError> {
    let mut state = shared
        .state
        .lock()
        .map_err(|_| HelperError::WorkerPanicked)?;
    if shared.shutdown.load(Ordering::Acquire) {
        return Ok(false);
    }
    if message.kind() != MessageKind::Cancel {
        return control_failure(
            shared,
            HelperError::InvalidRequest("control channel only accepts cancel"),
        );
    }
    match state.accept(message) {
        Ok(ControlAction::Cancel) => {
            // Claim terminal authority while the state lock still excludes close
            shared.accept_terminal(TerminalCause::CancelAccepted)
        }
        Ok(_) => control_failure(
            shared,
            HelperError::Protocol(l2_helper_protocol::ProtocolError::UnexpectedMessageKind(
                MessageKind::Cancel,
            )),
        ),
        Err(error) => control_failure(shared, HelperError::Protocol(error)),
    }
}

fn send_control_reply(
    control: &crate::transport::SeqPacketSocket,
    message: &l2_helper_protocol::Message<'_>,
) -> Result<(), HelperError> {
    let reply = HelperReply::empty(
        HelperReplyKind::Cancelled,
        message.session(),
        message.sequence(),
    )?;
    let mut encoded = vec![0_u8; crate::MAX_IPC_BYTES];
    let length = encode_reply(&reply, &mut encoded)?;
    let encoded = encoded
        .get(..length)
        .ok_or(HelperError::Reply(crate::ReplyError::LengthOverflow))?;
    control.try_send(encoded).map_err(HelperError::Transport)
}

fn control_failure<T>(shared: &SharedState, error: HelperError) -> Result<T, HelperError> {
    shared.cancel.cancel();
    Err(error)
}
