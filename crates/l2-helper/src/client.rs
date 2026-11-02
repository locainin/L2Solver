use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use l2_helper_protocol::{Message, MessageKind, SessionId, encode};

use crate::{
    FrontendTransport, HelperError, HelperReplyKind, HelperReplyOwned, InterfaceBindingRequest,
    SessionId as PublicSessionId, TransportError, decode_reply,
};

mod failure;
use failure::RequestFailure;

#[cfg(test)]
#[path = "../tests/client/sequence_boundaries.rs"]
mod sequence_boundaries;

/// Hard upper bound for one frontend request waiting for a helper reply
pub const MAX_FRONTEND_REPLY_WAIT: Duration = Duration::from_mins(5);

// Keep client-side sequence allocation separate from the helper's authoritative state
#[derive(Debug)]
struct ClientState {
    session: SessionId,
    next_sequence: AtomicU64,
    health: AtomicU8,
    data_request_lock: Mutex<()>,
    // This gate covers the health check and the workload send as one action
    workload_start_gate: Mutex<()>,
    // Holding this lock means cancellation is in flight; retain its terminal result
    control_request: Mutex<Option<Result<HelperReplyOwned, RequestFailure>>>,
}

// Shared lifecycle state controls every clone of one frontend client
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ClientHealth {
    Healthy = 0,
    Stopping = 1,
    Poisoned = 2,
    Closed = 3,
}

/// Frontend view of one receive-only helper session
#[derive(Debug)]
pub struct FrontendClient {
    transport: FrontendTransport,
    state: Arc<ClientState>,
    reply_wait: Duration,
}

impl FrontendClient {
    /// Create a client for the launch-specific session identity
    #[must_use]
    pub fn new(transport: FrontendTransport, session: PublicSessionId) -> Self {
        Self::from_parts(transport, session, MAX_FRONTEND_REPLY_WAIT)
    }

    /// Create a client with a shorter bounded reply deadline
    ///
    /// # Errors
    /// Returns an error when the requested deadline is zero or exceeds the
    /// helper's hard upper bound
    pub fn with_reply_timeout(
        transport: FrontendTransport,
        session: PublicSessionId,
        reply_wait: Duration,
    ) -> Result<Self, HelperError> {
        if reply_wait.is_zero() {
            return Err(HelperError::InvalidRequest(
                "frontend reply timeout must be nonzero",
            ));
        }
        if reply_wait > MAX_FRONTEND_REPLY_WAIT {
            return Err(HelperError::InvalidRequest(
                "frontend reply timeout exceeds helper ceiling",
            ));
        }
        Ok(Self::from_parts(transport, session, reply_wait))
    }

    fn from_parts(
        transport: FrontendTransport,
        session: PublicSessionId,
        reply_wait: Duration,
    ) -> Self {
        Self {
            transport,
            state: Arc::new(ClientState {
                session,
                next_sequence: AtomicU64::new(1),
                health: AtomicU8::new(ClientHealth::Healthy as u8),
                data_request_lock: Mutex::new(()),
                workload_start_gate: Mutex::new(()),
                control_request: Mutex::new(None),
            }),
            reply_wait,
        }
    }

    /// Clone the two channels and sequence allocator for a concurrent cancel
    /// caller
    ///
    /// # Errors
    /// Returns an error if the operating system cannot duplicate either channel
    pub fn try_clone(&self) -> Result<Self, HelperError> {
        Ok(Self {
            transport: self.transport.try_clone().map_err(HelperError::Transport)?,
            state: Arc::clone(&self.state),
            reply_wait: self.reply_wait,
        })
    }

    /// Return the launch-specific session identity
    #[must_use]
    pub fn session(&self) -> SessionId {
        self.state.session
    }

    /// Send the required handshake on the ordinary request channel
    ///
    /// # Errors
    /// Returns an error if transport, protocol, or helper validation fails
    pub fn hello(&self) -> Result<HelperReplyKind, HelperError> {
        let reply = self.request(MessageKind::Hello, &[])?;
        reply_result(&reply)
    }

    /// Ask the helper to open its already-bound receive source
    ///
    /// # Errors
    /// Returns an error if the binding is not held by the helper or transport
    /// validation fails
    pub fn open_receive(
        &self,
        binding: InterfaceBindingRequest,
    ) -> Result<HelperReplyKind, HelperError> {
        let mut payload = [0_u8; InterfaceBindingRequest::ENCODED_LENGTH];
        binding.encode(&mut payload)?;
        let reply = self.request(MessageKind::OpenReceive, &payload)?;
        reply_result(&reply)
    }

    /// Request one frame from the held receive source
    ///
    /// # Errors
    /// Returns an error if the helper rejects the receive request or transport
    /// validation fails
    pub fn receive_next(&self) -> Result<ClientReply, HelperError> {
        let reply = self.request(MessageKind::ReceiveNext, &[])?;
        // The exchange already restricted successful receive replies to Frame or Empty
        if reply_result(&reply)? == HelperReplyKind::Frame {
            Ok(ClientReply::Frame(reply.into_payload()))
        } else {
            Ok(ClientReply::Empty)
        }
    }

    /// Request cancellation on the dedicated control channel
    ///
    /// All clones share the first cancellation result, including a failure
    ///
    /// # Errors
    /// Returns an error if cancellation is rejected or the control channel fails
    pub fn cancel(&self) -> Result<HelperReplyKind, HelperError> {
        let mut cancellation = self
            .state
            .control_request
            .lock()
            .map_err(|_| HelperError::WorkerPanicked)?;
        // A completed cancellation keeps its original wire result for every clone
        if let Some(result) = cancellation.as_ref() {
            return match result {
                Ok(reply) => reply_result(reply),
                Err(error) => Err(error.to_helper_error()),
            };
        }

        // Revoke new workload before putting a stop request on the control channel
        {
            let _start = self
                .state
                .workload_start_gate
                .lock()
                .map_err(|_| HelperError::WorkerPanicked)?;
            match self.health() {
                ClientHealth::Healthy => {
                    self.state
                        .health
                        .store(ClientHealth::Stopping as u8, Ordering::Release);
                }
                ClientHealth::Stopping => return Err(HelperError::SessionStopping),
                ClientHealth::Closed => return Err(HelperError::SessionClosed),
                // A workload failure can still request one best-effort stop
                ClientHealth::Poisoned => {}
            }
        }

        // Only the first caller sends; waiting clones reuse success or failure
        let exchanged = self.exchange(MessageKind::Cancel, &[]);
        let result = match &exchanged {
            Ok(reply) => reply_result(reply),
            Err(error) => Err(error.to_helper_error()),
        };
        if result.is_err() {
            // Rejection, timeout, transport failure, and reply corruption are terminal
            self.poison_session();
        } else if matches!(result, Ok(HelperReplyKind::Cancelled)) {
            // Acknowledged cancellation ends workload authority for every clone
            self.close_session();
        }
        *cancellation = Some(exchanged);
        result
    }

    /// Close a running session on the ordinary request channel
    ///
    /// # Errors
    /// Returns an error if the helper rejects close or the data channel fails
    pub fn close(&self) -> Result<HelperReplyKind, HelperError> {
        let reply = self.request(MessageKind::Close, &[])?;
        reply_result(&reply)
    }

    fn request(&self, kind: MessageKind, payload: &[u8]) -> Result<HelperReplyOwned, HelperError> {
        // Keep data requests in sequence so replies cannot be consumed by another caller
        let _guard = self
            .state
            .data_request_lock
            .lock()
            .map_err(|_| HelperError::WorkerPanicked)?;
        let reply = match self.exchange(kind, payload) {
            Ok(reply) => reply,
            Err(error) => {
                let result = Err(error.to_helper_error());
                if self.health() == ClientHealth::Poisoned
                    && !matches!(error, RequestFailure::SessionPoisoned)
                {
                    // Preserve the original exchange failure if the stop also fails
                    let _ = self.cancel();
                }
                return result;
            }
        };

        if reply.kind() == HelperReplyKind::Error {
            // Every real helper error path exits, so retain the semantic error and fail closed
            let error = ClientReplyError::from_reply(&reply);
            self.poison_session();
            let _ = self.cancel();
            return Err(error);
        }
        if kind == MessageKind::Close && reply.kind() == HelperReplyKind::Closed {
            // Publish Closed while the data request lock still excludes new workload
            self.close_session();
        }
        Ok(reply)
    }

    fn exchange(
        &self,
        kind: MessageKind,
        payload: &[u8],
    ) -> Result<HelperReplyOwned, RequestFailure> {
        // Callers own the channel lock; this layer never requests cancellation
        let control = kind == MessageKind::Cancel;
        let mut request = [0_u8; l2_helper_protocol::MAX_MESSAGE_LENGTH];
        let sequence = if control {
            let (next_sequence, length) = self.encode_request(kind, payload, &mut request)?;
            let request = request.get(..length).ok_or(RequestFailure::InvalidRequest(
                "encoded request exceeded its buffer",
            ))?;
            if let Err(error) = self.transport.try_send_cancel(request) {
                // A control send failure cannot be retried safely
                self.poison_session();
                return Err(RequestFailure::Transport(error));
            }
            next_sequence
        } else {
            let _start = self
                .state
                .workload_start_gate
                .lock()
                .map_err(|_| RequestFailure::SessionPoisoned)?;
            self.ensure_workload_healthy()?;
            let (next_sequence, length) = self.encode_request(kind, payload, &mut request)?;
            let request = request.get(..length).ok_or(RequestFailure::InvalidRequest(
                "encoded request exceeded its buffer",
            ))?;
            match self.transport.try_send(request) {
                Ok(()) => {}
                Err(TransportError::WouldBlock) => {
                    // A full workload queue is retryable and does not poison the session
                    return Err(RequestFailure::Transport(TransportError::WouldBlock));
                }
                Err(error) => {
                    // Every other send failure means the stream cannot be trusted
                    self.poison_session();
                    return Err(RequestFailure::Transport(error));
                }
            }
            next_sequence
        };
        let started = Instant::now();
        // Reuse bounded storage while polling an empty socket
        let mut buffer = vec![0; crate::MAX_IPC_BYTES];
        let length = loop {
            if started.elapsed() >= self.reply_wait {
                self.poison_session();
                return Err(RequestFailure::ReplyTimeout);
            }
            let bytes = self.transport.try_recv_into(control, &mut buffer);
            match bytes {
                Ok(bytes) => break bytes,
                Err(TransportError::WouldBlock) => thread::sleep(Duration::from_millis(2)),
                Err(error) => {
                    // A consumed oversized record or failed receive cannot preserve the stream
                    self.poison_session();
                    return Err(RequestFailure::Transport(error));
                }
            }
        };
        let reply = buffer.get(..length).ok_or_else(|| {
            self.poison_session();
            RequestFailure::InvalidRequest("reply exceeded receive buffer")
        })?;
        let reply = decode_reply(reply).inspect_err(|_| self.poison_session())?;
        if reply.session() != self.state.session {
            self.poison_session();
            return Err(RequestFailure::InvalidRequest(
                "reply session did not match request",
            ));
        }
        if reply.sequence() != sequence {
            self.poison_session();
            return Err(RequestFailure::InvalidRequest(
                "reply sequence did not match request",
            ));
        }
        if !reply_kind_matches(kind, reply.kind()) {
            self.poison_session();
            return Err(RequestFailure::InvalidRequest(
                "helper returned an unexpected reply",
            ));
        }
        Ok(reply.into_owned())
    }

    fn encode_request(
        &self,
        kind: MessageKind,
        payload: &[u8],
        destination: &mut [u8],
    ) -> Result<(u64, usize), RequestFailure> {
        let sequence = self.next_sequence()?;
        let message = Message::new(kind, self.state.session, sequence, payload)?;
        let length = encode(&message, destination)?;
        Ok((sequence, length))
    }

    fn ensure_workload_healthy(&self) -> Result<(), RequestFailure> {
        match self.health() {
            ClientHealth::Healthy => Ok(()),
            ClientHealth::Stopping => Err(RequestFailure::SessionStopping),
            ClientHealth::Closed => Err(RequestFailure::SessionClosed),
            ClientHealth::Poisoned => Err(RequestFailure::SessionPoisoned),
        }
    }

    fn poison_session(&self) {
        let _ = self
            .state
            .health
            .try_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |current| match current {
                    value if value == ClientHealth::Closed as u8 => None,
                    value if value == ClientHealth::Poisoned as u8 => None,
                    _ => Some(ClientHealth::Poisoned as u8),
                },
            );
    }

    fn close_session(&self) {
        let _ = self
            .state
            .health
            .try_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |current| match current {
                    value if value == ClientHealth::Poisoned as u8 => None,
                    value if value == ClientHealth::Closed as u8 => None,
                    _ => Some(ClientHealth::Closed as u8),
                },
            );
    }

    fn health(&self) -> ClientHealth {
        match self.state.health.load(Ordering::Acquire) {
            value if value == ClientHealth::Healthy as u8 => ClientHealth::Healthy,
            value if value == ClientHealth::Stopping as u8 => ClientHealth::Stopping,
            value if value == ClientHealth::Closed as u8 => ClientHealth::Closed,
            _ => ClientHealth::Poisoned,
        }
    }

    fn next_sequence(&self) -> Result<u64, RequestFailure> {
        let sequence = self.state.next_sequence.try_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| current.checked_add(1),
        );
        sequence.map_err(|_| {
            // Exhaustion ends this shared session; a new helper must start a new counter
            self.poison_session();
            RequestFailure::InvalidRequest("request sequence exhausted")
        })
    }
}

fn reply_result(reply: &HelperReplyOwned) -> Result<HelperReplyKind, HelperError> {
    if reply.kind() == HelperReplyKind::Error {
        Err(ClientReplyError::from_reply(reply))
    } else {
        Ok(reply.kind())
    }
}

fn reply_kind_matches(request: MessageKind, reply: HelperReplyKind) -> bool {
    // A valid rejection preserves framing and identity, even when the operation failed
    reply == HelperReplyKind::Error
        || match request {
            MessageKind::Hello | MessageKind::OpenReceive => reply == HelperReplyKind::Ready,
            MessageKind::ReceiveNext => {
                matches!(reply, HelperReplyKind::Frame | HelperReplyKind::Empty)
            }
            MessageKind::Cancel => reply == HelperReplyKind::Cancelled,
            MessageKind::Close => reply == HelperReplyKind::Closed,
        }
}

/// Frontend-owned result of one receive poll
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientReply {
    /// One bounded frame returned by the helper
    Frame(Vec<u8>),
    /// No frame was ready at the time of the poll
    Empty,
}

// Keep the error-code mapping at the frontend edge so reply bytes never become authority
struct ClientReplyError;

impl ClientReplyError {
    fn from_reply(reply: &HelperReplyOwned) -> HelperError {
        let code = reply
            .payload()
            .get(..2)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u16::from_be_bytes)
            .unwrap_or_default();
        match code {
            3 => HelperError::Binding(crate::BindingError::IdentityLost),
            4 => HelperError::RemoteBudgetExhausted,
            7 => HelperError::CancellationRequiresControlChannel,
            8 => HelperError::ReceiveNotOpen,
            _ => HelperError::InvalidRequest("helper rejected the request"),
        }
    }
}
