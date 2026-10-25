use std::io;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use l2_helper::{
    BindingError, ClientReply, FrontendClient, FrontendTransport, HelperConfig, HelperError,
    HelperReplyKind, HelperServer, InterfaceBindingRequest, PeerIdentity, QueueReceiveSocket,
    ReceiveSocket, SessionId, SessionLimits, SessionStop, TransportError, decode_reply,
};
use l2_helper_protocol::{Message, MessageKind, encode};

mod support;

#[path = "server/deadline.rs"]
mod deadline;
#[path = "server/shutdown.rs"]
mod shutdown;
#[path = "server/terminal_race.rs"]
mod terminal_race;

fn session(value: u8) -> Result<SessionId, l2_helper::HelperError> {
    Ok(SessionId::new([value; 16])?)
}

fn binding(value: u8) -> Result<InterfaceBindingRequest, l2_helper::HelperError> {
    Ok(InterfaceBindingRequest::new(10, 20, u32::from(value), 1)?)
}

fn server_config(session: SessionId) -> Result<HelperConfig, l2_helper::HelperError> {
    Ok(HelperConfig::new(
        session,
        PeerIdentity::current(),
        SessionLimits::new(10, 1_024, Duration::from_secs(5))?,
    ))
}

fn assert_no_error_reply(frontend: &FrontendTransport) -> Result<(), Box<dyn std::error::Error>> {
    match frontend.try_recv() {
        Ok(bytes) => {
            let reply = decode_reply(&bytes)?;
            assert_ne!(
                reply.kind(),
                HelperReplyKind::Error,
                "helper emitted a late backend error reply"
            );
        }
        Err(TransportError::WouldBlock | TransportError::PeerClosed) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[test]
fn receive_session_bound_receive_only() -> Result<(), Box<dyn std::error::Error>> {
    let session = session(1)?;
    let binding = binding(1)?;
    let Some((transport, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let client = FrontendClient::new(transport, session);
    let receiver = QueueReceiveSocket::new(binding, vec![vec![0xaa, 0xbb]])?;
    let server = HelperServer::new(server_config(session)?, helper_transport, receiver)?;
    let worker = thread::spawn(move || server.run());

    assert_eq!(client.hello()?, HelperReplyKind::Ready);
    assert_eq!(client.open_receive(binding)?, HelperReplyKind::Ready);
    assert_eq!(client.receive_next()?, ClientReply::Frame(vec![0xaa, 0xbb]));
    assert_eq!(client.receive_next()?, ClientReply::Empty);
    assert_eq!(client.close()?, HelperReplyKind::Closed);

    let report = worker.join().map_err(|_| "helper worker panicked")??;
    assert_eq!(report.stop(), SessionStop::Closed);
    assert_eq!(report.frames(), 1);
    assert_eq!(report.bytes(), 2);
    Ok(())
}

#[test]
fn binding_mismatch_fails_closed_receive() -> Result<(), Box<dyn std::error::Error>> {
    let session = session(2)?;
    let held = binding(1)?;
    let requested = binding(2)?;
    let Some((transport, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let client = FrontendClient::new(transport, session);
    let receiver = QueueReceiveSocket::new(held, vec![vec![1]])?;
    let server = HelperServer::new(server_config(session)?, helper_transport, receiver)?;
    let worker = thread::spawn(move || server.run());

    assert_eq!(client.hello()?, HelperReplyKind::Ready);
    assert!(matches!(
        client.open_receive(requested),
        Err(HelperError::Binding(BindingError::IdentityLost))
    ));
    let error = worker.join().map_err(|_| "helper worker panicked")?;
    assert!(matches!(
        error,
        Err(HelperError::Binding(BindingError::Mismatch { .. }))
    ));
    Ok(())
}

#[test]
fn malformed_ipc_rejected_session_closes() -> Result<(), Box<dyn std::error::Error>> {
    let session = session(3)?;
    let binding = binding(3)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let receiver = QueueReceiveSocket::new(binding, vec![])?;
    let server = HelperServer::new(server_config(session)?, helper_transport, receiver)?;
    let worker = thread::spawn(move || server.run());
    frontend.try_send(b"not a helper message")?;
    let result = worker.join().map_err(|_| "helper worker panicked")?;
    assert!(matches!(result, Err(HelperError::MalformedIpc(_))));
    Ok(())
}

#[test]
fn cancellation_unblocks_receive() -> Result<(), Box<dyn std::error::Error>> {
    let session = session(4)?;
    let binding = binding(4)?;
    let Some((transport, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let client = FrontendClient::new(transport, session);
    let receiver = BlockingReceiveSocket::new(binding);
    let server = HelperServer::new(server_config(session)?, helper_transport, receiver)?;
    let worker = thread::spawn(move || server.run());
    assert_eq!(client.hello()?, HelperReplyKind::Ready);
    assert_eq!(client.open_receive(binding)?, HelperReplyKind::Ready);

    let receive_client = client.try_clone()?;
    let receive = thread::spawn(move || receive_client.receive_next());
    thread::sleep(Duration::from_millis(10));
    let started = Instant::now();
    assert_eq!(client.cancel()?, HelperReplyKind::Cancelled);
    assert!(started.elapsed() < Duration::from_secs(1));
    let receive_result = receive.join().map_err(|_| "receive client panicked")?;
    assert!(receive_result.is_err());
    let report = worker.join().map_err(|_| "helper worker panicked")??;
    assert_eq!(report.stop(), SessionStop::Cancelled);
    Ok(())
}

#[test]
fn cancellation_is_available_before_handshake() -> Result<(), Box<dyn std::error::Error>> {
    let session = session(5)?;
    let binding = binding(5)?;
    let Some((transport, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let client = FrontendClient::new(transport, session);
    let receiver = QueueReceiveSocket::new(binding, vec![])?;
    let server = HelperServer::new(server_config(session)?, helper_transport, receiver)?;
    let worker = thread::spawn(move || server.run());
    assert_eq!(client.cancel()?, HelperReplyKind::Cancelled);
    let report = worker.join().map_err(|_| "helper worker panicked")??;
    assert_eq!(report.stop(), SessionStop::Cancelled);
    Ok(())
}

#[test]
fn session_budget_stops_second_frame() -> Result<(), Box<dyn std::error::Error>> {
    let session = session(6)?;
    let binding = binding(6)?;
    let config = HelperConfig::new(
        session,
        PeerIdentity::current(),
        SessionLimits::new(1, 100, Duration::from_secs(5))?,
    );
    let Some((transport, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let client = FrontendClient::new(transport, session);
    let receiver = QueueReceiveSocket::new(binding, vec![vec![1], vec![2]])?;
    let server = HelperServer::new(config, helper_transport, receiver)?;
    let worker = thread::spawn(move || server.run());
    client.hello()?;
    client.open_receive(binding)?;
    assert_eq!(client.receive_next()?, ClientReply::Frame(vec![1]));
    assert!(matches!(
        client.receive_next(),
        Err(HelperError::RemoteBudgetExhausted)
    ));
    let result = worker.join().map_err(|_| "helper worker panicked")?;
    assert!(matches!(result, Err(HelperError::Budget(_))));
    Ok(())
}

#[test]
fn revalidation_rejects_link_replacement() -> Result<(), Box<dyn std::error::Error>> {
    let session = session(7)?;
    let held = binding(7)?;
    let Some((transport, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let client = FrontendClient::new(transport, session);
    let valid = Arc::new(AtomicBool::new(true));
    let receiver = RevalidatingReceiveSocket::new(held, Arc::clone(&valid));
    let server = HelperServer::new(server_config(session)?, helper_transport, receiver)?;
    let worker = thread::spawn(move || server.run());
    client.hello()?;
    client.open_receive(held)?;
    valid.store(false, Ordering::Release);
    assert!(matches!(
        client.receive_next(),
        Err(HelperError::Binding(BindingError::IdentityLost))
    ));
    let result = worker.join().map_err(|_| "helper worker panicked")?;
    assert!(matches!(
        result,
        Err(HelperError::Binding(BindingError::IdentityLost))
    ));
    Ok(())
}

#[test]
fn binding_revalidation_runs_again_receive() -> Result<(), Box<dyn std::error::Error>> {
    let session = session(71)?;
    let held = binding(71)?;
    let Some((transport, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let client = FrontendClient::new(transport, session);
    let valid = Arc::new(AtomicBool::new(true));
    let receiver = RevalidatingReceiveSocket::invalidates_after_receive(held, Arc::clone(&valid));
    let server = HelperServer::new(server_config(session)?, helper_transport, receiver)?;
    let worker = thread::spawn(move || server.run());
    client.hello()?;
    client.open_receive(held)?;
    assert!(matches!(
        client.receive_next(),
        Err(HelperError::Binding(BindingError::IdentityLost))
    ));
    let result = worker.join().map_err(|_| "helper worker panicked")?;
    assert!(matches!(
        result,
        Err(HelperError::Binding(BindingError::IdentityLost))
    ));
    Ok(())
}

#[test]
fn rejects_unauthorized_peer_identity() -> Result<(), Box<dyn std::error::Error>> {
    let session = session(8)?;
    let held = binding(8)?;
    let Some((transport, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let peer = PeerIdentity::current();
    let unauthorized = PeerIdentity::new(peer.uid(), peer.pid().saturating_add(1));
    let receiver = QueueReceiveSocket::new(held, vec![])?;
    let config = HelperConfig::new(
        session,
        unauthorized,
        SessionLimits::new(10, 1_024, Duration::from_secs(5))?,
    );
    let result = HelperServer::new(config, helper_transport, receiver);
    assert!(matches!(result, Err(HelperError::UnauthorizedPeer { .. })));
    drop(transport);
    Ok(())
}

#[test]
fn duplicate_sequence_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let session = session(9)?;
    let held = binding(9)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let receiver = QueueReceiveSocket::new(held, vec![])?;
    let server = HelperServer::new(server_config(session)?, helper_transport, receiver)?;
    let worker = thread::spawn(move || server.run());
    let hello = Message::new(MessageKind::Hello, session, 1, &[])?;
    let mut encoded = [0_u8; l2_helper_protocol::MAX_MESSAGE_LENGTH];
    let length = encode(&hello, &mut encoded)?;
    frontend.try_send(encoded.get(..length).ok_or("hello boundary")?)?;
    loop {
        match frontend.try_recv() {
            Ok(_) => break,
            Err(l2_helper::TransportError::WouldBlock) => thread::yield_now(),
            Err(error) => return Err(Box::new(error)),
        }
    }
    frontend.try_send(encoded.get(..length).ok_or("hello boundary")?)?;
    let result = worker.join().map_err(|_| "helper worker panicked")?;
    assert!(matches!(
        result,
        Err(HelperError::Protocol(
            l2_helper_protocol::ProtocolError::SequenceNotIncreasing
        ))
    ));
    Ok(())
}

#[test]
fn malformed_control_cannot_turn_workload() -> Result<(), Box<dyn std::error::Error>> {
    let session = session(10)?;
    let held = binding(10)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let receiver = QueueReceiveSocket::new(held, vec![])?;
    let server = HelperServer::new(server_config(session)?, helper_transport, receiver)?;
    let worker = thread::spawn(move || server.run());
    frontend.try_send_cancel(b"bad control record")?;
    let result = worker.join().map_err(|_| "helper worker panicked")?;
    assert!(matches!(result, Err(HelperError::MalformedIpc(_))));
    Ok(())
}

#[derive(Debug)]
struct BlockingReceiveSocket {
    binding: InterfaceBindingRequest,
}

#[derive(Clone, Copy, Debug)]
enum DelayedReceiveOutcome {
    Empty,
    BackendError,
}

#[derive(Debug)]
struct DelayedReceiveSocket {
    binding: InterfaceBindingRequest,
    delay: Duration,
    started: std::sync::mpsc::SyncSender<()>,
    outcome: DelayedReceiveOutcome,
    wait_for_cancellation: bool,
}

#[derive(Debug)]
struct RevalidatingReceiveSocket {
    binding: InterfaceBindingRequest,
    valid: Arc<AtomicBool>,
    invalidate_after_receive: bool,
}

impl RevalidatingReceiveSocket {
    const fn new(binding: InterfaceBindingRequest, valid: Arc<AtomicBool>) -> Self {
        Self {
            binding,
            valid,
            invalidate_after_receive: false,
        }
    }

    const fn invalidates_after_receive(
        binding: InterfaceBindingRequest,
        valid: Arc<AtomicBool>,
    ) -> Self {
        Self {
            binding,
            valid,
            invalidate_after_receive: true,
        }
    }
}

impl ReceiveSocket for RevalidatingReceiveSocket {
    fn binding(&self) -> InterfaceBindingRequest {
        self.binding
    }

    fn revalidate(&self) -> Result<(), BindingError> {
        if self.valid.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(BindingError::IdentityLost)
        }
    }

    fn receive(
        &mut self,
        cancellation: &l2_helper::CancellationToken,
    ) -> Result<Option<Vec<u8>>, HelperError> {
        if cancellation.is_cancelled() {
            Ok(None)
        } else {
            if self.invalidate_after_receive {
                self.valid.store(false, Ordering::Release);
            }
            Ok(Some(vec![1]))
        }
    }
}

impl BlockingReceiveSocket {
    const fn new(binding: InterfaceBindingRequest) -> Self {
        Self { binding }
    }
}

impl DelayedReceiveSocket {
    const fn cancellation_returns_empty(
        binding: InterfaceBindingRequest,
        delay: Duration,
        started: std::sync::mpsc::SyncSender<()>,
    ) -> Self {
        Self {
            binding,
            delay,
            started,
            outcome: DelayedReceiveOutcome::Empty,
            wait_for_cancellation: true,
        }
    }

    const fn cancellation_returns_backend_error(
        binding: InterfaceBindingRequest,
        delay: Duration,
        started: std::sync::mpsc::SyncSender<()>,
    ) -> Self {
        Self {
            binding,
            delay,
            started,
            outcome: DelayedReceiveOutcome::BackendError,
            wait_for_cancellation: true,
        }
    }

    const fn immediate_backend_error(
        binding: InterfaceBindingRequest,
        started: std::sync::mpsc::SyncSender<()>,
    ) -> Self {
        Self {
            binding,
            delay: Duration::ZERO,
            started,
            outcome: DelayedReceiveOutcome::BackendError,
            wait_for_cancellation: false,
        }
    }
}

impl ReceiveSocket for BlockingReceiveSocket {
    fn binding(&self) -> InterfaceBindingRequest {
        self.binding
    }

    fn revalidate(&self) -> Result<(), BindingError> {
        Ok(())
    }

    fn receive(
        &mut self,
        cancellation: &l2_helper::CancellationToken,
    ) -> Result<Option<Vec<u8>>, HelperError> {
        while !cancellation.is_cancelled() {
            thread::yield_now();
        }
        Ok(None)
    }
}

impl ReceiveSocket for DelayedReceiveSocket {
    fn binding(&self) -> InterfaceBindingRequest {
        self.binding
    }

    fn revalidate(&self) -> Result<(), BindingError> {
        Ok(())
    }

    fn receive(
        &mut self,
        cancellation: &l2_helper::CancellationToken,
    ) -> Result<Option<Vec<u8>>, HelperError> {
        let _ = self.started.send(());
        // Wait for cancellation when modeling an interruptible backend
        if self.wait_for_cancellation {
            while !cancellation.is_cancelled() {
                thread::yield_now();
            }
        }
        thread::sleep(self.delay);
        match self.outcome {
            DelayedReceiveOutcome::Empty => Ok(None),
            DelayedReceiveOutcome::BackendError => Err(HelperError::Backend(io::Error::other(
                "delayed backend failure",
            ))),
        }
    }
}
