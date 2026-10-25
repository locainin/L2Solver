use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{
    Arc,
    mpsc::{RecvTimeoutError, sync_channel},
};
use std::thread;
use std::time::Duration;

use l2_helper::{
    BindingError, BudgetError, CancellationToken, FrontendClient, FrontendTransport, HelperConfig,
    HelperError, HelperServer, InterfaceBindingRequest, PeerIdentity, QueueReceiveSocket,
    ReceiveSocket, SessionId, SessionLimits, TransportError, decode_reply,
};
use l2_helper_protocol::{MAX_MESSAGE_LENGTH, Message, MessageKind, encode};

use super::support;

const DEADLINE: Duration = Duration::from_secs(1);
const CLIENT_REPLY_TIMEOUT: Duration = Duration::from_millis(1_800);
const RESULT_TIMEOUT: Duration = Duration::from_millis(1_800);
const REVALIDATION_DELAY: Duration = Duration::from_millis(1_200);

fn deadline_config(session: SessionId, duration: Duration) -> Result<HelperConfig, Box<dyn Error>> {
    Ok(HelperConfig::new(
        session,
        PeerIdentity::current(),
        SessionLimits::new(10, 1_024, duration)?,
    ))
}

fn send_request(
    frontend: &FrontendTransport,
    kind: MessageKind,
    session: SessionId,
    sequence: u64,
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    let message = Message::new(kind, session, sequence, payload)?;
    let mut encoded = [0_u8; MAX_MESSAGE_LENGTH];
    let length = encode(&message, &mut encoded)?;
    frontend.try_send(encoded.get(..length).ok_or("request boundary")?)?;
    Ok(())
}

fn bounded_client(
    frontend: FrontendTransport,
    session: SessionId,
) -> Result<FrontendClient, Box<dyn Error>> {
    Ok(FrontendClient::with_reply_timeout(
        frontend,
        session,
        CLIENT_REPLY_TIMEOUT,
    )?)
}

#[test]
fn idle_expires_without_frontend_request() -> Result<(), Box<dyn Error>> {
    let session = super::session(86)?;
    let binding = super::binding(86)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let client = bounded_client(frontend, session)?;
    let receiver = QueueReceiveSocket::new(binding, vec![])?;
    let server = HelperServer::new(
        deadline_config(session, DEADLINE)?,
        helper_transport,
        receiver,
    )?;
    let (result_sender, result_receiver) = sync_channel(1);
    let worker = thread::spawn(move || result_sender.send(server.run()));

    assert_eq!(client.hello()?, l2_helper::HelperReplyKind::Ready);
    assert_eq!(
        client.open_receive(binding)?,
        l2_helper::HelperReplyKind::Ready
    );
    let result = match result_receiver.recv_timeout(RESULT_TIMEOUT) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => {
            // Drop both channels before reporting a timeout so a broken server can clean up
            drop(client);
            if result_receiver.recv_timeout(Duration::from_secs(1)).is_ok() {
                let _ = worker.join();
            }
            return Err("helper did not enforce its post-open idle deadline".into());
        }
        Err(RecvTimeoutError::Disconnected) => {
            return Err("helper result channel disconnected".into());
        }
    };

    assert!(matches!(
        result,
        Err(HelperError::Budget(BudgetError::Deadline))
    ));
    worker.join().map_err(|_| "helper worker panicked")??;
    Ok(())
}

#[test]
fn slow_revalidation_not_emit_ready() -> Result<(), Box<dyn Error>> {
    let session = super::session(87)?;
    let binding = super::binding(87)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let call_count = Arc::new(AtomicUsize::new(0));
    let receiver = StagedRevalidationReceiveSocket::new(binding, Arc::clone(&call_count), 2);
    let server = HelperServer::new(
        deadline_config(session, DEADLINE)?,
        helper_transport,
        receiver,
    )?;
    let client = bounded_client(frontend, session)?;
    let (result_sender, result_receiver) = sync_channel(1);
    let worker = thread::spawn(move || result_sender.send(server.run()));

    assert_eq!(client.hello()?, l2_helper::HelperReplyKind::Ready);
    let open_result = client.open_receive(binding);
    assert!(open_result.is_err());
    let result = match result_receiver.recv_timeout(RESULT_TIMEOUT) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => {
            // Cancellation remains bounded even if the old open path is still waiting
            let _ = client.cancel();
            if result_receiver.recv_timeout(Duration::from_secs(1)).is_ok() {
                let _ = worker.join();
            }
            return Err("slow open revalidation did not finish the helper".into());
        }
        Err(RecvTimeoutError::Disconnected) => {
            return Err("helper result channel disconnected".into());
        }
    };

    assert_eq!(call_count.load(Ordering::Acquire), 2);
    assert!(matches!(
        result,
        Err(HelperError::Budget(BudgetError::Deadline))
    ));
    worker.join().map_err(|_| "helper worker panicked")??;
    Ok(())
}

#[test]
fn slow_postreceive_not_emit_empty() -> Result<(), Box<dyn Error>> {
    let session = super::session(88)?;
    let binding = super::binding(88)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let call_count = Arc::new(AtomicUsize::new(0));
    let receiver = StagedRevalidationReceiveSocket::new(binding, Arc::clone(&call_count), 4);
    let server = HelperServer::new(
        deadline_config(session, DEADLINE)?,
        helper_transport,
        receiver,
    )?;
    let client = bounded_client(frontend, session)?;
    let (result_sender, result_receiver) = sync_channel(1);
    let worker = thread::spawn(move || result_sender.send(server.run()));

    assert_eq!(client.hello()?, l2_helper::HelperReplyKind::Ready);
    assert_eq!(
        client.open_receive(binding)?,
        l2_helper::HelperReplyKind::Ready
    );
    let receive_result = client.receive_next();
    assert!(receive_result.is_err());
    let result = match result_receiver.recv_timeout(RESULT_TIMEOUT) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => {
            // A late Empty reply must not leave the receive worker alive
            let _ = client.cancel();
            if result_receiver.recv_timeout(Duration::from_secs(1)).is_ok() {
                let _ = worker.join();
            }
            return Err("slow post-receive revalidation did not finish the helper".into());
        }
        Err(RecvTimeoutError::Disconnected) => {
            return Err("helper result channel disconnected".into());
        }
    };

    assert_eq!(call_count.load(Ordering::Acquire), 4);
    assert!(matches!(
        result,
        Err(HelperError::Budget(BudgetError::Deadline))
    ));
    worker.join().map_err(|_| "helper worker panicked")??;
    Ok(())
}

#[test]
fn idle_session_without_frontend_request() -> Result<(), Box<dyn Error>> {
    let session = super::session(80)?;
    let binding = super::binding(80)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let client = bounded_client(frontend, session)?;
    let receiver = QueueReceiveSocket::new(binding, vec![])?;
    let server = HelperServer::new(
        deadline_config(session, DEADLINE)?,
        helper_transport,
        receiver,
    )?;
    let (result_sender, result_receiver) = sync_channel(1);
    let worker = thread::spawn(move || result_sender.send(server.run()));

    let result = match result_receiver.recv_timeout(Duration::from_millis(1_500)) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => {
            // Release the data and control peers before reporting a regression
            drop(client);
            let _ = result_receiver.recv_timeout(Duration::from_secs(1));
            let _ = worker.join();
            return Err("helper did not enforce its idle session deadline".into());
        }
        Err(RecvTimeoutError::Disconnected) => {
            let _ = worker.join();
            return Err("helper result channel disconnected".into());
        }
    };

    assert!(matches!(
        result,
        Err(HelperError::Budget(BudgetError::Deadline))
    ));
    worker.join().map_err(|_| "helper worker panicked")??;
    Ok(())
}

#[test]
fn deadline_cancels_without_emitting_empty() -> Result<(), Box<dyn Error>> {
    let session = super::session(81)?;
    let binding = super::binding(81)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let raw_frontend = frontend.try_clone()?;
    let client = bounded_client(frontend, session)?;
    let receiver = super::BlockingReceiveSocket::new(binding);
    let server = HelperServer::new(
        deadline_config(session, DEADLINE)?,
        helper_transport,
        receiver,
    )?;
    let (result_sender, result_receiver) = sync_channel(1);
    let worker = thread::spawn(move || result_sender.send(server.run()));

    client.hello()?;
    client.open_receive(binding)?;
    send_request(&raw_frontend, MessageKind::ReceiveNext, session, 3, &[])?;

    let result = match result_receiver.recv_timeout(Duration::from_millis(1_500)) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => {
            // Force cooperative cleanup on the baseline implementation
            let _ = client.cancel();
            let cleanup = result_receiver
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| "helper cleanup did not complete")?;
            let _ = worker.join();
            assert!(
                matches!(cleanup, Ok(report) if report.stop() == l2_helper::SessionStop::Cancelled)
            );
            return Err("helper deadline did not cancel its blocked receive".into());
        }
        Err(RecvTimeoutError::Disconnected) => {
            let _ = worker.join();
            return Err("helper result channel disconnected".into());
        }
    };

    assert!(matches!(
        result,
        Err(HelperError::Budget(BudgetError::Deadline))
    ));
    // A receive that crossed the deadline must not publish a late Empty reply
    match raw_frontend.try_recv() {
        Ok(bytes) => assert_ne!(
            decode_reply(&bytes)?.kind(),
            l2_helper::HelperReplyKind::Empty
        ),
        Err(TransportError::WouldBlock | TransportError::PeerClosed) => {}
        Err(error) => return Err(error.into()),
    }
    drop(raw_frontend);
    worker.join().map_err(|_| "helper worker panicked")??;
    Ok(())
}

#[test]
fn deadline_wins_delayed_backend_error() -> Result<(), Box<dyn Error>> {
    let session = super::session(90)?;
    let binding = super::binding(90)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let raw_frontend = frontend.try_clone()?;
    let client = bounded_client(frontend, session)?;
    let (receive_started_sender, receive_started_receiver) = sync_channel(1);
    let receiver = super::DelayedReceiveSocket::cancellation_returns_backend_error(
        binding,
        Duration::from_millis(200),
        receive_started_sender,
    );
    let server = HelperServer::new(
        deadline_config(session, DEADLINE)?,
        helper_transport,
        receiver,
    )?;
    let (result_sender, result_receiver) = sync_channel(1);
    let worker = thread::spawn(move || result_sender.send(server.run()));

    client.hello()?;
    client.open_receive(binding)?;
    send_request(&raw_frontend, MessageKind::ReceiveNext, session, 3, &[])?;
    receive_started_receiver
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| "receive backend did not start")?;

    let result = result_receiver
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| "helper terminal result did not complete")?;
    assert!(matches!(
        result,
        Err(HelperError::Budget(BudgetError::Deadline))
    ));
    super::assert_no_error_reply(&raw_frontend)?;
    drop(raw_frontend);
    worker.join().map_err(|_| "helper worker panicked")??;
    Ok(())
}

#[test]
fn delayed_revalidation_deadline_budget_precedence() -> Result<(), Box<dyn Error>> {
    let session = super::session(92)?;
    let binding = super::binding(92)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let raw_frontend = frontend.try_clone()?;
    let client = bounded_client(frontend, session)?;
    let call_count = Arc::new(AtomicUsize::new(0));
    let receiver =
        StagedRevalidationReceiveSocket::failing_on_slow_call(binding, Arc::clone(&call_count), 2);
    let server = HelperServer::new(
        deadline_config(session, DEADLINE)?,
        helper_transport,
        receiver,
    )?;
    let (result_sender, result_receiver) = sync_channel(1);
    let worker = thread::spawn(move || result_sender.send(server.run()));

    client.hello()?;
    let mut payload = [0_u8; InterfaceBindingRequest::ENCODED_LENGTH];
    binding.encode(&mut payload)?;
    send_request(
        &raw_frontend,
        MessageKind::OpenReceive,
        session,
        2,
        &payload,
    )?;
    let result = result_receiver
        .recv_timeout(RESULT_TIMEOUT)
        .map_err(|_| "helper terminal result did not complete")?;
    assert_eq!(call_count.load(Ordering::Acquire), 2);
    assert!(matches!(
        result,
        Err(HelperError::Budget(BudgetError::Deadline))
    ));
    super::assert_no_error_reply(&raw_frontend)?;
    drop(raw_frontend);
    worker.join().map_err(|_| "helper worker panicked")??;
    Ok(())
}

#[derive(Debug)]
struct StagedRevalidationReceiveSocket {
    binding: InterfaceBindingRequest,
    revalidation_calls: Arc<AtomicUsize>,
    slow_call: usize,
    fail_on_slow_call: bool,
}

impl StagedRevalidationReceiveSocket {
    const fn new(
        binding: InterfaceBindingRequest,
        revalidation_calls: Arc<AtomicUsize>,
        slow_call: usize,
    ) -> Self {
        Self {
            binding,
            revalidation_calls,
            slow_call,
            fail_on_slow_call: false,
        }
    }

    const fn failing_on_slow_call(
        binding: InterfaceBindingRequest,
        revalidation_calls: Arc<AtomicUsize>,
        slow_call: usize,
    ) -> Self {
        Self {
            binding,
            revalidation_calls,
            slow_call,
            fail_on_slow_call: true,
        }
    }
}

impl ReceiveSocket for StagedRevalidationReceiveSocket {
    fn binding(&self) -> InterfaceBindingRequest {
        self.binding
    }

    fn revalidate(&self) -> Result<(), BindingError> {
        let call = self.revalidation_calls.fetch_add(1, Ordering::AcqRel) + 1;
        if call == self.slow_call {
            thread::sleep(REVALIDATION_DELAY);
            if self.fail_on_slow_call {
                return Err(BindingError::IdentityLost);
            }
        }
        Ok(())
    }

    fn receive(
        &mut self,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<u8>>, HelperError> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        Ok(None)
    }
}
