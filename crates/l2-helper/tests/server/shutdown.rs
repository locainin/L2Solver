use std::error::Error;
use std::sync::mpsc::sync_channel;
use std::thread;
use std::time::Duration;

use l2_helper::{
    FrontendClient, FrontendTransport, HelperConfig, HelperError, HelperReplyKind, HelperServer,
    PeerIdentity, QueueReceiveSocket, SessionId, SessionLimits, SessionStop,
};
use l2_helper_protocol::{MAX_MESSAGE_LENGTH, Message, MessageKind, encode};

use super::{binding, server_config as config, session, support};

fn send_receive_request(
    frontend: &FrontendTransport,
    session: SessionId,
    sequence: u64,
) -> Result<(), Box<dyn Error>> {
    let message = Message::new(MessageKind::ReceiveNext, session, sequence, &[])?;
    let mut encoded = [0_u8; MAX_MESSAGE_LENGTH];
    let length = encode(&message, &mut encoded)?;
    frontend.try_send(encoded.get(..length).ok_or("request boundary")?)?;
    Ok(())
}

fn send_control_request(
    frontend: &FrontendTransport,
    kind: MessageKind,
    session: SessionId,
    sequence: u64,
) -> Result<(), Box<dyn Error>> {
    let message = Message::new(kind, session, sequence, &[])?;
    let mut encoded = [0_u8; MAX_MESSAGE_LENGTH];
    let length = encode(&message, &mut encoded)?;
    frontend.try_send_cancel(encoded.get(..length).ok_or("request boundary")?)?;
    Ok(())
}

#[test]
fn genuine_control_not_data_shutdown() -> Result<(), Box<dyn Error>> {
    let session = session(85)?;
    let binding = binding(85)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let receiver = QueueReceiveSocket::new(binding, vec![])?;
    let server = HelperServer::new(config(session)?, helper_transport, receiver)?;
    let worker = thread::spawn(move || server.run());

    send_control_request(&frontend, MessageKind::Hello, session, 1)?;
    let result = worker.join().map_err(|_| "helper worker panicked")?;
    assert!(matches!(
        result,
        Err(HelperError::InvalidRequest(
            "control channel only accepts cancel"
        ))
    ));
    Ok(())
}

#[test]
fn close_acknowledgement_immediate_frontend_drop() -> Result<(), Box<dyn Error>> {
    let session = session(82)?;
    let binding = binding(82)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let client = FrontendClient::new(frontend, session);
    let receiver = QueueReceiveSocket::new(binding, vec![])?;
    let server = HelperServer::new(config(session)?, helper_transport, receiver)?;
    let (result_sender, result_receiver) = sync_channel(1);
    let worker = thread::spawn(move || result_sender.send(server.run()));

    assert_eq!(client.hello()?, HelperReplyKind::Ready);
    assert_eq!(client.close()?, HelperReplyKind::Closed);
    // Drop both frontend channels as soon as the terminal data acknowledgement arrives
    drop(client);
    let result = result_receiver
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| "helper terminal result did not complete")?;
    assert!(matches!(
        result,
        Ok(report) if report.stop() == SessionStop::Closed
    ));
    worker.join().map_err(|_| "helper worker panicked")??;
    Ok(())
}

#[test]
fn cancellation_acknowledgement_immediate_frontend_drop() -> Result<(), Box<dyn Error>> {
    let session = session(83)?;
    let binding = binding(83)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let client = FrontendClient::new(frontend, session);
    let receiver = QueueReceiveSocket::new(binding, vec![])?;
    let server = HelperServer::new(config(session)?, helper_transport, receiver)?;
    let (result_sender, result_receiver) = sync_channel(1);
    let worker = thread::spawn(move || result_sender.send(server.run()));

    assert_eq!(client.cancel()?, HelperReplyKind::Cancelled);
    // Drop both frontend channels as soon as the terminal control acknowledgement arrives
    drop(client);
    let result = result_receiver
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| "helper terminal result did not complete")?;
    assert!(matches!(
        result,
        Ok(report) if report.stop() == SessionStop::Cancelled
    ));
    worker.join().map_err(|_| "helper worker panicked")??;
    Ok(())
}

#[test]
fn cancellation_acknowledgement_backend_peer_drop() -> Result<(), Box<dyn Error>> {
    let session = session(84)?;
    let binding = binding(84)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let raw_frontend = frontend.try_clone()?;
    let client = FrontendClient::new(frontend, session);
    let (receive_started_sender, receive_started_receiver) = sync_channel(1);
    let receiver = super::DelayedReceiveSocket::cancellation_returns_empty(
        binding,
        Duration::from_millis(200),
        receive_started_sender,
    );
    let server = HelperServer::new(config(session)?, helper_transport, receiver)?;
    let (result_sender, result_receiver) = sync_channel(1);
    let worker = thread::spawn(move || result_sender.send(server.run()));

    assert_eq!(client.hello()?, HelperReplyKind::Ready);
    assert_eq!(client.open_receive(binding)?, HelperReplyKind::Ready);
    send_receive_request(&raw_frontend, session, 3)?;
    drop(raw_frontend);
    receive_started_receiver
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| "receive backend did not start")?;
    assert_eq!(client.cancel()?, HelperReplyKind::Cancelled);
    // The backend remains in receive after the controller acknowledgement
    drop(client);

    let result = result_receiver
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| "helper terminal result did not complete")?;
    assert!(matches!(
        result,
        Ok(report) if report.stop() == SessionStop::Cancelled
    ));
    worker.join().map_err(|_| "helper worker panicked")??;
    Ok(())
}

#[test]
fn cancellation_wins_delayed_backend_error() -> Result<(), Box<dyn Error>> {
    let session = session(89)?;
    let binding = binding(89)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let raw_frontend = frontend.try_clone()?;
    let client = FrontendClient::new(frontend, session);
    let (receive_started_sender, receive_started_receiver) = sync_channel(1);
    let receiver = super::DelayedReceiveSocket::cancellation_returns_backend_error(
        binding,
        Duration::from_millis(200),
        receive_started_sender,
    );
    let server = HelperServer::new(config(session)?, helper_transport, receiver)?;
    let (result_sender, result_receiver) = sync_channel(1);
    let worker = thread::spawn(move || result_sender.send(server.run()));

    assert_eq!(client.hello()?, HelperReplyKind::Ready);
    assert_eq!(client.open_receive(binding)?, HelperReplyKind::Ready);
    send_receive_request(&raw_frontend, session, 3)?;
    receive_started_receiver
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| "receive backend did not start")?;
    assert_eq!(client.cancel()?, HelperReplyKind::Cancelled);

    let result = result_receiver
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| "helper terminal result did not complete")?;
    assert!(matches!(
        result,
        Ok(report) if report.stop() == SessionStop::Cancelled
    ));
    super::assert_no_error_reply(&raw_frontend)?;
    drop(raw_frontend);
    worker.join().map_err(|_| "helper worker panicked")??;
    Ok(())
}

#[test]
fn accepted_cancellation_not_reclassified_deadline() -> Result<(), Box<dyn Error>> {
    let session = session(93)?;
    let binding = binding(93)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let raw_frontend = frontend.try_clone()?;
    let client = FrontendClient::new(frontend, session);
    let (receive_started_sender, receive_started_receiver) = sync_channel(1);
    let receiver = super::DelayedReceiveSocket::cancellation_returns_empty(
        binding,
        Duration::from_millis(1_200),
        receive_started_sender,
    );
    let config = HelperConfig::new(
        session,
        PeerIdentity::current(),
        SessionLimits::new(10, 1_024, Duration::from_secs(1))?,
    );
    let server = HelperServer::new(config, helper_transport, receiver)?;
    let (result_sender, result_receiver) = sync_channel(1);
    let worker = thread::spawn(move || result_sender.send(server.run()));

    assert_eq!(client.hello()?, HelperReplyKind::Ready);
    assert_eq!(client.open_receive(binding)?, HelperReplyKind::Ready);
    send_receive_request(&raw_frontend, session, 3)?;
    receive_started_receiver
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| "receive backend did not start")?;
    assert_eq!(client.cancel()?, HelperReplyKind::Cancelled);

    let result = result_receiver
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| "helper terminal result did not complete")?;
    assert!(matches!(
        result,
        Ok(report) if report.stop() == SessionStop::Cancelled
    ));
    super::assert_no_error_reply(&raw_frontend)?;
    drop(raw_frontend);
    worker.join().map_err(|_| "helper worker panicked")??;
    Ok(())
}

#[test]
fn backend_error_without_stop_preserved() -> Result<(), Box<dyn Error>> {
    let session = session(91)?;
    let binding = binding(91)?;
    let Some((frontend, helper_transport)) = support::pair()? else {
        return Ok(());
    };
    let raw_frontend = frontend.try_clone()?;
    let client = FrontendClient::new(frontend, session);
    let (receive_started_sender, receive_started_receiver) = sync_channel(1);
    let receiver =
        super::DelayedReceiveSocket::immediate_backend_error(binding, receive_started_sender);
    let server = HelperServer::new(config(session)?, helper_transport, receiver)?;
    let worker = thread::spawn(move || server.run());

    assert_eq!(client.hello()?, HelperReplyKind::Ready);
    assert_eq!(client.open_receive(binding)?, HelperReplyKind::Ready);
    send_receive_request(&raw_frontend, session, 3)?;
    receive_started_receiver
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| "receive backend did not start")?;

    let result = worker.join().map_err(|_| "helper worker panicked")?;
    match result {
        Err(HelperError::Backend(error)) => {
            assert_eq!(error.to_string(), "delayed backend failure");
        }
        other => return Err(format!("unexpected helper result: {other:?}").into()),
    }
    let reply_bytes = raw_frontend.try_recv()?;
    let reply = l2_helper::decode_reply(&reply_bytes)?;
    assert_eq!(reply.kind(), HelperReplyKind::Error);
    assert_eq!(reply.payload(), [0, 5]);
    drop(raw_frontend);
    Ok(())
}
