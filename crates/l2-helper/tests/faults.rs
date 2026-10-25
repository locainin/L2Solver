use std::time::Duration;

use l2_helper::{
    FrontendClient, HelperConfig, HelperError, HelperServer, InterfaceBindingRequest, PeerIdentity,
    QueueReceiveSocket, SessionId, SessionLimits, SessionStop,
};

mod support;

fn session(value: u8) -> Result<SessionId, Box<dyn std::error::Error>> {
    Ok(SessionId::new([value; 16])?)
}

fn binding(value: u8) -> Result<InterfaceBindingRequest, Box<dyn std::error::Error>> {
    Ok(InterfaceBindingRequest::new(1, 2, u32::from(value), 1)?)
}

#[test]
fn helper_exit_allows_session_restart() -> Result<(), Box<dyn std::error::Error>> {
    let first_session = session(20)?;
    let first_binding = binding(20)?;
    let Some((frontend, transport)) = support::pair()? else {
        return Ok(());
    };
    let client = FrontendClient::new(frontend, first_session);
    let receiver = QueueReceiveSocket::new(first_binding, vec![])?;
    let config = HelperConfig::new(
        first_session,
        PeerIdentity::current(),
        SessionLimits::new(1, 10, Duration::from_secs(5))?,
    );
    let server = HelperServer::new(config, transport, receiver)?;
    let worker = std::thread::spawn(move || server.run());
    drop(client);
    let first_result = worker.join().map_err(|_| "helper worker panicked")?;
    // Either channel can observe an abrupt frontend disconnect first
    assert!(
        matches!(
            first_result,
            Err(HelperError::FrontendClosed | HelperError::ControlChannelClosed)
        ),
        "unexpected helper result: {first_result:?}"
    );

    let second_session = session(21)?;
    let second_binding = binding(21)?;
    let Some((frontend, transport)) = support::pair()? else {
        return Ok(());
    };
    let client = FrontendClient::new(frontend, second_session);
    let receiver = QueueReceiveSocket::new(second_binding, vec![])?;
    let config = HelperConfig::new(
        second_session,
        PeerIdentity::current(),
        SessionLimits::new(1, 10, Duration::from_secs(5))?,
    );
    let server = HelperServer::new(config, transport, receiver)?;
    let worker = std::thread::spawn(move || server.run());
    assert_eq!(client.hello()?, l2_helper::HelperReplyKind::Ready);
    assert_eq!(client.cancel()?, l2_helper::HelperReplyKind::Cancelled);
    let report = worker.join().map_err(|_| "helper worker panicked")??;
    assert_eq!(report.stop(), SessionStop::Cancelled);
    Ok(())
}
