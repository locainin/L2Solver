use std::{error::Error, thread, time::Duration};

use l2_helper::{
    BudgetError, ClientReply, FrontendClient, HelperConfig, HelperError, HelperServer,
    InterfaceBindingRequest, PeerIdentity, QueueReceiveSocket, SessionId, SessionLimits,
    local_transport_pair,
};

#[test]
fn generic_wire_not_limit_dimension() -> Result<(), Box<dyn Error>> {
    for (frame_limit, byte_limit, expected) in [
        (1, 10, BudgetError::FrameWouldExceedCount),
        (2, 1, BudgetError::FrameWouldExceedBytes),
    ] {
        let session = SessionId::new([0x64; 16])?;
        let binding = InterfaceBindingRequest::new(1, 2, 3, 1)?;
        let (frontend, helper) = local_transport_pair()?;
        let client = FrontendClient::new(frontend, session);
        let receiver = QueueReceiveSocket::new(binding, vec![vec![1, 2], vec![3, 4]])?;
        let limits = SessionLimits::new(frame_limit, byte_limit, Duration::from_secs(5))?;
        let server = HelperServer::new(
            HelperConfig::new(session, PeerIdentity::current(), limits),
            helper,
            receiver,
        )?;
        let worker = thread::spawn(move || server.run());
        client.hello()?;
        client.open_receive(binding)?;
        if expected == BudgetError::FrameWouldExceedCount {
            assert_eq!(client.receive_next()?, ClientReply::Frame(vec![1, 2]));
        }
        let error = client
            .receive_next()
            .err()
            .ok_or("budget must reject the frame")?;
        assert!(matches!(error, HelperError::RemoteBudgetExhausted));
        // The stable wire code identifies exhaustion, not its count/byte/deadline cause
        assert_eq!(
            error.to_string(),
            "helper session budget exhausted (limit not specified by peer)"
        );
        assert!(
            matches!(worker.join().map_err(|_| "helper worker panicked")?,
            Err(HelperError::Budget(actual)) if actual == expected)
        );
    }
    Ok(())
}
