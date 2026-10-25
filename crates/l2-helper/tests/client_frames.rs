use std::{error::Error, thread, time::Duration};

use l2_helper::{
    ClientReply, FrontendClient, HelperConfig, HelperServer, InterfaceBindingRequest,
    MAX_FRAME_BYTES, PeerIdentity, QueueReceiveSocket, SessionId, SessionLimits,
    local_transport_pair,
};

#[test]
fn frame_ownership_empty_maximum_frames() -> Result<(), Box<dyn Error>> {
    let session = SessionId::new([0x63; 16])?;
    let binding = InterfaceBindingRequest::new(1, 2, 3, 1)?;
    let (frontend, helper) = local_transport_pair()?;
    let client = FrontendClient::new(frontend, session);
    let maximum = vec![0xa5; MAX_FRAME_BYTES];
    let receiver = QueueReceiveSocket::new(binding, vec![Vec::new(), maximum.clone()])?;
    let limits = SessionLimits::new(3, u64::try_from(MAX_FRAME_BYTES)?, Duration::from_secs(5))?;
    let config = HelperConfig::new(session, PeerIdentity::current(), limits);
    let server = HelperServer::new(config, helper, receiver)?;
    let worker = thread::spawn(move || server.run());
    client.hello()?;
    client.open_receive(binding)?;
    // An empty captured frame is distinct from an empty receive queue
    assert_eq!(client.receive_next()?, ClientReply::Frame(Vec::new()));
    assert_eq!(client.receive_next()?, ClientReply::Frame(maximum));
    assert_eq!(client.receive_next()?, ClientReply::Empty);
    client.close()?;
    let report = worker.join().map_err(|_| "helper worker panicked")??;
    assert_eq!(report.frames(), 2);
    assert_eq!(report.bytes(), u64::try_from(MAX_FRAME_BYTES)?);
    Ok(())
}
