use std::os::fd::AsFd;
use std::process::{Command, Stdio};
use std::time::Duration;

use l2_helper::{
    ClientReply, FrontendClient, HelperConfig, HelperError, HelperServer, InterfaceBindingRequest,
    PeerIdentity, QueueReceiveSocket, SessionId, SessionLimits, SessionStop, TransportError,
};

mod process_support;

const SESSION: [u8; 16] = [41; 16];
const BINDING: (u64, u64, u32, u32) = (10, 20, 41, 1);

fn session() -> Result<SessionId, Box<dyn std::error::Error>> {
    Ok(SessionId::new(SESSION)?)
}

fn binding() -> Result<InterfaceBindingRequest, Box<dyn std::error::Error>> {
    Ok(InterfaceBindingRequest::new(
        BINDING.0, BINDING.1, BINDING.2, BINDING.3,
    )?)
}

#[test]
fn process_request_reply_and_cancel() -> Result<(), Box<dyn std::error::Error>> {
    let Some((frontend, helper_data, helper_control)) = process_support::inherited_pair()? else {
        return Ok(());
    };
    let expected = frontend.peer_identity()?;
    let child = Command::new(std::env::current_exe()?)
        .arg("--exact")
        .arg("helper_child_process")
        .arg("--ignored")
        .arg("--nocapture")
        .env("L2_HELPER_EXPECTED_UID", expected.uid().to_string())
        .env("L2_HELPER_EXPECTED_PID", expected.pid().to_string())
        .stdin(Stdio::from(helper_data))
        .stderr(Stdio::from(helper_control))
        .stdout(Stdio::null())
        .spawn()?;
    let client = FrontendClient::new(frontend, session()?);
    let binding = binding()?;
    assert_eq!(client.hello()?, l2_helper::HelperReplyKind::Ready);
    assert_eq!(
        client.open_receive(binding)?,
        l2_helper::HelperReplyKind::Ready
    );
    assert_eq!(
        client.receive_next()?,
        ClientReply::Frame(vec![0xde, 0xad, 0xbe, 0xef])
    );
    assert_eq!(client.cancel()?, l2_helper::HelperReplyKind::Cancelled);
    let status = child.wait_with_output()?;
    assert!(
        status.status.success(),
        "child helper test failed: {status:?}"
    );
    Ok(())
}

#[test]
fn process_reports_peer_exit() -> Result<(), Box<dyn std::error::Error>> {
    let Some((frontend, helper_data, helper_control)) = process_support::inherited_pair()? else {
        return Ok(());
    };
    let child = Command::new(std::env::current_exe()?)
        .arg("--exact")
        .arg("helper_child_exit")
        .arg("--ignored")
        .arg("--nocapture")
        .stdin(Stdio::from(helper_data))
        .stderr(Stdio::from(helper_control))
        .stdout(Stdio::null())
        .spawn()?;
    let status = child.wait_with_output()?;
    assert!(
        status.status.success(),
        "child exit test failed: {status:?}"
    );
    let client = FrontendClient::new(frontend, session()?);
    assert!(matches!(
        client.hello(),
        Err(HelperError::Transport(TransportError::PeerClosed))
    ));
    Ok(())
}

#[test]
#[ignore = "run by the process boundary parent test"]
fn helper_child_process() -> Result<(), Box<dyn std::error::Error>> {
    let expected = PeerIdentity::new(
        std::env::var("L2_HELPER_EXPECTED_UID")?.parse()?,
        std::env::var("L2_HELPER_EXPECTED_PID")?.parse()?,
    );
    let data = nix::unistd::dup(std::io::stdin().as_fd())?;
    let control = nix::unistd::dup(std::io::stderr().as_fd())?;
    let transport = l2_helper::HelperTransport::from_owned_fds(data, control)?;
    let session = session()?;
    let binding = binding()?;
    let config = HelperConfig::new(
        session,
        expected,
        SessionLimits::new(10, 1_024, Duration::from_secs(5))?,
    );
    let receiver = QueueReceiveSocket::new(binding, vec![vec![0xde, 0xad, 0xbe, 0xef]])?;
    let server = HelperServer::new(config, transport, receiver)?;
    let report = server.run()?;
    assert_eq!(report.stop(), SessionStop::Cancelled);
    assert_eq!(report.frames(), 1);
    assert_eq!(report.bytes(), 4);
    Ok(())
}

#[test]
#[ignore = "run by the process boundary parent test"]
fn helper_child_exit() {}
