use std::thread;
use std::time::Duration;

use l2_helper::{
    FrontendClient, HelperError, HelperReply, HelperReplyKind, InterfaceBindingRequest, SessionId,
    TransportError,
};
use l2_helper_protocol::{MessageKind, decode};

use super::{delayed, wire};

#[test]
fn pending_cancel_workload_control_ack() -> wire::TestResult {
    let Some((frontend, data, control)) = delayed::pair()? else {
        return Ok(());
    };
    let session = SessionId::new([81; 16])?;
    let client = FrontendClient::with_reply_timeout(frontend, session, Duration::from_secs(1))?;
    let cancel_client = client.try_clone()?;
    let cancel = thread::spawn(move || cancel_client.cancel());
    let bytes = wire::receive(&control)?;
    let request = decode(&bytes)?;

    let workload = client.try_clone()?;
    let workload = thread::spawn(move || workload.hello());
    assert!(matches!(
        workload.join().map_err(|_| "workload worker panicked")?,
        Err(HelperError::SessionStopping)
    ));
    wire::no_request(&data);

    wire::send_bytes(
        &control,
        &wire::encoded(&HelperReply::empty(
            HelperReplyKind::Cancelled,
            session,
            request.sequence(),
        )?)?,
    )?;
    assert_eq!(
        cancel.join().map_err(|_| "cancel worker panicked")??,
        HelperReplyKind::Cancelled
    );
    Ok(())
}

#[test]
fn close_ack_clone_api_locally() -> wire::TestResult {
    let Some((frontend, data, control)) = delayed::pair()? else {
        return Ok(());
    };
    let session = SessionId::new([83; 16])?;
    let client = FrontendClient::with_reply_timeout(frontend, session, Duration::from_secs(1))?;
    let clone = client.try_clone()?;
    let close_worker = thread::spawn(move || client.close());
    let bytes = wire::receive(&data)?;
    let request = decode(&bytes)?;
    assert_eq!(request.kind(), MessageKind::Close);
    wire::send_bytes(
        &data,
        &wire::encoded(&HelperReply::empty(
            HelperReplyKind::Closed,
            session,
            request.sequence(),
        )?)?,
    )?;
    assert_eq!(
        close_worker.join().map_err(|_| "close worker panicked")??,
        HelperReplyKind::Closed
    );

    let binding = InterfaceBindingRequest::new(1, 2, 83, 1)?;
    assert!(matches!(clone.hello(), Err(HelperError::SessionClosed)));
    assert!(matches!(
        clone.open_receive(binding),
        Err(HelperError::SessionClosed)
    ));
    assert!(matches!(
        clone.receive_next(),
        Err(HelperError::SessionClosed)
    ));
    assert!(matches!(clone.close(), Err(HelperError::SessionClosed)));
    assert!(matches!(clone.cancel(), Err(HelperError::SessionClosed)));
    wire::no_request(&data);
    wire::no_request(&control);
    Ok(())
}

#[test]
fn peer_closed_session_later_workload() -> wire::TestResult {
    let Some((frontend, data, _control)) = delayed::pair()? else {
        return Ok(());
    };
    drop(data);
    let session = SessionId::new([84; 16])?;
    let client = FrontendClient::with_reply_timeout(frontend, session, Duration::from_millis(20))?;
    assert!(matches!(
        client.hello(),
        Err(HelperError::Transport(TransportError::PeerClosed))
    ));
    assert!(matches!(
        client.try_clone()?.hello(),
        Err(HelperError::SessionPoisoned)
    ));
    Ok(())
}

#[test]
fn workload_would_block_retryable_healthy() -> wire::TestResult {
    let Some((frontend, data, control)) = delayed::pair()? else {
        return Ok(());
    };
    let mut saturated = false;
    for _ in 0..10_000 {
        match frontend.try_send(&[0x5a]) {
            Ok(()) => {}
            Err(TransportError::WouldBlock) => {
                saturated = true;
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert!(saturated, "data queue did not reach its bounded capacity");

    let session = SessionId::new([85; 16])?;
    let client = FrontendClient::with_reply_timeout(frontend, session, Duration::from_secs(1))?;
    assert!(matches!(
        client.hello(),
        Err(HelperError::Transport(TransportError::WouldBlock))
    ));
    wire::drain(&data)?;
    let worker = thread::spawn(move || client.hello());
    let bytes = wire::receive(&data)?;
    let request = decode(&bytes)?;
    wire::send_bytes(
        &data,
        &wire::encoded(&HelperReply::empty(
            HelperReplyKind::Ready,
            session,
            request.sequence(),
        )?)?,
    )?;
    assert_eq!(
        worker.join().map_err(|_| "workload worker panicked")??,
        HelperReplyKind::Ready
    );
    drop(control);
    Ok(())
}
