use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use l2_helper::{FrontendClient, HelperError, HelperReply, HelperReplyKind, SessionId};
use l2_helper_protocol::{MessageKind, decode};

use super::{delayed, wire};

fn concurrent_cancel(callers: usize) -> wire::TestResult {
    let Some((frontend, _data, control)) = delayed::pair()? else {
        return Ok(());
    };
    let session = SessionId::new([40; 16])?;
    let client = FrontendClient::with_reply_timeout(frontend, session, Duration::from_secs(1))?;
    let barrier = Arc::new(Barrier::new(callers + 1));
    let mut workers = Vec::new();
    for _ in 0..callers {
        let clone = client.try_clone()?;
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            clone.cancel()
        }));
    }
    barrier.wait();
    let bytes = wire::receive(&control)?;
    let request = decode(&bytes)?;
    assert_eq!(request.kind(), MessageKind::Cancel);
    // Hold the first reply while the other callers contend for the same channel
    thread::sleep(Duration::from_millis(30));
    wire::send_bytes(
        &control,
        &wire::encoded(&HelperReply::empty(
            HelperReplyKind::Cancelled,
            session,
            request.sequence(),
        )?)?,
    )?;
    for worker in workers {
        assert_eq!(
            worker.join().map_err(|_| "cancel worker panicked")??,
            HelperReplyKind::Cancelled
        );
    }
    assert_eq!(client.cancel()?, HelperReplyKind::Cancelled);
    wire::no_request(&control);
    Ok(())
}

#[test]
fn pair_shared_cancel_ack() -> wire::TestResult {
    concurrent_cancel(2)
}

#[test]
fn triple_shared_cancel_ack() -> wire::TestResult {
    concurrent_cancel(3)
}

#[test]
fn acknowledged_cancel_workload_across_clones() -> wire::TestResult {
    let Some((frontend, data, control)) = delayed::pair()? else {
        return Ok(());
    };
    let session = SessionId::new([49; 16])?;
    let client = FrontendClient::with_reply_timeout(frontend, session, Duration::from_millis(50))?;
    let clone = client.try_clone()?;
    let worker = thread::spawn(move || clone.cancel());
    let bytes = wire::receive(&control)?;
    let request = decode(&bytes)?;
    wire::send_bytes(
        &control,
        &wire::encoded(&HelperReply::empty(
            HelperReplyKind::Cancelled,
            session,
            request.sequence(),
        )?)?,
    )?;
    assert_eq!(
        worker.join().map_err(|_| "cancel worker panicked")??,
        HelperReplyKind::Cancelled
    );
    let clone = client.try_clone()?;
    let binding = l2_helper::InterfaceBindingRequest::new(1, 2, 3, 1)?;
    assert!(matches!(client.hello(), Err(HelperError::SessionClosed)));
    assert!(matches!(
        clone.open_receive(binding),
        Err(HelperError::SessionClosed)
    ));
    assert!(matches!(
        clone.receive_next(),
        Err(HelperError::SessionClosed)
    ));
    assert!(matches!(clone.close(), Err(HelperError::SessionClosed)));
    assert_eq!(clone.cancel()?, HelperReplyKind::Cancelled);
    wire::no_request(&data);
    wire::no_request(&control);
    Ok(())
}

#[test]
fn failed_cancel_workload_not_retried() -> wire::TestResult {
    let Some((frontend, data, _control)) = delayed::pair()? else {
        return Ok(());
    };
    // Fill only the control queue so its next send fails before waiting for a reply
    let mut saturated = false;
    for _ in 0..10_000 {
        match frontend.try_send_cancel(&[1]) {
            Ok(()) => {}
            Err(l2_helper::TransportError::WouldBlock) => {
                saturated = true;
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert!(
        saturated,
        "control queue did not reach its bounded capacity"
    );
    let client = FrontendClient::with_reply_timeout(
        frontend,
        SessionId::new([50; 16])?,
        Duration::from_millis(50),
    )?;
    for clone in [client.try_clone()?, client.try_clone()?] {
        assert!(matches!(
            clone.cancel(),
            Err(HelperError::Transport(
                l2_helper::TransportError::WouldBlock
            ))
        ));
        assert!(matches!(clone.hello(), Err(HelperError::SessionPoisoned)));
    }
    wire::no_request(&data);
    Ok(())
}

#[test]
fn manual_cancel_share_control_request() -> wire::TestResult {
    let Some((frontend, data, control)) = delayed::pair()? else {
        return Ok(());
    };
    let session = SessionId::new([41; 16])?;
    let client = FrontendClient::with_reply_timeout(frontend, session, Duration::from_millis(100))?;
    let clone = client.try_clone()?;
    let workload = thread::spawn(move || clone.hello());
    wire::receive(&data)?;
    // Start cancellation near the workload deadline, leaving time for its own reply
    thread::sleep(Duration::from_millis(60));
    let clone = client.try_clone()?;
    let cancel = thread::spawn(move || clone.cancel());
    let bytes = wire::receive(&control)?;
    let request = decode(&bytes)?;
    thread::sleep(Duration::from_millis(60));
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
    assert!(matches!(
        workload.join().map_err(|_| "workload worker panicked")?,
        Err(HelperError::ReplyTimeout)
    ));
    assert!(matches!(client.hello(), Err(HelperError::SessionPoisoned)));
    wire::no_request(&control);
    wire::no_request(&data);
    Ok(())
}

#[test]
fn failed_cancel_cached_without_retrying() -> wire::TestResult {
    let Some((frontend, _data, control)) = delayed::pair()? else {
        return Ok(());
    };
    let session = SessionId::new([42; 16])?;
    let client = FrontendClient::with_reply_timeout(frontend, session, Duration::from_millis(10))?;
    assert!(matches!(client.cancel(), Err(HelperError::ReplyTimeout)));
    wire::receive(&control)?;
    assert!(matches!(
        client.try_clone()?.cancel(),
        Err(HelperError::ReplyTimeout)
    ));
    wire::no_request(&control);
    assert!(matches!(client.hello(), Err(HelperError::SessionPoisoned)));
    Ok(())
}

#[test]
fn rejected_cancel_shared_poisoning() -> wire::TestResult {
    let Some((frontend, data, control)) = delayed::pair()? else {
        return Ok(());
    };
    let session = SessionId::new([48; 16])?;
    let client = FrontendClient::with_reply_timeout(frontend, session, Duration::from_secs(1))?;
    let clone = client.try_clone()?;
    let first = thread::spawn(move || clone.cancel());
    let bytes = wire::receive(&control)?;
    let request = decode(&bytes)?;
    // A second caller arrives after the first request, before its rejection
    let clone = client.try_clone()?;
    let second = thread::spawn(move || clone.cancel());
    wire::send_bytes(
        &control,
        &wire::encoded(&HelperReply::error(
            session,
            request.sequence(),
            l2_helper::ReplyErrorCode::Protocol,
        )?)?,
    )?;
    for worker in [first, second] {
        assert!(matches!(
            worker.join().map_err(|_| "cancel worker panicked")?,
            Err(HelperError::InvalidRequest("helper rejected the request"))
        ));
    }
    wire::no_request(&control);
    assert!(matches!(client.hello(), Err(HelperError::SessionPoisoned)));
    wire::no_request(&data);
    Ok(())
}

#[test]
fn closed_control_channel_failure_shared() -> wire::TestResult {
    let Some((frontend, _data, control)) = delayed::pair()? else {
        return Ok(());
    };
    let session = SessionId::new([49; 16])?;
    let client = FrontendClient::with_reply_timeout(frontend, session, Duration::from_secs(1))?;
    let clone = client.try_clone()?;
    let worker = thread::spawn(move || clone.cancel());
    wire::receive(&control)?;
    drop(control);
    let first = worker
        .join()
        .map_err(|_| "cancel worker panicked")?
        .err()
        .ok_or("cancel unexpectedly succeeded")?;
    let second = client
        .cancel()
        .err()
        .ok_or("cached cancel unexpectedly succeeded")?;
    assert!(matches!(first, HelperError::Transport(_)));
    assert_eq!(first.to_string(), second.to_string());
    assert!(matches!(client.hello(), Err(HelperError::SessionPoisoned)));
    Ok(())
}
