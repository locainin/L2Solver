use std::thread;
use std::time::Duration;

use l2_helper::{
    FrontendClient, HelperError, HelperReply, HelperReplyKind, InterfaceBindingRequest,
    ReplyErrorCode, SessionId,
};
use l2_helper_protocol::{MessageKind, decode};

use super::{delayed, wire};

#[test]
fn corrupt_replies_poison_clone_workload() -> wire::TestResult {
    let session = SessionId::new([43; 16])?;
    let valid = wire::encoded(&HelperReply::empty(HelperReplyKind::Ready, session, 1)?)?;
    let mut cases = Vec::new();
    for (offset, value) in [(0, 0), (5, 2), (12, 9), (35, 2), (7, 4), (7, 99)] {
        let mut bytes = valid.clone();
        *bytes.get_mut(offset).ok_or("corruption offset")? = value;
        cases.push(bytes);
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    cases.push(trailing);
    cases.push(valid.get(..20).ok_or("truncated header")?.to_vec());
    // The transport rejects oversized records before the reply decoder runs
    cases.push(vec![0; l2_helper::MAX_IPC_BYTES + 1]);
    for reply in cases {
        let Some((frontend, data, control)) = delayed::pair()? else {
            return Ok(());
        };
        let client = FrontendClient::with_reply_timeout(frontend, session, Duration::from_secs(1))?;
        let clone = client.try_clone()?;
        let worker = thread::spawn(move || clone.hello());
        wire::receive(&data)?;
        wire::send_bytes(&data, &reply)?;
        // Poisoning must send cancellation, and its response must not recurse
        let bytes = wire::receive(&control)?;
        let cancel = decode(&bytes)?;
        wire::send_bytes(
            &control,
            &wire::encoded(&HelperReply::empty(
                HelperReplyKind::Cancelled,
                session,
                cancel.sequence(),
            )?)?,
        )?;
        assert!(
            worker
                .join()
                .map_err(|_| "workload worker panicked")?
                .is_err()
        );
        let binding = InterfaceBindingRequest::new(10, 20, 43, 1)?;
        assert!(matches!(client.hello(), Err(HelperError::SessionPoisoned)));
        assert!(matches!(
            client.open_receive(binding),
            Err(HelperError::SessionPoisoned)
        ));
        assert!(matches!(
            client.receive_next(),
            Err(HelperError::SessionPoisoned)
        ));
        assert!(matches!(client.close(), Err(HelperError::SessionPoisoned)));
        wire::no_request(&data);
        wire::no_request(&control);
    }
    Ok(())
}

#[test]
fn valid_error_workload_requests_cancel() -> wire::TestResult {
    let Some((frontend, data, control)) = delayed::pair()? else {
        return Ok(());
    };
    let session = SessionId::new([44; 16])?;
    let client = FrontendClient::with_reply_timeout(frontend, session, Duration::from_secs(1))?;
    let clone = client.try_clone()?;
    let worker = thread::spawn(move || clone.receive_next());
    let bytes = wire::receive(&data)?;
    let request = decode(&bytes)?;
    wire::send_bytes(
        &data,
        &wire::encoded(&HelperReply::error(
            session,
            request.sequence(),
            ReplyErrorCode::ReceiveNotOpen,
        )?)?,
    )?;
    let bytes = wire::receive(&control)?;
    let cancel = decode(&bytes)?;
    wire::send_bytes(
        &control,
        &wire::encoded(&HelperReply::empty(
            HelperReplyKind::Cancelled,
            session,
            cancel.sequence(),
        )?)?,
    )?;
    assert!(matches!(
        worker.join().map_err(|_| "workload worker panicked")?,
        Err(HelperError::ReceiveNotOpen)
    ));
    assert!(matches!(client.hello(), Err(HelperError::SessionPoisoned)));
    wire::no_request(&data);
    Ok(())
}

#[test]
fn corrupt_control_poisoning_not_recurse() -> wire::TestResult {
    let Some((frontend, data, control)) = delayed::pair()? else {
        return Ok(());
    };
    let session = SessionId::new([45; 16])?;
    let client = FrontendClient::with_reply_timeout(frontend, session, Duration::from_secs(1))?;
    let clone = client.try_clone()?;
    let worker = thread::spawn(move || clone.cancel());
    wire::receive(&control)?;
    wire::send_bytes(&control, b"bad reply")?;
    assert!(matches!(
        worker.join().map_err(|_| "cancel worker panicked")?,
        Err(HelperError::Reply(_))
    ));
    assert!(matches!(client.hello(), Err(HelperError::SessionPoisoned)));
    assert!(matches!(client.cancel(), Err(HelperError::Reply(_))));
    wire::no_request(&control);
    wire::no_request(&data);
    Ok(())
}

#[test]
fn queued_workload_observes_poison_sending() -> wire::TestResult {
    let Some((frontend, data, control)) = delayed::pair()? else {
        return Ok(());
    };
    let session = SessionId::new([46; 16])?;
    let client = FrontendClient::with_reply_timeout(frontend, session, Duration::from_secs(1))?;
    let first = client.try_clone()?;
    let first = thread::spawn(move || first.hello());
    wire::receive(&data)?;
    let queued = client.try_clone()?;
    let queued = thread::spawn(move || queued.receive_next());
    wire::send_bytes(&data, b"bad reply")?;
    let bytes = wire::receive(&control)?;
    let cancel = decode(&bytes)?;
    wire::send_bytes(
        &control,
        &wire::encoded(&HelperReply::empty(
            HelperReplyKind::Cancelled,
            session,
            cancel.sequence(),
        )?)?,
    )?;
    assert!(matches!(
        first.join().map_err(|_| "first worker panicked")?,
        Err(HelperError::Reply(_))
    ));
    assert!(matches!(
        queued.join().map_err(|_| "queued worker panicked")?,
        Err(HelperError::SessionPoisoned)
    ));
    wire::no_request(&data);
    Ok(())
}

#[test]
fn unexpected_reply_poison_workload_method() -> wire::TestResult {
    type Workload =
        fn(FrontendClient, InterfaceBindingRequest) -> thread::JoinHandle<Result<(), HelperError>>;

    let workloads: [(MessageKind, Workload); 4] = [
        (MessageKind::Hello, |client, _binding| {
            thread::spawn(move || client.hello().map(|_| ()))
        }),
        (MessageKind::OpenReceive, |client, binding| {
            thread::spawn(move || client.open_receive(binding).map(|_| ()))
        }),
        (MessageKind::ReceiveNext, |client, _binding| {
            thread::spawn(move || client.receive_next().map(|_| ()))
        }),
        (MessageKind::Close, |client, _binding| {
            thread::spawn(move || client.close().map(|_| ()))
        }),
    ];

    for (expected_kind, run_workload) in workloads {
        let Some((frontend, data, control)) = delayed::pair()? else {
            return Ok(());
        };
        let session = SessionId::new([47; 16])?;
        let binding = InterfaceBindingRequest::new(10, 20, 47, 1)?;
        let client = FrontendClient::with_reply_timeout(frontend, session, Duration::from_secs(1))?;
        let clone = client.try_clone()?;
        let worker = run_workload(clone, binding);
        let bytes = wire::receive(&data)?;
        let request = decode(&bytes)?;
        assert_eq!(request.kind(), expected_kind);
        // Cancelled is valid framing but never a workload response
        wire::send_bytes(
            &data,
            &wire::encoded(&HelperReply::empty(
                HelperReplyKind::Cancelled,
                session,
                request.sequence(),
            )?)?,
        )?;
        let bytes = wire::receive(&control)?;
        let cancel = decode(&bytes)?;
        wire::send_bytes(
            &control,
            &wire::encoded(&HelperReply::empty(
                HelperReplyKind::Cancelled,
                session,
                cancel.sequence(),
            )?)?,
        )?;
        assert!(matches!(
            worker.join().map_err(|_| "workload worker panicked")?,
            Err(HelperError::InvalidRequest(_))
        ));
        assert!(matches!(client.hello(), Err(HelperError::SessionPoisoned)));
        wire::no_request(&data);
    }
    Ok(())
}
