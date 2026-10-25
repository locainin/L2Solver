use std::{
    error::Error,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use l2_helper::{
    FrontendTransport, HelperConfig, HelperReplyKind, HelperServer, InterfaceBindingRequest,
    PeerIdentity, QueueReceiveSocket, SessionId, SessionLimits, SessionStop, TransportError,
    decode_reply, local_transport_pair,
};
use l2_helper_protocol::{ControlAction, Message, MessageKind, PeerState, decode, encode};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[derive(Clone, Debug)]
struct Record {
    control: bool,
    bytes: Vec<u8>,
}

fn record(
    kind: MessageKind,
    sequence: u64,
    session: SessionId,
    binding: InterfaceBindingRequest,
) -> TestResult<Record> {
    let mut payload = [0; InterfaceBindingRequest::ENCODED_LENGTH];
    binding.encode(&mut payload)?;
    let payload = if kind == MessageKind::OpenReceive {
        payload.as_slice()
    } else {
        &[]
    };
    let message = Message::new(kind, session, sequence, payload)?;
    let mut bytes = vec![0; l2_helper_protocol::MAX_MESSAGE_LENGTH];
    let length = encode(&message, &mut bytes)?;
    bytes.truncate(length);
    Ok(Record {
        control: kind == MessageKind::Cancel,
        bytes,
    })
}

// The protocol model governs framing/order; the receive service adds one open precondition
fn expected_reply(
    state: &mut PeerState,
    opened: &mut bool,
    record: &Record,
) -> Option<HelperReplyKind> {
    let message = decode(&record.bytes).ok()?;
    if record.control != (message.kind() == MessageKind::Cancel) {
        return None;
    }
    let before = *state;
    let Ok(action) = state.accept(&message) else {
        assert_eq!(*state, before, "rejected protocol input mutated state");
        return None;
    };
    match action {
        ControlAction::HandshakeAccepted => Some(HelperReplyKind::Ready),
        ControlAction::OpenReceive(_) if !*opened => {
            *opened = true;
            Some(HelperReplyKind::Ready)
        }
        ControlAction::ReceiveNext if *opened => Some(HelperReplyKind::Empty),
        ControlAction::Cancel => Some(HelperReplyKind::Cancelled),
        ControlAction::Close => Some(HelperReplyKind::Closed),
        ControlAction::OpenReceive(_) | ControlAction::ReceiveNext => None,
    }
}

fn receive(frontend: &FrontendTransport, control: bool) -> TestResult<Option<Vec<u8>>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let result = if control {
            frontend.try_recv_cancel()
        } else {
            frontend.try_recv()
        };
        match result {
            Ok(bytes) => return Ok(Some(bytes)),
            Err(TransportError::PeerClosed) => return Ok(None),
            Err(TransportError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn run_trace(trace: &[Record], session: SessionId, binding: InterfaceBindingRequest) -> TestResult {
    let (frontend, transport) = local_transport_pair()?;
    let server = HelperServer::new(
        HelperConfig::new(
            session,
            PeerIdentity::current(),
            SessionLimits::new(10, 1024, Duration::from_secs(2))?,
        ),
        transport,
        QueueReceiveSocket::new(binding, vec![])?,
    )?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || sender.send(server.run()));
    let mut model = PeerState::new(session);
    let mut opened = false;
    let mut terminal = None;
    let mut rejected = false;
    for record in trace {
        let expected = expected_reply(&mut model, &mut opened, record);
        if record.control {
            frontend.try_send_cancel(&record.bytes)?;
        } else {
            frontend.try_send(&record.bytes)?;
        }
        let bytes = receive(&frontend, record.control)?;
        if let Some(kind) = expected {
            let bytes = bytes.ok_or("helper closed an accepted model transition")?;
            let reply = decode_reply(&bytes)?;
            let request = decode(&record.bytes)?;
            assert_eq!(reply.kind(), kind, "trace: {trace:?}");
            assert_eq!(reply.session(), session);
            assert_eq!(reply.sequence(), request.sequence());
            if matches!(kind, HelperReplyKind::Closed | HelperReplyKind::Cancelled) {
                terminal = Some(kind);
                break;
            }
        } else {
            if let Some(bytes) = bytes {
                assert_eq!(decode_reply(&bytes)?.kind(), HelperReplyKind::Error);
            }
            rejected = true;
            break;
        }
    }
    // Deleted terminal records end by disconnect, rather than allowing a test to wait forever
    if terminal.is_none() && !rejected {
        drop(frontend);
    }
    let result = receiver.recv_timeout(Duration::from_secs(3))?;
    worker.join().map_err(|_| "helper worker panicked")??;
    match terminal {
        Some(HelperReplyKind::Closed) => assert_eq!(result?.stop(), SessionStop::Closed),
        Some(HelperReplyKind::Cancelled) => assert_eq!(result?.stop(), SessionStop::Cancelled),
        _ => assert!(
            result.is_err(),
            "rejected or disconnected trace must fail closed"
        ),
    }
    Ok(())
}

#[test]
fn socket_helper_single_trace_mutations() -> TestResult {
    let session = SessionId::new([0x71; 16])?;
    let binding = InterfaceBindingRequest::new(1, 2, 3, 1)?;
    for start in [1, u64::MAX - 4] {
        for ending in [MessageKind::Close, MessageKind::Cancel] {
            let kinds = [
                MessageKind::Hello,
                MessageKind::OpenReceive,
                MessageKind::ReceiveNext,
                MessageKind::ReceiveNext,
                ending,
            ];
            let baseline = kinds
                .into_iter()
                .enumerate()
                .map(|(index, kind)| {
                    let sequence = if kind == MessageKind::Cancel {
                        1
                    } else {
                        start + u64::try_from(index)?
                    };
                    record(kind, sequence, session, binding)
                })
                .collect::<TestResult<Vec<_>>>()?;
            let mut traces = vec![baseline.clone()];
            for index in 0..baseline.len() {
                let mut deleted = baseline.clone();
                deleted.remove(index);
                traces.push(deleted);
                let mut duplicated = baseline.clone();
                duplicated.insert(index, baseline.get(index).ok_or("record index")?.clone());
                traces.push(duplicated);
                if index + 1 < baseline.len() {
                    let mut reordered = baseline.clone();
                    reordered.swap(index, index + 1);
                    traces.push(reordered);
                }
                for offset in [0, 5, 7, 35] {
                    let mut corrupted = baseline.clone();
                    let byte = corrupted
                        .get_mut(index)
                        .and_then(|record| record.bytes.get_mut(offset))
                        .ok_or("corruption offset")?;
                    *byte = 0;
                    traces.push(corrupted);
                }
                let mut trailing = baseline.clone();
                trailing.get_mut(index).ok_or("record index")?.bytes.push(0);
                traces.push(trailing);
            }
            for trace in traces {
                run_trace(&trace, session, binding)?;
            }
        }
    }
    Ok(())
}
