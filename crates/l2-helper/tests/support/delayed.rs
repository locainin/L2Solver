use std::error::Error;
use std::io::ErrorKind;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use l2_helper::{
    FrontendTransport, HelperReply, HelperReplyKind, MAX_IPC_BYTES, SessionId, TransportError,
    encode_reply,
};
use l2_helper_protocol::{MessageKind, decode};
use nix::errno::Errno;
use nix::sys::socket::{AddressFamily, MsgFlags, SockFlag, SockType, recv, send, socketpair};

type TestError = Box<dyn Error + Send + Sync>;
type TestResult = Result<(), TestError>;
type PairResult = Result<Option<(FrontendTransport, OwnedFd, OwnedFd)>, Box<dyn Error>>;

pub struct DelayedHelper {
    pub late_reply: Receiver<()>,
    pub cancellation: Receiver<bool>,
    pub workload: Receiver<bool>,
    pub worker: JoinHandle<TestResult>,
}

pub fn pair() -> PairResult {
    let (frontend_data, helper_data) = match socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    ) {
        Ok(pair) => pair,
        // The managed development sandbox denies AF_UNIX creation
        Err(Errno::EPERM) => return Ok(None),
        Err(error) => return Err(Box::new(error)),
    };
    let (frontend_control, helper_control) = match socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    ) {
        Ok(pair) => pair,
        Err(Errno::EPERM) => return Ok(None),
        Err(error) => return Err(Box::new(error)),
    };
    let frontend = match FrontendTransport::from_owned_fds(frontend_data, frontend_control) {
        Ok(frontend) => frontend,
        Err(TransportError::Io(error)) if error.kind() == ErrorKind::PermissionDenied => {
            return Ok(None);
        }
        Err(error) => return Err(Box::new(error)),
    };
    Ok(Some((frontend, helper_data, helper_control)))
}

pub fn spawn(helper_data: OwnedFd, helper_control: OwnedFd, session: SessionId) -> DelayedHelper {
    let (late_reply_sender, late_reply) = mpsc::sync_channel(1);
    let (cancellation_sender, cancellation) = mpsc::sync_channel(1);
    let (workload_sender, workload) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        receive_first_request(&helper_data)?;
        let saw_cancellation = receive_cancellation(&helper_control, session)?;
        cancellation_sender.send(saw_cancellation)?;
        send_empty_reply(&helper_data, session, 1, HelperReplyKind::Ready)?;
        late_reply_sender.send(())?;
        thread::sleep(Duration::from_millis(60));
        workload_sender.send(receive_extra_request(&helper_data)?)?;
        drop(helper_control);
        Ok(())
    });
    DelayedHelper {
        late_reply,
        cancellation,
        workload,
        worker,
    }
}

fn receive_first_request(fd: &OwnedFd) -> TestResult {
    let mut request = [0_u8; l2_helper_protocol::MAX_MESSAGE_LENGTH];
    let received = recv(fd.as_raw_fd(), &mut request, MsgFlags::empty())?;
    let request = decode(request.get(..received).ok_or("request boundary")?)?;
    assert_eq!(request.kind(), MessageKind::Hello);
    assert_eq!(request.sequence(), 1);
    Ok(())
}

fn receive_cancellation(fd: &OwnedFd, session: SessionId) -> Result<bool, TestError> {
    let deadline = Instant::now() + Duration::from_millis(40);
    let mut request = [0_u8; l2_helper_protocol::MAX_MESSAGE_LENGTH];
    while Instant::now() < deadline {
        match recv(fd.as_raw_fd(), &mut request, MsgFlags::MSG_DONTWAIT) {
            Ok(received) => {
                let request = decode(request.get(..received).ok_or("control request boundary")?)?;
                assert_eq!(request.kind(), MessageKind::Cancel);
                assert_eq!(request.sequence(), 2);
                send_empty_reply(fd, session, request.sequence(), HelperReplyKind::Cancelled)?;
                return Ok(true);
            }
            Err(Errno::EAGAIN) => thread::sleep(Duration::from_millis(1)),
            Err(error) => return Err(Box::new(error)),
        }
    }
    Ok(false)
}

fn send_empty_reply(
    fd: &OwnedFd,
    session: SessionId,
    sequence: u64,
    kind: HelperReplyKind,
) -> TestResult {
    let reply = HelperReply::empty(kind, session, sequence)?;
    let mut encoded = vec![0_u8; MAX_IPC_BYTES];
    let length = encode_reply(&reply, &mut encoded)?;
    let sent = send(
        fd.as_raw_fd(),
        encoded.get(..length).ok_or("reply boundary")?,
        MsgFlags::empty(),
    )?;
    assert_eq!(sent, length);
    Ok(())
}

fn receive_extra_request(fd: &OwnedFd) -> Result<bool, TestError> {
    let mut request = [0_u8; l2_helper_protocol::MAX_MESSAGE_LENGTH];
    match recv(fd.as_raw_fd(), &mut request, MsgFlags::MSG_DONTWAIT) {
        Ok(_) => Ok(true),
        Err(Errno::EAGAIN) => Ok(false),
        Err(error) => Err(Box::new(error)),
    }
}
