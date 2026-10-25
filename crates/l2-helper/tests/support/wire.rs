use std::os::fd::{AsRawFd, OwnedFd};
use std::thread;
use std::time::{Duration, Instant};

use l2_helper::{HelperReply, MAX_IPC_BYTES, encode_reply};
use nix::errno::Errno;
use nix::sys::socket::{MsgFlags, recv, send};

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

pub fn receive(fd: &OwnedFd) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let mut bytes = vec![0; MAX_IPC_BYTES];
        match recv(fd.as_raw_fd(), &mut bytes, MsgFlags::MSG_DONTWAIT) {
            Ok(length) if length > 0 => {
                bytes.truncate(length);
                return Ok(bytes);
            }
            Err(Errno::EAGAIN) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(1));
            }
            other => return Err(format!("request did not arrive: {other:?}").into()),
        }
    }
}

pub fn encoded(reply: &HelperReply<'_>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = vec![0; MAX_IPC_BYTES];
    let length = encode_reply(reply, &mut bytes)?;
    bytes.truncate(length);
    Ok(bytes)
}

pub fn send_bytes(fd: &OwnedFd, bytes: &[u8]) -> TestResult {
    assert_eq!(
        send(fd.as_raw_fd(), bytes, MsgFlags::MSG_NOSIGNAL)?,
        bytes.len()
    );
    Ok(())
}

pub fn no_request(fd: &OwnedFd) {
    let mut bytes = [0; 128];
    assert_eq!(
        recv(fd.as_raw_fd(), &mut bytes, MsgFlags::MSG_DONTWAIT),
        Err(Errno::EAGAIN)
    );
}

pub fn drain(fd: &OwnedFd) -> TestResult {
    let mut bytes = vec![0; l2_helper::MAX_IPC_BYTES];
    loop {
        match recv(fd.as_raw_fd(), &mut bytes, MsgFlags::MSG_DONTWAIT) {
            Ok(length) if length > 0 => {}
            Err(Errno::EAGAIN) => return Ok(()),
            other => return Err(format!("failed to drain request queue: {other:?}").into()),
        }
    }
}
