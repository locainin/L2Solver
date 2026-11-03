use super::{Channel, future_deadline, records::own_peer};
use nix::{
    errno::Errno,
    sys::socket::{MsgFlags, recv, send},
};
use std::{
    io,
    os::fd::AsRawFd,
    thread,
    time::{Duration, Instant},
};

#[test]
fn expired_writable_channel_does_not_send() -> io::Result<()> {
    let (channel, remote) = Channel::pair(own_peer())?;
    // A deadline sampled now is already at or past its boundary
    let deadline = Instant::now();
    assert_eq!(
        channel
            .send(b"late", deadline)
            .map_err(|error| error.kind()),
        Err(io::ErrorKind::TimedOut)
    );
    let mut received = [0; 4];
    assert_eq!(
        recv(remote.as_raw_fd(), &mut received, MsgFlags::MSG_DONTWAIT),
        Err(Errno::EAGAIN)
    );
    channel.send(b"next", future_deadline())?;
    assert_eq!(
        recv(remote.as_raw_fd(), &mut received, MsgFlags::empty()),
        Ok(4)
    );
    assert_eq!(&received, b"next");
    Ok(())
}

#[test]
fn expired_queued_receive_leaves_the_record_for_a_later_attempt() -> io::Result<()> {
    let (channel, remote) = Channel::pair(own_peer())?;
    send(remote.as_raw_fd(), b"ready", MsgFlags::empty()).map_err(io::Error::other)?;
    assert_eq!(
        channel
            .receive(Instant::now())
            .map_err(|error| error.kind()),
        Err(io::ErrorKind::TimedOut)
    );
    assert_eq!(channel.receive(future_deadline())?, b"ready");
    Ok(())
}

#[test]
fn expired_nonblocking_receive_leaves_the_record_for_a_later_attempt() -> io::Result<()> {
    let (channel, remote) = Channel::pair(own_peer())?;
    send(remote.as_raw_fd(), b"ready", MsgFlags::empty()).map_err(io::Error::other)?;
    assert_eq!(
        channel
            .try_receive(Instant::now())
            .map_err(|error| error.kind()),
        Err(io::ErrorKind::TimedOut)
    );
    assert_eq!(
        channel.try_receive(future_deadline())?,
        Some(b"ready".to_vec())
    );
    Ok(())
}

#[test]
fn receive_retries_when_a_record_arrives_before_the_deadline() -> io::Result<()> {
    let (channel, remote) = Channel::pair(own_peer())?;
    let sender = thread::spawn(move || {
        thread::sleep(Duration::from_millis(25));
        send(remote.as_raw_fd(), b"ready", MsgFlags::empty()).map_err(io::Error::other)
    });
    let result = channel.receive(Instant::now() + Duration::from_secs(3));
    sender
        .join()
        .map_err(|_| io::Error::other("channel sender thread panicked"))??;
    assert_eq!(result?, b"ready");
    Ok(())
}

#[test]
fn interrupted_send_attempt_retries_while_the_deadline_remains() -> io::Result<()> {
    let mut attempts = 0;
    let result = super::super::retry_interrupted(future_deadline(), || {
        attempts += 1;
        if attempts == 1 {
            Err(Errno::EINTR)
        } else {
            Ok(4)
        }
    })?;
    assert_eq!(result, 4);
    assert_eq!(attempts, 2);
    Ok(())
}

#[test]
fn interrupted_send_attempt_is_not_retried_after_the_deadline() {
    let mut attempts = 0;
    let deadline = Instant::now() + Duration::from_millis(250);
    let result = super::super::retry_interrupted(deadline, || {
        attempts += 1;
        thread::sleep(Duration::from_millis(300));
        Err::<usize, _>(Errno::EINTR)
    });
    assert_eq!(
        result.map_err(|error| error.kind()),
        Err(io::ErrorKind::TimedOut)
    );
    assert_eq!(attempts, 1);
}

#[test]
fn full_channel_send_retries_after_the_peer_drains() -> io::Result<()> {
    let (channel, remote) = Channel::pair(own_peer())?;
    let record = [7; 8192];
    let mut filled = false;
    for _ in 0..4096 {
        match send(channel.fd.as_raw_fd(), &record, MsgFlags::MSG_DONTWAIT) {
            Ok(_) => {}
            Err(Errno::EAGAIN) => {
                filled = true;
                break;
            }
            Err(error) => return Err(io::Error::other(error)),
        }
    }
    assert!(filled, "channel did not reach its send limit");
    let reader = thread::spawn(move || {
        thread::sleep(Duration::from_millis(25));
        let mut bytes = [0; 8192];
        let mut count = 0;
        loop {
            match recv(remote.as_raw_fd(), &mut bytes, MsgFlags::MSG_DONTWAIT) {
                Ok(_) => count += 1,
                Err(Errno::EAGAIN) => break,
                Err(error) => return Err(io::Error::other(error)),
            }
        }
        // Keep the socket open until the blocked send has returned
        Ok((count, remote))
    });
    let result = channel.send(b"next", Instant::now() + Duration::from_secs(3));
    let (count, _remote) = reader
        .join()
        .map_err(|_| io::Error::other("channel reader thread panicked"))??;
    assert!(count > 0, "reader did not drain any records");
    result
}
