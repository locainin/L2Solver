use super::super::{Channel, Peer};
use crate::wire::MAX_RECORD;
use nix::sys::socket::{AddressFamily, MsgFlags, SockFlag, SockType, recv, send, socketpair};
use std::{
    io,
    os::fd::{AsRawFd, OwnedFd},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

fn own_peer() -> Peer {
    Peer {
        pid: std::process::id(),
        uid: nix::unistd::getuid().as_raw(),
    }
}

fn blocking_channel() -> io::Result<(Channel, OwnedFd)> {
    let (local, remote) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(io::Error::other)?;
    Ok((Channel::from_owned(local, own_peer())?, remote))
}

#[test]
fn empty_channel_receive_returns_without_waiting_for_a_peer() -> io::Result<()> {
    let (channel, remote) = blocking_channel()?;
    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let _ = sender.send(channel.try_receive());
    });
    let result = receiver.recv_timeout(Duration::from_secs(3));

    // Closing the peer also releases the reader if a blocking call regresses
    drop(remote);
    reader
        .join()
        .map_err(|_| io::Error::other("channel reader thread panicked"))?;
    assert!(matches!(result, Ok(Ok(None))), "receive result: {result:?}");
    Ok(())
}

#[test]
fn channel_sends_only_nonempty_records_within_the_size_limit() -> io::Result<()> {
    let (channel, remote) = Channel::pair(own_peer())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    for record in [Vec::new(), vec![1; MAX_RECORD + 1]] {
        assert_eq!(
            channel
                .send(&record, deadline)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData),
            "record length {}",
            record.len()
        );
    }

    let record = vec![7; MAX_RECORD];
    channel.send(&record, deadline)?;
    let mut received = vec![0; MAX_RECORD];
    let count = recv(remote.as_raw_fd(), &mut received, MsgFlags::MSG_DONTWAIT)
        .map_err(io::Error::other)?;
    assert_eq!(count, record.len());
    assert_eq!(received, record);
    Ok(())
}

#[test]
fn full_channel_send_respects_the_deadline() -> io::Result<()> {
    let (channel, remote) = blocking_channel()?;
    let (sender, receiver) = mpsc::channel();
    let writer = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(250);
        let record = vec![1; 8192];
        let mut result = Err(io::Error::other("channel never filled"));
        for _ in 0..4096 {
            if let Err(error) = channel.send(&record, deadline) {
                result = Ok(error.kind());
                break;
            }
        }
        let _ = sender.send(result);
    });
    let result = receiver.recv_timeout(Duration::from_secs(3));

    // Closing the peer releases a writer if a blocking send regresses
    drop(remote);
    writer
        .join()
        .map_err(|_| io::Error::other("channel writer thread panicked"))?;
    assert!(
        matches!(result, Ok(Ok(io::ErrorKind::TimedOut))),
        "send result: {result:?}"
    );
    Ok(())
}

#[test]
fn channel_accepts_the_expected_peer_and_the_maximum_record() -> io::Result<()> {
    let (channel, remote) = Channel::pair(own_peer())?;
    let record = vec![42; MAX_RECORD];
    send(remote.as_raw_fd(), &record, MsgFlags::empty()).map_err(io::Error::other)?;
    assert_eq!(channel.try_receive()?, Some(record));
    Ok(())
}

#[test]
fn channel_rejects_a_record_that_exceeds_the_limit() -> io::Result<()> {
    let (channel, remote) = Channel::pair(own_peer())?;
    let record = vec![42; MAX_RECORD + 1];
    send(remote.as_raw_fd(), &record, MsgFlags::empty()).map_err(io::Error::other)?;
    assert_eq!(
        channel.try_receive().err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    Ok(())
}

#[test]
fn channel_rejects_wrong_process_and_user_credentials() -> io::Result<()> {
    let actual = own_peer();
    for peer in [
        Peer {
            pid: actual.pid + 1,
            uid: actual.uid,
        },
        Peer {
            pid: actual.pid,
            uid: actual.uid ^ 1,
        },
    ] {
        let (channel, remote) = Channel::pair(peer)?;
        send(remote.as_raw_fd(), &[1], MsgFlags::empty()).map_err(io::Error::other)?;
        assert_eq!(
            channel.try_receive().err().map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied),
            "expected pid {} and uid {}",
            peer.pid,
            peer.uid
        );
    }
    Ok(())
}
