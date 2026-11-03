use super::{Channel, Peer, future_deadline, records::own_peer};
use crate::channel::fault::InterruptedReceive;
use nix::{
    errno::Errno,
    sys::socket::{MsgFlags, send},
};
use std::{
    fs::File,
    io,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

#[test]
fn interrupted_receive_retries_a_ready_authenticated_record() -> io::Result<()> {
    let (channel, remote) = Channel::pair(own_peer())?;
    send(remote.as_raw_fd(), b"ready", MsgFlags::empty()).map_err(io::Error::other)?;
    let _interrupted = InterruptedReceive::once();
    assert_eq!(
        channel.try_receive(future_deadline())?,
        Some(b"ready".to_vec())
    );
    assert_eq!(InterruptedReceive::attempts(), 2);
    Ok(())
}

#[test]
fn repeated_interruptions_stop_at_the_deadline_without_consuming_the_record() -> io::Result<()> {
    let (channel, remote) = Channel::pair(own_peer())?;
    send(remote.as_raw_fd(), b"ready", MsgFlags::empty()).map_err(io::Error::other)?;
    let interrupted = InterruptedReceive::repeated(Duration::from_millis(1));
    let deadline = Instant::now() + Duration::from_millis(100);
    assert_eq!(
        channel.receive(deadline).map_err(|error| error.kind()),
        Err(io::ErrorKind::TimedOut)
    );
    assert!(
        InterruptedReceive::attempts() > 1,
        "receive did not retry interrupted calls"
    );
    drop(interrupted);
    assert_eq!(
        channel.try_receive(future_deadline())?,
        Some(b"ready".to_vec())
    );
    Ok(())
}

#[test]
fn an_elapsed_deadline_makes_no_receive_attempt() -> io::Result<()> {
    let (channel, remote) = Channel::pair(own_peer())?;
    send(remote.as_raw_fd(), b"ready", MsgFlags::empty()).map_err(io::Error::other)?;
    let interrupted = InterruptedReceive::once();
    assert_eq!(
        channel
            .try_receive(Instant::now())
            .map_err(|error| error.kind()),
        Err(io::ErrorKind::TimedOut)
    );
    assert_eq!(InterruptedReceive::attempts(), 0);
    drop(interrupted);
    assert_eq!(
        channel.try_receive(future_deadline())?,
        Some(b"ready".to_vec())
    );
    Ok(())
}

#[test]
fn non_socket_receive_propagates_the_kernel_error() -> io::Result<()> {
    let channel = Channel {
        fd: File::open("/dev/null")?.into(),
        peer: own_peer(),
    };
    assert_eq!(
        channel
            .try_receive(future_deadline())
            .err()
            .and_then(|error| error.raw_os_error()),
        Some(Errno::ENOTSOCK as i32)
    );
    Ok(())
}

#[test]
fn interrupted_receive_still_rejects_wrong_credentials() -> io::Result<()> {
    let peer = own_peer();
    for expected in [
        Peer {
            pid: peer.pid + 1,
            uid: peer.uid,
        },
        Peer {
            pid: peer.pid,
            uid: peer.uid ^ 1,
        },
    ] {
        let (channel, remote) = Channel::pair(expected)?;
        send(remote.as_raw_fd(), b"ready", MsgFlags::empty()).map_err(io::Error::other)?;
        let _interrupted = InterruptedReceive::once();
        assert_eq!(
            channel
                .try_receive(future_deadline())
                .map_err(|error| error.kind()),
            Err(io::ErrorKind::PermissionDenied)
        );
        assert_eq!(InterruptedReceive::attempts(), 2);
    }
    Ok(())
}
