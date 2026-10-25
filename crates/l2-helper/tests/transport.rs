use nix::errno::Errno;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use nix::unistd::dup;

use l2_helper::{FrontendTransport, HelperTransport, PeerIdentity, TransportError};

mod support;

#[test]
fn local_pair_reports_peer_credentials() -> Result<(), Box<dyn std::error::Error>> {
    let Some((frontend, helper)) = support::pair()? else {
        return Ok(());
    };
    let expected = PeerIdentity::current();
    assert_eq!(frontend.peer_identity()?, expected);
    assert_eq!(helper.peer_identity()?, expected);
    assert_eq!(
        frontend.peer_socket_type()?,
        l2_helper::SocketType::SeqPacket
    );
    assert_eq!(helper.peer_socket_type()?, l2_helper::SocketType::SeqPacket);
    Ok(())
}

#[test]
fn rejects_oversized_datagrams_before_decode() -> Result<(), Box<dyn std::error::Error>> {
    let Some((frontend, helper)) = support::pair()? else {
        return Ok(());
    };
    let oversized = vec![0xa5; l2_helper::MAX_IPC_BYTES + 1];
    assert!(matches!(
        frontend.try_send(&oversized),
        Err(TransportError::MessageTooLarge { length, maximum })
            if length == oversized.len() && maximum == l2_helper::MAX_IPC_BYTES
    ));
    drop(helper);
    Ok(())
}

#[test]
fn queue_saturation_is_nonblocking() -> Result<(), Box<dyn std::error::Error>> {
    let Some((frontend, helper)) = support::pair()? else {
        return Ok(());
    };
    let packet = vec![0x5a; l2_helper::MAX_IPC_BYTES];
    let mut saturated = false;
    for _ in 0..100_000 {
        match frontend.try_send(&packet) {
            Ok(()) => {}
            Err(TransportError::WouldBlock) => {
                saturated = true;
                break;
            }
            Err(error) => return Err(Box::new(error)),
        }
    }
    assert!(
        saturated,
        "seqpacket queue did not fill within the test bound"
    );
    drop(helper);
    Ok(())
}

#[test]
fn peer_close_would_block_poll() -> Result<(), Box<dyn std::error::Error>> {
    let Some((frontend, helper)) = support::pair()? else {
        return Ok(());
    };
    drop(helper);
    assert!(matches!(
        frontend.try_recv(),
        Err(TransportError::PeerClosed)
    ));
    Ok(())
}

#[test]
fn unrelated_socket_types_not_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let (stream_a, stream_b) = match socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    ) {
        Ok(pair) => pair,
        // The managed sandbox blocks all AF_UNIX creation. The elevated run
        // exercises the wrong-type rejection with the real kernel socket.
        Err(Errno::EPERM) => return Ok(()),
        Err(error) => return Err(Box::new(error)),
    };
    let result = FrontendTransport::from_owned_fds(stream_a, stream_b);
    if matches!(
        &result,
        Err(TransportError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied
    ) {
        return Ok(());
    }
    assert!(matches!(result, Err(TransportError::WrongSocketType(_))));
    Ok(())
}

mod channel_alias {
    use super::*;

    #[test]
    fn frontend_rejects_duplicate_socket() -> Result<(), Box<dyn std::error::Error>> {
        let Some((data, _peer)) = seqpacket()? else {
            return Ok(());
        };
        let control = dup(&data)?;
        let result = FrontendTransport::from_owned_fds(data, control);
        assert!(matches!(result, Err(TransportError::AliasedChannels)));
        Ok(())
    }

    #[test]
    fn helper_rejects_duplicate_socket() -> Result<(), Box<dyn std::error::Error>> {
        let Some((data, _peer)) = seqpacket()? else {
            return Ok(());
        };
        let control = dup(&data)?;
        let result = HelperTransport::from_owned_fds(data, control);
        assert!(matches!(result, Err(TransportError::AliasedChannels)));
        Ok(())
    }

    type SocketPair = (std::os::fd::OwnedFd, std::os::fd::OwnedFd);

    fn seqpacket() -> Result<Option<SocketPair>, Box<dyn std::error::Error>> {
        match socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        ) {
            Ok(pair) => Ok(Some(pair)),
            // The managed development sandbox denies AF_UNIX creation
            Err(Errno::EPERM) => Ok(None),
            Err(error) => Err(Box::new(error)),
        }
    }
}
