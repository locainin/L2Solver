use std::error::Error;
use std::io::ErrorKind;
use std::os::fd::OwnedFd;

use nix::errno::Errno;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

use l2_helper::{FrontendTransport, TransportError};

type InheritedPair = Result<Option<(FrontendTransport, OwnedFd, OwnedFd)>, Box<dyn Error>>;

/// Return frontend transport plus child-owned seqpacket descriptors
pub fn inherited_pair() -> InheritedPair {
    let (frontend_data, helper_data) = match socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    ) {
        Ok(pair) => pair,
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
