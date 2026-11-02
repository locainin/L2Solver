use std::error::Error;
use std::os::fd::OwnedFd;

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

use l2_helper::FrontendTransport;

type InheritedPair = Result<(FrontendTransport, OwnedFd, OwnedFd), Box<dyn Error>>;

/// Return frontend transport plus child-owned seqpacket descriptors
pub fn inherited_pair() -> InheritedPair {
    let (frontend_data, helper_data) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(|error| format!("data SOCK_SEQPACKET socketpair is unavailable: {error}"))?;
    let (frontend_control, helper_control) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(|error| format!("control SOCK_SEQPACKET socketpair is unavailable: {error}"))?;
    let frontend = FrontendTransport::from_owned_fds(frontend_data, frontend_control)?;
    Ok((frontend, helper_data, helper_control))
}
