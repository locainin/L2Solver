//! Bounded Linux IPv6 route lookup for one selected NDP target

mod message;
mod policy;
mod transport;

#[cfg(test)]
#[path = "../../tests/route/control.rs"]
mod control_tests;
#[cfg(test)]
#[path = "../../tests/route/message.rs"]
mod message_tests;
#[cfg(test)]
#[path = "../../tests/route/policy.rs"]
mod policy_tests;
#[cfg(test)]
#[path = "../../tests/route/veth.rs"]
mod veth_tests;

use std::{io, net::Ipv6Addr, sync::atomic::AtomicBool, time::Instant};

use l2_capture::LinuxInterfaceIdentity;

use crate::{InterfaceSelector, pin::PinnedInterface};

#[derive(Clone, Copy, Debug)]
struct RouteQuery {
    source: Ipv6Addr,
    target: Ipv6Addr,
    ifindex: u32,
}

/// Verify that the selected source and target resolve directly on the pinned link
///
/// This read-only kernel lookup is a point-in-time admission check. The caller
/// must refresh the pinned interface and repeat it immediately before sending
///
/// # Errors
/// Returns an error for unavailable, stale, indirect, ambiguous, unsupported,
/// malformed, cancelled, or expired route evidence
pub fn verify_on_link(
    selector: &InterfaceSelector,
    expected: LinuxInterfaceIdentity,
    source: Ipv6Addr,
    target: Ipv6Addr,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<()> {
    transport::check_control(deadline, cancelled)?;
    if !valid_unicast(source) || !valid_unicast(target) || source == target {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "route lookup requires distinct unicast IPv6 addresses",
        ));
    }
    let pinned = PinnedInterface::open(selector)?;
    if pinned.identity != expected {
        return Err(io::Error::other(
            "selected interface changed before route lookup",
        ));
    }
    let query = RouteQuery {
        source,
        target,
        ifindex: expected.ifindex(),
    };
    transport::lookup(query, deadline, cancelled)?;
    pinned.revalidate(selector)?;
    transport::check_control(deadline, cancelled)
}

const fn valid_unicast(address: Ipv6Addr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && !address.is_loopback()
        && address.to_ipv4().is_none()
}
