//! Bounded request/reply transport for generic netlink

use std::{io, sync::atomic::AtomicBool, time::Instant};

use netlink_sys::{Socket, protocols::NETLINK_GENERIC};

use crate::netlink;

const MAX_REPLY: usize = 65_536;
const SEQUENCE: u32 = 1;

pub fn exchange(
    deadline: Instant,
    cancelled: &AtomicBool,
    build: impl FnOnce(u32, u32) -> io::Result<Vec<u8>>,
) -> io::Result<Vec<u8>> {
    netlink::check_control(deadline, cancelled)?;
    let mut socket = Socket::new(NETLINK_GENERIC)?;
    socket.set_non_blocking(true)?;
    let port = socket.bind_auto()?.port_number();
    let request = build(SEQUENCE, port)?;
    netlink::send(&socket, &request, deadline, cancelled)?;
    netlink::receive(&socket, MAX_REPLY, SEQUENCE, port, deadline, cancelled)
}
