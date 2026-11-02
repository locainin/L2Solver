use crate::{
    InterfaceSelector,
    channel::{Channel, Peer},
    direct::DirectLink,
    intent::{Intent, ListenKind},
    packet::errno,
    wire::{self, Reader, Writer},
};
use l2_active::{
    ActiveLink, ArpProbe, Limits, NdpProbe, ReceiveEvent, dhcp::DhcpProbe, dot1x::Dot1xProbe,
};
use l2_capture::{CapturedFrame, Direction};
use l2_onpath::MacAddress;
use nix::{
    poll::{PollFd, PollFlags, poll},
    sys::socket::{getsockopt, sockopt::PeerCredentials},
    unistd::{dup, getppid},
};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    num::{NonZeroU8, NonZeroU32},
    os::fd::{AsFd, OwnedFd},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const CLEANUP_RESERVE: Duration = Duration::from_secs(2);

#[cfg(test)]
#[path = "../tests/worker/admission.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/worker/discovery.rs"]
mod discovery_tests;

#[cfg(test)]
#[path = "../tests/worker/operation.rs"]
mod operation_tests;

enum OpenKind {
    Arp(Ipv4Addr, Ipv4Addr),
    Dhcp(NonZeroU32),
    Ndp(Ipv6Addr, u8, Ipv6Addr),
    Listen(ListenKind),
    Dot1x,
}

/// Run the inherited, credential-checked one-operation worker protocol
///
/// This entry point is for the separately installed helper binary
///
/// # Errors
/// Returns an error if the inherited channel, request, or operation fails
pub fn run_helper() -> io::Result<()> {
    let fd = dup(io::stdin().as_fd()).map_err(errno)?;
    let control = dup(io::stdout().as_fd()).map_err(errno)?;
    let credentials = getsockopt(&fd, PeerCredentials).map_err(errno)?;
    let parent = u32::try_from(getppid().as_raw()).map_err(io::Error::other)?;
    if u32::try_from(credentials.pid()).ok() != Some(parent)
        || credentials.uid() != nix::unistd::getuid().as_raw()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper launcher identity mismatch",
        ));
    }
    let channel = Channel::from_owned(
        fd,
        Peer {
            pid: parent,
            uid: credentials.uid(),
        },
    )?;
    let startup_deadline = Instant::now() + STARTUP_TIMEOUT;
    if let Err(error) = crate::privileges::restrict_startup() {
        channel.send(&wire::error_record(&error), startup_deadline)?;
        return Err(error);
    }
    let request = channel.receive(startup_deadline)?;
    let opened = open_request(&request).and_then(|opened| {
        // The already-bound socket remains usable after dropping raw authority
        crate::privileges::drop_all()?;
        Ok(opened)
    });
    let (mut link, deadline) = match opened {
        Ok(value) => value,
        Err(error) => {
            channel.send(&wire::error_record(&error), startup_deadline)?;
            return Err(error);
        }
    };
    let operation_deadline = deadline + CLEANUP_RESERVE;
    let cancelled = Arc::new(AtomicBool::new(false));
    if let Err(error) = start_cancellation_monitor(control, Arc::clone(&cancelled)) {
        channel.send(&wire::error_record(&error), startup_deadline)?;
        return Err(error);
    }
    let frame = link.request_frame();
    let mut opened = Writer::with_capacity(wire::OK, frame.len() + 14)?;
    opened.u8(link.request_tag());
    opened.u16(link.request_profile());
    opened.u16(u16::try_from(frame.len()).map_err(io::Error::other)?);
    opened.bytes(frame);
    opened.u64(link.deadline_bound());
    channel.send(&opened.finish(), startup_deadline)?;
    loop {
        let request = channel.receive(operation_deadline)?;
        let mut reader = Reader::new(&request);
        let opcode = reader.u8()?;
        if opcode == wire::CLOSE {
            reader.finish()?;
            // Release the raw socket before acknowledging a clean close
            drop(link);
            channel.send(&Writer::new(wire::OK).finish(), operation_deadline)?;
            return Ok(());
        }
        let response = match operation(opcode, reader, &mut link, &cancelled) {
            Ok(response) => response,
            Err(error) => wire::error_record(&error),
        };
        channel.send(&response, operation_deadline)?;
    }
}

fn open_request(bytes: &[u8]) -> io::Result<(DirectLink, Instant)> {
    let mut reader = Reader::new(bytes);
    if reader.u8()? != wire::OPEN || reader.u8()? != wire::VERSION {
        return Err(wire::invalid_record());
    }
    let kind = reader.u8()?;
    let name_length = usize::from(reader.u8()?);
    let name =
        std::str::from_utf8(reader.take(name_length)?).map_err(|_| wire::invalid_record())?;
    let selector = InterfaceSelector::new(name)?;
    let identity = wire::read_identity(&mut reader)?;
    let vlan = wire::read_vlan(&mut reader, identity)?;
    let mac = MacAddress::new(
        reader
            .take(6)?
            .try_into()
            .map_err(|_| wire::invalid_record())?,
    )
    .map_err(invalid_input)?;
    let profile = reader.u16()?;
    let kind = read_open_kind(&mut reader, kind, profile)?;
    let limits = Limits::new(
        Duration::from_millis(u64::from(reader.u32()?)),
        reader.u32()?,
        reader.u64()?,
    )
    .map_err(invalid_input)?;
    let requested = crate::deadline::decode_deadline(reader.u64()?)?;
    reader.finish()?;
    let intent = match kind {
        OpenKind::Arp(source, target) => {
            Intent::arp(&ArpProbe::new(mac, source, target, None, limits).map_err(invalid_input)?)?
        }
        OpenKind::Dhcp(transaction) => {
            Intent::dhcp(&DhcpProbe::new(mac, transaction, None, limits).map_err(invalid_input)?)?
        }
        OpenKind::Ndp(source, prefix_len, target) => Intent::ndp(
            &NdpProbe::new(mac, source, prefix_len, target, None, limits).map_err(invalid_input)?,
        )?,
        OpenKind::Listen(kind) => Intent::listen(mac, limits, kind),
        OpenKind::Dot1x => Intent::dot1x(&Dot1xProbe::new(mac, limits).map_err(invalid_input)?)?,
    };
    let deadline = requested.min(Instant::now() + limits.timeout());
    let link = DirectLink::open(&selector, identity, vlan, intent, deadline)?;
    Ok((link, deadline))
}

fn read_open_kind(reader: &mut Reader<'_>, kind: u8, profile: u16) -> io::Result<OpenKind> {
    if !matches!(kind, 7 | 8) && profile != 0 {
        return Err(wire::invalid_record());
    }
    Ok(match kind {
        1 => {
            let source = Ipv4Addr::from(
                <[u8; 4]>::try_from(reader.take(4)?).map_err(|_| wire::invalid_record())?,
            );
            let target = Ipv4Addr::from(
                <[u8; 4]>::try_from(reader.take(4)?).map_err(|_| wire::invalid_record())?,
            );
            OpenKind::Arp(source, target)
        }
        2 => OpenKind::Dhcp(NonZeroU32::new(reader.u32()?).ok_or_else(wire::invalid_record)?),
        3 => {
            let source = Ipv6Addr::from(
                <[u8; 16]>::try_from(reader.take(16)?).map_err(|_| wire::invalid_record())?,
            );
            let prefix_len = reader.u8()?;
            let target = Ipv6Addr::from(
                <[u8; 16]>::try_from(reader.take(16)?).map_err(|_| wire::invalid_record())?,
            );
            OpenKind::Ndp(source, prefix_len, target)
        }
        4 => OpenKind::Listen(ListenKind::Discovery),
        5 => OpenKind::Listen(ListenKind::Stp),
        6 => match reader.u8()? {
            1 => OpenKind::Dot1x,
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "802.1X requires dedicated-interface acknowledgement",
                ));
            }
            _ => return Err(wire::invalid_record()),
        },
        7 => OpenKind::Listen(ListenKind::Vrrp {
            vrid: NonZeroU8::new(u8::try_from(profile).map_err(|_| wire::invalid_record())?),
        }),
        8 => OpenKind::Listen(ListenKind::Hsrp {
            group: if profile == 0 {
                None
            } else {
                Some(u8::try_from(profile - 1).map_err(|_| wire::invalid_record())?)
            },
        }),
        9 => OpenKind::Listen(ListenKind::Dtp),
        10 => OpenKind::Listen(ListenKind::Vtp),
        11 => OpenKind::Listen(ListenKind::Mpls),
        12 => OpenKind::Listen(ListenKind::Isl),
        _ => return Err(wire::invalid_record()),
    })
}

fn operation(
    opcode: u8,
    mut reader: Reader<'_>,
    link: &mut DirectLink,
    cancelled: &AtomicBool,
) -> io::Result<Vec<u8>> {
    match opcode {
        wire::SEND => {
            let deadline = crate::deadline::decode_deadline(reader.u64()?)?;
            reader.finish()?;
            let frame = crate::buffer::copy(link.request_frame())?;
            link.send(&frame, deadline, cancelled)?;
            Ok(Writer::new(wire::OK).finish())
        }
        wire::RECEIVE => {
            let encoded_deadline = reader.u64()?;
            let max_bytes = usize::try_from(reader.u32()?).map_err(io::Error::other)?;
            reader.finish()?;
            let deadline = match crate::deadline::decode_deadline(encoded_deadline) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                    // A slice known to end before the worker bound consumed no frame
                    let status =
                        if encoded_deadline > link.deadline_bound() && link.deadline_elapsed() {
                            wire::FINAL_TIMEOUT
                        } else {
                            wire::TIMEOUT
                        };
                    return Ok(Writer::new(status).finish());
                }
                Err(error) => return Err(error),
            };
            match link.receive(deadline, cancelled, max_bytes)? {
                ReceiveEvent::Frame(frame) => encode_frame(&frame),
                ReceiveEvent::TimedOut => Ok(Writer::new(wire::TIMEOUT).finish()),
                ReceiveEvent::BackendTimedOut => Ok(Writer::new(wire::FINAL_TIMEOUT).finish()),
                ReceiveEvent::Cancelled => Ok(Writer::new(wire::CANCELLED).finish()),
                ReceiveEvent::InterfaceDown => Ok(Writer::new(wire::DOWN).finish()),
            }
        }
        wire::PRE_SEND => {
            reader.finish()?;
            let mut writer = Writer::new(wire::USAGE);
            match link.pre_send_usage()? {
                Some(usage) => {
                    writer.u8(1);
                    writer.u32(usage.packets());
                    writer.u64(usage.bytes());
                }
                None => writer.u8(0),
            }
            Ok(writer.finish())
        }
        wire::BACKLOG => {
            reader.finish()?;
            let mut writer = Writer::new(wire::BACKLOG_RESULT);
            writer.u8(match link.capture_backlog()? {
                None => 0,
                Some(false) => 1,
                Some(true) => 2,
            });
            Ok(writer.finish())
        }
        wire::LOSS => {
            reader.finish()?;
            let mut writer = Writer::new(wire::STATS);
            match link.capture_loss()? {
                Some(loss) => {
                    writer.u8(1);
                    writer.u64(loss);
                }
                None => writer.u8(0),
            }
            Ok(writer.finish())
        }
        _ => Err(wire::invalid_record()),
    }
}

fn encode_frame(frame: &CapturedFrame) -> io::Result<Vec<u8>> {
    let metadata = frame.metadata();
    let mut writer = Writer::with_capacity(wire::FRAME, frame.captured_len() + 16)?;
    writer.u8(u8::from(metadata.linux_interface().is_some()));
    writer.u8(match metadata.direction() {
        Direction::Inbound => 1,
        Direction::Outbound => 2,
        Direction::Unknown => 0,
    });
    match metadata.vlan() {
        Some(vlan) => {
            writer.u8(1);
            writer.u16(vlan.tpid);
            writer.u16(vlan.tci);
        }
        None => writer.u8(0),
    }
    writer.u32(metadata.original_len());
    writer.bytes(frame.bytes());
    let record = writer.finish();
    if record.len() > wire::MAX_RECORD {
        return Err(wire::invalid_record());
    }
    Ok(record)
}

fn start_cancellation_monitor(control: OwnedFd, cancelled: Arc<AtomicBool>) -> io::Result<()> {
    std::thread::Builder::new()
        .name("l2-active-cancel".into())
        .spawn(move || {
            let mut descriptors = [PollFd::new(
                control.as_fd(),
                PollFlags::POLLIN | PollFlags::POLLHUP,
            )];
            loop {
                match poll(&mut descriptors, 20_u16) {
                    Ok(0) | Err(nix::errno::Errno::EINTR) => {}
                    _ => {
                        cancelled.store(true, Ordering::Release);
                        break;
                    }
                }
            }
        })?;
    Ok(())
}

fn invalid_input(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}
