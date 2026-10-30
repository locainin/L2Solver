use super::{HelperLink, expect_open, helper_command, receive_deadline};
use crate::{
    channel::{Channel, Peer},
    wire,
};
use l2_active::{ArpProbe, Limits};
use l2_capture::LinuxInterfaceIdentity;
use l2_onpath::MacAddress;
use nix::unistd::{Pid, getpgid, getpgrp};
use nix::{fcntl::OFlag, unistd::pipe2};
use std::{
    io,
    net::Ipv4Addr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[test]
fn helper_runs_in_a_different_process_group_from_the_terminal_frontend() -> io::Result<()> {
    let mut child = helper_command(Path::new("sleep")).arg("60").spawn()?;
    let child_pid = i32::try_from(child.id()).map_err(io::Error::other)?;
    let group = getpgid(Some(Pid::from_raw(child_pid))).map_err(io::Error::other)?;
    let parent_group = getpgrp();
    let kill = child.kill();
    let wait = child.wait();
    assert_eq!(group.as_raw(), child_pid);
    assert_ne!(group, parent_group);
    kill?;
    wait?;
    Ok(())
}

#[test]
fn deadline_expiring_while_preparing_receive_is_a_timeout_event() -> io::Result<()> {
    assert_eq!(receive_deadline(Instant::now())?, None);
    Ok(())
}

#[test]
fn helper_open_requires_exact_reconstructed_frame_bytes() -> io::Result<()> {
    let mut writer = wire::Writer::new(wire::OK);
    writer.u8(1);
    writer.u16(3);
    writer.bytes(&[1, 2, 3]);
    let record = writer.finish();
    expect_open(&record, 1, &[1, 2, 3])?;
    assert_eq!(
        expect_open(&record, 1, &[1, 2, 4])
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    Ok(())
}

#[test]
fn helper_open_rejects_a_different_empty_frame_listen_profile() -> io::Result<()> {
    let mut writer = wire::Writer::new(wire::OK);
    writer.u8(4);
    writer.u16(0);
    let record = writer.finish();
    expect_open(&record, 4, &[])?;
    assert_eq!(
        expect_open(&record, 5, &[]).err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    Ok(())
}

#[test]
fn cancellation_interrupts_a_silent_helper_during_open() -> Result<(), Box<dyn std::error::Error>> {
    let uid = nix::unistd::getuid().as_raw();
    let (channel, _other) = Channel::pair(Peer {
        pid: std::process::id(),
        uid,
    })?;
    let (_control_read, control_write) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)?;
    let limits = Limits::new(Duration::from_secs(1), 1, 60)?;
    let probe = ArpProbe::new(
        MacAddress::new([2, 0, 0, 0, 0, 1])?,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(192, 0, 2, 2),
        None,
        limits,
    )?;
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let mut link = HelperLink {
        channel,
        control: Some(control_write),
        child: None,
        lease: None,
        intent: crate::intent::Intent::arp(&probe)?,
        identity,
        deadline: Instant::now() + Duration::from_secs(1),
        poisoned: false,
        signalled: false,
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&cancelled);
    let worker = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        signal.store(true, Ordering::Release);
    });
    let start = Instant::now();
    let result = link.exchange(
        &[wire::OPEN],
        start + Duration::from_secs(1),
        Some(&cancelled),
    );
    worker
        .join()
        .map_err(|_| io::Error::other("cancellation thread failed"))?;
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::Interrupted)
    );
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "cancellation waited for startup deadline"
    );
    Ok(())
}
