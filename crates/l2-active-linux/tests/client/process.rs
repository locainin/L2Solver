use super::{HelperLink, expect_open, helper_command, receive_deadline};
use crate::{
    channel::{Channel, Peer},
    wire,
};
use l2_active::{ActiveLink, ArpProbe, Limits, ReceiveEvent};
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

fn test_bound() -> io::Result<u64> {
    crate::deadline::encode_deadline(
        Instant::now() + Duration::from_secs(1),
        l2_active::MAX_TIMEOUT,
    )
}

fn link_for_deadline(deadline: Instant) -> Result<HelperLink, Box<dyn std::error::Error>> {
    let uid = nix::unistd::getuid().as_raw();
    let (channel, _peer) = Channel::pair(Peer {
        pid: std::process::id(),
        uid,
    })?;
    let limits = Limits::new(Duration::from_secs(1), 1, 60)?;
    let probe = ArpProbe::new(
        MacAddress::new([2, 0, 0, 0, 0, 1])?,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(192, 0, 2, 2),
        None,
        limits,
    )?;
    Ok(HelperLink {
        channel,
        control: None,
        child: None,
        lease: None,
        intent: crate::intent::Intent::arp(&probe)?,
        identity: LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?,
        deadline,
        send_confirmed: false,
        poisoned: false,
        signalled: false,
    })
}

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
    writer.u16(0);
    writer.u16(3);
    writer.bytes(&[1, 2, 3]);
    writer.u64(test_bound()?);
    let record = writer.finish();
    expect_open(
        &record,
        1,
        0,
        &[1, 2, 3],
        u64::MAX,
        Instant::now() + Duration::from_secs(1),
    )?;
    assert_eq!(
        expect_open(
            &record,
            1,
            0,
            &[1, 2, 4],
            u64::MAX,
            Instant::now() + Duration::from_secs(1)
        )
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
    writer.u16(0);
    writer.u64(test_bound()?);
    let record = writer.finish();
    expect_open(
        &record,
        4,
        0,
        &[],
        u64::MAX,
        Instant::now() + Duration::from_secs(1),
    )?;
    assert_eq!(
        expect_open(
            &record,
            5,
            0,
            &[],
            u64::MAX,
            Instant::now() + Duration::from_secs(1)
        )
        .err()
        .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    Ok(())
}

#[test]
fn helper_open_accepts_a_worker_deadline_in_the_acknowledgement() -> io::Result<()> {
    let client = Instant::now() + Duration::from_secs(2);
    let worker = Instant::now() + Duration::from_secs(1);
    let bound = crate::deadline::encode_deadline(worker, l2_active::MAX_TIMEOUT)?;
    let mut writer = wire::Writer::new(wire::OK);
    writer.u8(4);
    writer.u16(0);
    writer.u16(0);
    writer.u64(bound);
    let admitted = expect_open(&writer.finish(), 4, 0, &[], bound, client)?;
    assert!(admitted <= worker, "worker deadline must not be extended");
    assert!(admitted <= client, "client deadline must not be extended");
    Ok(())
}

#[test]
fn helper_open_rejects_missing_expired_zero_and_extended_worker_deadlines() -> io::Result<()> {
    let requested = test_bound()?;
    for (bound, kind) in [
        (None, io::ErrorKind::InvalidData),
        (Some(0), io::ErrorKind::InvalidData),
        (Some(1), io::ErrorKind::TimedOut),
        (requested.checked_add(1), io::ErrorKind::InvalidData),
    ] {
        let mut writer = wire::Writer::new(wire::OK);
        writer.u8(4);
        writer.u16(0);
        writer.u16(0);
        if let Some(bound) = bound {
            writer.u64(bound);
        }
        assert_eq!(
            expect_open(
                &writer.finish(),
                4,
                0,
                &[],
                requested,
                Instant::now() + Duration::from_secs(1),
            )
            .err()
            .map(|error| error.kind()),
            Some(kind),
            "worker bound {bound:?}"
        );
    }
    for payload in [vec![0; 7], vec![0; 9]] {
        let mut writer = wire::Writer::new(wire::OK);
        writer.u8(4);
        writer.u16(0);
        writer.u16(0);
        writer.bytes(&payload);
        assert_eq!(
            expect_open(
                &writer.finish(),
                4,
                0,
                &[],
                requested,
                Instant::now() + Duration::from_secs(1),
            )
            .err()
            .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData),
            "malformed deadline length {}",
            payload.len()
        );
    }
    Ok(())
}

#[test]
fn helper_open_retains_an_earlier_client_deadline() -> io::Result<()> {
    let client = Instant::now() + Duration::from_secs(1);
    let worker = Instant::now() + Duration::from_secs(2);
    let bound = crate::deadline::encode_deadline(worker, l2_active::MAX_TIMEOUT)?;
    let mut writer = wire::Writer::new(wire::OK);
    writer.u8(4);
    writer.u16(0);
    writer.u16(0);
    writer.u64(bound);
    assert_eq!(
        expect_open(&writer.finish(), 4, 0, &[], bound, client)?,
        client
    );
    Ok(())
}

#[test]
fn helper_open_rejects_an_expired_client_deadline() -> io::Result<()> {
    let bound = test_bound()?;
    let mut writer = wire::Writer::new(wire::OK);
    writer.u8(4);
    writer.u16(0);
    writer.u16(0);
    writer.u64(bound);
    assert_eq!(
        expect_open(&writer.finish(), 4, 0, &[], bound, Instant::now())
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}

#[test]
fn receive_reports_an_earlier_worker_deadline_even_when_both_deadlines_expired()
-> Result<(), Box<dyn std::error::Error>> {
    let now = Instant::now();
    let mut link = link_for_deadline(now - Duration::from_millis(20))?;
    let result = link.receive(now - Duration::from_millis(10), &AtomicBool::new(false), 60)?;
    assert!(matches!(result, ReceiveEvent::BackendTimedOut));
    Ok(())
}

#[test]
fn receive_reports_an_earlier_caller_deadline_when_both_deadlines_expired()
-> Result<(), Box<dyn std::error::Error>> {
    let now = Instant::now();
    let mut link = link_for_deadline(now - Duration::from_millis(10))?;
    let result = link.receive(now - Duration::from_millis(20), &AtomicBool::new(false), 60)?;
    assert!(matches!(result, ReceiveEvent::TimedOut));
    Ok(())
}

#[test]
fn send_rejects_an_expired_admitted_deadline_even_if_caller_allows_more_time()
-> Result<(), Box<dyn std::error::Error>> {
    let now = Instant::now();
    let mut link = link_for_deadline(now - Duration::from_millis(1))?;
    let frame = link.intent.frame().to_vec();
    let error = link
        .send(
            &frame,
            now + Duration::from_secs(1),
            &AtomicBool::new(false),
        )
        .err()
        .ok_or("send outlived the admitted deadline")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    Ok(())
}

#[test]
fn confirmed_send_is_rejected_before_the_expired_deadline_check()
-> Result<(), Box<dyn std::error::Error>> {
    let now = Instant::now();
    let mut link = link_for_deadline(now - Duration::from_millis(1))?;
    link.send_confirmed = true;
    let frame = link.intent.frame().to_vec();
    let error = link
        .send(
            &frame,
            now + Duration::from_secs(1),
            &AtomicBool::new(false),
        )
        .err()
        .ok_or("confirmed send was accepted again")?;
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    Ok(())
}

#[test]
fn helper_open_rejects_a_different_listener_selection() -> io::Result<()> {
    for (kind, profile, different) in [(7, 42, 43), (8, 0, 1), (8, 1, 0), (8, 256, 0)] {
        let mut writer = wire::Writer::new(wire::OK);
        writer.u8(kind);
        writer.u16(profile);
        writer.u16(0);
        writer.u64(test_bound()?);
        let record = writer.finish();
        expect_open(
            &record,
            kind,
            profile,
            &[],
            u64::MAX,
            Instant::now() + Duration::from_secs(1),
        )?;
        assert_eq!(
            expect_open(
                &record,
                kind,
                different,
                &[],
                u64::MAX,
                Instant::now() + Duration::from_secs(1)
            )
            .err()
            .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
        assert_eq!(
            expect_open(
                &record,
                if kind == 7 { 8 } else { 7 },
                profile,
                &[],
                u64::MAX,
                Instant::now() + Duration::from_secs(1)
            )
            .err()
            .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
    }
    Ok(())
}

#[test]
fn hsrp_open_distinguishes_all_groups_from_group_zero_and_group_255()
-> Result<(), Box<dyn std::error::Error>> {
    let mac = MacAddress::new([2, 0, 0, 0, 0, 1])?;
    let limits = Limits::new(Duration::from_secs(1), 1, 60)?;
    for (group, expected) in [(None, 0), (Some(0), 1), (Some(255), 256)] {
        let intent =
            crate::intent::Intent::listen(mac, limits, crate::intent::ListenKind::Hsrp { group });
        assert_eq!(intent.profile(), expected);
    }
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
        send_confirmed: false,
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
