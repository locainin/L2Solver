#![cfg(target_os = "linux")]

use l2_active::{ActiveLink, ArpProbe, Limits, NeighborStatus, ReceiveEvent, StopReason};
use l2_active_linux::{HelperLink, InterfaceInfo, InterfaceSelector, discover};
use l2_onpath::MacAddress;
use std::{
    error::Error,
    net::Ipv4Addr,
    os::unix::fs::MetadataExt,
    path::Path,
    process::Command,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[test]
#[ignore = "creates only an owned user, mount and network namespace with a veth pair"]
fn owned_veth_carries_one_real_arp_probe_and_confirms_cleanup() -> Result<(), Box<dyn Error>> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/namespace.py");
    let output = Command::new("python3")
        .arg(script)
        .arg(std::env::current_exe()?)
        .arg(env!("CARGO_BIN_EXE_l2solver-active-helper"))
        .output()?;
    assert!(
        output.status.success(),
        "fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("request_captured=true cleanup_confirmed=true")
    );
    if std::env::var_os("L2_TEST_ACTIVE_CLI").is_some() {
        assert!(String::from_utf8_lossy(&output.stdout).contains("cli_verified=true"));
    }
    Ok(())
}

#[test]
#[ignore = "invoked only by the proved isolated namespace fixture"]
fn owned_namespace_child_performs_one_arp_probe() -> Result<(), Box<dyn Error>> {
    let parent_device: u64 = std::env::var("L2_TEST_PARENT_NET_DEVICE")?.parse()?;
    let parent_inode: u64 = std::env::var("L2_TEST_PARENT_NET_INODE")?.parse()?;
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!(
        (namespace.dev(), namespace.ino()),
        (parent_device, parent_inode),
        "packet test must not run in the parent network namespace"
    );
    let selector = InterfaceSelector::new("l2src0")?;
    let info = discover(&selector)?;
    let mac = MacAddress::new(info.mac())?;
    let limits = Limits::new(Duration::from_millis(800), 256, 65_536)?;
    let probe = ArpProbe::new(
        mac,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(192, 0, 2, 2),
        None,
        limits,
    )?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let cancelled = AtomicBool::new(false);
    let requested = Instant::now() + probe.limits().timeout();
    let mut link = HelperLink::open(
        Path::new(&helper),
        &selector,
        &info,
        &probe,
        requested,
        &cancelled,
    )?;
    let admitted = link.deadline();
    let report = probe.run_until(&mut link, &cancelled, admitted)?;
    assert_eq!(report.summary().sent_packets(), 1);
    assert_eq!(report.summary().sent_bytes(), 60);
    assert_eq!(
        report.status(),
        NeighborStatus::Observed,
        "report: {report:?}"
    );
    assert_eq!(
        report.summary().stop_reason(),
        StopReason::Deadline,
        "report: {report:?}"
    );
    assert!(
        report
            .observations()
            .iter()
            .any(|item| item.mac().bytes() == [2, 0, 0, 0, 0, 2])
    );
    assert_eq!(report.summary().capture_loss(), Some(0));
    let repeated = link.send(
        probe.frame(),
        Instant::now() + Duration::from_millis(200),
        &AtomicBool::new(false),
    );
    assert_eq!(
        repeated.err().map(|error| error.kind()),
        Some(std::io::ErrorKind::PermissionDenied)
    );
    link.close()?;

    quiet_probe(&selector, &info, Path::new(&helper), mac)?;
    capped_probe(&selector, &info, Path::new(&helper), mac)?;
    backlog_probe(&selector, &info, Path::new(&helper), mac)?;
    link_down_probe(&selector, &info, Path::new(&helper), mac)?;
    Ok(())
}

fn quiet_probe(
    selector: &InterfaceSelector,
    info: &InterfaceInfo,
    helper: &Path,
    mac: MacAddress,
) -> Result<(), Box<dyn Error>> {
    // No peer claims this target, so the shorter worker deadline is terminal
    let quiet_limits = Limits::new(Duration::from_millis(250), 256, 65_536)?;
    let quiet = ArpProbe::new(
        mac,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(192, 0, 2, 3),
        None,
        quiet_limits,
    )?;
    let cancelled = AtomicBool::new(false);
    let requested = Instant::now() + quiet.limits().timeout();
    let mut quiet_link = HelperLink::open(helper, selector, info, &quiet, requested, &cancelled)?;
    // Delay the caller so the already-running worker limit expires first
    std::thread::sleep(Duration::from_millis(100));
    let later_deadline = Instant::now() + quiet.limits().timeout();
    let quiet_report = quiet.run_until(&mut quiet_link, &cancelled, later_deadline)?;
    assert_eq!(quiet_report.summary().sent_packets(), 1);
    assert_eq!(quiet_report.status(), NeighborStatus::Inconclusive);
    assert_eq!(
        quiet_report.summary().stop_reason(),
        StopReason::BackendDeadline,
        "report: {quiet_report:?}"
    );
    quiet_link.close()?;
    Ok(())
}

fn capped_probe(
    selector: &InterfaceSelector,
    info: &InterfaceInfo,
    helper: &Path,
    mac: MacAddress,
) -> Result<(), Box<dyn Error>> {
    // The peer queues one admitted reply before the one-packet budget is used
    let capped_limits = Limits::new(Duration::from_millis(800), 1, 65_536)?;
    let capped = ArpProbe::new(
        mac,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(192, 0, 2, 2),
        None,
        capped_limits,
    )?;
    let cancelled = AtomicBool::new(false);
    let requested = Instant::now() + capped.limits().timeout();
    let mut capped_link = HelperLink::open(helper, selector, info, &capped, requested, &cancelled)?;
    let sync_dir =
        std::env::var_os("L2_TEST_SYNC_DIR").ok_or("missing fixture synchronization directory")?;
    let ready = Path::new(&sync_dir).join("ready");
    let go = Path::new(&sync_dir).join("go");
    std::fs::write(ready, b"ready")?;
    let sync_deadline = Instant::now() + Duration::from_secs(2);
    while !go.exists() && Instant::now() < sync_deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        go.exists(),
        "independent peer did not inject the queued frame"
    );
    let admitted = capped_link.deadline();
    let capped_report = capped.run_until(&mut capped_link, &cancelled, admitted)?;
    let usage = capped_report
        .summary()
        .pre_send_usage()
        .ok_or("missing drain accounting")?;
    assert_eq!(usage.packets(), 1);
    assert_eq!(usage.bytes(), 60);
    assert_eq!(capped_report.summary().sent_packets(), 0);
    capped_link.close()?;
    Ok(())
}

fn link_down_probe(
    selector: &InterfaceSelector,
    info: &InterfaceInfo,
    helper: &Path,
    mac: MacAddress,
) -> Result<(), Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(800), 256, 65_536)?;
    let probe = ArpProbe::new(
        mac,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(192, 0, 2, 4),
        None,
        limits,
    )?;
    let cancelled = AtomicBool::new(false);
    let requested = Instant::now() + limits.timeout();
    let mut link = HelperLink::open(helper, selector, info, &probe, requested, &cancelled)?;
    let deadline = link.deadline();
    let report = probe.run_until(&mut link, &cancelled, deadline)?;
    assert_eq!(report.summary().sent_packets(), 1);
    assert_eq!(
        report.summary().stop_reason(),
        StopReason::InterfaceDown,
        "report: {report:?}"
    );
    link.close()?;
    Ok(())
}

fn backlog_probe(
    selector: &InterfaceSelector,
    info: &InterfaceInfo,
    helper: &Path,
    mac: MacAddress,
) -> Result<(), Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(800), 256, 65_536)?;
    let probe = ArpProbe::new(
        mac,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(192, 0, 2, 5),
        None,
        limits,
    )?;
    let cancelled = AtomicBool::new(false);
    let requested = Instant::now() + limits.timeout();
    let mut link = HelperLink::open(helper, selector, info, &probe, requested, &cancelled)?;
    let deadline = link.deadline();
    link.send(probe.frame(), deadline, &cancelled)?;
    let sync_dir =
        std::env::var_os("L2_TEST_SYNC_DIR").ok_or("missing fixture synchronization directory")?;
    let ready = Path::new(&sync_dir).join("backlog");
    while !ready.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(ready.exists(), "independent peer did not queue a frame");
    assert_eq!(link.capture_backlog()?, Some(true));
    assert!(matches!(
        link.receive(deadline, &cancelled, 65_535)?,
        ReceiveEvent::Frame(_)
    ));
    assert_eq!(link.capture_backlog()?, Some(false));
    link.close()?;
    Ok(())
}
