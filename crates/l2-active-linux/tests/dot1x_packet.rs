#![cfg(target_os = "linux")]

use std::{
    error::Error,
    io,
    os::unix::fs::MetadataExt,
    path::Path,
    process::Command,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use l2_active::{
    ActiveLink, Limits, StopReason,
    dot1x::{Dot1xDestination, Dot1xProbe, Dot1xStatus},
};
use l2_active_linux::{HelperLink, InterfaceSelector, discover};
use l2_onpath::MacAddress;

#[path = "support/child_mode.rs"]
mod child_mode;

const PARENT_TEST: &str = "owned_veth_carries_one_typed_start_and_observes_request";

#[test]
fn owned_veth_carries_one_typed_start_and_observes_request() -> Result<(), Box<dyn Error>> {
    if child_mode::selected(PARENT_TEST)? {
        return owned_namespace_child_performs_one_eapol_start();
    }
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../l2-active/tests/dot1x/fixtures/veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .env(child_mode::ENV, PARENT_TEST)
        .args(["--exact", PARENT_TEST, "--nocapture"])
        .env(
            "L2_TEST_ACTIVE_HELPER",
            env!("CARGO_BIN_EXE_l2solver-active-helper"),
        )
        .output()?;
    assert!(
        output.status.success(),
        "fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("start_captured=true request_captured=true cleanup_confirmed=true")
    );
    Ok(())
}

fn owned_namespace_child_performs_one_eapol_start() -> Result<(), Box<dyn Error>> {
    require_private_namespace()?;
    let selector = InterfaceSelector::new(&std::env::var("L2_TEST_DOT1X_INTERFACE")?)?;
    let info = discover(&selector)?;
    assert!(info.ipv4_assignments().is_empty());
    let limits = Limits::new(Duration::from_millis(900), 256, 65_536)?;
    let probe = Dot1xProbe::new(MacAddress::new(info.mac())?, limits)?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let cancelled = AtomicBool::new(false);

    // A Start is not admitted without an explicit dedicated-interface choice
    let denied = HelperLink::open_dot1x(
        Path::new(&helper),
        &selector,
        &info,
        &probe,
        false,
        Instant::now() + limits.timeout(),
        &cancelled,
    );
    assert_eq!(
        denied.err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );

    let mut link = HelperLink::open_dot1x(
        Path::new(&helper),
        &selector,
        &info,
        &probe,
        true,
        Instant::now() + limits.timeout(),
        &cancelled,
    )?;
    let deadline = link.deadline();
    let mut changed: [u8; 60] = probe
        .frame()
        .try_into()
        .map_err(|_| io::Error::other("unexpected Start length"))?;
    if let Some(byte) = changed.first_mut() {
        *byte ^= 1;
    }
    assert_eq!(
        link.send(&changed, deadline, &cancelled)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );

    let report = probe.run_until(&mut link, &cancelled, deadline)?;
    assert_eq!(report.summary().sent_packets(), 1);
    assert_eq!(report.summary().sent_bytes(), 60);
    assert_eq!(
        report.summary().stop_reason(),
        StopReason::Deadline,
        "report: {report:?}"
    );
    assert_eq!(report.status(), Dot1xStatus::Observed, "report: {report:?}");
    assert!(report.observations().iter().any(|request| {
        request.source_mac().bytes() == [2, 0, 0, 0, 0, 2]
            && request.destination() == Dot1xDestination::SelectedInterface
            && request.identifier() == 41
            && request.request_type() == 1
    }));
    // The fixture independently witnesses excluded traffic on the client veth
    assert!(report.malformed().is_empty(), "report: {report:?}");
    assert_eq!(report.unrelated_packets(), 0, "report: {report:?}");
    assert_eq!(report.summary().capture_loss(), Some(0));
    assert_eq!(report.summary().capture_backlog(), Some(false));
    assert_eq!(
        link.send(
            probe.frame(),
            Instant::now() + Duration::from_millis(200),
            &cancelled
        )
        .err()
        .map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    link.close()?;
    Ok(())
}

fn require_private_namespace() -> Result<(), Box<dyn Error>> {
    let parent_device: u64 = std::env::var("L2_TEST_PARENT_NET_DEVICE")?.parse()?;
    let parent_inode: u64 = std::env::var("L2_TEST_PARENT_NET_INODE")?.parse()?;
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!(
        (namespace.dev(), namespace.ino()),
        (parent_device, parent_inode)
    );
    Ok(())
}
