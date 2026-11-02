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

use l2_active::{ActiveLink, Limits, stp::StpMonitor};
use l2_active_linux::{HelperLink, InterfaceSelector, discover};

const CONFIGURATION: &[u8] = include_bytes!("../../l2-active/tests/fixtures/stp-configuration.bin");
const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];

#[path = "support/child_mode.rs"]
mod child_mode;

const PARENT_TEST: &str = "owned_veth_receives_stp_without_transmitting_and_confirms_cleanup";

#[test]
fn owned_veth_receives_stp_without_transmitting_and_confirms_cleanup() -> Result<(), Box<dyn Error>>
{
    if child_mode::selected(PARENT_TEST)? {
        return owned_namespace_child_observes_stp_without_sending();
    }
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/stp/namespace.py");
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
        "fixture failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(
        "stp_emitted=true stp_observed=true memberships_restored=true cleanup_confirmed=true"
    ));
    Ok(())
}

fn owned_namespace_child_observes_stp_without_sending() -> Result<(), Box<dyn Error>> {
    let parent_device: u64 = std::env::var("L2_TEST_PARENT_NET_DEVICE")?.parse()?;
    let parent_inode: u64 = std::env::var("L2_TEST_PARENT_NET_INODE")?.parse()?;
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!(
        (namespace.dev(), namespace.ino()),
        (parent_device, parent_inode),
        "STP packet test must run in its own network namespace"
    );
    let selector = InterfaceSelector::new(&std::env::var("L2_TEST_STP_INTERFACE")?)?;
    let info = discover(&selector)?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let limits = Limits::new(Duration::from_secs(4), 128, 65_536)?;
    let cancelled = AtomicBool::new(false);
    let requested = Instant::now() + limits.timeout();
    let mut link = HelperLink::open_stp(
        Path::new(&helper),
        &selector,
        &info,
        limits,
        requested,
        &cancelled,
    )?;
    let deadline = link.deadline();
    for frame in [&[][..], &[0_u8; 60][..]] {
        assert_eq!(
            link.send(frame, deadline, &cancelled)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
    }
    std::fs::write(
        std::env::var_os("L2_TEST_STP_READY").ok_or("missing ready marker")?,
        b"ready",
    )?;
    let report = StpMonitor::new(limits).run_until(&mut link, &cancelled, deadline)?;
    let mut expected = CONFIGURATION.to_vec();
    expected
        .get_mut(6..12)
        .ok_or("short STP fixture")?
        .copy_from_slice(&PEER_MAC);
    expected.resize(60, 0);
    let observed = report
        .observations()
        .iter()
        .find(|item| item.frame().bytes() == expected)
        .ok_or("independent STP frame was not retained")?;
    let decoded = observed.decoded().ok_or("STP candidate was not decoded")?;
    assert_eq!(
        decoded.root.map(|root| root.mac),
        Some([2, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
    assert_eq!(decoded.port.map(|port| port.raw), Some(0x8001));
    assert_eq!(
        observed.frame().metadata().linux_interface(),
        Some(info.identity())
    );
    assert!(!report.summary().send_attempted());
    assert_eq!(report.summary().sent_packets(), 0);
    assert_eq!(report.summary().capture_loss(), Some(0));
    assert_eq!(report.summary().capture_backlog(), Some(false));
    link.close()?;
    std::fs::write(
        std::env::var_os("L2_TEST_STP_OBSERVED").ok_or("missing observation marker")?,
        b"observed",
    )?;
    Ok(())
}
