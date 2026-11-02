#![cfg(target_os = "linux")]

use l2_active::{ActiveLink, Limits, NeighborStatus, StopReason};
use l2_active_linux::{HelperLink, InterfaceSelector, ndp};
use l2_onpath::MacAddress;
use std::{
    error::Error,
    io,
    net::Ipv6Addr,
    os::unix::fs::MetadataExt,
    path::Path,
    process::Command,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[path = "support/child_mode.rs"]
mod child_mode;

const PARENT_TEST: &str = "owned_veth_carries_one_typed_link_local_solicitation_and_advertisement";

#[test]
fn ndp_fixture_witnesses_synthetic_exchange_and_cleanup() -> Result<(), Box<dyn Error>> {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../l2-active/tests/ndp/fixtures/veth.py");
    let output = Command::new("python3").arg(fixture).output()?;
    assert!(
        output.status.success(),
        "fixture self-check failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("request_captured=true advertisement_captured=true cleanup_confirmed=true")
    );
    Ok(())
}

#[test]
fn ndp_fixture_rejects_a_command_that_sends_no_solicitation() -> Result<(), Box<dyn Error>> {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../l2-active/tests/ndp/fixtures/veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .args(["--", "python3", "-c", "pass"])
        .output()?;
    assert!(
        !output.status.success(),
        "a silent command must fail the fixture"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("requests=0"));
    Ok(())
}

#[test]
fn owned_veth_carries_one_typed_link_local_solicitation_and_advertisement()
-> Result<(), Box<dyn Error>> {
    if child_mode::selected(PARENT_TEST)? {
        return owned_namespace_child_performs_one_link_local_ndp_probe();
    }
    run_owned_veth(None)
}

#[test]
fn owned_veth_counts_only_frames_admitted_by_the_ndp_filter() -> Result<(), Box<dyn Error>> {
    for candidate in ["fragment", "other-target", "bad-hop"] {
        run_owned_veth(Some(candidate))?;
    }
    Ok(())
}

fn run_owned_veth(filter_noise: Option<&str>) -> Result<(), Box<dyn Error>> {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../l2-active/tests/ndp/fixtures/veth.py");
    let mut command = Command::new("python3");
    command
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .env(child_mode::ENV, PARENT_TEST)
        .args(["--exact", PARENT_TEST, "--nocapture"])
        .env(
            "L2_TEST_ACTIVE_HELPER",
            env!("CARGO_BIN_EXE_l2solver-active-helper"),
        );
    if let Some(candidate) = filter_noise {
        command.env("L2_TEST_NDP_FILTER_NOISE", candidate);
    } else {
        command.env_remove("L2_TEST_NDP_FILTER_NOISE");
    }
    let output = command.output()?;
    assert!(
        output.status.success(),
        "fixture {filter_noise:?} failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("request_captured=true advertisement_captured=true cleanup_confirmed=true")
    );
    if let Some(candidate) = filter_noise {
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains(&format!("filter_noise_witnessed={candidate}"))
        );
    }
    Ok(())
}

fn owned_namespace_child_performs_one_link_local_ndp_probe() -> Result<(), Box<dyn Error>> {
    let parent_device: u64 = std::env::var("L2_TEST_PARENT_NET_DEVICE")?.parse()?;
    let parent_inode: u64 = std::env::var("L2_TEST_PARENT_NET_INODE")?.parse()?;
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!(
        (namespace.dev(), namespace.ino()),
        (parent_device, parent_inode)
    );
    let selector = InterfaceSelector::new(&std::env::var("L2_TEST_NDP_INTERFACE")?)?;
    let info = ndp::discover(&selector)?;
    let source: Ipv6Addr = "fe80::1".parse()?;
    let target: Ipv6Addr = "fe80::2".parse()?;
    let peer_mac = MacAddress::new([2, 0, 0, 0, 0, 2])?;
    let limits = Limits::new(Duration::from_millis(900), 128, 65_536)?;
    let probe = ndp::prepare(&info, Some(source), target, Some(peer_mac), limits)?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let cancelled = AtomicBool::new(false);
    let requested = Instant::now() + limits.timeout();
    let mut link = HelperLink::open_ndp(
        Path::new(&helper),
        &selector,
        &info,
        &probe,
        requested,
        &cancelled,
    )?;
    let deadline = link.deadline();
    let mut changed: [u8; 86] = probe.frame().try_into().map_err(io::Error::other)?;
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
    assert_eq!(report.summary().sent_bytes(), 86);
    assert_eq!(
        report.summary().stop_reason(),
        StopReason::Deadline,
        "{report:?}"
    );
    assert_eq!(report.status(), NeighborStatus::Observed, "{report:?}");
    if let Ok(candidate) = std::env::var("L2_TEST_NDP_FILTER_NOISE") {
        let expected = match candidate.as_str() {
            "fragment" | "other-target" => 0,
            "bad-hop" => 1,
            _ => return Err("unknown filter candidate".into()),
        };
        assert_eq!(report.unmatched_packets(), expected, "{report:?}");
    }
    assert!(report.observations().iter().any(|item| {
        item.mac() == peer_mac
            && item.source_ip() == target
            && item.frame().metadata().linux_interface() == Some(info.interface().identity())
    }));
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
