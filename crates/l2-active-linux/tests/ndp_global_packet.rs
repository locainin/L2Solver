#![cfg(target_os = "linux")]

use l2_active::{Limits, NeighborStatus, StopReason};
use l2_active_linux::{HelperLink, InterfaceSelector, ndp};
use l2_onpath::MacAddress;
use std::{
    error::Error,
    fs, io,
    net::Ipv6Addr,
    os::unix::fs::MetadataExt,
    path::Path,
    process::Command,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

fn run_fixture(case: &str) -> Result<(), Box<dyn Error>> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../l2-active/tests/ndp/fixtures/global_veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "owned_global_ndp_child",
            "--nocapture",
        ])
        .env("L2_TEST_NDP_GLOBAL_CASE", case)
        .env(
            "L2_TEST_ACTIVE_HELPER",
            env!("CARGO_BIN_EXE_l2solver-active-helper"),
        )
        .output()?;
    assert!(
        output.status.success(),
        "{case} fixture failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("route_case_confirmed=true cleanup_confirmed=true")
    );
    Ok(())
}

#[test]
#[ignore = "uses a verified private namespace and an owned veth pair"]
fn global_direct_route_sends_one_solicitation_and_observes_a_reply() -> Result<(), Box<dyn Error>> {
    run_fixture("direct")
}

#[test]
#[ignore = "uses a verified private namespace and an owned veth pair"]
fn global_address_prefix_without_a_route_does_not_authorize_a_send() -> Result<(), Box<dyn Error>> {
    run_fixture("no_route")
}

#[test]
#[ignore = "uses a verified private namespace and an owned veth pair"]
fn global_gateway_route_does_not_authorize_a_send() -> Result<(), Box<dyn Error>> {
    run_fixture("gateway")
}

#[test]
#[ignore = "uses a verified private namespace and an owned veth pair"]
fn global_route_on_another_interface_does_not_authorize_a_send() -> Result<(), Box<dyn Error>> {
    run_fixture("other_interface")
}

#[test]
#[ignore = "uses a verified private namespace and an owned veth pair"]
fn global_route_removed_after_open_prevents_the_send() -> Result<(), Box<dyn Error>> {
    run_fixture("route_removed")
}

#[test]
#[ignore = "invoked only by the verified private global-NDP fixture"]
fn owned_global_ndp_child() -> Result<(), Box<dyn Error>> {
    let parent_device: u64 = std::env::var("L2_TEST_PARENT_NET_DEVICE")?.parse()?;
    let parent_inode: u64 = std::env::var("L2_TEST_PARENT_NET_INODE")?.parse()?;
    let namespace = fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!(
        (namespace.dev(), namespace.ino()),
        (parent_device, parent_inode)
    );
    let case = std::env::var("L2_TEST_NDP_GLOBAL_CASE")?;
    let selector = InterfaceSelector::new(&std::env::var("L2_TEST_NDP_INTERFACE")?)?;
    let info = ndp::discover(&selector)?;
    let source: Ipv6Addr = "2001:db8:1::1".parse()?;
    let target: Ipv6Addr = "2001:db8:1::2".parse()?;
    let expected = MacAddress::new([2, 0, 0, 0, 0, 2])?;
    let limits = Limits::new(Duration::from_secs(2), 128, 65_536)?;
    // A candidate is not permission to send until the worker proves the route
    let probe = ndp::prepare(&info, Some(source), target, Some(expected), limits)?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let cancelled = AtomicBool::new(false);
    let requested = Instant::now() + limits.timeout();
    let opened = HelperLink::open_ndp(
        Path::new(&helper),
        &selector,
        &info,
        &probe,
        requested,
        &cancelled,
    );
    if matches!(case.as_str(), "no_route" | "gateway" | "other_interface") {
        let error = opened.err().ok_or("unproved route was admitted")?;
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::Unsupported
                    | io::ErrorKind::NetworkUnreachable
                    | io::ErrorKind::HostUnreachable
            ),
            "unexpected admission failure: {error}"
        );
        return Ok(());
    }
    let mut link = opened?;
    let deadline = link.deadline();
    if case == "route_removed" {
        fs::write(
            std::env::var_os("L2_TEST_NDP_READY").ok_or("missing ready path")?,
            b"ready",
        )?;
        let go = std::env::var_os("L2_TEST_NDP_GO").ok_or("missing go path")?;
        while !Path::new(&go).exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(Path::new(&go).exists(), "route mutation was not confirmed");
    }
    let report = probe.run_until(&mut link, &cancelled, deadline)?;
    if case == "route_removed" {
        assert_eq!(report.summary().sent_packets(), 0, "{report:?}");
        assert_eq!(
            report.summary().stop_reason(),
            StopReason::TransportError,
            "{report:?}"
        );
    } else {
        assert_eq!(report.summary().sent_packets(), 1, "{report:?}");
        assert_eq!(report.status(), NeighborStatus::Observed, "{report:?}");
        assert!(
            report
                .observations()
                .iter()
                .any(|item| item.mac() == expected)
        );
    }
    link.close()?;
    Ok(())
}
