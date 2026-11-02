mod synchronize;
#[path = "../support/child_mode.rs"]
mod child_mode;

use l2_active::{ArpProbe, ArpReport, Limits, NeighborStatus, StopReason};
use l2_active_linux::{HelperLink, InterfaceSelector, discover};
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
fn vlan_witness_distinguishes_auxiliary_and_unmodified_frames() -> Result<(), Box<dyn Error>> {
    let test = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vlan/test_namespace.py");
    let result = Command::new("python3")
        .arg(test)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()?;
    assert!(
        result.status.success(),
        "VLAN witness checks failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}

#[test]
fn vlan_pin_fixture_requires_its_child_test_to_run() -> Result<(), Box<dyn Error>> {
    let test = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vlan/test_kernel.py");
    let result = Command::new("python3")
        .arg(test)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()?;
    assert!(
        result.status.success(),
        "VLAN pin child checks failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}

fn fixture(protocol: &str, case: &str) -> Result<(), Box<dyn Error>> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vlan/namespace.py");
    let result = Command::new("python3")
        .arg(script)
        .arg(protocol)
        .arg(std::env::current_exe()?)
        .arg(env!("CARGO_BIN_EXE_l2solver-active-helper"))
        .env("L2_TEST_VLAN_CASE", case)
        .output()?;
    assert!(
        result.status.success(),
        "{protocol} VLAN fixture failed: {} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8_lossy(&result.stdout);
    assert!(output.contains("cleanup_confirmed=true"));
    if matches!(case, "normal" | "after_reply") {
        assert!(
            output.contains("tagged_request_representation=auxiliary")
                || output.contains("tagged_request_representation=unmodified"),
            "tagged witness must identify its captured representation: {output}"
        );
    }
    Ok(())
}

#[test]
fn ieee8021q_arp_uses_the_configured_vlan_and_filters_wrong_vid() -> Result<(), Box<dyn Error>> {
    if child_mode::selected("vlan-normal")? {
        return owned_vlan_child_rejects_wrong_vid_and_observes_matching_reply();
    }
    fixture("802.1Q", "normal")
}

#[test]
fn ieee8021ad_arp_uses_the_configured_vlan_and_filters_wrong_vid() -> Result<(), Box<dyn Error>> {
    fixture("802.1ad", "normal")
}

#[test]
fn reorder_off_is_rejected_before_any_transmission() -> Result<(), Box<dyn Error>> {
    if child_mode::selected("vlan-change")? {
        return owned_vlan_child_checks_reorder_admission_and_changes();
    }
    fixture("802.1Q", "deny_off")
}

#[test]
fn reorder_changed_after_open_blocks_the_send() -> Result<(), Box<dyn Error>> {
    fixture("802.1Q", "before_send")
}

#[test]
fn reorder_changed_after_discovery_rejects_open() -> Result<(), Box<dyn Error>> {
    fixture("802.1Q", "before_open")
}

#[test]
fn reorder_changed_after_reply_retains_observation_and_marks_incomplete()
-> Result<(), Box<dyn Error>> {
    fixture("802.1Q", "after_reply")
}

#[test]
fn selected_name_changed_after_reply_retains_observation_and_marks_incomplete()
-> Result<(), Box<dyn Error>> {
    fixture("802.1Q", "rename_after_reply")
}

#[test]
fn final_scope_sample_detects_change_after_the_last_retained_frame() -> Result<(), Box<dyn Error>> {
    fixture("802.1Q", "after_limit")
}

fn owned_vlan_child_rejects_wrong_vid_and_observes_matching_reply() -> Result<(), Box<dyn Error>> {
    let parent_device: u64 = std::env::var("L2_TEST_PARENT_NET_DEVICE")?.parse()?;
    let parent_inode: u64 = std::env::var("L2_TEST_PARENT_NET_INODE")?.parse()?;
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!(
        (namespace.dev(), namespace.ino()),
        (parent_device, parent_inode)
    );
    let selector = InterfaceSelector::new("l2vlan0")?;
    let info = discover(&selector)?;
    let mac = MacAddress::new(info.mac())?;
    let peer = MacAddress::new([2, 0, 0, 0, 0, 2])?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let cancelled = AtomicBool::new(false);
    for expected in [NeighborStatus::Inconclusive, NeighborStatus::Observed] {
        let limits = Limits::new(Duration::from_millis(800), 128, 65_536)?;
        let probe = ArpProbe::new(
            mac,
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 2),
            Some(peer),
            limits,
        )?;
        let requested = Instant::now() + limits.timeout();
        let mut link = HelperLink::open(
            Path::new(&helper),
            &selector,
            &info,
            &probe,
            requested,
            &cancelled,
        )?;
        let deadline = link.deadline();
        let report = probe.run_until(&mut link, &cancelled, deadline)?;
        assert_eq!(report.summary().sent_packets(), 1, "{report:?}");
        assert_eq!(report.status(), expected, "{report:?}");
        if expected == NeighborStatus::Inconclusive {
            assert!(report.observations().is_empty(), "{report:?}");
        } else {
            let observation = report
                .observations()
                .iter()
                .find(|item| item.mac() == peer)
                .ok_or("missing expected peer reply")?;
            let frame = observation.frame();
            assert_eq!(frame.metadata().linux_interface(), Some(info.identity()));
            assert_eq!(frame.metadata().vlan(), None);
            assert_eq!(frame.bytes().len(), 60);
            assert_eq!(frame.bytes().get(12..14), Some([0x08, 0x06].as_slice()));
        }
        link.close()?;
    }
    Ok(())
}

fn owned_vlan_child_checks_reorder_admission_and_changes() -> Result<(), Box<dyn Error>> {
    let parent_device: u64 = std::env::var("L2_TEST_PARENT_NET_DEVICE")?.parse()?;
    let parent_inode: u64 = std::env::var("L2_TEST_PARENT_NET_INODE")?.parse()?;
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!(
        (namespace.dev(), namespace.ino()),
        (parent_device, parent_inode)
    );
    let case = std::env::var("L2_TEST_VLAN_CASE")?;
    let selector = InterfaceSelector::new("l2vlan0")?;
    let info = discover(&selector)?;
    let peer = MacAddress::new([2, 0, 0, 0, 0, 2])?;
    let packet_limit = if case == "after_limit" { 1 } else { 128 };
    let limits = Limits::new(Duration::from_secs(2), packet_limit, 65_536)?;
    let probe = ArpProbe::new(
        MacAddress::new(info.mac())?,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(192, 0, 2, 2),
        Some(peer),
        limits,
    )?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let cancelled = AtomicBool::new(false);
    if case == "before_open" {
        synchronize::wait_for_change(Instant::now() + limits.timeout())?;
    }
    let opened = HelperLink::open(
        Path::new(&helper),
        &selector,
        &info,
        &probe,
        Instant::now() + limits.timeout(),
        &cancelled,
    );
    if case == "deny_off" {
        assert_eq!(
            opened.err().map(|error| error.kind()),
            Some(std::io::ErrorKind::Unsupported)
        );
        return Ok(());
    }
    if case == "before_open" {
        let error = opened.err().ok_or("changed scope was admitted")?;
        assert_scope_error(Some(&error));
        return Ok(());
    }
    let mut link = synchronize::AfterFrame(opened?, false);
    let deadline = link.0.deadline();
    if case == "before_send" {
        synchronize::wait_for_change(deadline)?;
    }
    let report = probe.run_until(&mut link, &cancelled, deadline)?;
    check_changed_report(&case, &report, peer);
    link.0.close()?;
    Ok(())
}

fn check_changed_report(case: &str, report: &ArpReport, peer: MacAddress) {
    let summary = report.summary();
    if case == "after_limit" {
        assert_eq!(summary.stop_reason(), StopReason::PacketLimit, "{report:?}");
        assert_scope_error(summary.backlog_error());
    } else {
        assert_eq!(
            summary.stop_reason(),
            StopReason::TransportError,
            "{report:?}"
        );
        assert_scope_error(summary.transport_error());
    }
    if case == "before_send" {
        assert_eq!(report.summary().sent_packets(), 0);
        assert!(report.observations().is_empty());
    } else {
        assert_eq!(report.summary().sent_packets(), 1);
        assert_eq!(report.status(), NeighborStatus::Observed);
        assert!(
            report
                .observations()
                .iter()
                .any(|observation| observation.mac() == peer)
        );
    }
}

fn assert_scope_error(error: Option<&std::io::Error>) {
    assert!(
        matches!(error.and_then(std::io::Error::get_ref), Some(source) if source.is::<l2_active_linux::VlanScopeChanged>()),
        "{error:?}"
    );
}
