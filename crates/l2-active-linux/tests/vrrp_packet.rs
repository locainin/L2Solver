#![cfg(target_os = "linux")]

use std::{
    error::Error,
    num::NonZeroU8,
    os::unix::fs::MetadataExt,
    path::Path,
    process::Command,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use l2_active::{
    Limits,
    first_hop::vrrp::{VrrpEvidence, VrrpMalformed, VrrpMonitor, VrrpStatus},
};
use l2_active_linux::{HelperLink, InterfaceSelector, discover};

#[path = "support/receive_only.rs"]
mod support;

const PARENT_TEST: &str = "owned_veth_helper_observes_vrrp_v3_without_sending_or_exposing_v2";

#[test]
fn receive_only_child_rejects_the_parent_network_namespace() -> Result<(), Box<dyn Error>> {
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    let parent = PARENT_TEST;
    let output = Command::new(std::env::current_exe()?)
        .args(["--exact", parent, "--nocapture"])
        .env(support::child_mode::ENV, parent)
        .env("L2_TEST_PARENT_NET_DEVICE", namespace.dev().to_string())
        .env("L2_TEST_PARENT_NET_INODE", namespace.ino().to_string())
        .output()?;
    assert!(
        !output.status.success(),
        "receive-only child accepted the parent network namespace"
    );
    Ok(())
}

#[test]
fn owned_veth_helper_observes_vrrp_v3_without_sending_or_exposing_v2() -> Result<(), Box<dyn Error>>
{
    if support::child_mode::selected(PARENT_TEST)? {
        return owned_namespace_child_observes_vrrp_without_sending();
    }
    support::run_fixture(
        "../l2-active/tests/first_hop/vrrp/fixtures/veth.py",
        PARENT_TEST,
        "advertisements_delivered=true no_client_send=true cleanup_confirmed=true",
    )
}

fn owned_namespace_child_observes_vrrp_without_sending() -> Result<(), Box<dyn Error>> {
    support::assert_owned()?;
    let selector = InterfaceSelector::new(&std::env::var("L2_TEST_VRRP_INTERFACE")?)?;
    let info = discover(&selector)?;
    let original_promisc = support::promiscuous(&selector)?;
    let baseline_memberships = memberships(info.identity().ifindex())?;
    let limits = Limits::new(Duration::from_secs(3), 128, 65_536)?;
    let monitor = VrrpMonitor::new(NonZeroU8::new(42), limits);
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let cancelled = AtomicBool::new(false);
    let requested = Instant::now() + limits.timeout();
    let mut link = HelperLink::open_vrrp(
        Path::new(&helper),
        &selector,
        &info,
        &monitor,
        requested,
        &cancelled,
    )?;
    let deadline = link.deadline();
    assert!(memberships(info.identity().ifindex())? > baseline_memberships);
    assert_eq!(support::promiscuous(&selector)?, original_promisc);
    support::assert_send_denied(&mut link, deadline, &cancelled);
    support::ready("VRRP")?;
    let report = monitor.run_until(&mut link, &cancelled, deadline)?;
    assert_eq!(report.status(), VrrpStatus::Observed);
    assert_eq!(report.summary().sent_packets(), 0);
    assert_eq!(report.summary().received_packets(), 3);
    assert_eq!(report.summary().capture_loss(), Some(0));
    let [checksum, ttl, valid] = report.observations() else {
        return Err("expected two malformed candidates and one advertisement".into());
    };
    assert_eq!(
        checksum.evidence(),
        &VrrpEvidence::Malformed(VrrpMalformed::Checksum)
    );
    assert_eq!(ttl.evidence(), &VrrpEvidence::Malformed(VrrpMalformed::Ttl));
    let VrrpEvidence::Advertisement(advert) = valid.evidence() else {
        return Err("missing valid VRRP advertisement".into());
    };
    assert_eq!(advert.vrid().get(), 42);
    assert!(advert.source_matches_virtual_mac());
    assert_eq!(
        valid
            .addresses()
            .ok_or("missing virtual addresses")?
            .count(),
        2
    );
    // The discarded v2 authentication marker must not cross the helper channel
    for observation in report.observations() {
        assert!(
            !observation
                .frame()
                .bytes()
                .windows(8)
                .any(|bytes| bytes == b"VRRPauth")
        );
    }
    link.close()?;
    assert_eq!(
        memberships(info.identity().ifindex())?,
        baseline_memberships
    );
    assert_eq!(support::promiscuous(&selector)?, original_promisc);
    Ok(())
}

fn memberships(index: u32) -> Result<u32, Box<dyn Error>> {
    for line in std::fs::read_to_string("/proc/net/dev_mcast")?.lines() {
        let mut fields = line.split_whitespace();
        let Some(raw_index) = fields.next() else {
            continue;
        };
        let _name = fields.next();
        let users = fields.next();
        let _global = fields.next();
        let address = fields.next();
        if raw_index.parse::<u32>()? == index && address == Some("01005e000012") {
            return Ok(users.ok_or("missing multicast user count")?.parse()?);
        }
    }
    Ok(0)
}
