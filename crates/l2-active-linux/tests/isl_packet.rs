#![cfg(target_os = "linux")]

use std::{
    error::Error,
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use l2_active::{
    Limits,
    isl::{IslEvidence, IslMalformed, IslMonitor, IslStatus},
};
use l2_active_linux::{HelperLink, InterfaceSelector, discover};

#[path = "support/switching_membership.rs"]
mod membership;
#[path = "support/receive_only.rs"]
mod support;

const VALID: &[u8] = include_bytes!("../../l2-active/tests/isl/fixtures/valid.bin");
const MODE_FLAGS: u32 = 0x300;

#[test]
#[ignore = "uses a proved private namespace and owned receive-only veth pair"]
fn owned_veth_delivers_isl_through_the_restricted_helper() -> Result<(), Box<dyn Error>> {
    support::run_fixture(
        "../l2-active/tests/isl/fixtures/veth.py",
        "owned_namespace_child_observes_isl_without_sending",
        "isl_delivered=true no_client_send=true cleanup_confirmed=true",
    )
}

#[test]
#[ignore = "invoked only by the proved private ISL fixture"]
fn owned_namespace_child_observes_isl_without_sending() -> Result<(), Box<dyn Error>> {
    support::assert_owned()?;
    let selector = InterfaceSelector::new(&std::env::var("L2_TEST_ISL_INTERFACE")?)?;
    let info = discover(&selector)?;
    let initial_promisc = support::promiscuous(&selector)?;
    let original_modes = info.flags() & MODE_FLAGS;
    let before = membership::snapshot(info.identity().ifindex())?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let limits = Limits::new(Duration::from_secs(2), 128, 65_536)?;
    let monitor = IslMonitor::new(limits);
    let cancelled = AtomicBool::new(false);
    let requested = Instant::now() + limits.timeout();
    let mut link = HelperLink::open_isl(
        Path::new(&helper),
        &selector,
        &info,
        &monitor,
        requested,
        &cancelled,
    )?;
    let deadline = link.deadline();
    let after = membership::snapshot(info.identity().ifindex())?;
    let groups = [1_u8, 3]
        .into_iter()
        .flat_map(|prefix| (0_u8..16).map(move |user| format!("{prefix:02x}000c0000{user:02x}")));
    membership::assert_added(&before, &after, groups)?;
    assert_eq!(discover(&selector)?.flags() & MODE_FLAGS, original_modes);
    assert_eq!(support::promiscuous(&selector)?, initial_promisc);
    support::assert_send_denied(&mut link, deadline, &cancelled);
    support::ready("ISL")?;
    let report = monitor.run_until(&mut link, &cancelled, deadline)?;
    assert_eq!(report.status(), IslStatus::Observed);
    assert!(!report.summary().send_attempted());
    assert_eq!(report.summary().sent_packets(), 0);
    assert_eq!(report.summary().received_packets(), 3);
    assert_eq!(report.summary().capture_loss(), Some(0));
    assert_eq!(report.unmatched_packets(), 0);
    let [malformed, unspecified, valid] = report.observations() else {
        return Err("unexpected ISL candidates".into());
    };
    assert!(matches!(
        malformed.evidence(),
        IslEvidence::Malformed(IslMalformed::Header)
    ));
    assert!(matches!(
        unspecified.evidence(),
        IslEvidence::UnsupportedLength
    ));
    let IslEvidence::Frame(header) = valid.evidence() else {
        return Err("missing ISL frame".into());
    };
    assert_eq!(header.destination_prefix(), [1, 0, 0x0c, 0, 0]);
    assert_eq!(
        (
            header.media_type(),
            header.user(),
            header.vlan_id(),
            header.bpdu(),
            header.port_index()
        ),
        (0, 3, 37, true, 17)
    );
    assert_eq!(valid.frame().bytes(), VALID);
    assert_eq!(
        valid.frame().metadata().linux_interface(),
        Some(info.identity())
    );
    assert!(!format!("{report:?}").contains("PRIVATE-USER-CONTENT"));
    link.close()?;
    assert_eq!(membership::snapshot(info.identity().ifindex())?, before);
    assert_eq!(discover(&selector)?.flags() & MODE_FLAGS, original_modes);
    assert_eq!(support::promiscuous(&selector)?, initial_promisc);
    Ok(())
}
