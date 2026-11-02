#![cfg(target_os = "linux")]

use std::{
    error::Error,
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use l2_active::{
    Limits,
    mpls::{MplsEvidence, MplsLabel, MplsMonitor, MplsStatus, MplsUnsupported},
};
use l2_active_linux::{HelperLink, InterfaceSelector, discover};

#[path = "support/receive_only.rs"]
mod support;

const PARENT_TEST: &str = "owned_veth_helper_observes_local_mpls_without_sending";

#[test]
fn owned_veth_helper_observes_local_mpls_without_sending() -> Result<(), Box<dyn Error>> {
    if support::child_mode::selected(PARENT_TEST)? {
        return owned_namespace_child_observes_mpls_without_sending();
    }
    support::run_fixture(
        "../l2-active/tests/mpls/fixtures/veth.py",
        PARENT_TEST,
        "mpls_delivered=true no_client_send=true cleanup_confirmed=true",
    )
}

fn owned_namespace_child_observes_mpls_without_sending() -> Result<(), Box<dyn Error>> {
    support::assert_owned()?;
    let selector = InterfaceSelector::new(&std::env::var("L2_TEST_MPLS_INTERFACE")?)?;
    let info = discover(&selector)?;
    let original_promisc = support::promiscuous(&selector)?;
    let limits = Limits::new(Duration::from_secs(3), 128, 65_536)?;
    let monitor = MplsMonitor::new(info.mac(), Some(101), limits)?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let cancelled = AtomicBool::new(false);
    let requested = Instant::now() + limits.timeout();
    let mut link = HelperLink::open_mpls(
        Path::new(&helper),
        &selector,
        &info,
        &monitor,
        requested,
        &cancelled,
    )?;
    let deadline = link.deadline();
    assert_eq!(support::promiscuous(&selector)?, original_promisc);
    support::assert_send_denied(&mut link, deadline, &cancelled);
    support::ready("MPLS")?;
    let report = monitor.run_until(&mut link, &cancelled, deadline)?;
    assert_eq!(report.status(), MplsStatus::Observed);
    assert!(report.has_unexpected_top_label());
    assert_eq!(report.summary().sent_packets(), 0);
    assert_eq!(report.summary().received_packets(), 3);
    assert_eq!(report.summary().capture_loss(), Some(0));
    let [zero_ttl, special, valid] = report.observations() else {
        return Err("expected three scoped MPLS candidates".into());
    };
    assert_eq!(zero_ttl.evidence(), MplsEvidence::Stack);
    assert!(zero_ttl.top_ttl_is_zero());
    assert_eq!(
        special.evidence(),
        MplsEvidence::Unsupported(MplsUnsupported::SpecialPurposeLabel(4))
    );
    assert_eq!(valid.evidence(), MplsEvidence::Stack);
    assert_eq!(valid.labels().next().map(MplsLabel::value), Some(100));
    assert!(!format!("{report:?}").contains("SENSITIVE-PAYLOAD"));
    link.close()?;
    assert_eq!(support::promiscuous(&selector)?, original_promisc);
    Ok(())
}
