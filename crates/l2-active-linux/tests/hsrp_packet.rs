#![cfg(target_os = "linux")]

use std::{
    error::Error,
    net::Ipv4Addr,
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use l2_active::{
    Limits,
    first_hop::hsrp::{
        HsrpEvidence, HsrpMalformed, HsrpMonitor, HsrpOpcode, HsrpState, HsrpStatus,
    },
};
use l2_active_linux::{HelperLink, InterfaceSelector, discover};

#[path = "support/receive_only.rs"]
mod support;

#[test]
#[ignore = "uses a proved private namespace and owned receive-only veth pair"]
fn owned_veth_delivers_hsrp_through_the_restricted_helper() -> Result<(), Box<dyn Error>> {
    support::run_fixture(
        "../l2-active/tests/first_hop/hsrp/fixtures/veth.py",
        "owned_namespace_child_observes_hsrp_without_sending",
        "messages_delivered=true no_client_send=true cleanup_confirmed=true",
    )
}

#[test]
#[ignore = "invoked only by the proved private HSRP fixture"]
fn owned_namespace_child_observes_hsrp_without_sending() -> Result<(), Box<dyn Error>> {
    support::assert_owned()?;
    let selector = InterfaceSelector::new(&std::env::var("L2_TEST_HSRP_INTERFACE")?)?;
    let was_promiscuous = support::promiscuous(&selector)?;
    let info = discover(&selector)?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let limits = Limits::new(Duration::from_secs(2), 128, 65_536)?;
    let monitor = HsrpMonitor::new(Some(0), limits);
    let cancelled = AtomicBool::new(false);
    let requested = Instant::now() + limits.timeout();
    let mut link = HelperLink::open_hsrp(
        Path::new(&helper),
        &selector,
        &info,
        &monitor,
        requested,
        &cancelled,
    )?;
    let deadline = link.deadline();
    support::assert_send_denied(&mut link, deadline, &cancelled);
    support::ready("HSRP")?;
    let report = monitor.run_until(&mut link, &cancelled, deadline)?;
    assert_eq!(report.status(), HsrpStatus::Observed);
    assert_eq!(report.summary().sent_packets(), 0);
    assert!(!report.summary().send_attempted());
    assert_eq!(report.summary().capture_loss(), Some(0));
    assert_eq!(report.summary().received_packets(), 2);
    assert_eq!(report.unmatched_packets(), 0);
    let [bad_ttl, valid] = report.observations() else {
        return Err("unexpected scoped HSRP candidate count".into());
    };
    assert_eq!(
        bad_ttl.evidence(),
        &HsrpEvidence::Malformed(HsrpMalformed::Ipv4)
    );
    let HsrpEvidence::Advertisement(claim) = valid.evidence() else {
        return Err("missing valid HSRP claim".into());
    };
    assert_eq!(
        (
            claim.group(),
            claim.priority(),
            claim.opcode(),
            claim.state()
        ),
        (0, 120, HsrpOpcode::Hello, HsrpState::Active)
    );
    assert_eq!(claim.source_ip(), Ipv4Addr::new(192, 0, 2, 2));
    assert_eq!(claim.virtual_ip(), Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!(
        valid.frame().metadata().linux_interface(),
        Some(info.identity())
    );
    let fixture = std::env::var_os("L2_TEST_HSRP_FIXTURE").ok_or("missing fixture directory")?;
    let expected = std::fs::read(Path::new(&fixture).join("advertisement.bin"))?;
    assert!(
        valid.frame().bytes() == expected,
        "explicit frame did not preserve the wire capture"
    );
    for output in [format!("{report:?}"), format!("{valid:?}")] {
        for marker in [
            "AuthP@ss",
            "PAD-SECRET",
            "4175746850407373",
            "5041442d534543524554",
        ] {
            assert!(
                !output.contains(marker),
                "default Debug included fixture secrets"
            );
        }
    }
    link.close()?;
    assert_eq!(support::promiscuous(&selector)?, was_promiscuous);
    Ok(())
}
