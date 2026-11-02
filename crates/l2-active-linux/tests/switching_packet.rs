#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    error::Error,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use l2_active::{
    Limits,
    switching::{
        dtp::{DtpEvidence, DtpMonitor},
        vtp::{VtpEvidence, VtpMalformed, VtpMessageKind, VtpMonitor},
    },
};
use l2_active_linux::{HelperLink, InterfaceInfo, InterfaceSelector, discover};

#[path = "support/switching_membership.rs"]
mod membership;
#[path = "support/receive_only.rs"]
mod support;

const DTP: &[u8] = include_bytes!("../../l2-active/tests/switching/fixtures/dtp.bin");
const VTP: &[u8] = include_bytes!("../../l2-active/tests/switching/fixtures/vtp-summary.bin");
const MULTICAST: &str = "01000ccccccc";
const MODE_FLAGS: u32 = 0x300;

struct Context {
    selector: InterfaceSelector,
    info: InterfaceInfo,
    helper: PathBuf,
    limits: Limits,
    original_memberships: BTreeMap<String, u32>,
    original_modes: u32,
    original_promiscuous: bool,
}

impl Context {
    fn new() -> Result<Self, Box<dyn Error>> {
        support::assert_owned()?;
        let selector = InterfaceSelector::new(&std::env::var("L2_TEST_SWITCHING_INTERFACE")?)?;
        let info = discover(&selector)?;
        let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER")
            .ok_or("missing helper")?
            .into();
        let limits = Limits::new(Duration::from_secs(2), 128, 65_536)?;
        let original_memberships = membership::snapshot(info.identity().ifindex())?;
        let original_modes = info.flags() & MODE_FLAGS;
        let original_promiscuous = support::promiscuous(&selector)?;
        Ok(Self {
            selector,
            info,
            helper,
            limits,
            original_memberships,
            original_modes,
            original_promiscuous,
        })
    }

    fn check_joined(&self) -> Result<(), Box<dyn Error>> {
        let current = membership::snapshot(self.info.identity().ifindex())?;
        membership::assert_added(&self.original_memberships, &current, [MULTICAST.to_owned()])?;
        assert_eq!(
            discover(&self.selector)?.flags() & MODE_FLAGS,
            self.original_modes
        );
        assert_eq!(
            support::promiscuous(&self.selector)?,
            self.original_promiscuous
        );
        Ok(())
    }

    fn check_closed(&self) -> Result<(), Box<dyn Error>> {
        assert_eq!(
            membership::snapshot(self.info.identity().ifindex())?,
            self.original_memberships
        );
        assert_eq!(
            discover(&self.selector)?.flags() & MODE_FLAGS,
            self.original_modes
        );
        assert_eq!(
            support::promiscuous(&self.selector)?,
            self.original_promiscuous
        );
        Ok(())
    }
}

const DTP_PARENT_TEST: &str = "owned_veth_delivers_dtp_through_the_restricted_helper";
const VTP_PARENT_TEST: &str = "owned_veth_delivers_vtp_through_the_restricted_helper";

#[test]
fn owned_veth_delivers_dtp_through_the_restricted_helper() -> Result<(), Box<dyn Error>> {
    if support::child_mode::selected(DTP_PARENT_TEST)? {
        return owned_namespace_child_observes_dtp_without_sending();
    }
    support::run_fixture(
        "../l2-active/tests/switching/fixtures/veth.py",
        DTP_PARENT_TEST,
        "switching_delivered=true no_client_send=true cleanup_confirmed=true",
    )
}

#[test]
fn owned_veth_delivers_vtp_through_the_restricted_helper() -> Result<(), Box<dyn Error>> {
    if support::child_mode::selected(VTP_PARENT_TEST)? {
        return owned_namespace_child_observes_vtp_without_sending();
    }
    support::run_fixture(
        "../l2-active/tests/switching/fixtures/veth.py",
        VTP_PARENT_TEST,
        "switching_delivered=true no_client_send=true cleanup_confirmed=true",
    )
}

fn owned_namespace_child_observes_dtp_without_sending() -> Result<(), Box<dyn Error>> {
    let context = Context::new()?;
    let monitor = DtpMonitor::new(context.limits);
    let cancelled = AtomicBool::new(false);
    let requested = Instant::now() + context.limits.timeout();
    let mut link = HelperLink::open_dtp(
        Path::new(&context.helper),
        &context.selector,
        &context.info,
        &monitor,
        requested,
        &cancelled,
    )?;
    let deadline = link.deadline();
    context.check_joined()?;
    support::assert_send_denied(&mut link, deadline, &cancelled);
    support::ready("SWITCHING")?;
    let report = monitor.run_until(&mut link, &cancelled, deadline)?;
    assert!(!report.summary().send_attempted());
    assert_eq!(report.summary().sent_packets(), 0);
    assert_eq!(report.summary().received_packets(), 2);
    assert_eq!(report.summary().capture_loss(), Some(0));
    assert_eq!(report.unmatched_packets(), 0);
    let [unsupported, valid] = report.observations() else {
        return Err("unexpected DTP candidates".into());
    };
    assert!(matches!(
        unsupported.evidence(),
        DtpEvidence::UnsupportedVersion(2)
    ));
    let DtpEvidence::Advertisement(claim) = valid.evidence() else {
        return Err("missing DTP claim".into());
    };
    assert_eq!(claim.domain(), Some(b"PRIVATE-DOMAIN\0".as_slice()));
    assert_eq!(
        claim
            .status()
            .map(l2_active::switching::dtp::DtpStatus::raw),
        Some(0x83)
    );
    assert_eq!(valid.frame().bytes(), DTP);
    assert_eq!(
        valid.frame().metadata().linux_interface(),
        Some(context.info.identity())
    );
    assert!(!format!("{report:?}").contains("PRIVATE-DOMAIN"));
    link.close()?;
    context.check_closed()?;
    Ok(())
}

fn owned_namespace_child_observes_vtp_without_sending() -> Result<(), Box<dyn Error>> {
    let context = Context::new()?;
    let monitor = VtpMonitor::new(context.limits);
    let cancelled = AtomicBool::new(false);
    let requested = Instant::now() + context.limits.timeout();
    let mut link = HelperLink::open_vtp(
        Path::new(&context.helper),
        &context.selector,
        &context.info,
        &monitor,
        requested,
        &cancelled,
    )?;
    let deadline = link.deadline();
    context.check_joined()?;
    support::assert_send_denied(&mut link, deadline, &cancelled);
    support::ready("SWITCHING")?;
    let report = monitor.run_until(&mut link, &cancelled, deadline)?;
    assert!(!report.summary().send_attempted());
    assert_eq!(report.summary().sent_packets(), 0);
    assert_eq!(report.summary().received_packets(), 2);
    assert_eq!(report.summary().capture_loss(), Some(0));
    assert_eq!(report.unmatched_packets(), 0);
    let [malformed, valid] = report.observations() else {
        return Err("unexpected VTP candidates".into());
    };
    assert!(matches!(
        malformed.evidence(),
        VtpEvidence::Malformed(VtpMalformed::Protocol)
    ));
    let VtpEvidence::Message(message) = valid.evidence() else {
        return Err("missing VTP message".into());
    };
    assert_eq!(message.domain(), b"PRIVATE-DOMAIN");
    assert!(matches!(
        message.kind(),
        VtpMessageKind::Summary {
            revision: 0x0102_0304,
            followers: 1,
            ..
        }
    ));
    assert_eq!(valid.frame().bytes(), VTP);
    assert_eq!(
        valid.frame().metadata().linux_interface(),
        Some(context.info.identity())
    );
    for marker in ["PRIVATE-DOMAIN", "DIGEST-SECRET", "PADDING-SECRET"] {
        assert!(!format!("{report:?}").contains(marker));
    }
    link.close()?;
    context.check_closed()?;
    Ok(())
}
