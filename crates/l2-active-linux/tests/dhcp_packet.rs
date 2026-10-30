#![cfg(target_os = "linux")]

use l2_active::{
    ActiveLink, Limits, StopReason,
    dhcp::{DhcpProbe, DhcpStatus},
};
use l2_active_linux::{HelperLink, InterfaceSelector, discover};
use l2_onpath::MacAddress;
use std::{
    error::Error,
    io::{self, Read},
    net::Ipv4Addr,
    num::NonZeroU32,
    os::unix::fs::MetadataExt,
    path::Path,
    process::Command,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[test]
#[ignore = "uses an owned namespace and independent DHCP veth responder"]
fn owned_veth_carries_one_typed_discover_and_correlated_offer() -> Result<(), Box<dyn Error>> {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../l2-active/tests/dhcp/fixtures/veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .arg("--ignored")
        .arg("--exact")
        .arg("owned_namespace_child_performs_one_dhcp_discover")
        .arg("--nocapture")
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
            .contains("request_captured=true offer_captured=true cleanup_confirmed=true")
    );
    Ok(())
}

#[test]
#[ignore = "invoked only by the proved isolated DHCP namespace fixture"]
fn owned_namespace_child_performs_one_dhcp_discover() -> Result<(), Box<dyn Error>> {
    let parent_device: u64 = std::env::var("L2_TEST_PARENT_NET_DEVICE")?.parse()?;
    let parent_inode: u64 = std::env::var("L2_TEST_PARENT_NET_INODE")?.parse()?;
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!(
        (namespace.dev(), namespace.ino()),
        (parent_device, parent_inode)
    );
    let selector = InterfaceSelector::new(&std::env::var("L2_TEST_DHCP_INTERFACE")?)?;
    let info = discover(&selector)?;
    assert!(
        info.ipv4_assignments().is_empty(),
        "DHCP discovery must work before IPv4 assignment"
    );
    let mac = MacAddress::new(info.mac())?;
    let limits = Limits::new(Duration::from_millis(900), 256, 65_536)?;
    let probe = DhcpProbe::new(mac, fresh_transaction()?, None, limits)?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let cancelled = AtomicBool::new(false);
    let requested = Instant::now() + limits.timeout();
    let mut link = HelperLink::open_dhcp(
        Path::new(&helper),
        &selector,
        &info,
        &probe,
        requested,
        &cancelled,
    )?;
    let deadline = link.deadline();
    let mut changed: [u8; 342] = probe
        .frame()
        .try_into()
        .map_err(|_| io::Error::other("unexpected request length"))?;
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
    assert_eq!(report.summary().sent_bytes(), 342);
    assert_eq!(
        report.summary().stop_reason(),
        StopReason::Deadline,
        "report: {report:?}"
    );
    assert_eq!(report.status(), DhcpStatus::Observed, "report: {report:?}");
    assert!(
        report
            .observations()
            .iter()
            .any(
                |offer| offer.server_identifier() == Ipv4Addr::new(192, 0, 2, 1)
                    && offer.offered_address() == Ipv4Addr::new(192, 0, 2, 10)
            )
    );
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

fn fresh_transaction() -> io::Result<NonZeroU32> {
    let mut random = std::fs::File::open("/dev/urandom")?;
    for _ in 0..4 {
        let mut bytes = [0_u8; 4];
        random.read_exact(&mut bytes)?;
        if let Some(value) = NonZeroU32::new(u32::from_ne_bytes(bytes)) {
            return Ok(value);
        }
    }
    Err(io::Error::other(
        "random source repeatedly returned a zero transaction",
    ))
}
