#![cfg(target_os = "linux")]

use l2_active::{
    ActiveLink, Limits,
    discovery::{DiscoveryDisposition, DiscoveryMonitor, DiscoveryProtocol},
};
use l2_active_linux::{HelperLink, InterfaceSelector, discover};
use std::{
    error::Error,
    io,
    os::unix::fs::MetadataExt,
    path::Path,
    process::Command,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[test]
#[ignore = "uses a proved private namespace and independent veth sender"]
fn owned_veth_receives_scoped_discovery_without_transmitting() -> Result<(), Box<dyn Error>> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/listen/namespace.py");
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "owned_namespace_child_observes_discovery_without_sending",
            "--nocapture",
        ])
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
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("lldp_sent=3 cdp_sent=1 cleanup=true")
    );
    Ok(())
}

#[test]
#[ignore = "invoked only by the proved isolated discovery fixture"]
fn owned_namespace_child_observes_discovery_without_sending() -> Result<(), Box<dyn Error>> {
    let parent_device: u64 = std::env::var("L2_TEST_PARENT_NET_DEVICE")?.parse()?;
    let parent_inode: u64 = std::env::var("L2_TEST_PARENT_NET_INODE")?.parse()?;
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!(
        (namespace.dev(), namespace.ino()),
        (parent_device, parent_inode)
    );

    let selector = InterfaceSelector::new(&std::env::var("L2_TEST_DISCOVERY_INTERFACE")?)?;
    let info = discover(&selector)?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let limits = Limits::new(Duration::from_secs(2), 128, 65_536)?;
    let cancelled = AtomicBool::new(false);
    let requested = Instant::now() + limits.timeout();
    let mut link = HelperLink::open_discovery(
        Path::new(&helper),
        &selector,
        &info,
        limits,
        requested,
        &cancelled,
    )?;
    let deadline = link.deadline();
    // Neither an empty record nor an arbitrary frame can turn listening into sending
    for frame in [&[][..], &[0_u8; 60][..]] {
        assert_eq!(
            link.send(frame, deadline, &cancelled)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
    }
    std::fs::write(
        std::env::var_os("L2_TEST_DISCOVERY_READY").ok_or("missing ready path")?,
        b"ready",
    )?;
    let report = DiscoveryMonitor::new(limits).run_until(&mut link, &cancelled, deadline)?;
    assert_eq!(report.summary().sent_packets(), 0);
    assert_eq!(report.summary().capture_loss(), Some(0));
    assert_eq!(report.summary().capture_backlog(), Some(false));
    for (protocol, destination) in [
        (DiscoveryProtocol::Lldp, [1, 0x80, 0xc2, 0, 0, 14]),
        (DiscoveryProtocol::Lldp, [1, 0x80, 0xc2, 0, 0, 3]),
        (DiscoveryProtocol::Lldp, [1, 0x80, 0xc2, 0, 0, 0]),
        (DiscoveryProtocol::Cdp, [1, 0, 0x0c, 0xcc, 0xcc, 0xcc]),
    ] {
        assert!(
            report.observations().iter().any(|item| {
                item.protocol() == protocol
                    && item.destination_mac() == destination
                    && item.disposition() == DiscoveryDisposition::Advertisement
                    && item.frame().metadata().linux_interface() == Some(info.identity())
            }),
            "missing discovery scope {destination:02x?}: {report:?}"
        );
    }
    link.close()?;
    std::fs::write(
        std::env::var_os("L2_TEST_DISCOVERY_OBSERVED").ok_or("missing observation path")?,
        b"observed",
    )?;
    Ok(())
}
