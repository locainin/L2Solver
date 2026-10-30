use super::{DirectLink, operation};
use crate::{
    InterfaceSelector, discover,
    intent::{Intent, ListenKind},
    wire::{self, Reader, Writer},
};
use l2_active::{
    Limits,
    discovery::{DiscoveryMonitor, DiscoveryProtocol},
};
use l2_onpath::MacAddress;
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
fn owned_veth_worker_rejects_a_raw_send_opcode() -> Result<(), Box<dyn Error>> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/listen/namespace.py");
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "worker::discovery_tests::owned_namespace_child_rejects_raw_send_opcode",
        ])
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
fn owned_namespace_child_rejects_raw_send_opcode() -> Result<(), Box<dyn Error>> {
    let parent_device: u64 = std::env::var("L2_TEST_PARENT_NET_DEVICE")?.parse()?;
    let parent_inode: u64 = std::env::var("L2_TEST_PARENT_NET_INODE")?.parse()?;
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!(
        (namespace.dev(), namespace.ino()),
        (parent_device, parent_inode)
    );
    let selector = InterfaceSelector::new(&std::env::var("L2_TEST_DISCOVERY_INTERFACE")?)?;
    let info = discover(&selector)?;
    let limits = Limits::new(Duration::from_secs(2), 128, 65_536)?;
    let deadline = Instant::now() + limits.timeout();
    let cancelled = AtomicBool::new(false);
    let intent = Intent::listen(MacAddress::new(info.mac())?, limits, ListenKind::Discovery);
    let mut link = DirectLink::open(&selector, info.identity(), intent, deadline)?;

    // Exercise the helper's raw SEND opcode without the client-side guard
    let mut request = Writer::new(wire::SEND);
    request.u64(crate::deadline::encode_deadline(
        deadline,
        limits.timeout(),
    )?);
    let record = request.finish();
    let mut reader = Reader::new(&record);
    assert_eq!(reader.u8()?, wire::SEND);
    assert_eq!(
        operation(wire::SEND, reader, &mut link, &cancelled)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    std::fs::write(
        std::env::var_os("L2_TEST_DISCOVERY_READY").ok_or("missing ready path")?,
        b"ready",
    )?;
    let report = DiscoveryMonitor::new(limits).run_until(&mut link, &cancelled, deadline)?;
    assert_eq!(report.summary().sent_packets(), 0);
    assert!(
        report
            .observations()
            .iter()
            .any(|item| item.protocol() == DiscoveryProtocol::Lldp)
    );
    assert!(
        report
            .observations()
            .iter()
            .any(|item| item.protocol() == DiscoveryProtocol::Cdp)
    );
    // Closing the actual packet socket releases the joined groups
    drop(link);
    std::fs::write(
        std::env::var_os("L2_TEST_DISCOVERY_OBSERVED").ok_or("missing observation path")?,
        b"observed",
    )?;
    Ok(())
}
