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
fn owned_veth_worker_checks_raw_operation_boundaries() -> Result<(), Box<dyn Error>> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/listen/namespace.py");
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "worker::operation_tests::owned_namespace_child_checks_raw_operations",
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
fn owned_namespace_child_checks_raw_operations() -> Result<(), Box<dyn Error>> {
    let parent_device: u64 = std::env::var("L2_TEST_PARENT_NET_DEVICE")?.parse()?;
    let parent_inode: u64 = std::env::var("L2_TEST_PARENT_NET_INODE")?.parse()?;
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!(
        (namespace.dev(), namespace.ino()),
        (parent_device, parent_inode)
    );
    let selector = InterfaceSelector::new(&std::env::var("L2_TEST_DISCOVERY_INTERFACE")?)?;
    let info = discover(&selector)?;
    let limits = Limits::new(Duration::from_secs(3), 128, 65_536)?;
    let deadline = Instant::now() + limits.timeout();
    let cancelled = AtomicBool::new(false);
    let intent = Intent::listen(MacAddress::new(info.mac())?, limits, ListenKind::Discovery);
    let mut link = DirectLink::open(&selector, info.identity(), intent, deadline)?;
    let mut request = Writer::new(wire::RECEIVE);
    request.u64(0);
    request.u32(65_536);
    let expired = request.finish();

    // Unknown operations and malformed records cannot reach the capture socket
    assert_eq!(
        dispatch(&mut link, &cancelled, &[0xfe])
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    let mut truncated = Writer::new(wire::RECEIVE);
    truncated.u64(0);
    assert_eq!(
        dispatch(&mut link, &cancelled, &truncated.finish())
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    let mut trailing = expired.clone();
    trailing.push(1);
    assert_eq!(
        dispatch(&mut link, &cancelled, &trailing)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );

    signal_fixture("L2_TEST_DISCOVERY_READY", b"ready")?;
    let sent = std::env::var_os("L2_TEST_DISCOVERY_SENT").ok_or("missing sent path")?;
    while !Path::new(&sent).exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(Path::new(&sent).exists(), "fixture frames were not sent");
    assert!(
        !link.deadline_elapsed(),
        "worker deadline elapsed before test"
    );
    // An expired request is local to that request while the worker remains live
    assert_eq!(dispatch(&mut link, &cancelled, &expired)?, [wire::TIMEOUT]);

    let report = DiscoveryMonitor::new(limits).run_until(&mut link, &cancelled, deadline)?;
    assert_eq!(report.summary().sent_packets(), 0);
    assert_eq!(report.observations().len(), 4);
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
    // Once the worker deadline expires the same record has a final response
    assert!(link.deadline_elapsed());
    assert_eq!(
        dispatch(&mut link, &cancelled, &expired)?,
        [wire::FINAL_TIMEOUT]
    );
    drop(link);
    signal_fixture("L2_TEST_DISCOVERY_OBSERVED", b"observed")?;
    Ok(())
}

fn signal_fixture(variable: &str, marker: &[u8]) -> io::Result<()> {
    let path = std::env::var_os(variable)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing fixture signal path"))?;
    std::fs::write(path, marker)
}

fn dispatch(link: &mut DirectLink, cancelled: &AtomicBool, record: &[u8]) -> io::Result<Vec<u8>> {
    let mut reader = Reader::new(record);
    let opcode = reader.u8()?;
    operation(opcode, reader, link, cancelled)
}
