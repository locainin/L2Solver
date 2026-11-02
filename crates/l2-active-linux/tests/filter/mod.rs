use std::{
    error::Error,
    io,
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    os::unix::fs::MetadataExt,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use l2_active::Limits;
use l2_onpath::MacAddress;
use rscap::{
    Interface,
    linux::{addr::L2Protocol, l2::L2Socket},
};

use crate::intent::{Intent, ListenKind};

fn intents() -> Result<[Intent; 6], Box<dyn Error>> {
    let limits = Limits::new(Duration::from_secs(3), 256, 65_536)?;
    let mac = MacAddress::new([2, 0, 0, 0, 0, 1])?;
    let transaction = NonZeroU32::new(0x1234_5678).ok_or("zero transaction")?;
    let arp = l2_active::ArpProbe::new(
        mac,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(192, 0, 2, 2),
        None,
        limits,
    )?;
    let dhcp = l2_active::dhcp::DhcpProbe::new(mac, transaction, None, limits)?;
    let ndp = l2_active::NdpProbe::new(
        mac,
        "fe80::1".parse::<Ipv6Addr>()?,
        64,
        "fe80::2".parse::<Ipv6Addr>()?,
        None,
        limits,
    )?;
    let dot1x = l2_active::dot1x::Dot1xProbe::new(mac, limits)?;
    Ok([
        Intent::arp(&arp)?,
        Intent::dhcp(&dhcp)?,
        Intent::ndp(&ndp)?,
        Intent::dot1x(&dot1x)?,
        Intent::listen(mac, limits, ListenKind::Discovery),
        Intent::listen(mac, limits, ListenKind::Stp),
    ])
}

use crate::child_mode;

const PARENT_TEST: &str =
    "filter::tests::fixed_filters_accept_scoped_candidates_and_reject_unrelated_payloads";

#[test]
fn fixed_filters_accept_scoped_candidates_and_reject_unrelated_payloads()
-> Result<(), Box<dyn Error>> {
    if child_mode::selected(PARENT_TEST)? {
        return owned_namespace_child_checks_each_filter();
    }
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/filter/namespace.py");
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .env(child_mode::ENV, PARENT_TEST)
        .args(["--exact", PARENT_TEST, "--nocapture"])
        .output()?;
    assert!(
        output.status.success(),
        "filter fixture failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("filters_checked=true cleanup_confirmed=true")
    );
    Ok(())
}

fn owned_namespace_child_checks_each_filter() -> Result<(), Box<dyn Error>> {
    let parent_device: u64 = std::env::var("L2_TEST_PARENT_NET_DEVICE")?.parse()?;
    let parent_inode: u64 = std::env::var("L2_TEST_PARENT_NET_INODE")?.parse()?;
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!(
        (namespace.dev(), namespace.ino()),
        (parent_device, parent_inode)
    );
    let interface = std::env::var("L2_TEST_FILTER_INTERFACE")?;
    let directory =
        std::env::var_os("L2_TEST_FILTER_DIRECTORY").ok_or("missing fixture directory")?;
    let directory = Path::new(&directory);
    let cases = intents()?;
    for (index, intent) in cases.iter().enumerate() {
        let socket = L2Socket::new()?;
        socket.set_nonblocking(true)?;
        super::attach(&socket, intent)?;
        let mut replacement = rscap::filter::PacketFilter::accept_all();
        assert_eq!(
            socket
                .set_filter(&mut replacement)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        let all = u16::try_from(nix::libc::ETH_P_ALL)?.to_be();
        socket.bind(Interface::new(&interface)?, L2Protocol::Other(all))?;
        std::fs::write(directory.join(format!("ready-{index}")), b"ready")?;
        let count: usize =
            std::fs::read_to_string(directory.join(format!("count-{index}")))?.parse()?;
        let expected = (0..count)
            .map(|item| std::fs::read(directory.join(format!("expected-{index}-{item}"))))
            .collect::<Result<Vec<_>, _>>()?;
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut bytes = [0; 2048];
        while Instant::now() < deadline && seen.len() < count {
            match socket.recv(&mut bytes) {
                Ok(length) => seen.push(
                    bytes
                        .get(..length)
                        .ok_or("invalid captured length")?
                        .to_vec(),
                ),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
                Err(error) => return Err(error.into()),
            }
        }
        assert_eq!(seen, expected, "unexpected admitted packets for {index}");
        // A late unrelated packet must not be available after the expected pair
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(
            socket.recv(&mut bytes).err().map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        drop(socket);
        std::fs::write(directory.join(format!("observed-{index}")), b"observed")?;
    }
    Ok(())
}

#[test]
fn each_fixed_profile_produces_a_bounded_forward_only_program() -> Result<(), Box<dyn Error>> {
    for intent in intents()? {
        let instructions = super::instructions(&intent)?;
        assert!(!instructions.is_empty());
        assert!(instructions.len() <= super::MAX_INSTRUCTIONS);
    }
    Ok(())
}
