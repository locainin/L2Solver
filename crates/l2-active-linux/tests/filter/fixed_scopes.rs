use std::{
    error::Error,
    io,
    os::unix::fs::MetadataExt,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use rscap::{
    Interface,
    filter::{BpfInstruction, PacketFilter},
    linux::{addr::L2Protocol, l2::L2Socket},
};

use crate::filter::{
    EQUAL, LOAD_WORD, Label, PACKET_OUTGOING, PACKET_TYPE, Program, VLAN_TAG_PRESENT,
};

use crate::child_mode;

pub(super) fn program(emit: impl FnOnce(&mut Program)) -> io::Result<Vec<BpfInstruction>> {
    let mut program = Program::new()?;
    // Match the fixed common admission before adding the protocol-specific rule
    program.emit(LOAD_WORD, VLAN_TAG_PRESENT);
    program.require(EQUAL, 0);
    program.emit(LOAD_WORD, PACKET_TYPE);
    program.branch(EQUAL, PACKET_OUTGOING, Some(Label::Reject), None);
    emit(&mut program);
    program.finish()
}

pub(super) fn run_fixture(profile: &str, parent: &str) -> Result<(), Box<dyn Error>> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/filter/first_hop_mpls.py");
    let output = Command::new("python3")
        .arg(fixture)
        .arg(profile)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args(["--exact", parent, "--nocapture"])
        .env(child_mode::ENV, profile)
        .output()?;
    assert!(
        output.status.success(),
        "fixture failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("fixed_filter_checked=true cleanup_confirmed=true")
    );
    Ok(())
}

pub(super) fn check_child(instructions: Vec<BpfInstruction>) -> Result<(), Box<dyn Error>> {
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
    let count: usize = std::fs::read_to_string(directory.join("count"))?.parse()?;
    let expected = (0..count)
        .map(|index| std::fs::read(directory.join(format!("expected-{index}"))))
        .collect::<Result<Vec<_>, _>>()?;
    let socket = L2Socket::new()?;
    socket.set_nonblocking(true)?;
    let mut filter = PacketFilter::from_vec(instructions);
    socket.set_filter(&mut filter)?;
    socket.lock_filter()?;
    let mut replacement = PacketFilter::accept_all();
    assert_eq!(
        socket
            .set_filter(&mut replacement)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    let all = u16::try_from(nix::libc::ETH_P_ALL)?.to_be();
    socket.bind(Interface::new(&interface)?, L2Protocol::Other(all))?;
    std::fs::write(directory.join("ready"), b"ready")?;
    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut bytes = [0; 4_096];
    while Instant::now() < deadline && seen.len() < count {
        match socket.recv(&mut bytes) {
            Ok(length) => seen.push(bytes.get(..length).ok_or("invalid frame length")?.to_vec()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
            Err(error) => return Err(error.into()),
        }
    }
    // Frame bytes can contain payload or authentication data
    assert!(
        seen == expected,
        "unexpected filter admissions: received {}, expected {}",
        seen.len(),
        expected.len()
    );
    // Check that no late rejected candidate entered the capture queue
    std::thread::sleep(Duration::from_millis(40));
    assert_eq!(
        socket.recv(&mut bytes).err().map(|error| error.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    drop(socket);
    std::fs::write(directory.join("observed"), b"observed")?;
    Ok(())
}
