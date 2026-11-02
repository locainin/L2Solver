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

use super::super::{MAX_INSTRUCTIONS, Program, preamble};

fn instructions(group: Option<u8>) -> io::Result<Vec<BpfInstruction>> {
    let mut program = Program::new()?;
    // Exercise the same global VLAN and packet-direction rules as the worker
    preamble(&mut program);
    super::hsrp(&mut program, group);
    program.finish()
}

use crate::child_mode;

const PARENT_TEST: &str = "filter::hsrp::tests::kernel_hsrp_filters_apply_profile_and_bounds";

#[test]
fn hsrp_groups_produce_bounded_forward_only_programs() -> Result<(), Box<dyn Error>> {
    for group in [None, Some(0), Some(255)] {
        let instructions = instructions(group)?;
        assert_ne!(instructions, [] as [rscap::filter::BpfInstruction; 0]);
        assert!(instructions.len() <= MAX_INSTRUCTIONS);
    }
    Ok(())
}

#[test]
fn kernel_hsrp_filters_apply_profile_and_bounds() -> Result<(), Box<dyn Error>> {
    if child_mode::selected(PARENT_TEST)? {
        return owned_namespace_checks_hsrp_filters();
    }
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/filter/hsrp_namespace.py");
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .env(child_mode::ENV, PARENT_TEST)
        .args(["--exact", PARENT_TEST, "--nocapture"])
        .output()?;
    assert!(
        output.status.success(),
        "HSRP filter fixture failed with status {:?}",
        output.status.code()
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("filters_checked=true cleanup_confirmed=true")
    );
    Ok(())
}

fn owned_namespace_checks_hsrp_filters() -> Result<(), Box<dyn Error>> {
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
    for (index, group) in [Some(0), Some(255), None].into_iter().enumerate() {
        let socket = L2Socket::new()?;
        socket.set_nonblocking(true)?;
        socket.set_filter(&mut PacketFilter::from_vec(instructions(group)?))?;
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
        std::fs::write(directory.join(format!("ready-{index}")), b"ready")?;
        let count: usize =
            std::fs::read_to_string(directory.join(format!("count-{index}")))?.parse()?;
        let expected = (0..count)
            .map(|item| std::fs::read(directory.join(format!("expected-{index}-{item}"))))
            .collect::<Result<Vec<_>, _>>()?;
        let mut received = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut buffer = [0; 2048];
        while Instant::now() < deadline && received.len() < count {
            match socket.recv(&mut buffer) {
                Ok(length) => received.push(
                    buffer
                        .get(..length)
                        .ok_or("invalid captured length")?
                        .to_vec(),
                ),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
                Err(error) => return Err(error.into()),
            }
        }
        // Never include authentication or padding bytes in test failure output
        assert!(
            received.len() == expected.len()
                && received
                    .iter()
                    .zip(&expected)
                    .all(|(actual, wanted)| actual == wanted),
            "unexpected HSRP filter result for case {index}"
        );
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(
            socket.recv(&mut buffer).err().map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        drop(socket);
        std::fs::write(directory.join(format!("observed-{index}")), b"observed")?;
    }
    Ok(())
}
