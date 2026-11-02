use std::error::Error;

use super::super::{MAX_INSTRUCTIONS, Program};

#[path = "../support/child_mode.rs"]
mod child_mode;

const PARENT_TEST: &str =
    "filter::switching::tests::switching_filters_admit_only_scoped_candidates_in_the_kernel";

#[test]
fn dtp_and_vtp_programs_are_bounded_and_finish_successfully() -> Result<(), Box<dyn Error>> {
    for populate in [super::dtp as fn(&mut Program), super::vtp] {
        let mut program = Program::new()?;
        populate(&mut program);
        let code = program.finish()?;
        assert!(!code.is_empty());
        assert!(code.len() <= MAX_INSTRUCTIONS);
    }
    Ok(())
}

#[test]
fn switching_filters_admit_only_scoped_candidates_in_the_kernel() -> Result<(), Box<dyn Error>> {
    if child_mode::selected(PARENT_TEST)? {
        return switching_filter_namespace_child();
    }
    use std::{path::Path, process::Command};

    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/filter/switching_namespace.py");
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .env(child_mode::ENV, PARENT_TEST)
        .args(["--exact", PARENT_TEST, "--nocapture"])
        .output()?;
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("switching_filters_checked=true cleanup_confirmed=true")
    );
    Ok(())
}

fn switching_filter_namespace_child() -> Result<(), Box<dyn Error>> {
    use rscap::{
        Interface,
        filter::PacketFilter,
        linux::{addr::L2Protocol, l2::L2Socket},
    };
    use std::{
        io,
        os::unix::fs::MetadataExt,
        path::Path,
        time::{Duration, Instant},
    };

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
    let filters: [fn(&mut Program); 3] = [super::dtp, super::vtp, super::super::isl::isl];
    for (index, populate) in filters.into_iter().enumerate() {
        let mut program = Program::new()?;
        super::super::preamble(&mut program);
        populate(&mut program);
        let mut filter = PacketFilter::from_vec(program.finish()?);
        let socket = L2Socket::new()?;
        socket.set_nonblocking(true)?;
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
        assert_eq!(
            seen, expected,
            "unexpected admitted packets for profile {index}"
        );
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
