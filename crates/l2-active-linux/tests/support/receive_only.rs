use std::{
    error::Error, io, os::unix::fs::MetadataExt, path::Path, process::Command,
    sync::atomic::AtomicBool, time::Instant,
};

use l2_active::ActiveLink;
use l2_active_linux::{HelperLink, InterfaceSelector, discover};

pub fn run_fixture(fixture: &str, child: &str, marker: &str) -> Result<(), Box<dyn Error>> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join(fixture);
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args(["--ignored", "--exact", child, "--nocapture"])
        .env(
            "L2_TEST_ACTIVE_HELPER",
            env!("CARGO_BIN_EXE_l2solver-active-helper"),
        )
        .output()?;
    // Fixture error output may include untrusted network data
    assert!(
        output.status.success(),
        "private fixture failed with status {:?}",
        output.status.code()
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(marker));
    Ok(())
}

pub fn assert_owned() -> Result<(), Box<dyn Error>> {
    let parent = (
        std::env::var("L2_TEST_PARENT_NET_DEVICE")?.parse::<u64>()?,
        std::env::var("L2_TEST_PARENT_NET_INODE")?.parse::<u64>()?,
    );
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!((namespace.dev(), namespace.ino()), parent);
    Ok(())
}

pub fn ready(prefix: &str) -> Result<(), Box<dyn Error>> {
    let directory = std::env::var_os(format!("L2_TEST_{prefix}_SYNC_DIR"))
        .ok_or("missing fixture synchronization directory")?;
    std::fs::write(Path::new(&directory).join("ready"), b"ready")?;
    Ok(())
}

pub fn assert_send_denied(link: &mut HelperLink, deadline: Instant, cancelled: &AtomicBool) {
    for frame in [&[][..], &[0_u8; 60][..]] {
        assert_eq!(
            link.send(frame, deadline, cancelled)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
    }
}

pub fn promiscuous(selector: &InterfaceSelector) -> Result<bool, Box<dyn Error>> {
    const IFF_PROMISC: u32 = 0x100;
    Ok(discover(selector)?.flags() & IFF_PROMISC != 0)
}
