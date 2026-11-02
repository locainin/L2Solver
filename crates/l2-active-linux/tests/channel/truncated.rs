use super::{Channel, Peer, count_open_identity};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use std::{
    fs::{self, OpenOptions},
    io::{self, IoSlice},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    process::Command,
};

const CHILD_MARKER: &str = "L2_TEST_TRUNCATED_ANCILLARY_CHILD";

#[test]
fn truncated_ancillary_data_does_not_leak_descriptors() -> io::Result<()> {
    if std::env::var_os(CHILD_MARKER).is_none() {
        // Lower the limit only in the child so other tests keep their own limits
        let output = Command::new("sh")
            .arg("-c")
            .arg("ulimit -n 64 || exit 1; exec \"$1\" --exact channel::tests::truncated::truncated_ancillary_data_does_not_leak_descriptors --nocapture")
            .arg("sh")
            .arg(std::env::current_exe()?)
            .env(CHILD_MARKER, "1")
            .output()?;
        assert!(
            output.status.success(),
            "limited child failed: stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }

    let path = std::env::temp_dir().join(format!("l2-truncated-rights-{}", std::process::id()));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)?;
    fs::remove_file(path)?;
    let metadata = file.metadata()?;
    let before = count_open_identity(metadata.dev(), metadata.ino())?;
    let peer = Peer {
        pid: std::process::id(),
        uid: nix::unistd::getuid().as_raw(),
    };
    let (channel, remote) = Channel::pair(peer)?;
    let rights = vec![file.as_raw_fd(); 253];
    let controls = [ControlMessage::ScmRights(&rights)];
    let payload = [IoSlice::new(&[1])];
    sendmsg::<()>(
        remote.as_raw_fd(),
        &payload,
        &controls,
        MsgFlags::empty(),
        None,
    )
    .map_err(io::Error::other)?;
    let result = channel.try_receive();

    // Free one slot so the descriptor directory can be inspected at the limit
    drop(remote);
    let after = count_open_identity(metadata.dev(), metadata.ino())?;
    assert_eq!(after, before, "truncated ancillary data leaked descriptors");
    assert!(result.is_err(), "a descriptor transfer must be rejected");
    Ok(())
}
