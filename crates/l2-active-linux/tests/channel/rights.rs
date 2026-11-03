use super::{Channel, Peer};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use std::{
    fs::{self, OpenOptions},
    io::{self, IoSlice},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
    time::{Duration, Instant},
};

#[path = "deadline.rs"]
mod deadline;
#[path = "records.rs"]
mod records;
#[path = "truncated.rs"]
mod truncated;

fn future_deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn count_open_identity(device: u64, inode: u64) -> io::Result<usize> {
    let mut count = 0;
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        if let Ok(metadata) = fs::metadata(entry.path())
            && metadata.dev() == device
            && metadata.ino() == inode
        {
            count += 1;
        }
    }
    Ok(count)
}

#[test]
fn records_close_received_descriptors_before_reporting_the_error() -> io::Result<()> {
    let path = std::env::temp_dir().join(format!("l2-rights-test-{}", std::process::id()));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)?;
    fs::remove_file(Path::new(&path))?;
    let metadata = file.metadata()?;
    let before = count_open_identity(metadata.dev(), metadata.ino())?;
    let peer = Peer {
        pid: std::process::id(),
        uid: nix::unistd::getuid().as_raw(),
    };
    for (data, expected, descriptor_count) in [
        (&[][..], io::ErrorKind::BrokenPipe, 1),
        (&[1][..], io::ErrorKind::InvalidData, 1),
        (&[1][..], io::ErrorKind::InvalidData, 253),
    ] {
        let (channel, remote) = Channel::pair(peer)?;
        let rights = vec![file.as_raw_fd(); descriptor_count];
        let controls = [ControlMessage::ScmRights(&rights)];
        let payload = [IoSlice::new(data)];
        sendmsg::<()>(
            remote.as_raw_fd(),
            &payload,
            &controls,
            MsgFlags::empty(),
            None,
        )
        .map_err(io::Error::other)?;
        assert_eq!(
            channel
                .receive(Instant::now())
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut),
            "payload length {}",
            data.len()
        );
        assert_eq!(
            channel
                .try_receive(future_deadline())
                .err()
                .map(|error| error.kind()),
            Some(expected),
            "payload length {}, descriptor count {descriptor_count}",
            data.len(),
        );
        assert_eq!(
            count_open_identity(metadata.dev(), metadata.ino())?,
            before,
            "received descriptor leaked into the frontend process for {descriptor_count} descriptors"
        );
    }
    Ok(())
}
