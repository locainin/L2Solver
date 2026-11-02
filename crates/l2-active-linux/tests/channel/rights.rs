use super::{Channel, Peer};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use std::{
    fs::{self, OpenOptions},
    io::{self, IoSlice},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
};

#[path = "records.rs"]
mod records;

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
    for (data, expected) in [
        (&[][..], io::ErrorKind::BrokenPipe),
        (&[1][..], io::ErrorKind::InvalidData),
    ] {
        let (channel, remote) = Channel::pair(peer)?;
        let rights = [file.as_raw_fd()];
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
            channel.try_receive().err().map(|error| error.kind()),
            Some(expected),
            "payload length {}",
            data.len()
        );
        assert_eq!(
            count_open_identity(metadata.dev(), metadata.ino())?,
            before,
            "received descriptor leaked into the frontend process"
        );
    }
    Ok(())
}
