//! Check owner aliases and the mount record used for publication trust

use super::{
    TrustPolicy, mount_id, open_proc_entry, open_proc_fd_directory, open_proc_root,
    parse_overflow_uid, require_mount_id, trusted_owner, validate_proc_root, verify_mountinfo,
};
use rustix::{
    fs::{self, AtFlags, OFlags, StatxFlags},
    io::{FdFlags, fcntl_getfd},
};
use std::{fs::File, io, io::Cursor, os::fd::AsRawFd};

#[test]
fn proc_root_rejects_other_directories() -> io::Result<()> {
    assert!(validate_proc_root(&File::open(".")?.into()).is_err());
    assert!(validate_proc_root(&File::open("/proc/self/fd")?.into()).is_err());
    Ok(())
}

#[test]
fn overflow_owner_is_rejected() {
    assert!(!trusted_owner(65_534, 65_534, 65_534));
    assert!(!trusted_owner(0, 1_000, 0));
    assert!(trusted_owner(0, 1_000, 65_534));
    assert!(trusted_owner(1_000, 1_000, 65_534));
    assert!(!trusted_owner(1_001, 1_000, 65_534));
}

#[test]
fn mount_id_requires_kernel_support() -> io::Result<()> {
    assert!(require_mount_id(StatxFlags::INO.bits(), 42).is_err());
    assert_eq!(
        require_mount_id((StatxFlags::MNT_ID | StatxFlags::INO).bits(), 42)?,
        42
    );
    Ok(())
}

#[test]
fn overflow_uid_requires_one_number() {
    assert_eq!(parse_overflow_uid(b"65534\n").ok(), Some(65_534));
    assert_eq!(parse_overflow_uid(b"0\n").ok(), Some(0));
    for value in [
        b"".as_slice(),
        b"+42\n",
        b"-1\n",
        b"4294967296\n",
        b"12 34\n",
        b"12x\n",
        b"\xff\n",
    ] {
        assert!(parse_overflow_uid(value).is_err(), "{value:?}");
    }
}

#[test]
fn matching_mount_is_accepted() -> io::Result<()> {
    // Other paths may contain non-UTF-8 bytes and escaped whitespace
    let records = b"12 1 0:20 / / rw - ext4 /dev/disk rw\n\
                    42 12 0:21 / /bad\xff\\040path rw,nosuid - ext4 /dev/disk rw\n";
    verify_mountinfo(Cursor::new(records), 42)
}

#[test]
fn idmapped_mount_is_rejected() {
    let records = b"12 1 0:20 / / rw - ext4 /dev/disk rw\n\
                    42 12 0:21 / /data rw,nosuid,idmapped - ext4 /dev/disk rw\n";
    assert_eq!(
        verify_mountinfo(Cursor::new(records), 42)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert!(verify_mountinfo(Cursor::new(records), 12).is_ok());
}

#[test]
fn mount_record_is_required() {
    for records in [
        b"".as_slice(),
        b"12 1 0:20 / / rw - ext4 /dev/disk rw\n",
        b"42 12 0:21 / /data\n",
        b"42 12 0:21 / /data rw - ext4 /dev/disk rw",
        b"42 12 0:21 / /data rw\n",
    ] {
        assert!(verify_mountinfo(Cursor::new(records), 42).is_err());
    }
}

#[test]
fn mount_record_limit_checks_complete_lines() -> io::Result<()> {
    const LIMIT: usize = 1024 * 1024;
    let prefix = b"42 12 0:21 / /";
    let suffix = b" rw - ext4 /dev/disk rw\n";
    for length in [LIMIT - 1, LIMIT, LIMIT + 1] {
        let mut record = prefix.to_vec();
        record.resize(length - suffix.len(), b'x');
        record.extend_from_slice(suffix);
        let result = verify_mountinfo(Cursor::new(record), 42);
        if length <= LIMIT {
            result?;
        } else {
            assert_eq!(
                result.err().map(|error| error.to_string()).as_deref(),
                Some("mountinfo record is too long")
            );
        }
    }
    Ok(())
}

#[test]
fn mount_record_is_checked_until_the_mount_is_verified() -> io::Result<()> {
    let fixture = tempfile::tempdir()?;
    let directory = File::open(fixture.path())?;
    let id = mount_id(&directory)?;
    let owner = fs::fstat(&directory)?.st_uid;
    let records = fixture.path().join("thread-self");
    std::fs::create_dir(&records)?;
    std::fs::write(
        records.join("mountinfo"),
        format!("{id} 1 0:21 / /data rw,idmapped - ext4 /dev/disk rw\n"),
    )?;
    // Feed the caller a synthetic mount record without altering namespace mounts
    let policy = TrustPolicy {
        proc_root: File::open(fixture.path())?.into(),
        overflow_uid: u32::MAX,
    };
    for previous in [None, Some(id ^ 1)] {
        assert_eq!(
            policy
                .verify_owner(&directory, owner, previous)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
    }
    assert_eq!(policy.verify_owner(&directory, owner, Some(id))?, id);
    Ok(())
}

#[test]
fn proc_descriptors_are_typed_and_close_on_exec() -> io::Result<()> {
    let root = open_proc_root()?;
    let entries = open_proc_entry(&root, "thread-self/fd", true)?;
    let records = open_proc_entry(&root, "thread-self/mountinfo", false)?;
    for fd in [&root, &entries, &records] {
        assert!(fcntl_getfd(fd)?.contains(FdFlags::CLOEXEC));
    }
    assert!(fs::fcntl_getfl(&root)?.contains(OFlags::PATH));
    assert_eq!(
        open_proc_entry(&root, "thread-self/mountinfo", true)
            .err()
            .and_then(|error| error.raw_os_error()),
        Some(rustix::io::Errno::NOTDIR.raw_os_error())
    );
    Ok(())
}

#[test]
fn exact_mount_option_is_required() -> io::Result<()> {
    let records = b"42 12 0:21 / /data rw,notidmapped - ext4 /dev/disk rw\n";
    verify_mountinfo(Cursor::new(records), 42)
}

#[test]
fn matching_mount_stops_the_scan() -> io::Result<()> {
    let records = b"42 12 0:21 / /data rw - ext4 /dev/disk rw\nincomplete";
    verify_mountinfo(Cursor::new(records), 42)
}

#[test]
fn live_proc_policy_reads_open_descriptors() -> io::Result<()> {
    let policy = TrustPolicy::load()?;
    let directory = File::open("/proc")?;
    let id = mount_id(&directory)?;
    let owner = fs::fstat(&directory)?.st_uid;

    if trusted_owner(
        owner,
        rustix::process::geteuid().as_raw(),
        policy.overflow_uid,
    ) {
        assert_eq!(policy.verify_owner(&directory, owner, None)?, id);
        assert_eq!(policy.verify_owner(&directory, owner, Some(id))?, id);
    } else {
        assert!(policy.verify_owner(&directory, owner, None).is_err());
    }

    let proc_fd = open_proc_fd_directory()?;
    let resolved = fs::statat(
        &proc_fd,
        directory.as_raw_fd().to_string(),
        AtFlags::empty(),
    )?;
    let held = fs::fstat(&directory)?;
    assert_eq!(
        (resolved.st_dev, resolved.st_ino),
        (held.st_dev, held.st_ino)
    );
    Ok(())
}
