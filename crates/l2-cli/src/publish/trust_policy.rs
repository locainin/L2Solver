//! Check owner aliases and mount mappings before trusting output directories

use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{self, AtFlags, CWD, FileType, Mode, OFlags, PROC_SUPER_MAGIC, ResolveFlags, StatxFlags},
};
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read},
};

#[cfg(test)]
#[path = "../../tests/publish/trust_policy.rs"]
mod tests;

/// Information needed to check directory ownership in the current namespace
#[derive(Debug)]
pub(super) struct TrustPolicy {
    proc_root: OwnedFd,
    overflow_uid: u32,
}

impl TrustPolicy {
    /// Read the configured UID used for owners missing from the user namespace
    pub(super) fn load() -> io::Result<Self> {
        let proc_root = open_proc_root()?;
        // Read-only procfs binds are allowed when they preserve the sysctl target
        let overflow = fs::openat2(
            &proc_root,
            "sys/kernel/overflowuid",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )?;
        if fs::fstatfs(&overflow)?.f_type != PROC_SUPER_MAGIC
            || !FileType::from_raw_mode(fs::fstat(&overflow)?.st_mode).is_file()
        {
            return Err(unavailable("overflow UID is not a procfs file"));
        }
        let mut contents = Vec::new();
        File::from(overflow).take(65).read_to_end(&mut contents)?;
        if contents.len() > 64 {
            return Err(unavailable("overflow UID is too long"));
        }
        let overflow_uid = parse_overflow_uid(&contents)?;
        Ok(Self {
            proc_root,
            overflow_uid,
        })
    }

    /// Check the owner and mount of a held directory
    ///
    /// A previous mount ID may be reused only while its descriptor remains open
    pub(super) fn verify_owner(
        &self,
        fd: impl AsFd,
        owner: u32,
        previous_mount: Option<u64>,
    ) -> io::Result<u64> {
        if !trusted_owner(
            owner,
            rustix::process::geteuid().as_raw(),
            self.overflow_uid,
        ) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "output has an untrusted owner",
            ));
        }
        let id = mount_id(fd)?;
        if previous_mount != Some(id) {
            // A fresh mountinfo read cannot confuse this pinned mount with a reused ID
            let mountinfo = open_proc_entry(&self.proc_root, "thread-self/mountinfo", false)?;
            verify_mountinfo(BufReader::new(File::from(mountinfo)), id)?;
        }
        Ok(id)
    }
}

/// Return the mount ID of an open descriptor
pub(super) fn mount_id(fd: impl AsFd) -> io::Result<u64> {
    let stat = fs::statx(fd, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)?;
    if stat.stx_mask & StatxFlags::MNT_ID.bits() == 0 {
        return Err(unavailable("mount ID is unavailable"));
    }
    Ok(stat.stx_mnt_id)
}

/// Open the current thread's descriptor links under an authenticated procfs root
pub(super) fn open_proc_fd_directory() -> io::Result<OwnedFd> {
    let proc_root = open_proc_root()?;
    open_proc_entry(&proc_root, "thread-self/fd", true)
}

fn open_proc_root() -> io::Result<OwnedFd> {
    let root = fs::openat(
        CWD,
        "/proc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    validate_proc_root(&root)?;
    Ok(root)
}

fn validate_proc_root(root: &OwnedFd) -> io::Result<()> {
    // Inode 1 identifies the procfs root rather than a bind-mounted subtree
    if fs::fstatfs(root)?.f_type != PROC_SUPER_MAGIC || fs::fstat(root)?.st_ino != 1 {
        return Err(unavailable("procfs root is unavailable"));
    }
    Ok(())
}

fn open_proc_entry(root: &OwnedFd, path: &str, directory: bool) -> io::Result<OwnedFd> {
    let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    // Do not cross a bind mount that could substitute another process's entry
    Ok(fs::openat2(
        root,
        path,
        flags,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_MAGICLINKS,
    )?)
}

const fn trusted_owner(owner: u32, effective_uid: u32, overflow_uid: u32) -> bool {
    owner != overflow_uid && (owner == 0 || owner == effective_uid)
}

fn parse_overflow_uid(contents: &[u8]) -> io::Result<u32> {
    let contents = contents.trim_ascii();
    if contents.is_empty() || !contents.iter().all(u8::is_ascii_digit) {
        return Err(unavailable("invalid overflow UID"));
    }
    std::str::from_utf8(contents)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| unavailable("invalid overflow UID"))
}

fn verify_mountinfo(mut input: impl BufRead, expected_id: u64) -> io::Result<()> {
    const MAX_LINE_BYTES: u64 = 1024 * 1024;
    let mut line = Vec::new();
    loop {
        line.clear();
        // Bound a single record without loading the complete mount table
        let count = (&mut input)
            .take(MAX_LINE_BYTES + 1)
            .read_until(b'\n', &mut line)?;
        if count == 0 {
            break;
        }
        if u64::try_from(count).map_or(true, |size| size > MAX_LINE_BYTES) {
            return Err(unavailable("mountinfo record is too long"));
        }
        let record = line
            .strip_suffix(b"\n")
            .ok_or_else(|| unavailable("incomplete mountinfo record"))?;
        let mut fields = record.split(|byte| *byte == b' ');
        let id = fields
            .next()
            .and_then(|value| std::str::from_utf8(value).ok())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| unavailable("invalid mountinfo ID"))?;
        if id != expected_id {
            continue;
        }
        return verify_mount_record(&mut fields);
    }
    Err(unavailable("mount is absent from mountinfo"))
}

fn verify_mount_record<'a>(fields: &mut impl Iterator<Item = &'a [u8]>) -> io::Result<()> {
    for _ in 0..4 {
        required_field(fields)?;
    }
    let mut options = required_field(fields)?.split(|byte| *byte == b',');
    if !matches!(options.next(), Some(b"rw" | b"ro")) {
        return Err(unavailable("invalid mountinfo options"));
    }
    if options.any(|option| option == b"idmapped") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "output path is on an idmapped mount",
        ));
    }
    // The separator and final fields complete a valid mount record
    if !fields.by_ref().any(|field| field == b"-") {
        return Err(unavailable("incomplete mountinfo record"));
    }
    for _ in 0..3 {
        required_field(fields)?;
    }
    Ok(())
}

fn required_field<'a>(fields: &mut impl Iterator<Item = &'a [u8]>) -> io::Result<&'a [u8]> {
    fields
        .next()
        .filter(|field| !field.is_empty())
        .ok_or_else(|| unavailable("incomplete mountinfo record"))
}

fn unavailable(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
