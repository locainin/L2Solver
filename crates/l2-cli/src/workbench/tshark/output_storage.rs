//! Keep the sandbox's object mount alive without exposing host-writable storage

#[cfg(target_os = "linux")]
use {
    super::secure_files::descriptor_source,
    rustix::fs::{self, AtFlags, CWD, Mode, OFlags},
    std::{fs::File, io, path::PathBuf},
};

#[cfg(all(test, target_os = "linux"))]
#[path = "../../../tests/workbench/tshark/output_storage.rs"]
mod tests;

#[cfg(target_os = "linux")]
pub(super) struct OutputStorage {
    directory: File,
}

#[cfg(target_os = "linux")]
pub(super) struct SandboxProcess {
    directory: File,
}

#[cfg(target_os = "linux")]
impl SandboxProcess {
    /// Bind the reported PID to its original process and mount namespace
    pub(super) fn pin(pid: u32, mount_namespace: u64) -> io::Result<Self> {
        const PROC_SUPER_MAGIC: u64 = 0x9fa0;

        if pid == 0 || mount_namespace == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid sandbox process identity",
            ));
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let proc = File::from(fs::openat(CWD, "/proc", flags, Mode::empty())?);
        if u64::try_from(fs::fstatfs(&proc)?.f_type).ok() != Some(PROC_SUPER_MAGIC) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "sandbox process view is not procfs",
            ));
        }

        let directory = File::from(fs::openat(&proc, pid.to_string(), flags, Mode::empty())?);
        let namespace = fs::statat(&directory, "ns/mnt", AtFlags::empty())?;
        if namespace.st_ino != mount_namespace {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sandbox mount namespace changed",
            ));
        }
        Ok(Self { directory })
    }

    pub(super) const fn directory(&self) -> &File {
        &self.directory
    }

    /// Pin the private mount while the trusted bootstrap is waiting to start `TShark`
    pub(super) fn output(&self) -> io::Result<OutputStorage> {
        const TMPFS_MAGIC: u64 = 0x0102_1994;

        // A held proc directory never follows a PID reused for another process
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let directory = File::from(fs::openat(
            &self.directory,
            "root/output",
            flags,
            Mode::empty(),
        )?);
        if u64::try_from(fs::fstatfs(&directory)?.f_type).ok() != Some(TMPFS_MAGIC) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sandbox output is not tmpfs",
            ));
        }
        Ok(OutputStorage { directory })
    }
}

#[cfg(target_os = "linux")]
impl OutputStorage {
    /// Keep the final path component a real directory for no-follow opens
    pub(super) fn path(&self) -> io::Result<PathBuf> {
        Ok(descriptor_source(&self.directory)?.join("."))
    }

    /// A full block or inode quota means output may have been truncated
    pub(super) fn is_full(&self) -> io::Result<bool> {
        let filesystem = fs::fstatfs(&self.directory)?;
        Ok(filesystem.f_bfree == 0 || (filesystem.f_files != 0 && filesystem.f_ffree == 0))
    }
}
