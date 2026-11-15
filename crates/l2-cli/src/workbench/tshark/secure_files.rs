//! Hold trusted directories and executable files by descriptor

use std::{
    ffi::OsStr,
    fs::File,
    io,
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
use {
    rustix::{
        fs::{self, AtFlags, CWD, FileType, Mode, OFlags},
        process::geteuid,
    },
    std::{
        os::{
            fd::AsFd,
            unix::{ffi::OsStrExt, fs::PermissionsExt},
        },
        path::Component,
    },
};

#[cfg(all(test, target_os = "linux"))]
#[path = "../../../tests/workbench/tshark/secure_files.rs"]
mod tests;

/// A temporary workspace whose parent stays open until cleanup finishes
#[derive(Debug)]
pub struct Workspace {
    // Fields drop in order, so the proc-fd path stays valid during cleanup
    directory: tempfile::TempDir,
    pub(super) handle: File,
    parent: File,
}

impl Workspace {
    /// Create a workspace inside a trusted directory
    pub(crate) fn new(parent: Option<&Path>) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let default_parent;
            let parent = if let Some(parent) = parent {
                parent
            } else {
                default_parent = std::env::temp_dir();
                &default_parent
            };
            Self::in_parent(open_trusted_directory(parent)?)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = parent;
            Err(unsupported_platform())
        }
    }

    #[cfg(target_os = "linux")]
    fn in_parent(parent: File) -> io::Result<Self> {
        // The saved descriptor, not the original name, determines the creation target
        let parent_path = descriptor_source(&parent)?;
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(parent_path)?;
        let name = directory.path().file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "workspace name is missing")
        })?;
        let handle = open_directory_at(&parent, name)?;
        let metadata = fs::fstat(&handle)?;
        validate_directory(&metadata)?;
        if metadata.st_uid != geteuid().as_raw() || metadata.st_mode & 0o077 != 0 {
            return Err(untrusted("workspace ownership or permissions are unsafe"));
        }
        Ok(Self {
            directory,
            handle,
            parent,
        })
    }

    /// The proc-fd path remains valid while the workspace exists
    pub(crate) fn path(&self) -> &Path {
        self.directory.path()
    }

    /// Remove the workspace while its parent descriptor is still open
    pub(crate) fn close(self) -> io::Result<()> {
        let Self {
            directory,
            handle: _handle,
            parent: _parent,
        } = self;
        directory.close()
    }

    /// Create one private, new file relative to the held workspace
    pub(super) fn create_file(&self, name: &OsStr) -> io::Result<File> {
        #[cfg(target_os = "linux")]
        {
            let bytes = name.as_bytes();
            if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "workspace file must have a single leaf name",
                ));
            }
            let flags =
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let mode = Mode::RUSR | Mode::WUSR;
            let file = File::from(fs::openat(&self.handle, name, flags, mode)?);
            // The explicit mode also prevents a permissive process umask from exposing data
            Ok(file)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            Err(unsupported_platform())
        }
    }
}

/// An executable whose descriptor remains bound to its verified inode
#[derive(Debug)]
pub(super) struct VerifiedExecutable {
    pub(super) path: PathBuf,
    pub(super) file: File,
}

impl VerifiedExecutable {
    /// Open the selected executable only after checking its ownership and mode
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let path = path.canonicalize()?;
            let parent = path.parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "executable parent is missing")
            })?;
            let name = path.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "executable name is missing")
            })?;
            let parent = open_trusted_directory(parent)?;
            // Inspect a path-only handle before opening it for reading
            let candidate = open_path_inode(&parent, name)?;
            let file = open_verified_inode(&candidate)?;
            Ok(Self { path, file })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            Err(unsupported_platform())
        }
    }
}

#[cfg(target_os = "linux")]
fn open_path_inode(parent: &File, name: &OsStr) -> io::Result<File> {
    let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    Ok(File::from(fs::openat(parent, name, flags, Mode::empty())?))
}

#[cfg(target_os = "linux")]
fn open_verified_inode(candidate: &File) -> io::Result<File> {
    let metadata = fs::fstat(candidate)?;
    validate_executable(&metadata)?;
    let file = File::open(descriptor_source(candidate)?)?;
    let opened = fs::fstat(&file)?;
    if !same_inode(&metadata, &opened) {
        return Err(untrusted("executable descriptor changed while opening"));
    }
    validate_executable(&opened)?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn open_trusted_directory(path: &Path) -> io::Result<File> {
    let canonical = path.canonicalize()?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let current = File::from(fs::openat(CWD, Path::new("/"), flags, Mode::empty())?);
    validate_directory(&fs::fstat(&current)?)?;
    descend_trusted_directories(current, &canonical)
}

#[cfg(target_os = "linux")]
fn descend_trusted_directories(mut current: File, path: &Path) -> io::Result<File> {
    // Check each component after opening it relative to the last trusted descriptor
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                current = open_directory_at(&current, name)?;
                validate_directory(&fs::fstat(&current)?)?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "canonical directory path is invalid",
                ));
            }
        }
    }
    Ok(current)
}

#[cfg(target_os = "linux")]
fn open_directory_at(parent: &File, name: &OsStr) -> io::Result<File> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    Ok(File::from(fs::openat(parent, name, flags, Mode::empty())?))
}

#[cfg(target_os = "linux")]
fn validate_directory(metadata: &fs::Stat) -> io::Result<()> {
    if !FileType::from_raw_mode(metadata.st_mode).is_dir() || !trusted_owner(metadata.st_uid) {
        return Err(untrusted(
            "directory is not owned by root or the effective user",
        ));
    }
    // A trusted sticky directory protects each trusted-owned child from other users
    if metadata.st_mode & 0o022 != 0 && metadata.st_mode & 0o1000 == 0 {
        return Err(untrusted("directory permits untrusted changes"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_executable(metadata: &fs::Stat) -> io::Result<()> {
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || !trusted_owner(metadata.st_uid)
        || metadata.st_mode & 0o6022 != 0
        || metadata.st_mode & 0o111 == 0
    {
        return Err(untrusted(
            "executable has unsafe ownership, type, or permissions",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn trusted_owner(uid: u32) -> bool {
    uid == 0 || uid == geteuid().as_raw()
}

#[cfg(target_os = "linux")]
fn untrusted(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

/// Return a procfs path that refers to the same inode as the held descriptor
#[cfg(target_os = "linux")]
pub(super) fn descriptor_source(file: &impl AsFd) -> io::Result<PathBuf> {
    use std::os::fd::AsRawFd;

    const PROC_SUPER_MAGIC: u64 = 0x9fa0;
    let proc_directory = PathBuf::from(format!("/proc/{}/fd", std::process::id()));
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let proc_fd = fs::openat(CWD, &proc_directory, flags, Mode::empty())?;
    if u64::try_from(fs::fstatfs(&proc_fd)?.f_type).ok() != Some(PROC_SUPER_MAGIC) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "descriptor directory is not procfs",
        ));
    }
    let name = file.as_fd().as_raw_fd().to_string();
    let held = fs::fstat(file)?;
    let resolved = fs::statat(&proc_fd, name.as_str(), AtFlags::empty())?;
    if !same_inode(&held, &resolved) {
        return Err(untrusted("proc-fd entry does not match held descriptor"));
    }
    Ok(proc_directory.join(name))
}

#[cfg(target_os = "linux")]
const fn same_inode(first: &fs::Stat, second: &fs::Stat) -> bool {
    first.st_dev == second.st_dev && first.st_ino == second.st_ino
}

#[cfg(not(target_os = "linux"))]
fn unsupported_platform() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "secure TShark files require Linux",
    )
}
