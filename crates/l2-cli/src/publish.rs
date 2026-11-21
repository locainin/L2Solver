//! Publish complete files and directories without replacing existing destinations
//!
//! Ownership checks assume trusted procfs setup and backing storage, including overlay layers.
//! The final check and commit are separate syscalls, so this boundary assumes that a trusted
//! owner or administrator does not change permissions or mount topology between them.

use std::{
    error::Error,
    fmt,
    fs::File,
    io,
    path::{Path, PathBuf},
};
#[path = "publish/directory.rs"]
mod directory;
#[cfg(target_os = "linux")]
#[path = "publish/trust_policy.rs"]
mod trust_policy;
pub use directory::create_directory;
pub use directory::{
    DirectoryEntryKind, PreparedDirectoryReplacement, check_new_directory_destination,
    create_directory_with_precommit, prepare_directory_replacement,
    replace_directory_with_precommit,
};

/// A directory publication failure with its commit status
#[derive(Debug)]
pub enum DirectoryPublishError {
    /// The destination was not committed by this call
    BeforePublication(Box<dyn Error>),
    /// The rename committed, but syncing the parent directory failed
    PublishedDurabilityUncertain(io::Error),
    /// An exchange committed, but another destination change made cleanup unsafe
    PublishedReplacementUncertain {
        /// The operation that made the final state uncertain
        source: io::Error,
        /// The displaced directory entry retained for recovery
        retained_path: PathBuf,
    },
}

impl fmt::Display for DirectoryPublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforePublication(error) => {
                write!(
                    formatter,
                    "directory was not published by this call: {error}"
                )
            }
            Self::PublishedDurabilityUncertain(error) => write!(
                formatter,
                "directory was published but its durability is uncertain; it may already be published and blind retry is unsafe: {error}"
            ),
            Self::PublishedReplacementUncertain {
                source,
                retained_path,
            } => write!(
                formatter,
                "directory replacement is uncertain; displaced content was retained at {} and blind retry is unsafe: {source}",
                retained_path.display()
            ),
        }
    }
}

impl Error for DirectoryPublishError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BeforePublication(error) => Some(error.as_ref()),
            Self::PublishedDurabilityUncertain(error) => Some(error),
            Self::PublishedReplacementUncertain { source, .. } => Some(source),
        }
    }
}

impl From<io::Error> for DirectoryPublishError {
    fn from(error: io::Error) -> Self {
        Self::BeforePublication(Box::new(error))
    }
}

impl From<Box<dyn Error>> for DirectoryPublishError {
    fn from(error: Box<dyn Error>) -> Self {
        Self::BeforePublication(error)
    }
}

#[cfg(target_os = "linux")]
use std::{io::Write, path::Component};

/// Publish one complete file without making a partial destination visible
///
/// Linux uses an unnamed `O_TMPFILE` inode and descriptor-relative operations
/// so changed path components cannot redirect publication or cleanup
///
/// Parents must be real directories owned by root or the effective user.
/// Shared-writable parents must be sticky. Symlinks and `..` components are
/// rejected, and an existing destination symlink is never followed or replaced
///
/// # Errors
/// Returns an unsupported error on platforms without the reviewed Linux
/// publication boundary or when the filesystem/proc-fd mechanism is missing, a
/// destination-exists error when the final name is already present, or the
/// underlying staged I/O error
pub fn create<T>(path: &Path, write: impl FnOnce(&mut File) -> io::Result<T>) -> io::Result<T> {
    #[cfg(target_os = "linux")]
    {
        create_linux(path, write)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, write);
        Err(unsupported_platform())
    }
}

#[cfg(target_os = "linux")]
use {
    rustix::{
        fd::OwnedFd,
        fs::{self, AtFlags, CWD, Mode, OFlags},
    },
    std::{
        ffi::OsStr,
        os::{
            fd::{AsFd, AsRawFd},
            unix::ffi::OsStrExt,
        },
    },
};

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/publish/hooks.rs"]
pub mod test_hooks;

#[cfg(target_os = "linux")]
fn create_linux<T>(path: &Path, write: impl FnOnce(&mut File) -> io::Result<T>) -> io::Result<T> {
    let (parent, name) = parent_and_name(path)?;
    // Every later operation uses this descriptor rather than the parent path
    let parent_fd =
        open_parent(parent).map_err(|error| stage_error("open output parent", &error))?;
    let mut file = open_temporary(&parent_fd, path)?;
    // A callback can stream through File, but publication waits for its flush
    let result = write(&mut file).map_err(|error| stage_error("write temporary output", &error))?;
    file.flush()
        .map_err(|error| stage_error("flush temporary output", &error))?;
    sync_temporary(&file, path).map_err(|error| stage_error("sync temporary output", &error))?;

    #[cfg(test)]
    test_hooks::pause_before_link()
        .map_err(|error| stage_error("pause before linking temporary output", &error))?;
    recheck_output_parent(&parent_fd)
        .and_then(|_| link_from_fd(&file, &parent_fd, name, path))
        .map_err(|error| stage_error("link temporary output", &error))?;
    #[cfg(test)]
    test_hooks::pause_after_link()
        .map_err(|error| stage_error("pause after linking temporary output", &error))?;
    sync_parent_directory(&parent_fd, path)
        .map_err(|error| stage_error("sync output directory", &error))?;
    Ok(result)
}

#[cfg(target_os = "linux")]
fn parent_and_name(path: &Path) -> io::Result<(&Path, &OsStr)> {
    let raw_path = path.as_os_str().as_bytes();
    // Path::file_name normalizes a final `.` or separator into the prior component
    if raw_path.is_empty()
        || raw_path.ends_with(b"/")
        || raw_path == b"."
        || raw_path.ends_with(b"/.")
        || raw_path == b".."
        || raw_path.ends_with(b"/..")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output path must end with a destination filename",
        ));
    }
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "output path must name a destination file",
        )
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok((parent, name))
}

#[cfg(target_os = "linux")]
/// Permission bits that grant writes beyond the owner
pub const SHARED_WRITE: Mode = Mode::WGRP.union(Mode::WOTH);

#[cfg(target_os = "linux")]
fn verify_private_output_permissions(
    trust: &trust_policy::TrustPolicy,
    fd: impl AsFd,
    owner: u32,
    mode: u32,
    label: &str,
    previous_mount: Option<u64>,
) -> io::Result<()> {
    if Mode::from_raw_mode(mode).intersects(SHARED_WRITE) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{label} has unsafe ownership or permissions"),
        ));
    }
    trust
        .verify_owner(fd, owner, previous_mount)
        .map_err(|error| stage_error(label, &error))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_trusted_output_dir(
    trust: &trust_policy::TrustPolicy,
    fd: &OwnedFd,
    previous_mount: Option<u64>,
) -> io::Result<u64> {
    let stat = fs::fstat(fd)?;
    let mode = Mode::from_raw_mode(stat.st_mode);
    // A trusted sticky directory lets other users add names, while protecting existing names
    if mode.intersects(SHARED_WRITE) && !mode.contains(Mode::SVTX) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "output path contains an untrusted directory",
        ));
    }
    trust.verify_owner(fd, stat.st_uid, previous_mount)
}

#[cfg(target_os = "linux")]
const OUTPUT_DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);

#[cfg(target_os = "linux")]
const WALK_DIRECTORY_FLAGS: OFlags = OUTPUT_DIRECTORY_FLAGS.union(OFlags::PATH);

#[cfg(target_os = "linux")]
fn open_parent(parent: &Path) -> io::Result<OwnedFd> {
    open_parent_with_trust(parent, &trust_policy::TrustPolicy::load()?)
}

#[cfg(target_os = "linux")]
fn open_parent_with_trust(parent: &Path, trust: &trust_policy::TrustPolicy) -> io::Result<OwnedFd> {
    // Reject parent traversal before acquiring any descriptor
    if parent
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(reject_parent_directory_component());
    }

    let root = fs::openat(CWD, "/", WALK_DIRECTORY_FLAGS, Mode::empty())?;
    let parent_path = if parent.is_absolute() {
        open_trusted_components(trust, root, parent)?
    } else {
        // Hold the working directory while resolving and checking its full ancestry
        let cwd = fs::openat(CWD, ".", WALK_DIRECTORY_FLAGS, Mode::empty())?;
        open_relative_parent(trust, root, &cwd, &std::env::current_dir()?, parent)?
    };
    // Search permission is enough during the walk, while the final parent needs fsync
    Ok(fs::openat(
        &parent_path,
        ".",
        OUTPUT_DIRECTORY_FLAGS,
        Mode::empty(),
    )?)
}

#[cfg(target_os = "linux")]
fn open_relative_parent(
    trust: &trust_policy::TrustPolicy,
    root: OwnedFd,
    held_cwd: &OwnedFd,
    cwd_path: &Path,
    parent: &Path,
) -> io::Result<OwnedFd> {
    let checked_cwd = open_trusted_components(trust, root, cwd_path)?;
    // A reopened path must identify the working directory the call started from
    if !same_directory_view(held_cwd, &checked_cwd)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "working directory changed while checking the output path",
        ));
    }
    open_trusted_components(trust, checked_cwd, parent)
}

#[cfg(target_os = "linux")]
fn same_directory_view(left: &OwnedFd, right: &OwnedFd) -> io::Result<bool> {
    let left_stat = fs::fstat(left)?;
    let right_stat = fs::fstat(right)?;
    let same_device = left_stat.st_dev == right_stat.st_dev;
    let same_inode = left_stat.st_ino == right_stat.st_ino;
    Ok(
        same_device
            && same_inode
            && trust_policy::mount_id(left)? == trust_policy::mount_id(right)?,
    )
}

#[cfg(target_os = "linux")]
fn recheck_output_parent(parent: &OwnedFd) -> io::Result<trust_policy::TrustPolicy> {
    let proc_fd = open_proc_fd_directory()?;
    let name = parent.as_raw_fd().to_string();
    verify_proc_fd_entry(&proc_fd, parent, &name)?;
    let path = fs::readlinkat(&proc_fd, name.as_str(), Vec::new())?;
    let path = Path::new(OsStr::from_bytes(path.as_bytes()));
    let trust = trust_policy::TrustPolicy::load()?;
    if !path.is_absolute() || !same_directory_view(parent, &open_parent_with_trust(path, &trust)?)?
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output parent changed while checking its current location",
        ));
    }
    Ok(trust)
}

#[cfg(target_os = "linux")]
fn open_trusted_components(
    trust: &trust_policy::TrustPolicy,
    mut current: OwnedFd,
    path: &Path,
) -> io::Result<OwnedFd> {
    let mut mount = check_trusted_output_dir(trust, &current, None)?;
    // Check each opened directory before resolving another name through it
    for component in path.components() {
        let name: &OsStr = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir | Component::Prefix(_) => {
                return Err(reject_parent_directory_component());
            }
        };
        let next = fs::openat(&current, name, WALK_DIRECTORY_FLAGS, Mode::empty())?;
        // Keep the previous mount pinned while checking the next descriptor
        mount = check_trusted_output_dir(trust, &next, Some(mount))?;
        current = next;
    }
    Ok(current)
}

#[cfg(target_os = "linux")]
fn reject_parent_directory_component() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "output path cannot contain parent-directory components",
    )
}

#[cfg(target_os = "linux")]
fn open_temporary(parent: &OwnedFd, display_path: &Path) -> io::Result<File> {
    #[cfg(test)]
    if test_hooks::take_fault(test_hooks::TestFault::UnsupportedFilesystem) {
        return Err(unsupported_filesystem(
            display_path,
            "unnamed temporary files",
        ));
    }

    let flags = OFlags::WRONLY | OFlags::CLOEXEC | OFlags::TMPFILE;
    let mode = Mode::RUSR | Mode::WUSR;
    let fd = fs::openat(parent, Path::new("."), flags, mode).map_err(|source| {
        let error: io::Error = source.into();
        if is_unsupported_tmpfile(&error) {
            unsupported_filesystem(display_path, "unnamed temporary files")
        } else {
            stage_error("create unnamed temporary output", &error)
        }
    })?;
    Ok(File::from(fd))
}

#[cfg(target_os = "linux")]
fn is_unsupported_tmpfile(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::Unsupported
        || matches!(
            error.raw_os_error(),
            Some(code) if code == libc::EOPNOTSUPP
                || code == libc::ENOSYS
                || code == libc::EISDIR
                || code == libc::ENOENT
                || code == libc::EINVAL
        )
}

#[cfg(target_os = "linux")]
fn sync_temporary(file: &File, display_path: &Path) -> io::Result<()> {
    #[cfg(test)]
    if test_hooks::take_fault(test_hooks::TestFault::FileSync) {
        return Err(io::Error::other("injected temporary-file sync failure"));
    }
    file.sync_all().map_err(|error| {
        if is_unsupported_sync_error(&error) {
            unsupported_filesystem(display_path, "temporary-file synchronization")
        } else {
            error
        }
    })
}

#[cfg(target_os = "linux")]
fn link_from_fd(
    file: &File,
    parent: &OwnedFd,
    name: &OsStr,
    display_path: &Path,
) -> io::Result<()> {
    #[cfg(test)]
    if test_hooks::take_fault(test_hooks::TestFault::SecurePublication) {
        return Err(secure_publication_unavailable());
    }
    #[cfg(test)]
    if test_hooks::take_fault(test_hooks::TestFault::Link) {
        return Err(io::Error::other("injected link failure"));
    }

    // Hold procfs itself before resolving the descriptor entry
    let proc_fd = open_proc_fd_directory()?;
    let fd_name = file.as_raw_fd().to_string();
    // Confirm that the proc-fd link still resolves to the inode held by File
    verify_proc_fd_entry(&proc_fd, file, &fd_name).map_err(|_| secure_publication_unavailable())?;
    match fs::linkat(
        &proc_fd,
        Path::new(&fd_name),
        parent,
        name,
        AtFlags::SYMLINK_FOLLOW,
    ) {
        Ok(()) => Ok(()),
        Err(source) => {
            let error: io::Error = source.into();
            if error.raw_os_error() == Some(libc::EEXIST) {
                Err(destination_exists(display_path))
            } else if is_unavailable_proc_fd_error(&error) {
                Err(secure_publication_unavailable())
            } else {
                Err(error)
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn open_proc_fd_directory() -> io::Result<OwnedFd> {
    trust_policy::open_proc_fd_directory().map_err(|error| {
        if is_unavailable_proc_fd_error(&error) {
            secure_publication_unavailable()
        } else {
            error
        }
    })
}

#[cfg(target_os = "linux")]
fn verify_proc_fd_entry(proc_fd: &OwnedFd, file: impl AsFd, fd_name: &str) -> io::Result<()> {
    // `statat` follows the proc-fd symlink when no no-follow flag is present
    let held = fs::fstat(file)?;
    let resolved = fs::statat(proc_fd, Path::new(fd_name), AtFlags::empty())?;
    if held.st_dev != resolved.st_dev || held.st_ino != resolved.st_ino {
        return Err(io::Error::other(
            "proc-fd entry does not reference the held temporary file",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_unavailable_proc_fd_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::Unsupported
        || matches!(
            error.raw_os_error(),
            Some(code)
                if code == libc::EACCES
                    || code == libc::EPERM
                    || code == libc::ENOENT
                    || code == libc::ENOTDIR
                    || code == libc::ELOOP
                    || code == libc::ENOSYS
                    || code == libc::EOPNOTSUPP
                    || code == libc::EINVAL
        )
}

#[cfg(target_os = "linux")]
fn sync_parent_directory(parent: &OwnedFd, display_path: &Path) -> io::Result<()> {
    #[cfg(test)]
    if test_hooks::take_fault(test_hooks::TestFault::DirectorySync) {
        return Err(io::Error::other("injected output-directory sync failure"));
    }
    fs::fsync(parent).map_err(|source| {
        let error: io::Error = source.into();
        if is_unsupported_sync_error(&error) {
            unsupported_filesystem(display_path, "output-directory synchronization")
        } else {
            error
        }
    })
}

#[cfg(target_os = "linux")]
fn is_unsupported_sync_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::Unsupported
        || matches!(
            error.raw_os_error(),
            Some(code) if code == libc::EINVAL || code == libc::EOPNOTSUPP || code == libc::ENOSYS
        )
}

#[cfg(target_os = "linux")]
fn stage_error(stage: &str, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{stage}: {error}"))
}

#[cfg(not(target_os = "linux"))]
fn unsupported_platform() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "secure file publication requires Linux",
    )
}

#[cfg(target_os = "linux")]
fn unsupported_filesystem(path: &Path, feature: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "destination filesystem does not support {feature}: {}",
            path.display()
        ),
    )
}

#[cfg(target_os = "linux")]
fn secure_publication_unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "secure publication requires /proc/self/fd",
    )
}

#[cfg(target_os = "linux")]
fn destination_exists(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("destination already exists: {}", path.display()),
    )
}
