use std::{
    error::Error,
    ffi::OsStr,
    io,
    path::{Path, PathBuf},
};

#[cfg(all(test, target_os = "linux"))]
#[path = "../../tests/publish/exchange_identity.rs"]
mod exchange_identity_tests;
#[path = "directory/inspection.rs"]
pub mod inspection;
#[cfg(target_os = "linux")]
#[path = "directory/staging.rs"]
mod staging;
#[cfg(target_os = "linux")]
#[path = "directory/tree.rs"]
mod tree;

pub use inspection::{DirectoryEntryKind, PreparedDirectoryReplacement};
#[cfg(target_os = "linux")]
use inspection::{
    DirectoryIdentity, destination_entry_exists, stat_identity_at, trusted_directory_identity,
    verify_named_directory,
};
#[cfg(target_os = "linux")]
use staging::StagedDirectory;
#[cfg(target_os = "linux")]
use tree::sync_tree;

/// Validate the safe parent of a new directory destination and confirm its name is absent
///
/// # Errors
/// Returns an error when a parent component is unsafe or the destination already exists
pub fn check_new_directory_destination(path: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let (parent, name) = super::parent_and_name(path)?;
        let parent_fd = super::open_parent(parent)?;
        if destination_entry_exists(&parent_fd, name)? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "result destination appeared while it was being inspected",
            ));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(unsupported_platform())
    }
}

/// Publish a complete directory only when its destination name is absent
///
/// An existing entry is rejected before `write` runs. Linux uses a held parent
/// descriptor and `RENAME_NOREPLACE` for the final race-safe commit.
///
/// # Errors
/// Returns [`super::DirectoryPublishError::BeforePublication`] when the callback or a
/// pre-publication operation fails, and
/// [`super::DirectoryPublishError::PublishedDurabilityUncertain`] when the rename committed
/// but syncing the parent directory failed
pub fn create_directory<T>(
    path: &Path,
    write: impl FnOnce(&Path) -> Result<T, Box<dyn Error>>,
) -> Result<T, super::DirectoryPublishError> {
    create_directory_with_precommit(path, write, || Ok(()))
}

/// Publish a new complete directory after one final caller check
///
/// `before_commit` runs after the staged tree is synced and immediately before the atomic
/// no-replace rename. A failure leaves the destination name absent
pub fn create_directory_with_precommit<T>(
    path: &Path,
    write: impl FnOnce(&Path) -> Result<T, Box<dyn Error>>,
    before_commit: impl FnOnce() -> Result<(), Box<dyn Error>>,
) -> Result<T, super::DirectoryPublishError> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{RenameFlags, renameat_with};

        let (parent, name) = super::parent_and_name(path)?;
        let parent_fd = super::open_parent(parent)?;
        if destination_entry_exists(&parent_fd, name)? {
            return Err(super::destination_exists(path).into());
        }

        let mut staging = StagedDirectory::create(&parent_fd, name)?;
        let result = write(&staging.writer_path())?;
        sync_tree(&staging.fd, path)?;
        before_commit().map_err(super::DirectoryPublishError::BeforePublication)?;
        staging.check()?;

        renameat_with(
            &parent_fd,
            &staging.name,
            &parent_fd,
            name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            let error: io::Error = error.into();
            if error.raw_os_error() == Some(libc::EEXIST) {
                super::destination_exists(path)
            } else if is_unsupported_rename(&error) {
                unsupported_filesystem(
                    path,
                    "atomic no-replace directory publication (RENAME_NOREPLACE)",
                )
            } else {
                error
            }
        })?;

        staging.retain();
        super::sync_parent_directory(&parent_fd, path)
            .map_err(super::DirectoryPublishError::PublishedDurabilityUncertain)?;
        Ok(result)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, write, before_commit);
        Err(unsupported_platform().into())
    }
}

/// Safely inspect and hold an existing directory before applying caller-owned policy checks
///
/// The returned value retains the parent and target descriptors plus the target's device and
/// inode identity. Its descriptor-relative readers let callers validate ownership without
/// reopening an unchecked pathname. The target must be owned by root or the effective
/// user and writable only by its owner.
///
/// # Errors
/// Returns an error if the destination is missing or unsafe, or changes while its
/// descriptors are being prepared
pub fn prepare_directory_replacement(
    path: &Path,
) -> Result<PreparedDirectoryReplacement, super::DirectoryPublishError> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::Mode;

        let (parent, name) = super::parent_and_name(path)?;
        let trust = super::trust_policy::TrustPolicy::load()?;
        let parent_fd = super::open_parent_with_trust(parent, &trust)?;
        let parent_mount = super::trust_policy::mount_id(&parent_fd)?;
        let target_fd = rustix::fs::openat(
            &parent_fd,
            name,
            super::OUTPUT_DIRECTORY_FLAGS,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        // The sticky bit protects the name in the parent, not writes inside the target
        let target_identity = trusted_directory_identity(
            &trust,
            &target_fd,
            "existing output directory",
            Some(parent_mount),
        )?;
        verify_named_directory(&parent_fd, name, target_identity)?;

        Ok(PreparedDirectoryReplacement {
            destination_path: path.to_owned(),
            parent_fd,
            target_fd,
            name: name.to_owned(),
            target_identity,
            trust,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(unsupported_platform().into())
    }
}

/// Replace a prepared directory after one final caller check
///
/// `before_commit` runs after the staged tree and destination identity are checked and
/// immediately before the atomic exchange. A failure preserves the old destination
/// The displaced directory is retained and its path is returned with the callback result
/// Cooperative replacement commits in the same parent cannot overlap; contention or
/// unsupported advisory locking fails before publication
/// The exchange and identity checks are separate operations. A writer that ignores the
/// advisory lock can still replace an entry between them, leaving publication uncertain
pub fn replace_directory_with_precommit<T>(
    prepared: &PreparedDirectoryReplacement,
    write: impl FnOnce(&Path) -> Result<T, Box<dyn Error>>,
    before_commit: impl FnOnce() -> Result<(), Box<dyn Error>>,
) -> Result<(T, PathBuf), super::DirectoryPublishError> {
    #[cfg(target_os = "linux")]
    {
        replace_directory_linux(prepared, write, before_commit)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (prepared, write, before_commit);
        Err(unsupported_platform().into())
    }
}

#[cfg(target_os = "linux")]
fn replace_directory_linux<T>(
    prepared: &PreparedDirectoryReplacement,
    write: impl FnOnce(&Path) -> Result<T, Box<dyn Error>>,
    before_commit: impl FnOnce() -> Result<(), Box<dyn Error>>,
) -> Result<(T, PathBuf), super::DirectoryPublishError> {
    let path = &prepared.destination_path;
    prepared.check_target_at(&prepared.parent_fd, &prepared.name)?;
    let staging = StagedDirectory::create(&prepared.parent_fd, &prepared.name)?;

    let result = write(&staging.writer_path())?;
    sync_tree(&staging.fd, path)?;
    // Hold an independent parent description through the final checks and exchange
    let _commit_lock = lock_replacement_parent(&prepared.parent_fd)?;
    before_commit().map_err(super::DirectoryPublishError::BeforePublication)?;
    staging.check()?;
    prepared.check_target_at(&prepared.parent_fd, &prepared.name)?;
    finish_directory_replacement(prepared, staging, result)
}

#[cfg(target_os = "linux")]
fn lock_replacement_parent(parent: &rustix::fd::OwnedFd) -> io::Result<rustix::fd::OwnedFd> {
    use rustix::fs::{FlockOperation, Mode, OFlags, flock, openat};

    // A separate open creates an independent lock even for callers sharing a parent
    let lock = openat(
        parent,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        let error: io::Error = error.into();
        io::Error::new(
            error.kind(),
            format!("cannot lock output parent for directory replacement: {error}"),
        )
    })?;
    Ok(lock)
}

#[cfg(target_os = "linux")]
fn finish_directory_replacement<T>(
    prepared: &PreparedDirectoryReplacement,
    mut staging: StagedDirectory<'_>,
    result: T,
) -> Result<(T, PathBuf), super::DirectoryPublishError> {
    use rustix::fs::{RenameFlags, renameat_with};

    let path = &prepared.destination_path;

    #[cfg(test)]
    if super::test_hooks::take_fault(super::test_hooks::TestFault::UnsupportedDirectoryExchange) {
        return Err(unsupported_directory_exchange(path).into());
    }
    #[cfg(test)]
    super::test_hooks::before_directory_exchange()?;

    renameat_with(
        &prepared.parent_fd,
        &staging.name,
        &prepared.parent_fd,
        &prepared.name,
        RenameFlags::EXCHANGE,
    )
    .map_err(|error| {
        let error: io::Error = error.into();
        if is_unsupported_rename(&error) {
            unsupported_directory_exchange(path)
        } else {
            error
        }
    })?;

    // The exchange moved the old result into the stage name
    staging.retain();
    let retained_path = retained_display_path(&prepared.parent_fd, path, &staging.name);
    stat_identity_at(&prepared.parent_fd, &staging.name)
        .and_then(|displaced| {
            let published = stat_identity_at(&prepared.parent_fd, &prepared.name)?;
            verify_exchange_identities(
                (displaced, published),
                (prepared.target_identity, staging.identity),
            )
        })
        .map_err(
            |source| super::DirectoryPublishError::PublishedReplacementUncertain {
                source,
                retained_path: retained_path.clone(),
            },
        )?;

    // Another process can still write through an open handle to the displaced directory
    super::sync_parent_directory(&prepared.parent_fd, path).map_err(|source| {
        let kind = source.kind();
        super::DirectoryPublishError::PublishedDurabilityUncertain(io::Error::new(
            kind,
            RetainedAfterSyncFailure {
                source,
                path: retained_path.clone(),
            },
        ))
    })?;
    Ok((result, retained_path))
}

#[cfg(target_os = "linux")]
fn verify_exchange_identities(
    actual: (DirectoryIdentity, DirectoryIdentity),
    expected: (DirectoryIdentity, DirectoryIdentity),
) -> io::Result<()> {
    // RENAME_EXCHANGE has no inode compare-and-swap flag, so preserve unexpected entries
    if actual != expected {
        return Err(io::Error::other(
            "directory names changed during atomic exchange; displaced content was retained",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct RetainedAfterSyncFailure {
    source: io::Error,
    path: PathBuf,
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for RetainedAfterSyncFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[expect(
            clippy::unnecessary_debug_formatting,
            reason = "Debug preserves non-Unicode path bytes"
        )]
        let path = if self.path.to_str().is_some() {
            self.path.display().to_string().escape_debug().to_string()
        } else {
            format!("{:?}", self.path.as_os_str())
        };
        write!(
            formatter,
            "{}; previous output retained at {path}",
            self.source
        )
    }
}

#[cfg(target_os = "linux")]
impl Error for RetainedAfterSyncFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

#[cfg(target_os = "linux")]
fn retained_display_path(
    parent_fd: &rustix::fd::OwnedFd,
    path: &Path,
    staging_name: &OsStr,
) -> PathBuf {
    use std::os::fd::AsRawFd;

    let original_parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let held_parent = PathBuf::from(format!("/proc/thread-self/fd/{}", parent_fd.as_raw_fd()));
    std::fs::read_link(held_parent)
        .ok()
        .filter(|parent| parent.exists())
        .unwrap_or_else(|| original_parent.to_owned())
        .join(staging_name)
}

#[cfg(target_os = "linux")]
fn is_unsupported_rename(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::Unsupported
        || matches!(
            error.raw_os_error(),
            Some(code) if code == libc::EINVAL || code == libc::EOPNOTSUPP || code == libc::ENOSYS
        )
}

#[cfg(target_os = "linux")]
fn unsupported_directory_exchange(path: &Path) -> io::Error {
    unsupported_filesystem(path, "atomic directory replacement (RENAME_EXCHANGE)")
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

#[cfg(not(target_os = "linux"))]
fn unsupported_platform() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "secure directory publication and replacement require Linux",
    )
}
