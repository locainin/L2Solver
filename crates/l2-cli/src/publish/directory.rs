use std::{
    error::Error,
    ffi::OsStr,
    io,
    path::{Path, PathBuf},
};

#[path = "directory/inspection.rs"]
mod inspection;
#[cfg(target_os = "linux")]
#[path = "directory/tree.rs"]
mod tree;

pub use inspection::{DirectoryEntry, DirectoryEntryKind, PreparedDirectoryReplacement};
#[cfg(target_os = "linux")]
use inspection::{
    destination_entry_exists, identity_from_fd, open_directory_at, stat_identity_at,
    verify_named_directory,
};
#[cfg(target_os = "linux")]
use tree::{remove_directory_at, sync_tree};

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
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{RenameFlags, renameat_with};
        use std::{os::fd::AsRawFd, path::PathBuf};

        let (parent, name) = super::parent_and_name(path)?;
        let parent_fd = super::open_parent(parent)?;
        if destination_entry_exists(&parent_fd, name)? {
            return Err(super::destination_exists(path).into());
        }

        // A proc-fd path keeps tempfile's helper bound to the parent held above
        let stable_parent = PathBuf::from(format!("/proc/self/fd/{}", parent_fd.as_raw_fd()));
        let staging = tempfile::Builder::new()
            .prefix(".l2solver-")
            .tempdir_in(stable_parent)?;
        let staging_name = staging_name(staging.path())?.to_owned();
        let staging_fd = open_directory_at(&parent_fd, &staging_name, None)?;
        let staging_identity = identity_from_fd(&staging_fd)?;

        let result = write(staging.path())?;
        sync_tree(&staging_fd, path)?;
        verify_named_directory(&parent_fd, &staging_name, staging_identity)?;

        renameat_with(
            &parent_fd,
            &staging_name,
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

        // The staging name now belongs to the destination and must not be removed by TempDir
        let _published_path = staging.keep();
        super::sync_parent_directory(&parent_fd, path)
            .map_err(super::DirectoryPublishError::PublishedDurabilityUncertain)?;
        Ok(result)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, write);
        Err(unsupported_platform().into())
    }
}

/// Safely inspect and hold an existing directory before applying caller-owned policy checks
///
/// The returned value retains the parent and target descriptors plus the target's device and
/// inode identity. Its descriptor-relative readers let callers validate ownership without
/// reopening an unchecked pathname. This function validates directory type only.
///
/// # Errors
/// Returns an error if the destination is missing, is not a real directory, or changes while
/// its descriptors are being prepared
pub fn prepare_directory_replacement(
    path: &Path,
) -> Result<PreparedDirectoryReplacement, super::DirectoryPublishError> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{Mode, OFlags};

        let (parent, name) = super::parent_and_name(path)?;
        let parent_fd = super::open_parent(parent)?;
        let target_fd = rustix::fs::openat(
            &parent_fd,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let target_identity = identity_from_fd(&target_fd)?;
        verify_named_directory(&parent_fd, name, target_identity)?;

        Ok(PreparedDirectoryReplacement {
            destination_path: path.to_owned(),
            parent_fd,
            target_fd,
            name: name.to_owned(),
            target_identity,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(unsupported_platform().into())
    }
}

/// Atomically replace a prepared directory after the new tree has been fully written and synced
///
/// The old directory remains at its destination until staging completes. Linux exchanges the
/// two names with `RENAME_EXCHANGE`, then checks both resulting inodes before deleting the old
/// tree. A detected race keeps the displaced entry at a reported recovery path.
///
/// # Errors
/// Returns [`super::DirectoryPublishError::BeforePublication`] when writing, syncing, or the
/// pre-exchange identity check fails; returns an uncertainty error when an exchange races with
/// another destination change or parent-directory synchronization fails
pub fn replace_directory<T>(
    prepared: PreparedDirectoryReplacement,
    write: impl FnOnce(&Path) -> Result<T, Box<dyn Error>>,
) -> Result<T, super::DirectoryPublishError> {
    #[cfg(target_os = "linux")]
    {
        replace_directory_linux(prepared, write)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (prepared, write);
        Err(unsupported_platform().into())
    }
}

#[cfg(target_os = "linux")]
fn replace_directory_linux<T>(
    prepared: PreparedDirectoryReplacement,
    write: impl FnOnce(&Path) -> Result<T, Box<dyn Error>>,
) -> Result<T, super::DirectoryPublishError> {
    use rustix::fs::{RenameFlags, renameat_with};
    use std::{os::fd::AsRawFd, path::PathBuf};

    let path = &prepared.destination_path;
    verify_named_directory(
        &prepared.parent_fd,
        &prepared.name,
        prepared.target_identity,
    )
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("destination changed after it was validated: {error}"),
        )
    })?;
    // The staging path remains anchored to the same parent even if its pathname is renamed
    let stable_parent = PathBuf::from(format!("/proc/self/fd/{}", prepared.parent_fd.as_raw_fd()));
    let staging = tempfile::Builder::new()
        .prefix(".l2solver-")
        .tempdir_in(stable_parent)?;
    let staging_name = staging_name(staging.path())?.to_owned();
    let staging_fd = open_directory_at(&prepared.parent_fd, &staging_name, None)?;
    let staging_identity = identity_from_fd(&staging_fd)?;

    let result = write(staging.path())?;
    sync_tree(&staging_fd, path)?;
    verify_named_directory(&prepared.parent_fd, &staging_name, staging_identity)?;
    verify_named_directory(
        &prepared.parent_fd,
        &prepared.name,
        prepared.target_identity,
    )
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("destination changed after it was validated: {error}"),
        )
    })?;

    #[cfg(test)]
    if super::test_hooks::take_fault(super::test_hooks::TestFault::UnsupportedDirectoryExchange) {
        return Err(unsupported_directory_exchange(path).into());
    }
    #[cfg(test)]
    super::test_hooks::before_directory_exchange()?;

    renameat_with(
        &prepared.parent_fd,
        &staging_name,
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

    let retained_path = retained_display_path(path, &staging_name);
    // From this point TempDir must not clean a name whose inode may have changed
    let _retained_path = staging.keep();
    let identities = stat_identity_at(&prepared.parent_fd, &staging_name).and_then(|displaced| {
        stat_identity_at(&prepared.parent_fd, &prepared.name)
            .map(|published| (displaced, published))
    });
    let (displaced_identity, published_identity) = match identities {
        Ok(identities) => identities,
        Err(error) => {
            return Err(
                super::DirectoryPublishError::PublishedReplacementUncertain {
                    source: error,
                    retained_path,
                },
            );
        }
    };
    if displaced_identity != prepared.target_identity || published_identity != staging_identity {
        // RENAME_EXCHANGE has no inode compare-and-swap flag, so preserve unexpected entries
        return Err(
            super::DirectoryPublishError::PublishedReplacementUncertain {
                source: io::Error::other(
                    "directory names changed during atomic exchange; displaced content was retained",
                ),
                retained_path,
            },
        );
    }

    // The retained name is checked before cleanup, and cleanup opens every directory without following links
    if let Err(error) =
        remove_directory_at(&prepared.parent_fd, &staging_name, prepared.target_identity)
    {
        return Err(
            super::DirectoryPublishError::PublishedReplacementUncertain {
                source: error,
                retained_path,
            },
        );
    }

    super::sync_parent_directory(&prepared.parent_fd, path)
        .map_err(super::DirectoryPublishError::PublishedDurabilityUncertain)?;
    Ok(result)
}

#[cfg(target_os = "linux")]
fn staging_name(path: &Path) -> io::Result<&OsStr> {
    path.file_name()
        .ok_or_else(|| io::Error::other("temporary directory has no name"))
}

#[cfg(target_os = "linux")]
fn retained_display_path(path: &Path, staging_name: &OsStr) -> PathBuf {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    parent.join(staging_name)
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
