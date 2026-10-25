//! Exact-inode publication for review artifacts

use super::PackageError;
use rustix::{
    fd::OwnedFd,
    fs::{
        self, AtFlags, CWD, Mode, OFlags, PROC_SUPER_MAGIC, fstat, fstatfs, linkat, openat, statat,
    },
    io::Errno,
};
use std::{
    fs::File,
    io::Write,
    os::fd::AsRawFd,
    path::{Component, Path, PathBuf},
};

/// A complete synced inode that has no filesystem name yet
pub(super) struct StagedOutput {
    file: File,
    name: PathBuf,
    display_path: PathBuf,
}

/// Write and sync an output without exposing a partial destination
pub(super) fn stage_output(
    parent: &OwnedFd,
    name: &Path,
    display_path: &Path,
    bytes: &[u8],
) -> Result<StagedOutput, PackageError> {
    validate_name(name, display_path)?;
    let file_fd = openat(
        parent,
        Path::new("."),
        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::TMPFILE,
        Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
    )
    .map_err(|source| map_temporary_error(display_path, source))?;
    let mut file = File::from(file_fd);
    file.write_all(bytes)
        .map_err(|source| PackageError::Io(display_path.to_owned(), source))?;
    file.flush()
        .map_err(|source| PackageError::Io(display_path.to_owned(), source))?;
    fs::fsync(&file).map_err(|source| {
        if unsupported_filesystem(source) {
            PackageError::UnsupportedFilesystem {
                path: display_path.to_owned(),
                feature: "file synchronization",
            }
        } else {
            PackageError::Io(display_path.to_owned(), source.into())
        }
    })?;
    Ok(StagedOutput {
        file,
        name: name.to_owned(),
        display_path: display_path.to_owned(),
    })
}

/// Link the exact held inode into the pinned parent without replacement
pub(super) fn publish_output(parent: &OwnedFd, output: &StagedOutput) -> Result<(), PackageError> {
    let proc_fd = open_proc_fd_directory()?;
    let fd_name = output.file.as_raw_fd().to_string();
    verify_proc_entry(&proc_fd, &output.file, &fd_name)?;
    linkat(
        &proc_fd,
        Path::new(&fd_name),
        parent,
        &output.name,
        AtFlags::SYMLINK_FOLLOW,
    )
    .map_err(|source| map_link_error(&output.display_path, source))
}

/// Fail before staging when any destination already has a directory entry
pub(super) fn preflight_outputs(
    parent: &OwnedFd,
    outputs: &[(&Path, &Path)],
) -> Result<(), PackageError> {
    for (name, display_path) in outputs {
        validate_name(name, display_path)?;
        match statat(parent, *name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => return Err(PackageError::ExistingOutput((*display_path).to_owned())),
            Err(Errno::NOENT) => {}
            Err(source) => {
                return Err(PackageError::Io((*display_path).to_owned(), source.into()));
            }
        }
    }
    Ok(())
}

/// Sync every linked directory entry through the held parent descriptor
pub(super) fn sync_parent(parent: &OwnedFd, path: &Path) -> Result<(), PackageError> {
    fs::fsync(parent).map_err(|source| {
        if unsupported_filesystem(source) {
            PackageError::UnsupportedFilesystem {
                path: path.to_owned(),
                feature: "directory synchronization",
            }
        } else {
            PackageError::Io(path.to_owned(), source.into())
        }
    })
}

fn validate_name(name: &Path, display_path: &Path) -> Result<(), PackageError> {
    let mut components = name.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(PackageError::Io(
            display_path.to_owned(),
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "publication name must be one filename component",
            ),
        ));
    }
    Ok(())
}

fn open_proc_fd_directory() -> Result<OwnedFd, PackageError> {
    let proc_fd = openat(
        CWD,
        Path::new("/proc/self/fd"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| PackageError::SecurePublicationUnavailable)?;
    let filesystem = fstatfs(&proc_fd).map_err(|_| PackageError::SecurePublicationUnavailable)?;
    if filesystem.f_type != PROC_SUPER_MAGIC {
        return Err(PackageError::SecurePublicationUnavailable);
    }
    Ok(proc_fd)
}

fn verify_proc_entry(proc_fd: &OwnedFd, file: &File, fd_name: &str) -> Result<(), PackageError> {
    let held = fstat(file).map_err(|_| PackageError::SecurePublicationUnavailable)?;
    let resolved = statat(proc_fd, Path::new(fd_name), AtFlags::empty())
        .map_err(|_| PackageError::SecurePublicationUnavailable)?;
    if held.st_dev != resolved.st_dev || held.st_ino != resolved.st_ino {
        return Err(PackageError::SecurePublicationUnavailable);
    }
    Ok(())
}

fn map_temporary_error(path: &Path, source: Errno) -> PackageError {
    if matches!(
        source,
        Errno::OPNOTSUPP | Errno::NOSYS | Errno::ISDIR | Errno::NOENT | Errno::INVAL
    ) {
        PackageError::UnsupportedFilesystem {
            path: path.to_owned(),
            feature: "unnamed temporary files",
        }
    } else {
        PackageError::Io(path.to_owned(), source.into())
    }
}

fn map_link_error(path: &Path, source: Errno) -> PackageError {
    if source == Errno::EXIST {
        PackageError::ExistingOutput(path.to_owned())
    } else if matches!(
        source,
        Errno::ACCESS
            | Errno::PERM
            | Errno::NOENT
            | Errno::NOTDIR
            | Errno::LOOP
            | Errno::NOSYS
            | Errno::OPNOTSUPP
            | Errno::INVAL
    ) {
        PackageError::SecurePublicationUnavailable
    } else {
        PackageError::Io(path.to_owned(), source.into())
    }
}

const fn unsupported_filesystem(source: Errno) -> bool {
    matches!(source, Errno::INVAL | Errno::OPNOTSUPP | Errno::NOSYS)
}
