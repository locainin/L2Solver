use std::{
    ffi::{OsStr, OsString},
    io,
    path::Path,
};

use super::inspection::{
    DirectoryIdentity, identity_from_fd, identity_from_stat, open_directory_at,
    verify_named_directory, verify_opened_identity, visit_directory_entries,
};

#[cfg(target_os = "linux")]
pub(super) fn sync_tree(directory: &rustix::fd::OwnedFd, display_path: &Path) -> io::Result<()> {
    use rustix::fs::{FileType, Mode, OFlags};
    use std::fs::File;

    visit_directory_entries(directory, &mut |name| {
        let stat = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        let file_type = FileType::from_raw_mode(stat.st_mode);
        if file_type.is_file() {
            if stat.st_nlink != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "staged output contains a hard-linked file",
                ));
            }
            let file_fd = rustix::fs::openat(
                directory,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )?;
            verify_opened_identity(&file_fd, identity_from_stat(&stat), FileType::RegularFile)?;
            File::from(file_fd).sync_all().map_err(|error| {
                if super::super::is_unsupported_sync_error(&error) {
                    super::unsupported_filesystem(display_path, "staged-file synchronization")
                } else {
                    error
                }
            })?;
        } else if file_type.is_dir() {
            let child = open_directory_at(directory, name, Some(identity_from_stat(&stat)))?;
            sync_tree(&child, display_path)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "staged output contains a symbolic link or special entry",
            ));
        }
        Ok(())
    })?;

    rustix::fs::fsync(directory).map_err(|error| {
        let error: io::Error = error.into();
        if super::super::is_unsupported_sync_error(&error) {
            super::unsupported_filesystem(display_path, "staged-directory synchronization")
        } else {
            error
        }
    })
}

#[cfg(target_os = "linux")]
pub(super) fn remove_directory_at(
    parent: &rustix::fd::OwnedFd,
    name: &OsStr,
    expected: DirectoryIdentity,
) -> io::Result<()> {
    use rustix::fs::{AtFlags, FileType};

    let directory = open_directory_at(parent, name, Some(expected))?;
    remove_directory_contents(&directory)?;
    verify_named_directory(parent, name, expected)?;
    let current = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if !FileType::from_raw_mode(current.st_mode).is_dir()
        || identity_from_stat(&current) != expected
    {
        return Err(io::Error::other(
            "retained directory changed type during cleanup",
        ));
    }
    rustix::fs::unlinkat(parent, name, AtFlags::REMOVEDIR).map_err(Into::into)
}

#[cfg(target_os = "linux")]
fn remove_directory_contents(directory: &rustix::fd::OwnedFd) -> io::Result<()> {
    use rustix::fs::{AtFlags, FileType};

    let names = directory_names(directory)?;
    for name in names {
        let stat = rustix::fs::statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(stat.st_mode).is_dir() {
            let child = open_directory_at(directory, &name, Some(identity_from_stat(&stat)))?;
            remove_directory_contents(&child)?;
            let current = rustix::fs::statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW)?;
            if identity_from_stat(&current) != identity_from_fd(&child)? {
                return Err(io::Error::other(
                    "directory entry changed during descriptor-relative cleanup",
                ));
            }
            rustix::fs::unlinkat(directory, &name, AtFlags::REMOVEDIR)?;
        } else {
            // unlinkat removes a symbolic link itself and never opens its target
            let current = rustix::fs::statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW)?;
            if identity_from_stat(&current) != identity_from_stat(&stat) {
                return Err(io::Error::other(
                    "entry changed during descriptor-relative cleanup",
                ));
            }
            rustix::fs::unlinkat(directory, &name, AtFlags::empty())?;
        }
    }
    rustix::fs::fsync(directory).map_err(Into::into)
}

#[cfg(target_os = "linux")]
fn directory_names(directory: &rustix::fd::OwnedFd) -> io::Result<Vec<OsString>> {
    let mut names = Vec::new();
    visit_directory_entries(directory, &mut |name| {
        names.push(name.to_owned());
        Ok(())
    })?;
    Ok(names)
}
