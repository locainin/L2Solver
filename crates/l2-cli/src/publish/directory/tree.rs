use std::{io, path::Path};

use super::inspection::{
    identity_from_stat, open_directory_at, verify_opened_identity, visit_directory_entries,
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
