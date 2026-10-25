use std::{
    ffi::{OsStr, OsString},
    io,
    path::{Component, Path, PathBuf},
};

/// The kind of one entry found inside a prepared directory
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryEntryKind {
    /// A regular file
    File,
    /// A directory
    Directory,
    /// A symbolic link, reported without following it
    Symlink,
    /// A socket, device, pipe, or another non-file entry
    Other,
}

/// Safe metadata for one entry, named relative to its prepared directory
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    /// The relative entry path
    pub relative_path: PathBuf,
    /// The entry type observed without following symbolic links
    pub kind: DirectoryEntryKind,
    /// The byte length reported for this entry
    pub length: u64,
    /// The entry's hard-link count
    pub link_count: u64,
}

/// A held directory target that can be validated and then atomically replaced
#[derive(Debug)]
pub struct PreparedDirectoryReplacement {
    pub(super) destination_path: PathBuf,
    #[cfg(target_os = "linux")]
    pub(super) parent_fd: rustix::fd::OwnedFd,
    #[cfg(target_os = "linux")]
    pub(super) target_fd: rustix::fd::OwnedFd,
    #[cfg(target_os = "linux")]
    pub(super) name: OsString,
    #[cfg(target_os = "linux")]
    pub(super) target_identity: DirectoryIdentity,
    #[cfg(target_os = "linux")]
    pub(super) parent_identity: DirectoryIdentity,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DirectoryIdentity {
    device: rustix::fs::Dev,
    inode: u64,
}

impl PreparedDirectoryReplacement {
    /// Open one single-link regular file beneath the held directory without following links
    ///
    /// Every parent component is opened relative to held descriptors. This keeps readers bound
    /// to the inspected directory even if another process changes its pathname
    ///
    /// # Errors
    /// Returns an error if the relative path is unsafe, the entry is not a single-link regular
    /// file, the destination moved after inspection, or opening fails
    pub fn open_file(&self, relative_path: impl AsRef<Path>) -> io::Result<std::fs::File> {
        #[cfg(target_os = "linux")]
        {
            self.check_location()?;
            open_file_linux(self, relative_path.as_ref())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = relative_path;
            Err(super::super::unsupported_platform())
        }
    }

    /// Check that the held destination still occupies the inspected path
    ///
    /// The saved parent and target identities are compared with freshly opened path components
    /// before a caller trusts files read through the held target descriptor
    ///
    /// # Errors
    /// Returns an error if a path component is unsafe or either directory identity changed
    pub fn check_location(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let (parent_path, name) = super::super::parent_and_name(&self.destination_path)?;
            let current_parent = super::super::open_parent(parent_path)?;
            if identity_from_fd(&current_parent)? != self.parent_identity {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "destination parent changed after it was inspected",
                ));
            }
            if identity_from_fd(&self.target_fd)? != self.target_identity {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "held destination identity changed after inspection",
                ));
            }
            verify_named_directory(&current_parent, name, self.target_identity)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(super::super::unsupported_platform())
        }
    }

    /// List entries recursively without following symbolic links
    ///
    /// The result includes directories and special entries and is sorted by relative path.
    /// `max_entries` bounds memory use when inspecting an untrusted existing directory.
    ///
    /// # Errors
    /// Returns an error if the directory cannot be read or contains more than `max_entries`
    /// entries
    pub fn entries(&self, max_entries: usize) -> io::Result<Vec<DirectoryEntry>> {
        #[cfg(target_os = "linux")]
        {
            let mut entries = Vec::new();
            collect_entries(&self.target_fd, Path::new(""), max_entries, &mut entries)?;
            entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
            Ok(entries)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = max_entries;
            Err(super::unsupported_platform())
        }
    }
}

#[cfg(target_os = "linux")]
fn open_file_linux(
    prepared: &PreparedDirectoryReplacement,
    relative_path: &Path,
) -> io::Result<std::fs::File> {
    use rustix::fs::{FileType, Mode, OFlags};

    let components = normal_components(relative_path)?;
    let mut current = rustix::fs::openat(
        &prepared.target_fd,
        Path::new("."),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    for component in &components[..components.len() - 1] {
        current = rustix::fs::openat(
            &current,
            component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
    }
    let final_name = components
        .last()
        .ok_or_else(|| invalid_relative_path(relative_path))?;
    let file_fd = rustix::fs::openat(
        &current,
        final_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    let metadata = rustix::fs::fstat(&file_fd)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file() || metadata.st_nlink != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inspected entry is not a single-link regular file",
        ));
    }
    Ok(std::fs::File::from(file_fd))
}

#[cfg(target_os = "linux")]
fn collect_entries(
    directory: &rustix::fd::OwnedFd,
    prefix: &Path,
    max_entries: usize,
    entries: &mut Vec<DirectoryEntry>,
) -> io::Result<()> {
    use rustix::fs::FileType;

    visit_directory_entries(directory, &mut |name| {
        if entries.len() >= max_entries {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("directory contains more than {max_entries} entries"),
            ));
        }
        let stat = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        let file_type = FileType::from_raw_mode(stat.st_mode);
        let kind = if file_type.is_file() {
            DirectoryEntryKind::File
        } else if file_type.is_dir() {
            DirectoryEntryKind::Directory
        } else if file_type.is_symlink() {
            DirectoryEntryKind::Symlink
        } else {
            DirectoryEntryKind::Other
        };
        let relative_path = prefix.join(name);
        entries.push(DirectoryEntry {
            relative_path: relative_path.clone(),
            kind,
            length: nonnegative_length(stat.st_size)?,
            link_count: stat.st_nlink,
        });

        if file_type.is_dir() {
            let child = open_directory_at(directory, name, Some(identity_from_stat(&stat)))?;
            collect_entries(&child, &relative_path, max_entries, entries)?;
        }
        Ok(())
    })
}

#[cfg(target_os = "linux")]
pub(super) fn visit_directory_entries(
    directory: &rustix::fd::OwnedFd,
    visit: &mut impl FnMut(&OsStr) -> io::Result<()>,
) -> io::Result<()> {
    use rustix::fs::{Mode, OFlags, RawDir};
    use std::mem::MaybeUninit;
    use std::os::unix::ffi::OsStrExt;

    // A fresh open description keeps getdents offsets from changing the held target descriptor
    let listing_fd = rustix::fs::openat(
        directory,
        Path::new("."),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut buffer = [MaybeUninit::<u8>::uninit(); 8192];
    let mut entries = RawDir::new(&listing_fd, &mut buffer);
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(io::Error::from)?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        visit(OsStr::from_bytes(bytes))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn open_directory_at(
    parent: &rustix::fd::OwnedFd,
    name: &OsStr,
    expected: Option<DirectoryIdentity>,
) -> io::Result<rustix::fd::OwnedFd> {
    use rustix::fs::{FileType, Mode, OFlags};

    let directory = rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    verify_opened_identity(&directory, expected, FileType::Directory)?;
    Ok(directory)
}

#[cfg(target_os = "linux")]
pub(super) fn verify_opened_identity(
    fd: &rustix::fd::OwnedFd,
    expected: impl Into<Option<DirectoryIdentity>>,
    expected_type: rustix::fs::FileType,
) -> io::Result<()> {
    use rustix::fs::FileType;

    let stat = rustix::fs::fstat(fd)?;
    if FileType::from_raw_mode(stat.st_mode) != expected_type {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "opened entry changed type during inspection",
        ));
    }
    if let Some(expected) = expected.into()
        && identity_from_stat(&stat) != expected
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "opened entry changed during inspection",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn verify_named_directory(
    parent: &rustix::fd::OwnedFd,
    name: &OsStr,
    expected: DirectoryIdentity,
) -> io::Result<()> {
    use rustix::fs::{AtFlags, FileType};

    let stat = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir() || identity_from_stat(&stat) != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory name no longer identifies the checked directory",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn destination_entry_exists(
    parent: &rustix::fd::OwnedFd,
    name: &OsStr,
) -> io::Result<bool> {
    use rustix::fs::AtFlags;

    match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(error) => {
            let error: io::Error = error.into();
            if error.kind() == io::ErrorKind::NotFound {
                Ok(false)
            } else {
                Err(error)
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn stat_identity_at(
    parent: &rustix::fd::OwnedFd,
    name: &OsStr,
) -> io::Result<DirectoryIdentity> {
    use rustix::fs::AtFlags;

    let stat = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    Ok(identity_from_stat(&stat))
}

#[cfg(target_os = "linux")]
pub(super) fn identity_from_fd(fd: &rustix::fd::OwnedFd) -> io::Result<DirectoryIdentity> {
    Ok(identity_from_stat(&rustix::fs::fstat(fd)?))
}

#[cfg(target_os = "linux")]
pub(super) fn identity_from_stat(stat: &rustix::fs::Stat) -> DirectoryIdentity {
    DirectoryIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    }
}

#[cfg(target_os = "linux")]
fn normal_components(path: &Path) -> io::Result<Vec<OsString>> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => components.push(name.to_owned()),
            _ => return Err(invalid_relative_path(path)),
        }
    }
    if components.is_empty() {
        return Err(invalid_relative_path(path));
    }
    Ok(components)
}

#[cfg(target_os = "linux")]
fn invalid_relative_path(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "inspection path must be relative and contain normal components: {}",
            path.display()
        ),
    )
}

#[cfg(target_os = "linux")]
fn nonnegative_length(length: i64) -> io::Result<u64> {
    u64::try_from(length).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "filesystem reported a negative length",
        )
    })
}
