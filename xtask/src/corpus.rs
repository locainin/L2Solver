//! Bounded corpus copying for fuzz minimization

use std::path::{Path, PathBuf};

#[cfg(unix)]
use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{CWD, Dir, FileType, Mode, OFlags, fstat, mkdirat, openat},
    io::Errno,
};
#[cfg(unix)]
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Write},
    os::unix::ffi::OsStringExt,
    path::Component,
};

const MAX_CORPUS_FILES: usize = 65_535;
const MAX_CORPUS_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CORPUS_ENTRIES: usize = 262_144;
const MAX_CORPUS_DEPTH: usize = 64;

#[derive(Clone, Copy)]
struct CorpusLimits {
    entries: usize,
    files: usize,
    bytes: u64,
    depth: usize,
}

impl CorpusLimits {
    const PRODUCTION: Self = Self {
        entries: MAX_CORPUS_ENTRIES,
        files: MAX_CORPUS_FILES,
        bytes: MAX_CORPUS_BYTES,
        depth: MAX_CORPUS_DEPTH,
    };
}

struct CorpusTraversal {
    limits: CorpusLimits,
    entries: usize,
    files: usize,
    bytes: u64,
}

impl CorpusTraversal {
    const fn new(limits: CorpusLimits) -> Self {
        Self {
            limits,
            entries: 0,
            files: 0,
            bytes: 0,
        }
    }
}

#[derive(Debug)]
enum CorpusCopyError {
    #[cfg(not(unix))]
    UnsupportedPlatform,
    InvalidPath(PathBuf),
    Io(PathBuf, std::io::Error),
    Symlink(PathBuf),
    SpecialFile(PathBuf),
    TooManyEntries {
        count: usize,
        maximum: usize,
    },
    TooManyFiles {
        count: usize,
        maximum: usize,
    },
    TooManyBytes {
        count: u64,
        maximum: u64,
    },
    TooDeep {
        depth: usize,
        maximum: usize,
    },
}

impl std::fmt::Display for CorpusCopyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(not(unix))]
            Self::UnsupportedPlatform => formatter
                .write_str("corpus copying requires Unix descriptor-relative filesystem access"),
            Self::InvalidPath(path) => {
                write!(formatter, "corpus path is not safe: {}", path.display())
            }
            Self::Io(path, source) => write!(formatter, "{}: {source}", path.display()),
            Self::Symlink(path) => {
                write!(
                    formatter,
                    "refusing to copy corpus symlink: {}",
                    path.display()
                )
            }
            Self::SpecialFile(path) => write!(
                formatter,
                "refusing to copy corpus special file: {}",
                path.display()
            ),
            Self::TooManyEntries { count, maximum } => write!(
                formatter,
                "corpus traversal encountered more than {maximum} entries at entry {count}"
            ),
            Self::TooManyFiles { count, maximum } => write!(
                formatter,
                "corpus contains more than {maximum} files at file {count}"
            ),
            Self::TooManyBytes { count, maximum } => write!(
                formatter,
                "corpus contains more than {maximum} bytes at byte {count}"
            ),
            Self::TooDeep { depth, maximum } => write!(
                formatter,
                "corpus directory depth {depth} exceeds depth limit {maximum}"
            ),
        }
    }
}

impl std::error::Error for CorpusCopyError {}

/// Copy one fuzz corpus without following path substitutions or exceeding limits
pub fn copy_corpus(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    copy_corpus_with_limits(source, destination, CorpusLimits::PRODUCTION).map_err(Into::into)
}

#[cfg(unix)]
fn copy_corpus_with_limits(
    source: &Path,
    destination: &Path,
    limits: CorpusLimits,
) -> Result<(), CorpusCopyError> {
    let source_fd = open_directory_path(source)?;
    let destination_fd = open_directory_path(destination)?;
    let mut traversal = CorpusTraversal::new(limits);
    visit_directory(
        source,
        source_fd,
        destination,
        &destination_fd,
        0,
        &mut traversal,
    )
}

#[cfg(not(unix))]
fn copy_corpus_with_limits(
    _source: &Path,
    _destination: &Path,
    _limits: CorpusLimits,
) -> Result<(), CorpusCopyError> {
    Err(CorpusCopyError::UnsupportedPlatform)
}

#[cfg(unix)]
fn open_directory_path(path: &Path) -> Result<OwnedFd, CorpusCopyError> {
    if path.as_os_str().is_empty() {
        return Err(CorpusCopyError::InvalidPath(path.to_owned()));
    }
    let mut current = openat(
        CWD,
        if path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        },
        directory_flags(),
        Mode::empty(),
    )
    .map_err(|source| CorpusCopyError::Io(path.to_owned(), source.into()))?;

    for component in path.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir | Component::CurDir) {
                continue;
            }
            return Err(CorpusCopyError::InvalidPath(path.to_owned()));
        };
        current = open_child(&current, name, directory_flags(), path)?;
    }
    Ok(current)
}

#[cfg(unix)]
fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

#[cfg(unix)]
fn open_child<Fd: AsFd>(
    parent: Fd,
    name: &OsStr,
    flags: OFlags,
    path: &Path,
) -> Result<OwnedFd, CorpusCopyError> {
    openat(parent, name, flags, Mode::empty()).map_err(|source| {
        if source == Errno::LOOP {
            CorpusCopyError::Symlink(path.to_owned())
        } else {
            CorpusCopyError::Io(path.to_owned(), source.into())
        }
    })
}

#[cfg(unix)]
fn create_destination_file<Fd: AsFd>(
    parent: Fd,
    name: &OsStr,
    path: &Path,
) -> Result<OwnedFd, CorpusCopyError> {
    openat(
        parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|source| CorpusCopyError::Io(path.to_owned(), source.into()))
}

#[cfg(unix)]
fn visit_directory(
    source_path: &Path,
    source_fd: OwnedFd,
    destination_path: &Path,
    destination_fd: &OwnedFd,
    depth: usize,
    traversal: &mut CorpusTraversal,
) -> Result<(), CorpusCopyError> {
    let mut directory = Dir::new(source_fd)
        .map_err(|source| CorpusCopyError::Io(source_path.to_owned(), source.into()))?;
    let mut children = Vec::new();
    for result in &mut directory {
        let entry =
            result.map_err(|source| CorpusCopyError::Io(source_path.to_owned(), source.into()))?;
        let name_bytes = entry.file_name().to_bytes();
        if matches!(name_bytes, b"." | b"..") {
            continue;
        }
        reserve_entry(traversal)?;
        children.push(OsString::from_vec(name_bytes.to_vec()));
    }
    children.sort_unstable();

    for name in children {
        let child_source_path = source_path.join(&name);
        let child_destination_path = destination_path.join(&name);
        let parent_fd = directory
            .fd()
            .map_err(|source| CorpusCopyError::Io(source_path.to_owned(), source.into()))?;
        let source_child = open_child(
            parent_fd,
            &name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            &child_source_path,
        )?;
        let stat = fstat(&source_child)
            .map_err(|source| CorpusCopyError::Io(child_source_path.clone(), source.into()))?;
        let file_type = FileType::from_raw_mode(stat.st_mode);

        if file_type.is_dir() {
            let child_depth = depth.checked_add(1).ok_or(CorpusCopyError::TooDeep {
                depth: usize::MAX,
                maximum: traversal.limits.depth,
            })?;
            if child_depth > traversal.limits.depth {
                return Err(CorpusCopyError::TooDeep {
                    depth: child_depth,
                    maximum: traversal.limits.depth,
                });
            }
            mkdirat(destination_fd, &name, Mode::from_raw_mode(0o700)).map_err(|source| {
                CorpusCopyError::Io(child_destination_path.clone(), source.into())
            })?;
            let destination_child = open_child(
                destination_fd,
                &name,
                directory_flags(),
                &child_destination_path,
            )?;
            visit_directory(
                &child_source_path,
                source_child,
                &child_destination_path,
                &destination_child,
                child_depth,
                traversal,
            )?;
            continue;
        }
        if !file_type.is_file() {
            return Err(CorpusCopyError::SpecialFile(child_source_path));
        }
        reserve_file(traversal)?;
        let destination_child =
            create_destination_file(destination_fd, &name, &child_destination_path)?;
        copy_regular_file(
            source_child,
            destination_child,
            &child_source_path,
            traversal,
        )?;
    }
    Ok(())
}

#[cfg(unix)]
fn reserve_entry(traversal: &mut CorpusTraversal) -> Result<(), CorpusCopyError> {
    let count = traversal
        .entries
        .checked_add(1)
        .ok_or(CorpusCopyError::TooManyEntries {
            count: usize::MAX,
            maximum: traversal.limits.entries,
        })?;
    if count > traversal.limits.entries {
        return Err(CorpusCopyError::TooManyEntries {
            count,
            maximum: traversal.limits.entries,
        });
    }
    traversal.entries = count;
    Ok(())
}

#[cfg(unix)]
fn reserve_file(traversal: &mut CorpusTraversal) -> Result<(), CorpusCopyError> {
    let count = traversal
        .files
        .checked_add(1)
        .ok_or(CorpusCopyError::TooManyFiles {
            count: usize::MAX,
            maximum: traversal.limits.files,
        })?;
    if count > traversal.limits.files {
        return Err(CorpusCopyError::TooManyFiles {
            count,
            maximum: traversal.limits.files,
        });
    }
    traversal.files = count;
    Ok(())
}

#[cfg(unix)]
fn copy_regular_file(
    source_fd: OwnedFd,
    destination_fd: OwnedFd,
    source_path: &Path,
    traversal: &mut CorpusTraversal,
) -> Result<(), CorpusCopyError> {
    let mut source = File::from(source_fd);
    let mut destination = File::from(destination_fd);
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|source| CorpusCopyError::Io(source_path.to_owned(), source))?;
        if read == 0 {
            return Ok(());
        }
        let read = u64::try_from(read).map_err(|_| CorpusCopyError::TooManyBytes {
            count: u64::MAX,
            maximum: traversal.limits.bytes,
        })?;
        let count = traversal
            .bytes
            .checked_add(read)
            .ok_or(CorpusCopyError::TooManyBytes {
                count: u64::MAX,
                maximum: traversal.limits.bytes,
            })?;
        if count > traversal.limits.bytes {
            return Err(CorpusCopyError::TooManyBytes {
                count,
                maximum: traversal.limits.bytes,
            });
        }
        let read = usize::try_from(read).map_err(|_| CorpusCopyError::TooManyBytes {
            count: u64::MAX,
            maximum: traversal.limits.bytes,
        })?;
        let bytes = buffer.get(..read).ok_or(CorpusCopyError::TooManyBytes {
            count: u64::MAX,
            maximum: traversal.limits.bytes,
        })?;
        destination
            .write_all(bytes)
            .map_err(|source| CorpusCopyError::Io(source_path.to_owned(), source))?;
        traversal.bytes = count;
    }
}

#[cfg(test)]
#[path = "../tests/corpus/internal.rs"]
mod tests;
