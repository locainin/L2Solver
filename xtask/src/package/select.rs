//! Bounded source-tree selection for review packages

use super::{Entry, PackageError};
#[cfg(unix)]
use super::{MAX_FILE_BYTES, MAX_FILES, MAX_SOURCE_BYTES, MAX_TRAVERSAL_ENTRIES};
#[cfg(unix)]
use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{CWD, Dir, FileType, Mode, OFlags, fstat, openat},
    io::Errno,
};
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path};
#[cfg(unix)]
use std::{ffi::OsString, io::Read};

// Capture archives and partial downloads may have no capture suffix of their own
const SAMPLE_ARTIFACT_EXTENSIONS: &[&str] = &[
    "cap",
    "pcap",
    "pcapng",
    "gz",
    "bz2",
    "xz",
    "zst",
    "lz4",
    "zip",
    "7z",
    "part",
    "partial",
    "crdownload",
    "download",
];

// Root-level raw captures are local inputs, while test fixtures stay packageable
const ROOT_CAPTURE_EXTENSIONS: &[&str] = &["cap", "pcap", "pcapng"];

/// Return whether a relative path belongs to an excluded build, VCS, review, or secret path
#[must_use]
pub fn is_excluded_path(path: &Path) -> bool {
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    if components.len() != path.components().count() {
        return true;
    }
    for component in &components {
        if matches!(
            *component,
            ".agents"
                | ".codex"
                | ".git"
                | ".hg"
                | ".svn"
                | ".bzr"
                | "_darcs"
                | ".pijul"
                | ".pytest_cache"
                | ".ruff_cache"
                | "__pycache__"
                | "target"
        ) || component.starts_with("mutants.out")
        {
            return true;
        }
    }
    let root = components.first().copied();
    let second = components.get(1).copied();
    if root == Some("investigations")
        || root == Some("benchmarks") && matches!(second, Some("cache" | "results"))
        || root == Some("pcap_samples") && second == Some("local")
        || components.windows(2).any(|pair| {
            matches!(
                pair,
                ["docs", "evidence"] | ["fuzz", "artifacts" | "corpus"]
            )
        })
    {
        return true;
    }
    let Some(name) = components.last() else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    // Keep sample bytes local while retaining capture fixtures elsewhere
    let local_capture_artifact = root == Some("pcap_samples")
        && (components.contains(&"runs")
            || SAMPLE_ARTIFACT_EXTENSIONS
                .iter()
                .any(|extension| has_extension(name, extension)));
    let root_capture_artifact = components.len() == 1
        && ROOT_CAPTURE_EXTENSIONS
            .iter()
            .any(|extension| has_extension(name, extension));
    let generated_heaptrack_doc = root == Some("docs")
        && matches!(second, Some("profiles" | "screenshots"))
        && lower.starts_with("heaptrack-");
    lower == ".env"
        || lower.starts_with(".env.")
        || lower == "id_rsa"
        || lower == "id_dsa"
        || lower == "credentials"
        || lower == "credentials.json"
        || lower == "secrets.json"
        || has_secret_extension(name)
        || is_review_output_name(&lower)
        || local_capture_artifact
        || root_capture_artifact
        || lower == "perf.data"
        || lower.starts_with("perf.data.")
        || lower.starts_with("heaptrack.")
        || generated_heaptrack_doc
        || lower == "flamegraph.svg"
        || lower == "rust_out"
        || lower == ".bacon-locations"
}

pub(super) fn collect_entries(root: &Path) -> Result<Vec<Entry>, PackageError> {
    #[cfg(unix)]
    return collect_entries_pinned(root).map(|collected| collected.entries);
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(PackageError::UnsupportedPlatform)
    }
}

#[cfg(unix)]
pub(super) struct PinnedEntries {
    pub(super) entries: Vec<Entry>,
    pub(super) root_fd: OwnedFd,
}

#[cfg(unix)]
pub(super) fn collect_entries_pinned(root: &Path) -> Result<PinnedEntries, PackageError> {
    let root_fd = open_root(root)?;
    let root_stat =
        fstat(&root_fd).map_err(|source| PackageError::Io(root.to_owned(), source.into()))?;
    if !FileType::from_raw_mode(root_stat.st_mode).is_dir() {
        return Err(PackageError::InvalidRoot(root.to_owned()));
    }
    let publication_fd = root_fd
        .try_clone()
        .map_err(|source| PackageError::Io(root.to_owned(), source))?;
    let mut entries = Vec::new();
    let mut source_bytes = 0_u64;
    let mut traversal_entries = 0_usize;
    visit_directory_unix(
        root,
        root,
        root_fd,
        &mut entries,
        &mut source_bytes,
        &mut traversal_entries,
    )?;
    entries.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    Ok(PinnedEntries {
        entries,
        root_fd: publication_fd,
    })
}

#[cfg(unix)]
fn open_root(root: &Path) -> Result<OwnedFd, PackageError> {
    // An empty path must retain the standard ENOENT behavior instead of
    // accidentally treating the current directory as the root
    if root.as_os_str().is_empty() {
        return open_nofollow(
            CWD,
            root.as_os_str(),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            root,
        );
    }

    // Open the starting directory once, then resolve every root component
    // relative to the descriptor held for its parent
    let mut current = openat(
        CWD,
        if root.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        },
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| PackageError::Io(root.to_owned(), source.into()))?;
    let mut components = Vec::new();
    for component in root.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(value) => components.push(value.to_owned()),
            Component::ParentDir => components.push(OsString::from("..")),
            Component::Prefix(_) => return Err(PackageError::InvalidRoot(root.to_owned())),
        }
    }
    for (index, component) in components.iter().enumerate() {
        let is_final = index + 1 == components.len();
        current = open_nofollow(
            &current,
            component,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            root,
        )?;
        if !is_final {
            let stat = fstat(&current)
                .map_err(|source| PackageError::Io(root.to_owned(), source.into()))?;
            if !FileType::from_raw_mode(stat.st_mode).is_dir() {
                return Err(PackageError::Io(
                    root.to_owned(),
                    std::io::Error::new(
                        std::io::ErrorKind::NotADirectory,
                        "root ancestor is not a directory",
                    ),
                ));
            }
        }
    }
    Ok(current)
}

#[cfg(unix)]
fn open_nofollow<Fd: AsFd>(
    parent: Fd,
    name: &std::ffi::OsStr,
    flags: OFlags,
    path: &Path,
) -> Result<OwnedFd, PackageError> {
    openat(parent, name, flags, Mode::empty()).map_err(|source| {
        if source == Errno::LOOP {
            PackageError::Symlink(path.to_owned())
        } else {
            PackageError::Io(path.to_owned(), source.into())
        }
    })
}

#[cfg(unix)]
fn visit_directory_unix(
    root: &Path,
    directory_path: &Path,
    directory_fd: OwnedFd,
    entries: &mut Vec<Entry>,
    source_bytes: &mut u64,
    traversal_entries: &mut usize,
) -> Result<(), PackageError> {
    let mut directory = Dir::new(directory_fd)
        .map_err(|source| PackageError::Io(directory_path.to_owned(), source.into()))?;
    let mut children = Vec::new();
    for result in &mut directory {
        let entry =
            result.map_err(|source| PackageError::Io(directory_path.to_owned(), source.into()))?;
        let name_bytes = entry.file_name().to_bytes();
        if matches!(name_bytes, b"." | b"..") {
            continue;
        }
        reserve_traversal_entry(traversal_entries)?;
        let name = OsString::from_vec(name_bytes.to_vec());
        let path = directory_path.join(&name);
        let relative = relative_path(root, &path)?;
        children.push((name, path, relative));
    }
    children.sort_unstable_by(|left, right| left.2.cmp(&right.2));

    for (name, path, relative) in children {
        if is_excluded_path(Path::new(&relative)) {
            continue;
        }
        let parent_fd = directory
            .fd()
            .map_err(|source| PackageError::Io(directory_path.to_owned(), source.into()))?;
        let file = open_nofollow(
            parent_fd,
            &name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            &path,
        )?;
        let stat = fstat(&file).map_err(|source| PackageError::Io(path.clone(), source.into()))?;
        let file_type = FileType::from_raw_mode(stat.st_mode);
        if file_type.is_dir() {
            visit_directory_unix(root, &path, file, entries, source_bytes, traversal_entries)?;
            continue;
        }
        if !file_type.is_file() {
            return Err(PackageError::SpecialFile(path));
        }
        if entries.len() >= MAX_FILES {
            return Err(PackageError::TooManyFiles {
                count: entries.len() + 1,
                maximum: MAX_FILES,
            });
        }
        let bytes = read_bounded_fd(&path, file)?;
        *source_bytes = source_bytes
            .checked_add(
                u64::try_from(bytes.len()).map_err(|_| PackageError::ArchiveFieldOverflow)?,
            )
            .ok_or(PackageError::SourceTooLarge {
                size: u64::MAX,
                maximum: MAX_SOURCE_BYTES,
            })?;
        if *source_bytes > MAX_SOURCE_BYTES {
            return Err(PackageError::SourceTooLarge {
                size: *source_bytes,
                maximum: MAX_SOURCE_BYTES,
            });
        }
        if looks_like_secret(&bytes) {
            continue;
        }
        entries.push(Entry {
            path: relative,
            sha256: super::archive::digest_hex(&bytes),
            bytes,
        });
    }
    Ok(())
}

#[cfg(unix)]
fn reserve_traversal_entry(count: &mut usize) -> Result<(), PackageError> {
    let next = count.checked_add(1).ok_or(PackageError::TooManyEntries {
        count: usize::MAX,
        maximum: MAX_TRAVERSAL_ENTRIES,
    })?;
    if next > MAX_TRAVERSAL_ENTRIES {
        return Err(PackageError::TooManyEntries {
            count: next,
            maximum: MAX_TRAVERSAL_ENTRIES,
        });
    }
    *count = next;
    Ok(())
}

#[cfg(unix)]
fn read_bounded_fd(path: &Path, fd: OwnedFd) -> Result<Vec<u8>, PackageError> {
    let mut file = File::from(fd);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| PackageError::Io(path.to_owned(), source))?;
    let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if size > MAX_FILE_BYTES {
        return Err(PackageError::FileTooLarge {
            path: path.to_owned(),
            size,
            maximum: MAX_FILE_BYTES,
        });
    }
    Ok(bytes)
}

#[cfg(unix)]
fn relative_path(root: &Path, path: &Path) -> Result<String, PackageError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| PackageError::NonUnicodePath(path.to_owned()))?;
    let mut output = String::new();
    for component in relative.components() {
        let Component::Normal(value) = component else {
            return Err(PackageError::NonUnicodePath(path.to_owned()));
        };
        let value = value
            .to_str()
            .ok_or_else(|| PackageError::NonUnicodePath(path.to_owned()))?;
        if !output.is_empty() {
            output.push('/');
        }
        output.push_str(value);
    }
    Ok(output)
}

#[cfg(unix)]
fn looks_like_secret(bytes: &[u8]) -> bool {
    ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"]
        .iter()
        .any(|label| has_pem_block(bytes, label))
        || [
            "AWS_SECRET_ACCESS_KEY=",
            "GITHUB_TOKEN=",
            "API_KEY=",
            "PASSWORD=",
            "SECRET_KEY=",
        ]
        .iter()
        .any(|marker| has_assignment_value(bytes, marker.as_bytes()))
}

#[cfg(unix)]
fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

#[cfg(unix)]
fn has_pem_block(bytes: &[u8], label: &str) -> bool {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    contains_ascii_case_insensitive(bytes, begin.as_bytes())
        && contains_ascii_case_insensitive(bytes, end.as_bytes())
}

#[cfg(unix)]
fn has_assignment_value(bytes: &[u8], marker: &[u8]) -> bool {
    let mut offset = 0_usize;
    while let Some(tail) = bytes.get(offset..) {
        let Some(relative) = tail.windows(marker.len()).position(|window| {
            window
                .iter()
                .zip(marker)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
        }) else {
            break;
        };
        let value_start = offset + relative + marker.len();
        let mut value_start = value_start;
        while bytes
            .get(value_start)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            value_start += 1;
        }
        let Some(first) = bytes.get(value_start) else {
            break;
        };
        if matches!(first, b'"' | b'\'' | b'`') {
            let content_start = value_start.saturating_add(1);
            if let Some(tail) = bytes.get(content_start..) {
                for (length, byte) in tail.iter().enumerate() {
                    if *byte == *first {
                        if length > 0 {
                            return true;
                        }
                        break;
                    }
                    if matches!(byte, b'\r' | b'\n') {
                        break;
                    }
                }
            }
        } else {
            return true;
        }
        offset = value_start.saturating_add(1);
        if offset >= bytes.len() {
            return false;
        }
    }
    false
}

fn is_review_output_name(name: &str) -> bool {
    (name == "review.zip" || name.starts_with("review-") || name.starts_with("review."))
        && (has_extension(name, "zip")
            || name.ends_with(".zip.sha256")
            || name.ends_with(".manifest")
            || name.ends_with(".zip.partial"))
}

fn has_secret_extension(name: &str) -> bool {
    ["pem", "key", "p12", "pfx", "jks"]
        .iter()
        .any(|extension| has_extension(name, extension))
}

fn has_extension(name: &str, extension: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|value| value.eq_ignore_ascii_case(extension))
}

#[cfg(all(test, unix))]
mod tests {
    include!("../../tests/package/descriptor.rs");
}
