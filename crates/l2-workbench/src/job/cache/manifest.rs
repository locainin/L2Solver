use std::{
    fs::{self, Metadata},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::{
    error::{CacheError, Result},
    fingerprint::FileTimestamp,
};

const MAX_TREE_ITEMS: usize = 100_000;
const MAX_TREE_DEPTH: usize = 64;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct Manifest {
    items: Vec<ManifestItem>,
    total_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ManifestItem {
    relative_path: String,
    is_directory: bool,
    size_bytes: u64,
    device_id: Option<u64>,
    file_id: Option<u64>,
    modified: Option<FileTimestamp>,
    changed: Option<FileTimestamp>,
}

impl Manifest {
    pub(super) fn scan(directory: &Path) -> Result<Self> {
        // File identity and change times detect replacement without hashing every cached byte
        let metadata = fs::symlink_metadata(directory)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CacheError::UnsafePath(
                "entry root must be a real directory",
            ));
        }

        let mut items = Vec::new();
        let mut total_bytes = 0_u64;
        visit(directory, directory, 0, &mut items, &mut total_bytes)?;
        items.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        Ok(Self { items, total_bytes })
    }

    pub(super) const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

fn visit(
    root: &Path,
    directory: &Path,
    depth: usize,
    items: &mut Vec<ManifestItem>,
    total_bytes: &mut u64,
) -> Result<()> {
    if depth > MAX_TREE_DEPTH {
        return Err(CacheError::InvalidInput(
            "cache entry directory tree is too deep",
        ));
    }

    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        let is_directory = metadata.is_dir();
        if metadata.file_type().is_symlink() || (!is_directory && !metadata.is_file()) {
            return Err(CacheError::UnsafePath(
                "cache entries may contain only files and directories",
            ));
        }

        if items.len() >= MAX_TREE_ITEMS {
            return Err(CacheError::InvalidInput(
                "cache entry contains too many files",
            ));
        }
        let relative_path = relative_path(root, &path)?;
        let identity = metadata_identity(&metadata);
        items.push(ManifestItem {
            relative_path,
            is_directory,
            size_bytes: metadata.len(),
            device_id: identity.0,
            file_id: identity.1,
            modified: identity.2,
            changed: identity.3,
        });

        if is_directory {
            visit(root, &path, depth + 1, items, total_bytes)?;
        } else {
            *total_bytes = total_bytes
                .checked_add(metadata.len())
                .ok_or(CacheError::SizeOverflow)?;
        }
    }
    Ok(())
}

fn relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| CacheError::UnsafePath("cache entry path escaped its root"))?;
    let normalized = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(name) => name
                .to_str()
                .ok_or(CacheError::InvalidInput("cache entry path is not UTF-8")),
            _ => Err(CacheError::UnsafePath("cache entry path is not relative")),
        })
        .collect::<Result<Vec<_>>>()?;
    if normalized.is_empty() {
        return Err(CacheError::UnsafePath("cache entry path is empty"));
    }
    Ok(normalized.join("/"))
}

fn metadata_identity(
    metadata: &Metadata,
) -> (
    Option<u64>,
    Option<u64>,
    Option<FileTimestamp>,
    Option<FileTimestamp>,
) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (
            Some(metadata.dev()),
            Some(metadata.ino()),
            Some(FileTimestamp {
                seconds: metadata.mtime(),
                nanoseconds: u32::try_from(metadata.mtime_nsec()).unwrap_or_default(),
            }),
            Some(FileTimestamp {
                seconds: metadata.ctime(),
                nanoseconds: u32::try_from(metadata.ctime_nsec()).unwrap_or_default(),
            }),
        )
    }
    #[cfg(not(unix))]
    {
        let modified = metadata.modified().ok().and_then(|time| {
            let duration = time.duration_since(std::time::UNIX_EPOCH).ok()?;
            Some(FileTimestamp {
                seconds: i64::try_from(duration.as_secs()).ok()?,
                nanoseconds: duration.subsec_nanos(),
            })
        });
        (None, None, modified, None)
    }
}

pub(super) fn safe_entry_path(root: &Path, key: &str, relative: &str) -> Result<PathBuf> {
    let mut components = Path::new(relative).components();
    let first = components.next();
    let second = components.next();
    if components.next().is_some()
        || !matches!(first, Some(std::path::Component::Normal(name)) if name == key)
        || !matches!(second, Some(std::path::Component::Normal(_)))
    {
        return Err(CacheError::CorruptEntry("entry path is invalid".to_owned()));
    }
    Ok(root.join(relative))
}
