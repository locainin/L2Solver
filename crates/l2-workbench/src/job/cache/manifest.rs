use std::{
    fs::{self, Metadata},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::job::{MemoryBudget, MemoryLease};

use super::{
    error::{CacheError, Result},
    fingerprint::FileTimestamp,
    memory,
};

pub(super) const MAX_TREE_ITEMS: usize = 100_000;
pub(super) const MAX_TREE_DEPTH: usize = 64;
// Generated cache paths contain one digest and one filesystem component
pub(super) const MAX_RELATIVE_PATH_BYTES: usize = 4096;

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
    pub(super) fn scan(
        directory: &Path,
        budget: Option<&MemoryBudget>,
    ) -> Result<(Self, Option<MemoryLease>)> {
        let mut charge = memory::reserve(budget, 0)?;
        let mut items = Vec::new();
        let mut state = WalkState::new(MAX_TREE_ITEMS, usize::MAX);
        walk(
            directory,
            directory,
            0,
            &mut state,
            &mut |relative, metadata, is_directory| {
                if let Some(charge) = &mut charge {
                    // Reserve for vector capacity and path copies before adding a new item
                    let path_bytes = u64::try_from(relative.as_os_str().len())
                        .map_err(|_| CacheError::SizeOverflow)?;
                    let extra = path_bytes
                        .checked_mul(4)
                        .and_then(|bytes| bytes.checked_add(512))
                        .ok_or(CacheError::SizeOverflow)?;
                    charge.try_resize(
                        charge
                            .bytes()
                            .checked_add(extra)
                            .ok_or(CacheError::SizeOverflow)?,
                    )?;
                }
                items.push(manifest_item(relative, metadata, is_directory)?);
                Ok(())
            },
        )?;
        items.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        Ok((
            Self {
                items,
                total_bytes: state.total_bytes,
            },
            charge,
        ))
    }

    pub(super) fn validate(&self, directory: &Path) -> Result<()> {
        if self.items.len() > MAX_TREE_ITEMS
            || self.items.windows(2).any(
                |pair| matches!(pair, [left, right] if left.relative_path >= right.relative_path),
            )
        {
            return Err(CacheError::CorruptEntry(
                "entry manifest order is invalid".to_owned(),
            ));
        }
        let path_bytes = self.items.iter().try_fold(0_usize, |sum, item| {
            sum.checked_add(item.relative_path.len())
                .ok_or(CacheError::SizeOverflow)
        })?;
        let mut state = WalkState::new(self.items.len(), path_bytes);
        walk(
            directory,
            directory,
            0,
            &mut state,
            &mut |relative, metadata, is_directory| {
                let actual = manifest_item(relative, metadata, is_directory)?;
                let index = self
                    .items
                    .binary_search_by(|item| item.relative_path.cmp(&actual.relative_path))
                    .map_err(|_| {
                        CacheError::CorruptEntry("entry file is not in the manifest".to_owned())
                    })?;
                if self.items.get(index) != Some(&actual) {
                    return Err(CacheError::CorruptEntry("entry file changed".to_owned()));
                }
                Ok(())
            },
        )?;
        if state.items != self.items.len() || state.total_bytes != self.total_bytes {
            return Err(CacheError::CorruptEntry(
                "entry manifest totals differ".to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

struct WalkState {
    items: usize,
    total_bytes: u64,
    path_bytes: usize,
    max_items: usize,
    max_path_bytes: usize,
}

impl WalkState {
    const fn new(max_items: usize, max_path_bytes: usize) -> Self {
        Self {
            items: 0,
            total_bytes: 0,
            path_bytes: 0,
            max_items,
            max_path_bytes,
        }
    }
}

fn walk<F>(
    root: &Path,
    directory: &Path,
    depth: usize,
    state: &mut WalkState,
    visit: &mut F,
) -> Result<()>
where
    F: FnMut(&Path, &Metadata, bool) -> Result<()>,
{
    if depth > MAX_TREE_DEPTH {
        return Err(CacheError::InvalidInput(
            "cache entry directory tree is too deep",
        ));
    }
    let root_metadata = fs::symlink_metadata(directory)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(CacheError::UnsafePath(
            "entry root must be a real directory",
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
        if state.items >= state.max_items {
            return Err(CacheError::InvalidInput(
                "cache entry contains too many files",
            ));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| CacheError::UnsafePath("cache entry path escaped its root"))?;
        state.path_bytes = state
            .path_bytes
            .checked_add(relative.as_os_str().len())
            .ok_or(CacheError::SizeOverflow)?;
        if state.path_bytes > state.max_path_bytes {
            return Err(CacheError::InvalidInput(
                "cache entry paths exceed the stored manifest",
            ));
        }
        visit(relative, &metadata, is_directory)?;
        state.items += 1;
        if is_directory {
            walk(root, &path, depth + 1, state, visit)?;
        } else {
            state.total_bytes = state
                .total_bytes
                .checked_add(metadata.len())
                .ok_or(CacheError::SizeOverflow)?;
        }
    }
    Ok(())
}

fn manifest_item(relative: &Path, metadata: &Metadata, is_directory: bool) -> Result<ManifestItem> {
    let mut relative_path = String::with_capacity(relative.as_os_str().len());
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(CacheError::UnsafePath("cache entry path is not relative"));
        };
        let name = name
            .to_str()
            .ok_or(CacheError::InvalidInput("cache entry path is not UTF-8"))?;
        if !relative_path.is_empty() {
            relative_path.push('/');
        }
        relative_path.push_str(name);
    }
    if relative_path.is_empty() {
        return Err(CacheError::UnsafePath("cache entry path is empty"));
    }
    let identity = metadata_identity(metadata);
    Ok(ManifestItem {
        relative_path,
        is_directory,
        size_bytes: metadata.len(),
        device_id: identity.0,
        file_id: identity.1,
        modified: identity.2,
        changed: identity.3,
    })
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
    if relative.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(CacheError::CorruptEntry(
            "entry path is too long".to_owned(),
        ));
    }
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
