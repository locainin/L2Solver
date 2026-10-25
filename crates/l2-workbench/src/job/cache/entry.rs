use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::job::JobSnapshot;
use serde_json::Value;

use super::{
    Cache,
    error::{CacheError, Result},
    filesystem::{HeldDirectory, LockGuard},
    key::StageKey,
    manifest::{Manifest, safe_entry_path},
    model::StageStatus,
};

const MAX_METADATA_BYTES: usize = 4 * 1024 * 1024;

/// A pinned, validated result directory returned by a cache lookup or commit
pub struct CacheEntry {
    key: StageKey,
    status: StageStatus,
    metadata: Value,
    directory: HeldDirectory,
    _lock: LockGuard,
}

/// An exclusive work area for one stable stage key
pub struct Lease {
    cache: Cache,
    key: StageKey,
    lock: Option<LockGuard>,
    staging_path: PathBuf,
    cleanup_on_drop: bool,
    directory: HeldDirectory,
}

pub(super) struct EntryRecord {
    pub(super) stage: String,
    pub(super) status: StageStatus,
    pub(super) relative_path: String,
    pub(super) metadata_json: String,
    pub(super) manifest_json: String,
    pub(super) bytes: i64,
}

impl std::fmt::Debug for CacheEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CacheEntry")
            .field("key", &self.key)
            .field("status", &self.status)
            .field("directory", &self.directory.path())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Lease")
            .field("key", &self.key)
            .field("directory", &self.directory.path())
            .finish_non_exhaustive()
    }
}

impl CacheEntry {
    pub(super) const fn new(
        key: StageKey,
        status: StageStatus,
        metadata: Value,
        directory: HeldDirectory,
        lock: LockGuard,
    ) -> Self {
        Self {
            key,
            status,
            metadata,
            directory,
            _lock: lock,
        }
    }

    /// Returns the stable key for this cached stage
    #[must_use]
    pub const fn key(&self) -> &StageKey {
        &self.key
    }

    /// Returns whether the stored result is complete or resumable
    #[must_use]
    pub const fn status(&self) -> StageStatus {
        self.status
    }

    /// Returns the validated metadata receipt stored with this entry
    #[must_use]
    pub const fn metadata(&self) -> &Value {
        &self.metadata
    }

    /// Returns the pinned directory containing stage files
    #[must_use]
    pub fn directory(&self) -> &Path {
        self.directory.path()
    }
}

impl Lease {
    pub(super) const fn new(
        cache: Cache,
        key: StageKey,
        lock: LockGuard,
        staging_path: PathBuf,
        directory: HeldDirectory,
    ) -> Self {
        Self {
            cache,
            key,
            lock: Some(lock),
            staging_path,
            cleanup_on_drop: true,
            directory,
        }
    }

    /// Returns the stable key held by this writer lease
    #[must_use]
    pub const fn key(&self) -> &StageKey {
        &self.key
    }

    /// Returns the managed work directory for stage output
    #[must_use]
    pub fn directory(&self) -> &Path {
        self.directory.path()
    }

    /// Durably checkpoints the current work and keeps its files for a later lease
    ///
    /// This is the resumable path for interrupted work. Dropping a lease without calling this
    /// method removes its uncommitted work directory
    ///
    /// # Errors
    /// Returns an error when the work directory changed or the full-synchronous checkpoint write fails
    pub fn preserve(mut self, snapshot: &JobSnapshot) -> Result<()> {
        self.cache.inner.check_locations()?;
        self.directory.check_location()?;
        let snapshot_json = serde_json::to_string(snapshot)?;
        self.cleanup_on_drop = false;
        self.cache.inner.record_checkpoint(
            &self.key,
            super::model::CheckpointStatus::Active,
            &snapshot_json,
        )?;
        Ok(())
    }

    /// Atomically seals the work directory and publishes its metadata
    ///
    /// The returned entry downgrades the writer lease to a shared reader pin. A partial result
    /// remains explicitly partial and is never selected by a complete-only lookup
    ///
    /// # Errors
    /// Returns an error when the work directory contains unsafe files, has changed location,
    /// or cannot be committed to the `SQLite` index
    pub fn commit(mut self, status: StageStatus, metadata: Value) -> Result<CacheEntry> {
        self.cache.inner.check_locations()?;
        self.directory.check_location()?;
        let metadata_json = serde_json::to_string(&metadata)?;
        if metadata_json.len() > MAX_METADATA_BYTES {
            return Err(CacheError::InvalidInput(
                "entry metadata exceeds the size limit",
            ));
        }
        let manifest = Manifest::scan(self.directory.path())?;
        let manifest_json = serde_json::to_string(&manifest)?;
        let bytes = i64::try_from(manifest.total_bytes()).map_err(|_| CacheError::SizeOverflow)?;

        let staging_path = self.staging_path.clone();
        let generation = staging_path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or(CacheError::UnsafePath(
                "managed work directory name is invalid",
            ))?
            .to_owned();
        let entry_root = self
            .cache
            .inner
            .entries
            .open_child_or_create(self.key.as_str())?;
        let entry_root_path = entry_root.path().to_path_buf();
        let destination = entry_root_path.join(&generation);

        // A new generation keeps the previous indexed result available until the rename completes
        if let Err(error) = fs::rename(&staging_path, &destination) {
            return Err(error.into());
        }
        self.cleanup_on_drop = false;

        let relative_path = format!("{}/{generation}", self.key.as_str());
        let old_relative = match self.cache.inner.record_entry(
            &self.key,
            status,
            &relative_path,
            &metadata_json,
            &manifest_json,
            bytes,
        ) {
            Ok(old_relative) => old_relative,
            Err(error) => {
                let _ = fs::remove_dir_all(&destination);
                return Err(error);
            }
        };

        if let Some(old_relative) = old_relative {
            let old_path = safe_entry_path(
                self.cache.inner.entries.path(),
                self.key.as_str(),
                &old_relative,
            )?;
            if old_path != destination && old_path.exists() {
                // The active database row already points at the new generation
                // A failed best-effort removal leaves an unindexed directory for pruning
                let _ = fs::remove_dir_all(old_path);
            }
        }

        entry_root.check_location()?;
        let final_directory = entry_root.open_child(&generation)?;
        let lock = self
            .lock
            .take()
            .ok_or(CacheError::InvalidInput("lease has no OS lock"))?;
        lock.downgrade()?;

        Ok(CacheEntry::new(
            self.key.clone(),
            status,
            metadata,
            final_directory,
            lock,
        ))
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            let _ = fs::remove_dir_all(&self.staging_path);
        }
    }
}

pub(super) fn read_entry(
    cache_root: &HeldDirectory,
    entries: &HeldDirectory,
    key: &StageKey,
    record: &EntryRecord,
    lock: LockGuard,
) -> Result<CacheEntry> {
    if record.stage != key.stage() {
        return Err(CacheError::CorruptEntry(
            "entry stage label does not match its key".to_owned(),
        ));
    }
    let path = safe_entry_path(entries.path(), key.as_str(), &record.relative_path)?;
    let root = entries
        .open_child(key.as_str())
        .map_err(|_| CacheError::CorruptEntry("entry directory is missing or unsafe".to_owned()))?;
    let generation = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| CacheError::CorruptEntry("entry generation is invalid".to_owned()))?;
    let directory = root.open_child(generation).map_err(|_| {
        CacheError::CorruptEntry("entry generation is missing or unsafe".to_owned())
    })?;
    let metadata: Value = serde_json::from_str(&record.metadata_json)
        .map_err(|_| CacheError::CorruptEntry("entry metadata is not valid JSON".to_owned()))?;
    let expected: Manifest = serde_json::from_str(&record.manifest_json)
        .map_err(|_| CacheError::CorruptEntry("entry manifest is not valid JSON".to_owned()))?;
    let actual = Manifest::scan(directory.path())
        .map_err(|_| CacheError::CorruptEntry("entry files are missing or unsafe".to_owned()))?;
    let recorded_bytes = u64::try_from(record.bytes)
        .map_err(|_| CacheError::CorruptEntry("entry size is invalid".to_owned()))?;
    if actual != expected || actual.total_bytes() != recorded_bytes {
        return Err(CacheError::CorruptEntry(
            "entry files no longer match their committed manifest".to_owned(),
        ));
    }
    cache_root.check_location()?;
    directory.check_location()?;
    Ok(CacheEntry::new(
        key.clone(),
        record.status,
        metadata,
        directory,
        lock,
    ))
}
