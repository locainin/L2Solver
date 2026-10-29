use std::{
    fs, io,
    path::{Path, PathBuf},
};

use crate::job::{JobSnapshot, MemoryBudget, MemoryLease};
use serde_json::Value;

use super::{
    Cache,
    error::{CacheError, Result},
    filesystem::{HeldDirectory, LockGuard},
    key::StageKey,
    manifest::{Manifest, safe_entry_path},
    memory,
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
    _memory: Option<MemoryLease>,
}

struct ChargedMetadata {
    value: Value,
    // Drop the metadata before releasing its accounting on every error path
    memory: Option<MemoryLease>,
}

impl ChargedMetadata {
    const fn new(value: Value, memory: Option<MemoryLease>) -> Self {
        Self { value, memory }
    }
}

/// An exclusive work area for one stable stage key
pub struct Lease {
    pub(super) cache: Cache,
    pub(super) key: StageKey,
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
        memory: Option<MemoryLease>,
    ) -> Self {
        Self {
            key,
            status,
            metadata,
            directory,
            _lock: lock,
            _memory: memory,
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
    ///
    /// The entry keeps its budget charge for this value; copies made by the caller need their own
    /// accounting
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
        let (snapshot_json, memory) = self.cache.inner.encode_checkpoint(snapshot)?;
        self.cleanup_on_drop = false;
        let result = self.cache.inner.record_checkpoint(
            &self.key,
            super::model::CheckpointStatus::Active,
            &snapshot_json,
        );
        drop(snapshot_json);
        drop(memory);
        result
    }

    /// Atomically seals the work directory and publishes its metadata
    ///
    /// Space is reserved first by pruning older unpinned entries. The returned entry downgrades
    /// the writer lease to a shared reader pin. A partial result remains explicitly partial and
    /// is never selected by a complete-only lookup
    ///
    /// # Errors
    /// Returns an error when the work directory contains unsafe files, has changed location,
    /// exceeds the configured cache quota, or cannot be committed to the `SQLite` index
    pub fn commit(self, status: StageStatus, metadata: Value) -> Result<CacheEntry> {
        self.commit_inner(status, metadata, None)
    }

    /// Commit metadata while transferring its existing shared-memory charge to the entry
    ///
    /// The charge must use the cache allocation class and the cache's shared budget when one is
    /// attached. Callers must reserve it before constructing the owned metadata value
    ///
    /// # Errors
    /// Returns an error for an incompatible reservation or any failure also reported by `commit`
    pub fn commit_with_reserved_metadata(
        self,
        status: StageStatus,
        metadata: Value,
        reservation: MemoryLease,
    ) -> Result<CacheEntry> {
        self.commit_inner(status, metadata, Some(reservation))
    }

    fn commit_inner(
        mut self,
        status: StageStatus,
        metadata: Value,
        reservation: Option<MemoryLease>,
    ) -> Result<CacheEntry> {
        let mut metadata = ChargedMetadata::new(metadata, reservation);
        self.cache.inner.check_locations()?;
        self.directory.check_location()?;
        let transient_memory = memory::reserve_metadata(
            self.cache.inner.memory_budget(),
            &metadata.value,
            MAX_METADATA_BYTES,
            &mut metadata.memory,
        )?;
        let metadata_json = serde_json::to_string(&metadata.value)?;
        if metadata_json.len() > MAX_METADATA_BYTES {
            return Err(CacheError::MetadataTooLarge {
                limit_bytes: MAX_METADATA_BYTES,
                actual_bytes: metadata_json.len(),
            });
        }
        // Manifest and quota scratch belong to the same worker as the metadata it commits
        let budget = metadata.memory.as_ref().map(MemoryLease::budget);
        let (prepared, bytes, _quota_lock) =
            prepare_commit(&self.cache, self.directory.path(), &self.key, budget)?;
        self.cache.inner.check_locations()?;
        self.directory.check_location()?;

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
        let staging_key = self.cache.inner.staging.open_child(self.key.as_str())?;
        let relative_path = format!("{}/{generation}", self.key.as_str());
        self.cache
            .inner
            .reserve_stage(&self.key, &relative_path, bytes)?;
        // Make every output file and directory durable before publishing the new pointer
        self.directory.sync_tree()?;
        prepared
            .manifest
            .validate(self.directory.path())
            .map_err(|_| CacheError::CorruptEntry("stage changed while syncing".to_owned()))?;
        self.cache.inner.entries.sync()?;
        staging_key.rename_child_to(&generation, &entry_root)?;
        self.cleanup_on_drop = false;
        // An uncertain rename or commit remains reserved for exclusive-key recovery
        staging_key.sync()?;
        entry_root.sync()?;

        self.cache.inner.record_entry(
            &self.key,
            status,
            &relative_path,
            &metadata_json,
            &prepared.json,
            bytes,
        )?;

        entry_root.check_location()?;
        let final_directory = entry_root.open_child(&generation)?;
        let lock = self
            .lock
            .take()
            .ok_or(CacheError::InvalidInput("lease has no OS lock"))?;
        lock.downgrade()?;

        drop(metadata_json);
        drop(prepared);
        drop(transient_memory);
        let (metadata, metadata_memory) = (metadata.value, metadata.memory);
        Ok(CacheEntry::new(
            self.key.clone(),
            status,
            metadata,
            final_directory,
            lock,
            metadata_memory,
        ))
    }
}

struct PreparedManifest {
    manifest: Manifest,
    json: String,
    _manifest_memory: Option<MemoryLease>,
    _json_memory: Option<MemoryLease>,
}

fn prepare_commit(
    cache: &Cache,
    directory: &Path,
    key: &StageKey,
    budget: Option<&MemoryBudget>,
) -> Result<(PreparedManifest, i64, LockGuard)> {
    let prepared = prepare_manifest(directory, budget)?;
    let entry_bytes = prepared.manifest.total_bytes();
    let bytes = i64::try_from(entry_bytes).map_err(|_| CacheError::SizeOverflow)?;
    let lock = if let Some(budget) = budget {
        cache.reserve_capacity_with_memory(key, entry_bytes, budget)?
    } else {
        cache.reserve_capacity(key, entry_bytes)?
    };
    Ok((prepared, bytes, lock))
}

fn prepare_manifest(directory: &Path, budget: Option<&MemoryBudget>) -> Result<PreparedManifest> {
    let (manifest, manifest_memory) = Manifest::scan(directory, budget)?;
    let json_memory = if budget.is_some() {
        memory::reserve(
            budget,
            memory::serialized_charge(memory::json_size(&manifest)?)?,
        )?
    } else {
        None
    };
    let json = serde_json::to_string(&manifest)?;
    Ok(PreparedManifest {
        manifest,
        json,
        _manifest_memory: manifest_memory,
        _json_memory: json_memory,
    })
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
    memory: Option<MemoryLease>,
) -> Result<CacheEntry> {
    if record.stage != key.stage() {
        return Err(CacheError::CorruptEntry(
            "entry stage label does not match its key".to_owned(),
        ));
    }
    let path = safe_entry_path(entries.path(), key.as_str(), &record.relative_path)?;
    let root = entries
        .open_child(key.as_str())
        .map_err(|error| missing_entry(error, "entry directory is missing"))?;
    let generation = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| CacheError::CorruptEntry("entry generation is invalid".to_owned()))?;
    let directory = root
        .open_child(generation)
        .map_err(|error| missing_entry(error, "entry generation is missing"))?;
    let metadata: Value = serde_json::from_str(&record.metadata_json)
        .map_err(|_| CacheError::CorruptEntry("entry metadata is not valid JSON".to_owned()))?;
    let expected: Manifest = serde_json::from_str(&record.manifest_json)
        .map_err(|_| CacheError::CorruptEntry("entry manifest is not valid JSON".to_owned()))?;
    expected.validate(directory.path()).map_err(|error| {
        // Keep resource and I/O failures distinct from an invalid cached tree
        match error {
            CacheError::UnsafePath(_) | CacheError::InvalidInput(_) => {
                CacheError::CorruptEntry("entry files are unsafe or invalid".to_owned())
            }
            other => missing_entry(other, "entry files are missing"),
        }
    })?;
    let recorded_bytes = u64::try_from(record.bytes)
        .map_err(|_| CacheError::CorruptEntry("entry size is invalid".to_owned()))?;
    if expected.total_bytes() != recorded_bytes {
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
        memory,
    ))
}

fn missing_entry(error: CacheError, detail: &'static str) -> CacheError {
    if matches!(&error, CacheError::Io(source) if source.kind() == io::ErrorKind::NotFound) {
        CacheError::CorruptEntry(detail.to_owned())
    } else {
        error
    }
}
