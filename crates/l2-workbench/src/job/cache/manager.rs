use std::{
    collections::HashSet,
    env, fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use tempfile::Builder;

use crate::hashing::is_sha256_digest;
use crate::job::JobSnapshot;

use super::{
    database::{self, Durability},
    entry::{CacheEntry, EntryRecord, Lease, read_entry},
    error::{CacheError, Result},
    filesystem::{HeldDirectory, LockGuard},
    fingerprint::SourceFingerprint,
    key::StageKey,
    manifest::safe_entry_path,
    model::{CacheReadPolicy, CacheStats, Checkpoint, CheckpointStatus, PruneReport, StageStatus},
};

const KEY_LOCK_SUFFIX: &str = ".lock";
const QUOTA_LOCK: &str = "quota.lock";

/// A process-safe `SQLite` and filesystem cache for stable recovery stages
#[derive(Clone)]
pub struct Cache {
    pub(super) inner: Arc<CacheInner>,
}

pub(super) struct CacheInner {
    pub(super) cache_root: HeldDirectory,
    pub(super) state_root: HeldDirectory,
    pub(super) entries: HeldDirectory,
    pub(super) staging: HeldDirectory,
    locks: HeldDirectory,
    pub(super) max_bytes: u64,
}

struct EvictionSnapshot {
    total_bytes: u64,
    rows: Vec<(String, u64)>,
    active_checkpoints: HashSet<String>,
}

struct CapacityCandidate {
    key: String,
    _lock: LockGuard,
}

struct CapacityPlan {
    base_bytes: u64,
    incoming_bytes: u64,
    candidates: Vec<CapacityCandidate>,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Cache")
            .field("cache_root", &self.inner.cache_root.path())
            .field("state_root", &self.inner.state_root.path())
            .field("max_bytes", &self.inner.max_bytes)
            .finish()
    }
}

impl CacheInner {
    pub(super) fn check_locations(&self) -> Result<()> {
        self.cache_root.check_location()?;
        self.state_root.check_location()?;
        self.entries.check_location()?;
        self.staging.check_location()?;
        self.locks.check_location()?;
        Ok(())
    }

    fn lock(&self, key: &StageKey, exclusive: bool) -> Result<LockGuard> {
        key.validate()?;
        self.check_locations()?;
        // The lock file stays in place while the kernel releases ownership with the held descriptor
        self.locks
            .lock(&format!("{}{KEY_LOCK_SUFFIX}", key.as_str()), exclusive)
    }

    fn quota_lock(&self) -> Result<LockGuard> {
        self.check_locations()?;
        self.locks.lock_with_retry(QUOTA_LOCK, true)
    }

    pub(super) fn active_checkpoint(&self, key: &str) -> Result<bool> {
        let connection = database::open_connection(&self.state_root, Durability::Recomputable)?;
        connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM checkpoints WHERE key = ?1 AND status = ?2)
                    OR EXISTS(SELECT 1 FROM executions WHERE key = ?1)",
                params![key, CheckpointStatus::Active.to_database()],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    pub(super) fn record_entry(
        &self,
        key: &StageKey,
        status: StageStatus,
        relative_path: &str,
        metadata_json: &str,
        manifest_json: &str,
        bytes: i64,
    ) -> Result<Option<String>> {
        let mut connection = database::open_connection(&self.state_root, Durability::Checkpoint)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Publish the directory pointer and receipt together after the stage tree has been renamed
        let old_relative = transaction
            .query_row(
                "SELECT relative_path FROM entries WHERE key = ?1",
                [key.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(path) = &old_relative {
            safe_entry_path(self.entries.path(), key.as_str(), path)?;
        }
        let now = now_ns();
        transaction.execute(
            "INSERT INTO entries (key, stage, status, relative_path, metadata_json, manifest_json, bytes, created_ns, accessed_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
             ON CONFLICT(key) DO UPDATE SET
                 stage = excluded.stage,
                 status = excluded.status,
                 relative_path = excluded.relative_path,
                 metadata_json = excluded.metadata_json,
                 manifest_json = excluded.manifest_json,
                 bytes = excluded.bytes,
                 created_ns = excluded.created_ns,
                 accessed_ns = excluded.accessed_ns",
            params![
                key.as_str(),
                key.stage(),
                status.to_database(),
                relative_path,
                metadata_json,
                manifest_json,
                bytes,
                now,
            ],
        )?;
        if status == StageStatus::Complete {
            // Keep the terminal result and cursor retirement in the same transaction
            transaction.execute("DELETE FROM executions WHERE key = ?1", [key.as_str()])?;
            transaction.execute(
                "UPDATE checkpoints SET status = ?1 WHERE key = ?2",
                params![CheckpointStatus::Complete.to_database(), key.as_str()],
            )?;
        }
        transaction.commit()?;
        Ok(old_relative)
    }

    pub(super) fn record_checkpoint(
        &self,
        key: &StageKey,
        status: CheckpointStatus,
        snapshot_json: &str,
    ) -> Result<()> {
        let mut connection = database::open_connection(&self.state_root, Durability::Checkpoint)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO checkpoints (key, status, snapshot_version, snapshot_json, updated_ns)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(key) DO UPDATE SET
                 status = excluded.status,
                 snapshot_version = excluded.snapshot_version,
                 snapshot_json = excluded.snapshot_json,
                 updated_ns = excluded.updated_ns",
            params![
                key.as_str(),
                status.to_database(),
                i64::from(super::model::JOB_SNAPSHOT_VERSION),
                snapshot_json,
                now_ns(),
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

impl Cache {
    /// Opens a cache in explicit cache and state directories
    ///
    /// The cache directory stores stage files. The state directory stores the versioned `SQLite`
    /// index and held-file lock objects. Opening also prunes old unpinned entries; active leases
    /// can leave `stats().over_limit_bytes` positive until a later prune
    ///
    /// # Errors
    /// Returns an error when either root is unsafe, the `SQLite` schema is incompatible, or storage
    /// cannot be initialized
    pub fn open_at(
        cache_root: impl AsRef<Path>,
        state_root: impl AsRef<Path>,
        max_bytes: u64,
    ) -> Result<Self> {
        let cache_root = HeldDirectory::open_root(cache_root.as_ref())?;
        let state_root = HeldDirectory::open_root(state_root.as_ref())?;
        if cache_root.path().starts_with(state_root.path())
            || state_root.path().starts_with(cache_root.path())
        {
            return Err(CacheError::InvalidInput(
                "cache and state roots must be separate",
            ));
        }

        let entries = cache_root.open_child_or_create("entries")?;
        let staging = cache_root.open_child_or_create("staging")?;
        let locks = state_root.open_child_or_create("locks")?;
        let inner = Arc::new(CacheInner {
            cache_root,
            state_root,
            entries,
            staging,
            locks,
            max_bytes,
        });
        inner.check_locations()?;
        database::initialize(&inner.state_root, &inner.locks)?;
        let cache = Self { inner };
        match cache.prune() {
            Ok(_) | Err(CacheError::CacheBusy) => {}
            Err(error) => return Err(error),
        }
        Ok(cache)
    }

    /// Opens the default cache under the user's XDG cache and state directories
    ///
    /// `XDG_CACHE_HOME/l2solver` stores stage directories and `XDG_STATE_HOME/l2solver` stores
    /// durable progress checkpoints and `SQLite` metadata. When either XDG variable is unset, the
    /// standard `$HOME/.cache` or `$HOME/.local/state` directory is used
    ///
    /// # Errors
    /// Returns an error when the required home or XDG paths are missing, relative, or unsafe
    pub fn from_environment(max_bytes: u64) -> Result<Self> {
        let cache_base = xdg_path("XDG_CACHE_HOME", Path::new(".cache"))?;
        let state_fallback = PathBuf::from(".local").join("state");
        let state_base = xdg_path("XDG_STATE_HOME", &state_fallback)?;
        Self::open_at(
            cache_base.join("l2solver"),
            state_base.join("l2solver"),
            max_bytes,
        )
    }

    /// Returns the configured maximum size in bytes
    #[must_use]
    pub fn max_bytes(&self) -> u64 {
        self.inner.max_bytes
    }

    /// Calculates a fast metadata and sample fingerprint for a regular source file
    ///
    /// # Errors
    /// Returns an error for symlinked, unreadable, non-regular, or changing files
    pub fn fingerprint_source(path: impl AsRef<Path>) -> Result<SourceFingerprint> {
        SourceFingerprint::fast(path)
    }

    /// Looks up a validated entry while holding a shared OS file lock
    ///
    /// Complete-only lookups never expose partial results, so an incomplete search cannot be
    /// replayed as a complete negative result
    ///
    /// # Errors
    /// Returns an error when a writer holds the key, a path was replaced, or the entry is corrupt
    pub fn lookup(&self, key: &StageKey, policy: CacheReadPolicy) -> Result<Option<CacheEntry>> {
        key.validate()?;
        self.inner.check_locations()?;
        let lock = self.inner.lock(key, false)?;
        // Keep the directory pinned while its metadata and relative files are checked
        let connection =
            database::open_connection(&self.inner.state_root, Durability::Recomputable)?;
        let row = connection
            .query_row(
                "SELECT stage, status, relative_path, metadata_json, manifest_json, bytes
                 FROM entries WHERE key = ?1",
                [key.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((stage, status_value, relative_path, metadata_json, manifest_json, bytes)) = row
        else {
            return Ok(None);
        };
        let status = StageStatus::from_database(status_value)
            .ok_or_else(|| CacheError::CorruptEntry("entry status is invalid".to_owned()))?;
        if status == StageStatus::Partial && policy == CacheReadPolicy::CompleteOnly {
            return Ok(None);
        }

        let entry = read_entry(
            &self.inner.cache_root,
            &self.inner.entries,
            key,
            &EntryRecord {
                stage,
                status,
                relative_path,
                metadata_json,
                manifest_json,
                bytes,
            },
            lock,
        )?;
        connection.execute(
            "UPDATE entries SET accessed_ns = MAX(?1, accessed_ns + 1) WHERE key = ?2",
            params![now_ns(), key.as_str()],
        )?;
        Ok(Some(entry))
    }

    /// Reserves an exclusive work directory for one stage key
    ///
    /// The returned lease keeps a file descriptor lock open for its full lifetime. A competing
    /// writer or reader gets [`CacheError::LockBusy`] instead of observing changing files
    ///
    /// # Errors
    /// Returns an error when another operation holds the key or the managed directory is unsafe
    pub fn lease(&self, key: &StageKey) -> Result<Lease> {
        key.validate()?;
        self.inner.check_locations()?;
        let lock = self.inner.lock(key, true)?;
        {
            let _quota_lock = self.inner.quota_lock()?;
            self.clear_stale_execution(key.as_str())?;
        }
        let staging_key = self.inner.staging.open_child_or_create(key.as_str())?;
        let active_checkpoint = self.inner.active_checkpoint(key.as_str())?;
        // A checkpointed work directory remains available to the next lease
        let existing = find_staging_directory(&staging_key)?;
        let (staging_path, name) = if active_checkpoint {
            match existing {
                Some(existing) => existing,
                None => create_staging_directory(&staging_key)?,
            }
        } else {
            clean_staging_directory(&staging_key)?;
            create_staging_directory(&staging_key)?
        };
        let directory = match staging_key.open_child(&name) {
            Ok(directory) => directory,
            Err(error) => {
                let _ = fs::remove_dir_all(&staging_path);
                return Err(error);
            }
        };
        Ok(Lease::new(
            self.clone(),
            key.clone(),
            lock,
            staging_path,
            directory,
        ))
    }

    /// Saves the canonical job snapshot with full `SQLite` synchronization
    ///
    /// Active checkpoints protect their associated stage entry from LRU pruning and clearing
    ///
    /// # Errors
    /// Returns an error when the key is locked by a writer or the durable database write fails
    pub fn write_checkpoint(
        &self,
        key: &StageKey,
        snapshot: &JobSnapshot,
        status: CheckpointStatus,
    ) -> Result<()> {
        key.validate()?;
        self.inner.check_locations()?;
        // Shared ownership prevents pruning until the full-synchronous checkpoint commits
        let _pin = self.inner.lock(key, false)?;
        let snapshot_json = serde_json::to_string(snapshot)?;
        self.inner.record_checkpoint(key, status, &snapshot_json)
    }

    /// Reads a durable snapshot together with its stable key and saved status
    ///
    /// # Errors
    /// Returns an error when the row is corrupt or cannot be decoded as a job snapshot
    pub fn read_checkpoint(&self, key: &StageKey) -> Result<Option<Checkpoint>> {
        key.validate()?;
        self.inner.check_locations()?;
        let connection = database::open_connection(&self.inner.state_root, Durability::Checkpoint)?;
        let row = connection
            .query_row(
                "SELECT status, snapshot_version, snapshot_json FROM checkpoints WHERE key = ?1",
                [key.as_str()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(status, snapshot_version, snapshot_json)| {
            let snapshot_version =
                u32::try_from(snapshot_version).map_err(|_| CacheError::CorruptCheckpoint)?;
            if !super::model::supports_job_snapshot_version(snapshot_version) {
                return Err(CacheError::CorruptCheckpoint);
            }
            let status =
                CheckpointStatus::from_database(status).ok_or(CacheError::CorruptCheckpoint)?;
            let snapshot: JobSnapshot =
                serde_json::from_str(&snapshot_json).map_err(|_| CacheError::CorruptCheckpoint)?;
            if !snapshot.is_valid_checkpoint() {
                return Err(CacheError::CorruptCheckpoint);
            }
            Ok(Checkpoint {
                key: key.clone(),
                status,
                snapshot_version,
                snapshot,
            })
        })
        .transpose()
    }

    /// Reports indexed entry usage, checkpoints, and bytes retained above the configured limit
    ///
    /// # Errors
    /// Returns an error when `SQLite` cannot read the cache index
    pub fn stats(&self) -> Result<CacheStats> {
        self.inner.check_locations()?;
        let connection =
            database::open_connection(&self.inner.state_root, Durability::Recomputable)?;
        let (entries, bytes, checkpoints): (i64, i64, i64) = connection.query_row(
            "SELECT
                 (SELECT count(*) FROM entries),
                 (SELECT COALESCE(sum(bytes), 0) FROM (
                    SELECT bytes FROM entries UNION ALL SELECT bytes FROM executions
                    UNION ALL SELECT bytes FROM execution_reservations)),
                 (SELECT count(*) FROM checkpoints)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let entry_bytes = nonnegative(bytes)?;
        Ok(CacheStats {
            entries: nonnegative(entries)?,
            entry_bytes,
            over_limit_bytes: entry_bytes.saturating_sub(self.inner.max_bytes),
            checkpoints: nonnegative(checkpoints)?,
        })
    }

    /// Removes least-recently-used unpinned entries until the configured size is met
    ///
    /// Active OS leases and active durable checkpoints keep their entries in place. A remaining
    /// overage is available through [`CacheStats::over_limit_bytes`]
    ///
    /// # Errors
    /// Returns an error when the index or entry directories cannot be updated safely
    pub fn prune(&self) -> Result<PruneReport> {
        self.evict(Some(self.inner.max_bytes))
    }

    /// Removes all entries that are not held by a lease or active checkpoint
    ///
    /// Completed checkpoints are removed. Active checkpoints and their pinned entries remain
    ///
    /// # Errors
    /// Returns an error when the index or entry directories cannot be updated safely
    pub fn clear(&self) -> Result<PruneReport> {
        let mut report = self.evict(None)?;
        let mut connection =
            database::open_connection(&self.inner.state_root, Durability::Checkpoint)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM checkpoints WHERE status = ?1",
            [CheckpointStatus::Complete.to_database()],
        )?;
        transaction.commit()?;
        report.remaining_bytes = self.stats()?.entry_bytes;
        Ok(report)
    }

    /// Runs a passive WAL checkpoint without blocking readers
    ///
    /// `SQLite` will leave frames that another connection is reading in the write-ahead log
    ///
    /// # Errors
    /// Returns an error when `SQLite` cannot checkpoint the cache database
    pub fn checkpoint_wal(&self) -> Result<()> {
        self.inner.check_locations()?;
        database::checkpoint_wal(&self.inner.state_root)
    }

    pub(super) fn reserve_capacity(
        &self,
        key: &StageKey,
        incoming_bytes: u64,
    ) -> Result<LockGuard> {
        let quota_lock = self.inner.quota_lock()?;
        self.inner.check_locations()?;
        if incoming_bytes > self.inner.max_bytes {
            return Err(CacheError::QuotaExceeded {
                limit_bytes: self.inner.max_bytes,
                required_bytes: incoming_bytes,
            });
        }

        let plan = self.capacity_plan(key, incoming_bytes, true)?;
        self.remove_capacity_candidates(&plan)?;
        drop(plan);
        Ok(quota_lock)
    }

    pub(super) fn reserve_execution_capacity(
        &self,
        key: &StageKey,
        token: &str,
        incoming_bytes: u64,
    ) -> Result<()> {
        self.reserve_execution(key, token, incoming_bytes, true)
    }

    pub(super) fn reserve_execution_spare(
        &self,
        key: &StageKey,
        token: &str,
        incoming_bytes: u64,
    ) -> Result<()> {
        self.reserve_execution(key, token, incoming_bytes, false)
    }

    fn reserve_execution(
        &self,
        key: &StageKey,
        token: &str,
        incoming_bytes: u64,
        evict: bool,
    ) -> Result<()> {
        let _quota_lock = self.inner.quota_lock()?;
        self.inner.check_locations()?;
        // Speculative reservation credit never causes an unrelated result to be evicted
        if evict {
            let plan = self.capacity_plan(key, incoming_bytes, false)?;
            self.remove_capacity_candidates(&plan)?;
        } else {
            let required_bytes = self
                .eviction_snapshot()?
                .total_bytes
                .checked_add(incoming_bytes)
                .ok_or(CacheError::SizeOverflow)?;
            if required_bytes > self.inner.max_bytes {
                return Err(CacheError::QuotaExceeded {
                    limit_bytes: self.inner.max_bytes,
                    required_bytes,
                });
            }
        }
        let connection = database::open_connection(&self.inner.state_root, Durability::Checkpoint)?;
        let changed = connection.execute(
            "INSERT INTO execution_reservations (token, key, bytes) VALUES (?1, ?2, ?3)
             ON CONFLICT(token) DO UPDATE SET bytes = execution_reservations.bytes + excluded.bytes
             WHERE execution_reservations.key = excluded.key
                 AND execution_reservations.bytes <= 9223372036854775807 - excluded.bytes",
            params![
                token,
                key.as_str(),
                i64::try_from(incoming_bytes).map_err(|_| CacheError::SizeOverflow)?
            ],
        )?;
        if changed != 1 {
            return Err(CacheError::SizeOverflow);
        }
        Ok(())
    }

    fn capacity_plan(
        &self,
        key: &StageKey,
        incoming_bytes: u64,
        replace_entry: bool,
    ) -> Result<CapacityPlan> {
        let snapshot = self.eviction_snapshot()?;
        let replaced_bytes = snapshot
            .rows
            .iter()
            .find(|(candidate, _)| replace_entry && candidate == key.as_str())
            .map_or(0, |(_, bytes)| *bytes);
        let base_bytes = snapshot
            .total_bytes
            .checked_sub(replaced_bytes)
            .ok_or(CacheError::CorruptDatabase)?;
        let mut required_bytes = base_bytes
            .checked_add(incoming_bytes)
            .ok_or(CacheError::SizeOverflow)?;
        let mut candidates = Vec::new();
        if required_bytes > self.inner.max_bytes {
            for (candidate_key, _) in snapshot.rows {
                if candidate_key == key.as_str()
                    || snapshot.active_checkpoints.contains(&candidate_key)
                {
                    continue;
                }
                let lock = match self
                    .inner
                    .locks
                    .lock(&format!("{candidate_key}{KEY_LOCK_SUFFIX}"), true)
                {
                    Ok(lock) => lock,
                    Err(CacheError::LockBusy) => continue,
                    Err(error) => return Err(error),
                };
                if self.inner.active_checkpoint(&candidate_key)? {
                    drop(lock);
                    continue;
                }
                let Some(bytes) = self.current_entry_bytes(&candidate_key)? else {
                    drop(lock);
                    continue;
                };
                required_bytes = required_bytes
                    .checked_sub(bytes)
                    .ok_or(CacheError::CorruptDatabase)?;
                candidates.push(CapacityCandidate {
                    key: candidate_key,
                    _lock: lock,
                });
                if required_bytes <= self.inner.max_bytes {
                    break;
                }
            }
        }

        if required_bytes > self.inner.max_bytes {
            return Err(CacheError::QuotaExceeded {
                limit_bytes: self.inner.max_bytes,
                required_bytes,
            });
        }
        Ok(CapacityPlan {
            base_bytes,
            incoming_bytes,
            candidates,
        })
    }

    fn remove_capacity_candidates(&self, plan: &CapacityPlan) -> Result<()> {
        if plan.candidates.is_empty() {
            return Ok(());
        }
        let mut connection =
            database::open_connection(&self.inner.state_root, Durability::Recomputable)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut remaining_bytes = plan
            .base_bytes
            .checked_add(plan.incoming_bytes)
            .ok_or(CacheError::SizeOverflow)?;
        let mut removed = Vec::new();
        for candidate in &plan.candidates {
            if remaining_bytes <= self.inner.max_bytes {
                break;
            }
            let active: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM checkpoints WHERE key = ?1 AND status = ?2)
                    OR EXISTS(SELECT 1 FROM executions WHERE key = ?1)",
                params![candidate.key, CheckpointStatus::Active.to_database()],
                |row| row.get(0),
            )?;
            if active {
                continue;
            }
            let current = transaction
                .query_row(
                    "SELECT relative_path, bytes FROM entries WHERE key = ?1",
                    [&candidate.key],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()?;
            let Some((relative_path, bytes)) = current else {
                continue;
            };
            let bytes = nonnegative(bytes)?;
            safe_entry_path(self.inner.entries.path(), &candidate.key, &relative_path)?;
            if transaction.execute("DELETE FROM entries WHERE key = ?1", [&candidate.key])? == 1 {
                remaining_bytes = remaining_bytes
                    .checked_sub(bytes)
                    .ok_or(CacheError::CorruptDatabase)?;
                removed.push((candidate.key.clone(), relative_path));
            }
        }
        if remaining_bytes > self.inner.max_bytes {
            return Err(CacheError::QuotaExceeded {
                limit_bytes: self.inner.max_bytes,
                required_bytes: remaining_bytes,
            });
        }
        transaction.commit()?;
        for (candidate_key, relative_path) in removed {
            remove_generation(&self.inner.entries, &candidate_key, &relative_path)?;
        }
        Ok(())
    }

    fn current_entry_bytes(&self, key: &str) -> Result<Option<u64>> {
        let connection =
            database::open_connection(&self.inner.state_root, Durability::Recomputable)?;
        connection
            .query_row("SELECT bytes FROM entries WHERE key = ?1", [key], |row| {
                row.get::<_, i64>(0)
            })
            .optional()?
            .map(nonnegative)
            .transpose()
    }

    fn evict(&self, limit: Option<u64>) -> Result<PruneReport> {
        let _quota_lock = self.inner.quota_lock()?;
        self.inner.check_locations()?;
        self.cleanup_stale_reservations()?;
        let snapshot = self.eviction_snapshot()?;
        self.cleanup_stale_staging(&snapshot.active_checkpoints)?;
        self.cleanup_orphan_generations()?;
        let mut remaining = snapshot.total_bytes;
        let mut report = PruneReport::default();

        for (key, snapshot_bytes) in snapshot.rows {
            if limit.is_some_and(|limit| remaining <= limit) {
                break;
            }
            if snapshot.active_checkpoints.contains(&key) {
                report.skipped_checkpoints = report.skipped_checkpoints.saturating_add(1);
                continue;
            }
            self.evict_entry(&key, snapshot_bytes, &mut remaining, &mut report)?;
        }

        report.remaining_bytes = self.stats()?.entry_bytes;
        Ok(report)
    }

    fn evict_entry(
        &self,
        key: &str,
        snapshot_bytes: u64,
        remaining: &mut u64,
        report: &mut PruneReport,
    ) -> Result<()> {
        let lock = match self
            .inner
            .locks
            .lock(&format!("{key}{KEY_LOCK_SUFFIX}"), true)
        {
            Ok(lock) => lock,
            Err(CacheError::LockBusy) => {
                report.skipped_locked = report.skipped_locked.saturating_add(1);
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let mut connection =
            database::open_connection(&self.inner.state_root, Durability::Recomputable)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Recheck the durable pin in the same transaction that removes the entry row
        let active: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM checkpoints WHERE key = ?1 AND status = ?2)
                    OR EXISTS(SELECT 1 FROM executions WHERE key = ?1)",
            params![key, CheckpointStatus::Active.to_database()],
            |row| row.get(0),
        )?;
        if active {
            report.skipped_checkpoints = report.skipped_checkpoints.saturating_add(1);
            let current_bytes = transaction
                .query_row("SELECT bytes FROM entries WHERE key = ?1", [key], |row| {
                    row.get::<_, i64>(0)
                })
                .optional()?;
            *remaining = match current_bytes {
                Some(bytes) => remaining
                    .saturating_sub(snapshot_bytes)
                    .checked_add(nonnegative(bytes)?)
                    .ok_or(CacheError::SizeOverflow)?,
                None => remaining.saturating_sub(snapshot_bytes),
            };
            return Ok(());
        }

        let current = transaction
            .query_row(
                "SELECT relative_path, bytes FROM entries WHERE key = ?1",
                [key],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        let Some((relative_path, bytes)) = current else {
            *remaining = remaining.saturating_sub(snapshot_bytes);
            return Ok(());
        };
        let bytes = nonnegative(bytes)?;
        *remaining = remaining
            .saturating_sub(snapshot_bytes)
            .checked_add(bytes)
            .ok_or(CacheError::SizeOverflow)?;
        safe_entry_path(self.inner.entries.path(), key, &relative_path)?;
        transaction.execute("DELETE FROM entries WHERE key = ?1", [key])?;
        transaction.commit()?;

        remove_generation(&self.inner.entries, key, &relative_path)?;
        *remaining = remaining.saturating_sub(bytes);
        report.removed_entries = report.removed_entries.saturating_add(1);
        report.removed_bytes = report.removed_bytes.saturating_add(bytes);
        drop(lock);
        Ok(())
    }

    fn cleanup_stale_reservations(&self) -> Result<()> {
        let connection = database::open_connection(&self.inner.state_root, Durability::Checkpoint)?;
        let mut statement =
            connection.prepare("SELECT DISTINCT key FROM execution_reservations")?;
        let keys = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for key in keys {
            if !is_sha256_digest(&key) {
                return Err(CacheError::CorruptDatabase);
            }
            let lock = match self
                .inner
                .locks
                .lock(&format!("{key}{KEY_LOCK_SUFFIX}"), true)
            {
                Ok(lock) => lock,
                Err(CacheError::LockBusy) => continue,
                Err(error) => return Err(error),
            };
            self.clear_stale_execution(&key)?;
            drop(lock);
        }
        Ok(())
    }

    pub(super) fn clear_execution_debris(&self, key: &str) -> Result<()> {
        let _quota_lock = self.inner.quota_lock()?;
        self.clear_stale_execution(key)
    }

    fn clear_stale_execution(&self, key: &str) -> Result<()> {
        match self.inner.staging.open_child(key) {
            Ok(directory) => {
                let mut changed = false;
                for item in fs::read_dir(directory.path())? {
                    let item = item?;
                    let name = item.file_name();
                    let name = name
                        .to_str()
                        .ok_or(CacheError::UnsafePath("staging name is invalid"))?;
                    if !name.starts_with("active-") {
                        continue;
                    }
                    let metadata = fs::symlink_metadata(item.path())?;
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        return Err(CacheError::UnsafePath(
                            "checkpoint staging directory is unsafe",
                        ));
                    }
                    fs::remove_dir_all(item.path())?;
                    changed = true;
                }
                if changed {
                    directory.sync()?;
                }
            }
            Err(CacheError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let connection = database::open_connection(&self.inner.state_root, Durability::Checkpoint)?;
        let mut statement = connection.prepare(
            "SELECT relative_path FROM entries WHERE key = ?1 UNION ALL
             SELECT relative_path FROM executions WHERE key = ?1",
        )?;
        let current = statement
            .query_map([key], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        for relative in &current {
            safe_entry_path(self.inner.entries.path(), key, relative)?;
        }
        match self.inner.entries.open_child(key) {
            Ok(directory) => {
                let mut changed = false;
                for item in fs::read_dir(directory.path())? {
                    let item = item?;
                    let name = item.file_name();
                    let name = name
                        .to_str()
                        .ok_or(CacheError::UnsafePath("generation name is invalid"))?;
                    if !name.starts_with("active-") || current.contains(&format!("{key}/{name}")) {
                        continue;
                    }
                    let metadata = fs::symlink_metadata(item.path())?;
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        return Err(CacheError::UnsafePath("checkpoint generation is unsafe"));
                    }
                    fs::remove_dir_all(item.path())?;
                    changed = true;
                }
                if changed {
                    directory.sync()?;
                }
            }
            Err(CacheError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        connection.execute("DELETE FROM execution_reservations WHERE key = ?1", [key])?;
        Ok(())
    }

    fn cleanup_stale_staging(&self, active_checkpoints: &HashSet<String>) -> Result<()> {
        for entry in fs::read_dir(self.inner.staging.path())? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CacheError::UnsafePath(
                    "staging root contains an unsafe item",
                ));
            }
            let key = entry
                .file_name()
                .into_string()
                .map_err(|_| CacheError::UnsafePath("staging key is not valid UTF-8"))?;
            if !is_sha256_digest(&key) {
                continue;
            }
            let lock = match self
                .inner
                .locks
                .lock(&format!("{key}{KEY_LOCK_SUFFIX}"), true)
            {
                Ok(lock) => lock,
                Err(CacheError::LockBusy) => continue,
                Err(error) => return Err(error),
            };
            self.clear_stale_execution(&key)?;
            let staging_key = self.inner.staging.open_child(&key)?;
            // Check again after the exclusive lock closes the checkpoint-write race
            if active_checkpoints.contains(&key) || self.inner.active_checkpoint(&key)? {
                drop(lock);
                continue;
            }
            clean_staging_directory(&staging_key)?;
            let _ = fs::remove_dir(staging_key.path());
            drop(lock);
        }
        Ok(())
    }

    fn cleanup_orphan_generations(&self) -> Result<()> {
        for entry in fs::read_dir(self.inner.entries.path())? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CacheError::UnsafePath("entry root contains an unsafe item"));
            }
            let key = entry
                .file_name()
                .into_string()
                .map_err(|_| CacheError::UnsafePath("entry key is not valid UTF-8"))?;
            if !is_sha256_digest(&key) {
                return Err(CacheError::UnsafePath("entry key is invalid"));
            }
            let lock = match self
                .inner
                .locks
                .lock(&format!("{key}{KEY_LOCK_SUFFIX}"), true)
            {
                Ok(lock) => lock,
                Err(CacheError::LockBusy) => continue,
                Err(error) => return Err(error),
            };
            let connection =
                database::open_connection(&self.inner.state_root, Durability::Recomputable)?;
            let mut statement = connection.prepare(
                "SELECT relative_path FROM entries WHERE key = ?1 UNION ALL
                 SELECT relative_path FROM executions WHERE key = ?1",
            )?;
            let current = statement
                .query_map([&key], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<HashSet<_>>>()?;
            for relative in &current {
                safe_entry_path(self.inner.entries.path(), &key, relative)?;
            }
            let key_directory = self.inner.entries.open_child(&key)?;
            for generation in fs::read_dir(key_directory.path())? {
                let generation = generation?;
                let path = generation.path();
                let metadata = fs::symlink_metadata(&path)?;
                let name = generation
                    .file_name()
                    .into_string()
                    .map_err(|_| CacheError::UnsafePath("entry generation is not valid UTF-8"))?;
                if current.contains(&format!("{key}/{name}")) {
                    continue;
                }
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    fs::remove_file(path)?;
                } else {
                    fs::remove_dir_all(path)?;
                }
            }
            let _ = fs::remove_dir(key_directory.path());
            drop(lock);
        }
        Ok(())
    }

    fn eviction_snapshot(&self) -> Result<EvictionSnapshot> {
        let connection =
            database::open_connection(&self.inner.state_root, Durability::Recomputable)?;
        let mut statement = connection
            .prepare("SELECT key, bytes FROM entries ORDER BY accessed_ns, created_ns, key")?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut total_bytes = 0_u64;
        let mut keys = Vec::with_capacity(rows.len());
        for (key, bytes) in rows {
            let bytes = nonnegative(bytes)?;
            total_bytes = total_bytes
                .checked_add(bytes)
                .ok_or(CacheError::SizeOverflow)?;
            keys.push((key, bytes));
        }
        let mut statement = connection.prepare(
            "SELECT bytes FROM executions UNION ALL SELECT bytes FROM execution_reservations",
        )?;
        let protected_bytes = statement.query_map([], |row| row.get::<_, i64>(0))?;
        for bytes in protected_bytes {
            total_bytes = total_bytes
                .checked_add(nonnegative(bytes?)?)
                .ok_or(CacheError::SizeOverflow)?;
        }
        let mut statement = connection.prepare(
            "SELECT key FROM checkpoints WHERE status = ?1 UNION SELECT key FROM executions",
        )?;
        let active_checkpoints = statement
            .query_map([CheckpointStatus::Active.to_database()], |row| row.get(0))?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        Ok(EvictionSnapshot {
            total_bytes,
            rows: keys,
            active_checkpoints,
        })
    }
}

fn xdg_path(name: &str, fallback: &Path) -> Result<PathBuf> {
    let path = if let Some(path) = env::var_os(name) {
        PathBuf::from(path)
    } else {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or(CacheError::InvalidInput("HOME is not set"))?;
        home.join(fallback)
    };
    if !path.is_absolute() {
        return Err(CacheError::InvalidInput(
            "XDG cache and state paths must be absolute",
        ));
    }
    Ok(path)
}

fn clean_staging_directory(directory: &HeldDirectory) -> Result<()> {
    directory.check_location()?;
    for entry in fs::read_dir(directory.path())? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CacheError::UnsafePath(
                "managed staging directory contains an unsafe item",
            ));
        }
        fs::remove_dir_all(entry.path())?;
    }
    Ok(())
}

fn find_staging_directory(directory: &HeldDirectory) -> Result<Option<(PathBuf, String)>> {
    directory.check_location()?;
    let mut found = None;
    for entry in fs::read_dir(directory.path())? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CacheError::UnsafePath(
                "managed staging directory contains an unsafe item",
            ));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CacheError::UnsafePath("managed work directory name is invalid"))?;
        if !name.starts_with("lease-") || found.is_some() {
            return Err(CacheError::CorruptEntry(
                "multiple or unrecognized resumable work directories exist".to_owned(),
            ));
        }
        found = Some((entry.path(), name));
    }
    Ok(found)
}

fn create_staging_directory(directory: &HeldDirectory) -> Result<(PathBuf, String)> {
    let staging = Builder::new()
        .prefix("lease-")
        .tempdir_in(directory.path())?;
    let name = staging
        .path()
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(CacheError::UnsafePath(
            "managed work directory name is invalid",
        ))?
        .to_owned();
    let path = staging.keep();
    Ok((path, name))
}

pub(super) fn remove_generation(
    entries: &HeldDirectory,
    key: &str,
    relative_path: &str,
) -> Result<()> {
    let path = safe_entry_path(entries.path(), key, relative_path)?;
    let entry_root = match entries.open_child(key) {
        Ok(root) => root,
        Err(CacheError::Io(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    entry_root.check_location()?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => fs::remove_file(&path)?,
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(&path)?,
        Ok(_) => fs::remove_file(&path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    let _ = fs::remove_dir(entry_root.path());
    Ok(())
}

fn nonnegative(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| CacheError::CorruptDatabase)
}

pub(super) fn now_ns() -> i64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    i64::try_from(elapsed).unwrap_or(i64::MAX)
}
