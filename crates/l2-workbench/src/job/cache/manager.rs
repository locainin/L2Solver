use std::{
    env, fs, io,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use tempfile::Builder;

use crate::hashing::is_sha256_digest;
use crate::job::{JobSnapshot, MemoryBudget, MemoryLease};

use super::{
    database::{self, Durability},
    entry::{CacheEntry, EntryRecord, Lease, read_entry},
    error::{CacheError, Result},
    filesystem::{HeldDirectory, LockGuard},
    fingerprint::SourceFingerprint,
    key::StageKey,
    manifest::{MAX_RELATIVE_PATH_BYTES, safe_entry_path},
    memory,
    model::{CacheReadPolicy, CacheStats, Checkpoint, CheckpointStatus, PruneReport, StageStatus},
    retired,
};

const KEY_LOCK_SUFFIX: &str = ".lock";
const QUOTA_LOCK: &str = "quota.lock";
// One row, directory entry, and their bounded path buffers are live at a time
const MAINTENANCE_BYTES: u64 = 64 * 1024;

/// A process-safe `SQLite` and filesystem cache for stable recovery stages
#[derive(Clone)]
pub struct Cache {
    pub(super) inner: Arc<CacheInner>,
    pub(super) memory_scope: Option<MemoryBudget>,
}

pub(super) struct CacheInner {
    pub(super) cache_root: HeldDirectory,
    pub(super) state_root: HeldDirectory,
    pub(super) entries: HeldDirectory,
    pub(super) staging: HeldDirectory,
    locks: HeldDirectory,
    pub(super) max_bytes: u64,
    memory_budget: OnceLock<Option<MemoryBudget>>,
}

struct LruRow {
    accessed_ns: i64,
    created_ns: i64,
    key: String,
    bytes: u64,
}

struct CapacityPlan {
    base_bytes: u64,
    incoming_bytes: u64,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Cache")
            .field("cache_root", &self.inner.cache_root.path())
            .field("state_root", &self.inner.state_root.path())
            .field("max_bytes", &self.inner.max_bytes)
            .finish_non_exhaustive()
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
        // New key pins pass a shared gate so quota maintenance can plan without retaining locks
        let gate = self.locks.lock_with_retry(QUOTA_LOCK, false)?;
        let result = self
            .locks
            .lock(&format!("{}{KEY_LOCK_SUFFIX}", key.as_str()), exclusive);
        drop(gate);
        result
    }

    pub(super) fn quota_lock(&self) -> Result<LockGuard> {
        self.check_locations()?;
        self.locks.lock_with_retry(QUOTA_LOCK, true)
    }

    pub(super) fn active_checkpoint(&self, key: &str) -> Result<bool> {
        let connection = database::open_connection(&self.state_root, Durability::Recomputable)?;
        active_checkpoint_in(&connection, key)
    }

    // The quota lock is held while this reservation is created
    pub(super) fn reserve_stage(&self, key: &StageKey, token: &str, bytes: i64) -> Result<()> {
        let connection = database::open_connection(&self.state_root, Durability::Checkpoint)?;
        connection.execute(
            "INSERT INTO execution_reservations(token, key, bytes) VALUES (?1, ?2, ?3)",
            params![token, key.as_str(), bytes],
        )?;
        Ok(())
    }

    pub(super) fn record_entry(
        &self,
        key: &StageKey,
        status: StageStatus,
        relative_path: &str,
        metadata_json: &str,
        manifest_json: &str,
        bytes: i64,
    ) -> Result<()> {
        let mut connection = database::open_connection(&self.state_root, Durability::Checkpoint)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Keep old bytes counted in the transaction that switches the live pointer
        let old_stage = retired::record_current(
            &transaction,
            &self.entries,
            retired::Current::Stage,
            key.as_str(),
            relative_path,
        )?;
        let old_execution = if status == StageStatus::Complete {
            retired::record_current(
                &transaction,
                &self.entries,
                retired::Current::Execution,
                key.as_str(),
                relative_path,
            )?
        } else {
            None
        };
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
        if transaction.execute(
            "DELETE FROM execution_reservations WHERE token = ?1 AND key = ?2",
            params![relative_path, key.as_str()],
        )? != 1
        {
            return Err(CacheError::CorruptDatabase);
        }
        if status == StageStatus::Complete {
            // Keep the terminal result and cursor retirement in the same transaction
            transaction.execute("DELETE FROM executions WHERE key = ?1", [key.as_str()])?;
            transaction.execute(
                "UPDATE checkpoints SET status = ?1 WHERE key = ?2",
                params![CheckpointStatus::Complete.to_database(), key.as_str()],
            )?;
        }
        transaction.commit()?;
        for old in [old_stage, old_execution].into_iter().flatten() {
            // Cleanup failure cannot undo a committed result or release its old quota
            let _ = retired::cleanup(self, key.as_str(), &old);
        }
        Ok(())
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
    pub(super) fn configured_memory_budget(&self) -> Option<&MemoryBudget> {
        self.memory_scope
            .as_ref()
            .or_else(|| self.inner.memory_budget.get().and_then(Option::as_ref))
    }

    pub(super) fn memory_budget(&self) -> Option<&MemoryBudget> {
        // Data access fixes the shared choice, while startup maintenance leaves it attachable
        let _ = self.inner.memory_budget.get_or_init(|| None);
        self.configured_memory_budget()
    }

    fn maintenance_charge(&self) -> Result<Option<MemoryLease>> {
        memory::reserve(self.configured_memory_budget(), MAINTENANCE_BYTES)
    }

    pub(super) fn encode_checkpoint(
        &self,
        snapshot: &JobSnapshot,
    ) -> Result<(String, Option<MemoryLease>)> {
        let budget = self.memory_budget();
        let charge = if budget.is_some() {
            memory::reserve(
                budget,
                memory::checkpoint_charge(memory::json_size(snapshot)?)?,
            )?
        } else {
            None
        };
        Ok((serde_json::to_string(snapshot)?, charge))
    }

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
        Self::open_at_inner(cache_root.as_ref(), state_root.as_ref(), max_bytes, None)
    }

    /// Opens a cache with its shared memory budget installed before startup maintenance
    ///
    /// # Errors
    /// Returns an error if the budget cannot admit maintenance or the cache cannot be opened
    pub fn open_at_with_memory_budget(
        cache_root: impl AsRef<Path>,
        state_root: impl AsRef<Path>,
        max_bytes: u64,
        budget: MemoryBudget,
    ) -> Result<Self> {
        Self::open_at_inner(
            cache_root.as_ref(),
            state_root.as_ref(),
            max_bytes,
            Some(budget),
        )
    }

    fn open_at_inner(
        cache_root: &Path,
        state_root: &Path,
        max_bytes: u64,
        budget: Option<MemoryBudget>,
    ) -> Result<Self> {
        let cache_root = HeldDirectory::open_root(cache_root)?;
        let state_root = HeldDirectory::open_root(state_root)?;
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
        let memory_budget =
            budget.map_or_else(OnceLock::new, |budget| OnceLock::from(Some(budget)));
        let inner = Arc::new(CacheInner {
            cache_root,
            state_root,
            entries,
            staging,
            locks,
            max_bytes,
            memory_budget,
        });
        inner.check_locations()?;
        database::initialize(&inner.state_root, &inner.locks)?;
        let cache = Self {
            inner,
            memory_scope: None,
        };
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
        Self::from_environment_inner(max_bytes, None)
    }

    /// Opens the default cache with a budget installed before startup maintenance
    ///
    /// # Errors
    /// Returns an error if the budget cannot admit maintenance or the cache cannot be opened
    pub fn from_environment_with_memory_budget(
        max_bytes: u64,
        budget: MemoryBudget,
    ) -> Result<Self> {
        Self::from_environment_inner(max_bytes, Some(budget))
    }

    fn from_environment_inner(max_bytes: u64, budget: Option<MemoryBudget>) -> Result<Self> {
        let cache_base = xdg_path("XDG_CACHE_HOME", Path::new(".cache"))?;
        let state_fallback = PathBuf::from(".local").join("state");
        let state_base = xdg_path("XDG_STATE_HOME", &state_fallback)?;
        Self::open_at_inner(
            &cache_base.join("l2solver"),
            &state_base.join("l2solver"),
            max_bytes,
            budget,
        )
    }

    /// Attaches the shared live-memory budget before the first cache data operation
    ///
    /// Cache clones share this one-time choice. Lookup and commit keep the metadata charge while
    /// the returned entry lives; checkpoint snapshot charges cover decoding only
    ///
    /// Lookup reserves 128 logical bytes per encoded metadata byte plus 256 bytes for the retained
    /// value. Its temporary allowance reserves 128 per encoded manifest byte, twice the encoded
    /// row string sizes, and 64 KiB for traversal. These are logical estimates rather than exact
    /// allocator or process RSS limits. `SQLite` connection and page-cache allocations are not
    /// included, and callers must account for metadata or checkpoint snapshots they clone
    ///
    /// # Errors
    /// Returns an error if a budget was already attached or cache data was already accessed
    pub fn attach_memory_budget(&self, budget: MemoryBudget) -> Result<()> {
        self.inner
            .memory_budget
            .set(Some(budget))
            .map_err(|_| CacheError::InvalidInput("cache memory budget is already fixed"))
    }

    /// Returns a handle that charges this worker's budget for cache operations
    ///
    /// The new handle shares cache data and locks, while other handles keep their own budgets
    /// The supplied budget must belong to the cache's already attached aggregate ledger
    /// Dropping a worker guard releases its unused credit; live entries retain their charges
    ///
    /// # Errors
    /// Returns an error when the cache has no attached budget or uses a different ledger
    pub fn with_memory_scope(&self, budget: &MemoryBudget) -> Result<Self> {
        let attached = self
            .inner
            .memory_budget
            .get()
            .and_then(Option::as_ref)
            .ok_or(CacheError::InvalidInput(
                "cache memory budget is not attached",
            ))?;
        if !attached.same_ledger(budget) {
            return Err(CacheError::InvalidInput(
                "cache memory scope belongs to another budget",
            ));
        }
        Ok(Self {
            inner: Arc::clone(&self.inner),
            memory_scope: Some(budget.clone()),
        })
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
    /// A concurrent `SQLite` writer may prevent this hit from refreshing its LRU position
    ///
    /// # Errors
    /// Returns an error when a writer holds the key, a path was replaced, or the entry is corrupt
    pub fn lookup(&self, key: &StageKey, policy: CacheReadPolicy) -> Result<Option<CacheEntry>> {
        key.validate()?;
        self.inner.check_locations()?;
        let lock = self.inner.lock(key, false)?;
        // The database snapshot and OS lock keep lengths and their row contents consistent
        let budget = self.memory_budget();
        let mut connection =
            database::open_connection(&self.inner.state_root, Durability::Recomputable)?;
        let transaction = connection.transaction()?;
        let header = transaction
            .query_row(
                "SELECT rowid, status FROM entries WHERE key = ?1",
                [key.as_str()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        let Some((rowid, status_value)) = header else {
            return Ok(None);
        };
        let status = StageStatus::from_database(status_value)
            .ok_or_else(|| CacheError::CorruptEntry("entry status is invalid".to_owned()))?;
        if status == StageStatus::Partial && policy == CacheReadPolicy::CompleteOnly {
            return Ok(None);
        }
        // Reserve before fetching any column into a Rust String or decoding either JSON value
        let (retained, transient) = if budget.is_some() {
            let lengths = entry_lengths(&transaction, rowid)?;
            (
                memory::reserve(budget, memory::metadata_charge(lengths.metadata)?)?,
                memory::reserve(
                    budget,
                    memory::lookup_transient_charge(
                        lengths.metadata,
                        lengths.manifest,
                        lengths.stage,
                        lengths.path,
                    )?,
                )?,
            )
        } else {
            (None, None)
        };
        let record = transaction.query_row(
            "SELECT stage, relative_path, metadata_json, manifest_json, bytes FROM entries WHERE rowid = ?1",
            [rowid], |row| Ok(EntryRecord {
                stage: row.get(0)?, status, relative_path: row.get(1)?,
                metadata_json: row.get(2)?, manifest_json: row.get(3)?, bytes: row.get(4)?,
            }),
        )?;
        let entry = read_entry(
            &self.inner.cache_root,
            &self.inner.entries,
            key,
            &record,
            lock,
            retained,
        )?;
        drop(record);
        drop(transient);
        transaction.commit()?;
        // This connection is dropped after the optional recency write
        connection.busy_timeout(Duration::ZERO)?;
        match connection.execute(
            "UPDATE entries SET accessed_ns = MAX(?1, accessed_ns + 1) WHERE key = ?2",
            params![now_ns(), key.as_str()],
        ) {
            Ok(_) => {}
            // A busy writer cannot invalidate the already checked and pinned entry
            Err(rusqlite::Error::SqliteFailure(code, _))
                if matches!(
                    code.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) => {}
            Err(error) => return Err(error.into()),
        }
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
            let _memory = self.maintenance_charge()?;
            self.clear_stale_execution(key.as_str())?;
            retired::cleanup_key(&self.inner, key.as_str())?;
        }
        let _memory = self.maintenance_charge()?;
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
        let (snapshot_json, charge) = self.encode_checkpoint(snapshot)?;
        let result = self.inner.record_checkpoint(key, status, &snapshot_json);
        drop(snapshot_json);
        drop(charge);
        result
    }

    /// Reads a durable snapshot together with its stable key and saved status
    ///
    /// The cache charges serialized input and decoding while reading. The returned snapshot and
    /// any later clones belong to the caller and are outside this temporary cache charge
    ///
    /// # Errors
    /// Returns an error when the row is corrupt or cannot be decoded as a job snapshot
    pub fn read_checkpoint(&self, key: &StageKey) -> Result<Option<Checkpoint>> {
        key.validate()?;
        self.inner.check_locations()?;
        let budget = self.memory_budget();
        let mut connection =
            database::open_connection(&self.inner.state_root, Durability::Checkpoint)?;
        let transaction = connection.transaction()?;
        let header = transaction
            .query_row(
                "SELECT rowid, status, snapshot_version FROM checkpoints WHERE key = ?1",
                [key.as_str()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((rowid, status, version)) = header else {
            return Ok(None);
        };
        let snapshot_version = u32::try_from(version).map_err(|_| CacheError::CorruptCheckpoint)?;
        if !super::model::supports_job_snapshot_version(snapshot_version) {
            return Err(CacheError::CorruptCheckpoint);
        }
        let status =
            CheckpointStatus::from_database(status).ok_or(CacheError::CorruptCheckpoint)?;
        let charge = if budget.is_some() {
            let size = column_length(&transaction, "checkpoints", "snapshot_json", rowid)?;
            memory::reserve(budget, memory::checkpoint_charge(size)?)?
        } else {
            None
        };
        let snapshot_json: String = transaction.query_row(
            "SELECT snapshot_json FROM checkpoints WHERE rowid = ?1",
            [rowid],
            |row| row.get(0),
        )?;
        transaction.commit()?;
        let snapshot: JobSnapshot =
            serde_json::from_str(&snapshot_json).map_err(|_| CacheError::CorruptCheckpoint)?;
        if !snapshot.is_valid_checkpoint() {
            return Err(CacheError::CorruptCheckpoint);
        }
        drop(snapshot_json);
        // The returned snapshot and its clones are owned and accounted for by the caller
        drop(charge);
        Ok(Some(Checkpoint {
            key: key.clone(),
            status,
            snapshot_version,
            snapshot,
        }))
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
                    UNION ALL SELECT bytes FROM execution_reservations
                    UNION ALL SELECT bytes FROM retired_generations)),
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
        budget: Option<&MemoryBudget>,
    ) -> Result<LockGuard> {
        let quota_lock = self.inner.quota_lock()?;
        let _memory = memory::reserve(budget, MAINTENANCE_BYTES)?;
        self.inner.check_locations()?;
        if incoming_bytes > self.inner.max_bytes {
            return Err(CacheError::QuotaExceeded {
                limit_bytes: self.inner.max_bytes,
                required_bytes: incoming_bytes,
            });
        }

        let plan = self.capacity_plan(key, incoming_bytes)?;
        self.remove_capacity_candidates(key, &plan)?;
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
        let _memory = self.maintenance_charge()?;
        self.inner.check_locations()?;
        // Speculative reservation credit never causes an unrelated result to be evicted
        if evict {
            let plan = self.capacity_plan(key, incoming_bytes)?;
            self.remove_capacity_candidates(key, &plan)?;
        } else {
            let required_bytes = self
                .stats()?
                .entry_bytes
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

    fn capacity_plan(&self, key: &StageKey, incoming_bytes: u64) -> Result<CapacityPlan> {
        let base_bytes = self.stats()?.entry_bytes;
        let mut required_bytes = base_bytes
            .checked_add(incoming_bytes)
            .ok_or(CacheError::SizeOverflow)?;
        if required_bytes > self.inner.max_bytes {
            let connection =
                database::open_connection(&self.inner.state_root, Durability::Recomputable)?;
            let mut cursor = None;
            while let Some(row) = next_lru_row(&connection, cursor.as_ref())? {
                if row.key != key.as_str() {
                    let lock = match self
                        .inner
                        .locks
                        .lock(&format!("{}{KEY_LOCK_SUFFIX}", row.key), true)
                    {
                        Ok(lock) => Some(lock),
                        Err(CacheError::LockBusy) => None,
                        Err(error) => return Err(error),
                    };
                    if let Some(lock) = lock {
                        if !active_checkpoint_in(&connection, &row.key)? {
                            required_bytes = required_bytes
                                .checked_sub(row.bytes)
                                .ok_or(CacheError::CorruptDatabase)?;
                        }
                        drop(lock);
                    }
                }
                cursor = Some(row);
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
        })
    }

    fn remove_capacity_candidates(&self, key: &StageKey, plan: &CapacityPlan) -> Result<()> {
        let mut remaining = plan
            .base_bytes
            .checked_add(plan.incoming_bytes)
            .ok_or(CacheError::SizeOverflow)?;
        if remaining <= self.inner.max_bytes {
            return Ok(());
        }
        let mut connection =
            database::open_connection(&self.inner.state_root, Durability::Recomputable)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut cursor = None;
        while remaining > self.inner.max_bytes {
            let Some(row) = next_lru_row(&transaction, cursor.as_ref())? else {
                return Err(CacheError::QuotaExceeded {
                    limit_bytes: self.inner.max_bytes,
                    required_bytes: remaining,
                });
            };
            if row.key != key.as_str() {
                let lock = match self
                    .inner
                    .locks
                    .lock(&format!("{}{KEY_LOCK_SUFFIX}", row.key), true)
                {
                    Ok(lock) => Some(lock),
                    Err(CacheError::LockBusy) => None,
                    Err(error) => return Err(error),
                };
                if let Some(lock) = lock {
                    if !active_checkpoint_in(&transaction, &row.key)? {
                        let (path, stored_bytes) = current_entry_record(&transaction, &row.key)?
                            .ok_or(CacheError::CorruptDatabase)?;
                        let bytes = nonnegative(stored_bytes)?;
                        retired::record(
                            &transaction,
                            &self.inner.entries,
                            &row.key,
                            &path,
                            stored_bytes,
                        )?;
                        if transaction.execute("DELETE FROM entries WHERE key = ?1", [&row.key])?
                            == 1
                        {
                            remaining = remaining
                                .checked_sub(bytes)
                                .ok_or(CacheError::CorruptDatabase)?;
                        }
                    }
                    drop(lock);
                }
            }
            cursor = Some(row);
        }
        // New key pins are barred by the quota gate until this atomic row change commits
        transaction.commit()?;
        self.cleanup_retired_generations()?;
        let required = self
            .stats()?
            .entry_bytes
            .checked_add(plan.incoming_bytes)
            .ok_or(CacheError::SizeOverflow)?;
        if required > self.inner.max_bytes {
            return Err(CacheError::QuotaExceeded {
                limit_bytes: self.inner.max_bytes,
                required_bytes: required,
            });
        }
        Ok(())
    }

    fn evict(&self, limit: Option<u64>) -> Result<PruneReport> {
        let _quota_lock = self.inner.quota_lock()?;
        let _memory = self.maintenance_charge()?;
        self.inner.check_locations()?;
        self.cleanup_stale_reservations()?;
        self.cleanup_retired_generations()?;
        self.cleanup_stale_staging()?;
        self.cleanup_orphan_generations()?;
        let mut remaining = self.stats()?.entry_bytes;
        let mut report = PruneReport::default();
        let connection =
            database::open_connection(&self.inner.state_root, Durability::Recomputable)?;
        let mut cursor = None;
        while limit.is_none_or(|limit| remaining > limit) {
            let Some(row) = next_lru_row(&connection, cursor.as_ref())? else {
                break;
            };
            if active_checkpoint_in(&connection, &row.key)? {
                report.skipped_checkpoints = report.skipped_checkpoints.saturating_add(1);
            } else {
                self.evict_entry(&row.key, row.bytes, &mut remaining, &mut report)?;
            }
            cursor = Some(row);
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

        let current = current_entry_record(&transaction, key)?;
        let Some((relative_path, stored_bytes)) = current else {
            *remaining = remaining.saturating_sub(snapshot_bytes);
            return Ok(());
        };
        let bytes = nonnegative(stored_bytes)?;
        *remaining = remaining
            .saturating_sub(snapshot_bytes)
            .checked_add(bytes)
            .ok_or(CacheError::SizeOverflow)?;
        retired::record(
            &transaction,
            &self.inner.entries,
            key,
            &relative_path,
            stored_bytes,
        )?;
        transaction.execute("DELETE FROM entries WHERE key = ?1", [key])?;
        transaction.commit()?;

        retired::cleanup(&self.inner, key, &relative_path)?;
        *remaining = remaining.saturating_sub(bytes);
        report.removed_entries = report.removed_entries.saturating_add(1);
        report.removed_bytes = report.removed_bytes.saturating_add(bytes);
        drop(lock);
        Ok(())
    }

    fn cleanup_retired_generations(&self) -> Result<()> {
        let connection = database::open_connection(&self.inner.state_root, Durability::Checkpoint)?;
        let mut cursor = None;
        while let Some(key) =
            next_maintenance_key(&connection, MaintenanceKeys::Retired, cursor.as_deref())?
        {
            let lock = match self
                .inner
                .locks
                .lock(&format!("{key}{KEY_LOCK_SUFFIX}"), true)
            {
                Ok(lock) => Some(lock),
                Err(CacheError::LockBusy) => None,
                Err(error) => return Err(error),
            };
            if let Some(lock) = lock {
                retired::cleanup_key(&self.inner, &key)?;
                drop(lock);
            }
            cursor = Some(key);
        }
        Ok(())
    }

    fn cleanup_stale_reservations(&self) -> Result<()> {
        let connection = database::open_connection(&self.inner.state_root, Durability::Checkpoint)?;
        let mut cursor = None;
        while let Some(key) = next_maintenance_key(
            &connection,
            MaintenanceKeys::Reservations,
            cursor.as_deref(),
        )? {
            let lock = match self
                .inner
                .locks
                .lock(&format!("{key}{KEY_LOCK_SUFFIX}"), true)
            {
                Ok(lock) => Some(lock),
                Err(CacheError::LockBusy) => None,
                Err(error) => return Err(error),
            };
            if let Some(lock) = lock {
                self.clear_stale_execution(&key)?;
                drop(lock);
            }
            cursor = Some(key);
        }
        Ok(())
    }

    pub(super) fn clear_execution_debris(&self, key: &str) -> Result<()> {
        let _quota_lock = self.inner.quota_lock()?;
        let _memory = self.maintenance_charge()?;
        self.clear_stale_execution(key)?;
        retired::cleanup_key(&self.inner, key)
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
        validate_references(&connection, &self.inner.entries, key)?;
        match self.inner.entries.open_child(key) {
            Ok(directory) => {
                let mut changed = false;
                for item in fs::read_dir(directory.path())? {
                    let item = item?;
                    let name = item.file_name();
                    let name = name
                        .to_str()
                        .ok_or(CacheError::UnsafePath("generation name is invalid"))?;
                    if !(name.starts_with("active-") || name.starts_with("lease-"))
                        || is_referenced(&connection, key, &format!("{key}/{name}"))?
                    {
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
        super::execution::cleanup_cursor_debris(self, key)?;
        // Cursor files in a retired generation remain charged until that generation is removed
        connection.execute(
            "DELETE FROM execution_reservations WHERE key = ?1 AND NOT EXISTS (
                 SELECT 1 FROM retired_generations
                 WHERE retired_generations.key = execution_reservations.key
                   AND (execution_reservations.token = retired_generations.relative_path
                        OR substr(execution_reservations.token, 1, length(retired_generations.relative_path) + 1)
                            = retired_generations.relative_path || '/')
             )",
            [key],
        )?;
        Ok(())
    }

    fn cleanup_stale_staging(&self) -> Result<()> {
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
            if self.inner.active_checkpoint(&key)? {
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
            validate_references(&connection, &self.inner.entries, &key)?;
            let key_directory = self.inner.entries.open_child(&key)?;
            for generation in fs::read_dir(key_directory.path())? {
                let generation = generation?;
                let path = generation.path();
                let metadata = fs::symlink_metadata(&path)?;
                let name = generation
                    .file_name()
                    .into_string()
                    .map_err(|_| CacheError::UnsafePath("entry generation is not valid UTF-8"))?;
                if is_referenced(&connection, &key, &format!("{key}/{name}"))? {
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
}

#[derive(Clone, Copy)]
enum MaintenanceKeys {
    Reservations,
    Retired,
}

fn next_maintenance_key(
    connection: &Connection,
    source: MaintenanceKeys,
    cursor: Option<&str>,
) -> Result<Option<String>> {
    let query = match (source, cursor.is_some()) {
        (MaintenanceKeys::Reservations, false) => {
            "SELECT key FROM execution_reservations ORDER BY key LIMIT 1"
        }
        (MaintenanceKeys::Reservations, true) => {
            "SELECT key FROM execution_reservations WHERE key > ?1 ORDER BY key LIMIT 1"
        }
        (MaintenanceKeys::Retired, false) => {
            "SELECT key FROM retired_generations ORDER BY key LIMIT 1"
        }
        (MaintenanceKeys::Retired, true) => {
            "SELECT key FROM retired_generations WHERE key > ?1 ORDER BY key LIMIT 1"
        }
    };
    let mut statement = connection.prepare_cached(query)?;
    let mut rows = if let Some(cursor) = cursor {
        statement.query([cursor])?
    } else {
        statement.query([])?
    };
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let key = row
        .get_ref(0)?
        .as_str()
        .map_err(|_| CacheError::CorruptDatabase)?;
    if !is_sha256_digest(key) {
        return Err(CacheError::CorruptDatabase);
    }
    Ok(Some(key.to_owned()))
}

fn validate_references(connection: &Connection, entries: &HeldDirectory, key: &str) -> Result<()> {
    let mut statement = connection.prepare_cached(
        "SELECT relative_path FROM entries WHERE key = ?1 UNION ALL
         SELECT relative_path FROM executions WHERE key = ?1 UNION ALL
         SELECT relative_path FROM retired_generations WHERE key = ?1",
    )?;
    let mut rows = statement.query([key])?;
    while let Some(row) = rows.next()? {
        let relative = row
            .get_ref(0)?
            .as_str()
            .map_err(|_| CacheError::CorruptDatabase)?;
        if relative.len() > MAX_RELATIVE_PATH_BYTES {
            return Err(CacheError::CorruptEntry(
                "entry path is too long".to_owned(),
            ));
        }
        safe_entry_path(entries.path(), key, relative)?;
    }
    Ok(())
}

fn is_referenced(connection: &Connection, key: &str, relative: &str) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM entries WHERE key = ?1 AND relative_path = ?2)
            OR EXISTS(SELECT 1 FROM executions WHERE key = ?1 AND relative_path = ?2)
            OR EXISTS(SELECT 1 FROM retired_generations WHERE key = ?1 AND relative_path = ?2)",
            params![key, relative],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn current_entry_record(connection: &Connection, key: &str) -> Result<Option<(String, i64)>> {
    let mut statement =
        connection.prepare_cached("SELECT relative_path, bytes FROM entries WHERE key = ?1")?;
    let mut rows = statement.query([key])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let path = row
        .get_ref(0)?
        .as_str()
        .map_err(|_| CacheError::CorruptDatabase)?;
    if path.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(CacheError::CorruptEntry(
            "entry path is too long".to_owned(),
        ));
    }
    Ok(Some((path.to_owned(), row.get(1)?)))
}

fn active_checkpoint_in(connection: &Connection, key: &str) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM checkpoints WHERE key = ?1 AND status = ?2)
            OR EXISTS(SELECT 1 FROM executions WHERE key = ?1)",
            params![key, CheckpointStatus::Active.to_database()],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn next_lru_row(connection: &Connection, cursor: Option<&LruRow>) -> Result<Option<LruRow>> {
    let query = if cursor.is_some() {
        "SELECT accessed_ns, created_ns, key, bytes FROM entries
         WHERE (accessed_ns, created_ns, key) > (?1, ?2, ?3)
         ORDER BY accessed_ns, created_ns, key LIMIT 1"
    } else {
        "SELECT accessed_ns, created_ns, key, bytes FROM entries
         ORDER BY accessed_ns, created_ns, key LIMIT 1"
    };
    let mut statement = connection.prepare_cached(query)?;
    let mut rows = if let Some(cursor) = cursor {
        statement.query(params![cursor.accessed_ns, cursor.created_ns, cursor.key])?
    } else {
        statement.query([])?
    };
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let key = row
        .get_ref(2)?
        .as_str()
        .map_err(|_| CacheError::CorruptDatabase)?;
    if !is_sha256_digest(key) {
        return Err(CacheError::CorruptDatabase);
    }
    Ok(Some(LruRow {
        accessed_ns: row.get(0)?,
        created_ns: row.get(1)?,
        key: key.to_owned(),
        bytes: nonnegative(row.get(3)?)?,
    }))
}

struct EntryLengths {
    stage: u64,
    path: u64,
    metadata: u64,
    manifest: u64,
}

fn entry_lengths(connection: &Connection, rowid: i64) -> Result<EntryLengths> {
    Ok(EntryLengths {
        stage: column_length(connection, "entries", "stage", rowid)?,
        path: column_length(connection, "entries", "relative_path", rowid)?,
        metadata: column_length(connection, "entries", "metadata_json", rowid)?,
        manifest: column_length(connection, "entries", "manifest_json", rowid)?,
    })
}

pub(super) fn column_length(
    connection: &Connection,
    table: &str,
    column: &str,
    rowid: i64,
) -> Result<u64> {
    // Incremental blob handles expose encoded length without materializing the column
    let blob = connection.blob_open("main", table, column, rowid, true)?;
    u64::try_from(blob.len()).map_err(|_| CacheError::SizeOverflow)
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
