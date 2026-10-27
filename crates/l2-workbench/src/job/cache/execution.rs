use std::{
    cell::RefCell,
    fs::{self, File, Metadata},
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
    marker::PhantomData,
    path::PathBuf,
    rc::Rc,
};

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::job::JobSnapshot;

use super::{
    Cache, Lease,
    database::{self, Durability},
    error::{CacheError, Result},
    filesystem::HeldDirectory,
    key::StageKey,
    manager::now_ns,
    manifest::safe_entry_path,
    model::{CheckpointStatus, JOB_SNAPSHOT_VERSION, supports_job_snapshot_version},
    retired,
};

const ENVELOPE_VERSION: u32 = 1;
const COMPONENT_NAMES: [&str; 3] = ["graph", "blobs", "executor"];
const MAX_RELATIVE_PATH_BYTES: i64 = 256;
const RESERVATION_BLOCK: u64 = 4096;

/// Bounds for the encoded case streams, executor stream, and complete JSON envelope
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionCheckpointLimits {
    /// Maximum combined graph and blob stream size
    pub max_encoded_bytes: u64,
    /// Maximum executor stream size
    pub max_executor_bytes: u64,
    /// Maximum serialized snapshot, metadata, and manifest envelope size
    pub max_metadata_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Component {
    bytes: u64,
    sha256: String,
}

#[derive(Serialize)]
struct EnvelopeRef<'a> {
    version: u32,
    snapshot_version: u32,
    snapshot: &'a JobSnapshot,
    metadata: &'a Value,
    components: &'a [Component; 3],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    snapshot_version: u32,
    snapshot: JobSnapshot,
    metadata: Value,
    components: [Component; 3],
}

struct Budget {
    cache: Cache,
    key: StageKey,
    token: String,
    limits: ExecutionCheckpointLimits,
    encoded_bytes: u64,
    executor_bytes: u64,
    available: u64,
    failure: Option<CacheError>,
}

impl Budget {
    fn reserve(&mut self, count: u64) -> Result<()> {
        if count <= self.available {
            return Ok(());
        }
        let needed = count - self.available;
        let block = needed.max(RESERVATION_BLOCK);
        let result = self
            .cache
            .reserve_execution_spare(&self.key, &self.token, block);
        match result {
            Ok(()) => {
                self.available = self
                    .available
                    .checked_add(block)
                    .ok_or(CacheError::SizeOverflow)?;
            }
            Err(CacheError::QuotaExceeded { .. }) => {
                self.cache
                    .reserve_execution_capacity(&self.key, &self.token, needed)?;
                self.available = self
                    .available
                    .checked_add(needed)
                    .ok_or(CacheError::SizeOverflow)?;
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }
}

struct ComponentWriter {
    file: BufWriter<File>,
    hash: Sha256,
    bytes: u64,
    executor: bool,
    budget: Rc<RefCell<Budget>>,
}

/// Three bounded streams used to save an opaque execution generation
pub struct ExecutionWriter {
    graph: ComponentWriter,
    blobs: ComponentWriter,
    executor: ComponentWriter,
}

impl std::fmt::Debug for ExecutionWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionWriter")
            .finish_non_exhaustive()
    }
}

impl ExecutionWriter {
    /// Returns graph, blob, and executor streams in that order
    pub fn streams(&mut self) -> (&mut dyn Write, &mut dyn Write, &mut dyn Write) {
        (&mut self.graph, &mut self.blobs, &mut self.executor)
    }
}

impl Write for ComponentWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let count = u64::try_from(bytes.len()).map_err(|_| io::Error::other("write too large"))?;
        {
            let mut budget = self.budget.borrow_mut();
            if budget.failure.is_some() {
                return Err(io::Error::other("checkpoint writer already failed"));
            }
            let (used, limit) = if self.executor {
                (budget.executor_bytes, budget.limits.max_executor_bytes)
            } else {
                (budget.encoded_bytes, budget.limits.max_encoded_bytes)
            };
            let Some(required) = used.checked_add(count) else {
                budget.failure = Some(CacheError::SizeOverflow);
                return Err(io::Error::other("checkpoint stream size overflow"));
            };
            if required > limit {
                budget.failure = Some(CacheError::QuotaExceeded {
                    limit_bytes: limit,
                    required_bytes: required,
                });
                return Err(io::Error::other("checkpoint stream limit exceeded"));
            }
            // Reserve before writing so simultaneous keys cannot overcommit the cache
            if let Err(error) = budget.reserve(count) {
                budget.failure = Some(error);
                return Err(io::Error::other("checkpoint cache quota unavailable"));
            }
        }
        match self.file.write(bytes) {
            Ok(written) => {
                let accepted = bytes
                    .get(..written)
                    .ok_or_else(|| io::Error::other("invalid write count"))?;
                self.hash.update(accepted);
                let written =
                    u64::try_from(written).map_err(|_| io::Error::other("write too large"))?;
                self.bytes += written;
                let mut budget = self.budget.borrow_mut();
                budget.available -= written;
                if self.executor {
                    budget.executor_bytes += written;
                } else {
                    budget.encoded_bytes += written;
                }
                usize::try_from(written).map_err(|_| io::Error::other("write too large"))
            }
            Err(error) => {
                let message = error.to_string();
                self.budget.borrow_mut().failure = Some(error.into());
                Err(io::Error::other(message))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.file.flush() {
            Ok(()) => Ok(()),
            Err(error) => {
                let message = error.to_string();
                self.budget.borrow_mut().failure = Some(error.into());
                Err(io::Error::other(message))
            }
        }
    }
}

/// A verified execution generation pinned by its exclusive lease
pub struct ActiveExecution<'lease> {
    snapshot: JobSnapshot,
    metadata: Value,
    graph: File,
    blobs: File,
    executor: File,
    _lease: PhantomData<&'lease Lease>,
}

impl std::fmt::Debug for ActiveExecution<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActiveExecution")
            .finish_non_exhaustive()
    }
}

impl ActiveExecution<'_> {
    /// Returns the job snapshot committed with these streams
    #[must_use]
    pub const fn snapshot(&self) -> &JobSnapshot {
        &self.snapshot
    }

    /// Returns the caller's metadata committed with these streams
    #[must_use]
    pub const fn metadata(&self) -> &Value {
        &self.metadata
    }

    /// Returns graph, blob, and executor readers in that order
    pub fn streams(&mut self) -> (&mut dyn Read, &mut dyn Read, &mut dyn Read) {
        (&mut self.graph, &mut self.blobs, &mut self.executor)
    }
}

struct PendingGeneration {
    cache: Cache,
    token: String,
    path: PathBuf,
    rename_attempted: bool,
}

impl Drop for PendingGeneration {
    fn drop(&mut self) {
        // A failed rename or commit can be ambiguous, so recovery inspects the pointer first
        if self.rename_attempted {
            return;
        }
        match fs::remove_dir_all(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return,
        }
        if let Ok(connection) =
            database::open_connection(&self.cache.inner.state_root, Durability::Checkpoint)
        {
            let _ = connection.execute(
                "DELETE FROM execution_reservations WHERE token = ?1",
                [&self.token],
            );
        }
    }
}

impl Lease {
    /// Saves all execution streams and the snapshot as one durable generation
    ///
    /// The caller must validate recipes and exclude secret material before invoking this method
    ///
    /// # Errors
    /// Returns an error for quota, I/O, integrity, serialization, or database failures
    pub fn save_active<F>(
        &mut self,
        snapshot: &JobSnapshot,
        limits: ExecutionCheckpointLimits,
        write: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut ExecutionWriter) -> Result<Value>,
    {
        if !snapshot.is_valid_checkpoint() {
            return Err(CacheError::CorruptCheckpoint);
        }
        self.cache.inner.check_locations()?;
        self.cache.clear_execution_debris(self.key.as_str())?;
        let staging_key = self
            .cache
            .inner
            .staging
            .open_child_or_create(self.key.as_str())?;
        let (name, directory) = staging_key.create_private_child("active-")?;
        let token = format!("{}/{name}", self.key.as_str());
        let mut pending = PendingGeneration {
            cache: self.cache.clone(),
            token: token.clone(),
            path: directory.path().to_path_buf(),
            rename_attempted: false,
        };
        self.cache
            .reserve_execution_capacity(&self.key, &token, 0)?;
        let budget = Rc::new(RefCell::new(Budget {
            cache: self.cache.clone(),
            key: self.key.clone(),
            token: token.clone(),
            limits,
            encoded_bytes: 0,
            executor_bytes: 0,
            available: 0,
            failure: None,
        }));
        let (envelope_json, snapshot_json, total) =
            write_generation(&directory, &budget, snapshot, limits, write)?;
        let entry_root = self
            .cache
            .inner
            .entries
            .open_child_or_create(self.key.as_str())?;
        self.cache.inner.entries.sync()?;
        // Once rename is attempted, leave uncertain outcomes for lock-protected recovery
        pending.rename_attempted = true;
        staging_key.rename_child_to(&name, &entry_root)?;
        staging_key.sync()?;
        entry_root.sync()?;
        let relative = format!("{}/{name}", self.key.as_str());
        let old = publish(
            self,
            &token,
            &relative,
            &envelope_json,
            &snapshot_json,
            total,
        )?;
        if let Some(old) = old {
            // The new pointer is durable before the old generation can be removed
            let _ = retired::cleanup(&self.cache.inner, self.key.as_str(), &old);
        }
        Ok(())
    }

    /// Opens only the committed generation and verifies all component hashes before returning
    ///
    /// # Errors
    /// Returns an error when limits, paths, metadata, or component integrity checks fail
    pub fn load_active(
        &self,
        limits: ExecutionCheckpointLimits,
    ) -> Result<Option<ActiveExecution<'_>>> {
        self.cache.inner.check_locations()?;
        let mut connection =
            database::open_connection(&self.cache.inner.state_root, Durability::Checkpoint)?;
        let transaction = connection.transaction()?;
        let lengths = transaction.query_row(
            "SELECT length(CAST(relative_path AS BLOB)), length(CAST(envelope_json AS BLOB)), bytes FROM executions WHERE key = ?1",
            [self.key.as_str()], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
        ).optional()?;
        let Some((path_len, envelope_len, recorded_bytes)) = lengths else {
            return Ok(None);
        };
        let envelope_size = u64::try_from(envelope_len).map_err(|_| corrupt())?;
        if !(1..=MAX_RELATIVE_PATH_BYTES).contains(&path_len)
            || envelope_size > limits.max_metadata_bytes
        {
            return Err(corrupt());
        }
        let (relative, json): (String, String) = transaction.query_row(
            "SELECT relative_path, envelope_json FROM executions WHERE key = ?1",
            [self.key.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let envelope: Envelope = serde_json::from_str(&json).map_err(|_| corrupt())?;
        if envelope.version != ENVELOPE_VERSION
            || !supports_job_snapshot_version(envelope.snapshot_version)
            || !envelope.snapshot.is_valid_checkpoint()
        {
            return Err(corrupt());
        }
        let [graph, blobs, executor] = &envelope.components;
        let encoded = graph.bytes.checked_add(blobs.bytes).ok_or_else(corrupt)?;
        let total = encoded
            .checked_add(executor.bytes)
            .and_then(|size| size.checked_add(envelope_size))
            .ok_or_else(corrupt)?;
        if encoded > limits.max_encoded_bytes
            || executor.bytes > limits.max_executor_bytes
            || u64::try_from(recorded_bytes).ok() != Some(total)
        {
            return Err(corrupt());
        }
        let path = safe_entry_path(
            self.cache.inner.entries.path(),
            self.key.as_str(),
            &relative,
        )?;
        let generation = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(corrupt)?;
        if !generation.starts_with("active-") {
            return Err(corrupt());
        }
        let root = self.cache.inner.entries.open_child(self.key.as_str())?;
        let directory = root.open_child(generation)?;
        let graph = verified_component(&directory, COMPONENT_NAMES[0], graph)?;
        let blobs = verified_component(&directory, COMPONENT_NAMES[1], blobs)?;
        let executor = verified_component(&directory, COMPONENT_NAMES[2], executor)?;
        transaction.commit()?;
        Ok(Some(ActiveExecution {
            snapshot: envelope.snapshot,
            metadata: envelope.metadata,
            graph,
            blobs,
            executor,
            _lease: PhantomData,
        }))
    }
}

fn write_generation<F>(
    directory: &HeldDirectory,
    budget: &Rc<RefCell<Budget>>,
    snapshot: &JobSnapshot,
    limits: ExecutionCheckpointLimits,
    write: F,
) -> Result<(String, String, u64)>
where
    F: FnOnce(&mut ExecutionWriter) -> Result<Value>,
{
    let component = |name: &str, executor| -> Result<ComponentWriter> {
        Ok(ComponentWriter {
            file: BufWriter::new(directory.create_new_file(name)?),
            hash: Sha256::new(),
            bytes: 0,
            executor,
            budget: Rc::clone(budget),
        })
    };
    let mut writer = ExecutionWriter {
        graph: component(COMPONENT_NAMES[0], false)?,
        blobs: component(COMPONENT_NAMES[1], false)?,
        executor: component(COMPONENT_NAMES[2], true)?,
    };
    let result = write(&mut writer);
    if let Some(error) = budget.borrow_mut().failure.take() {
        return Err(error);
    }
    let metadata = result?;
    let ExecutionWriter {
        graph,
        blobs,
        executor,
    } = writer;
    let (graph, graph_file) = finish_component(graph)?;
    let (blobs, blobs_file) = finish_component(blobs)?;
    let (executor, executor_file) = finish_component(executor)?;
    let components = [graph, blobs, executor];
    let written_files = [graph_file, blobs_file, executor_file];
    let envelope = EnvelopeRef {
        version: ENVELOPE_VERSION,
        snapshot_version: JOB_SNAPSHOT_VERSION,
        snapshot,
        metadata: &metadata,
        components: &components,
    };
    let envelope_json = encode_envelope(&envelope, limits.max_metadata_bytes)?;
    let envelope_bytes =
        u64::try_from(envelope_json.len()).map_err(|_| CacheError::SizeOverflow)?;
    {
        let mut budget = budget.borrow_mut();
        budget.reserve(envelope_bytes)?;
        budget.available -= envelope_bytes;
    }
    let snapshot_json = serde_json::to_string(snapshot)?;
    for ((name, expected), written) in COMPONENT_NAMES.iter().zip(&components).zip(&written_files) {
        // The open writer and named file must still identify the same synced object
        let held = written.file.metadata()?;
        let named = directory.open_file(name)?.metadata()?;
        if held.len() != expected.bytes
            || !same_content_identity(&written.synced_metadata, &held)
            || !same_content_identity(&held, &named)
        {
            return Err(corrupt());
        }
    }
    directory.sync()?;
    let total = components.iter().try_fold(envelope_bytes, |sum, item| {
        sum.checked_add(item.bytes).ok_or(CacheError::SizeOverflow)
    })?;
    Ok((envelope_json, snapshot_json, total))
}

struct WrittenFile {
    file: File,
    synced_metadata: Metadata,
}

fn finish_component(mut component: ComponentWriter) -> Result<(Component, WrittenFile)> {
    component.file.flush()?;
    let before = component.file.get_ref().metadata()?;
    component.file.get_ref().sync_all()?;
    let synced_metadata = component.file.get_ref().metadata()?;
    if before.len() != component.bytes || !same_content_identity(&before, &synced_metadata) {
        return Err(corrupt());
    }
    let file = component
        .file
        .into_inner()
        .map_err(io::IntoInnerError::into_error)?;
    let digest = Component {
        bytes: component.bytes,
        sha256: format!("{:x}", component.hash.finalize()),
    };
    Ok((
        digest,
        WrittenFile {
            file,
            synced_metadata,
        },
    ))
}

struct BoundedBytes {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("checkpoint metadata limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_envelope(envelope: &EnvelopeRef<'_>, limit: u64) -> Result<String> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut output = BoundedBytes {
        bytes: Vec::new(),
        limit,
        exceeded: false,
    };
    let result = serde_json::to_writer(&mut output, envelope);
    if output.exceeded {
        return Err(CacheError::MetadataTooLarge {
            limit_bytes: limit,
            actual_bytes: limit.saturating_add(1),
        });
    }
    result?;
    String::from_utf8(output.bytes)
        .map_err(|_| CacheError::InvalidInput("checkpoint JSON is not UTF-8"))
}

fn publish(
    lease: &Lease,
    token: &str,
    relative: &str,
    envelope: &str,
    snapshot: &str,
    bytes: u64,
) -> Result<Option<String>> {
    let mut connection =
        database::open_connection(&lease.cache.inner.state_root, Durability::Checkpoint)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let old = retired::record_current(
        &transaction,
        &lease.cache.inner.entries,
        retired::Current::Execution,
        lease.key.as_str(),
        relative,
    )?;
    transaction.execute(
        "INSERT INTO executions(key, relative_path, envelope_json, bytes) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(key) DO UPDATE SET relative_path = excluded.relative_path, envelope_json = excluded.envelope_json, bytes = excluded.bytes",
        params![lease.key.as_str(), relative, envelope, i64::try_from(bytes).map_err(|_| CacheError::SizeOverflow)?],
    )?;
    transaction.execute(
        "INSERT INTO checkpoints(key, status, snapshot_version, snapshot_json, updated_ns) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(key) DO UPDATE SET status = excluded.status, snapshot_version = excluded.snapshot_version, snapshot_json = excluded.snapshot_json, updated_ns = excluded.updated_ns",
        params![lease.key.as_str(), CheckpointStatus::Active.to_database(), i64::from(JOB_SNAPSHOT_VERSION), snapshot, now_ns()],
    )?;
    if transaction.execute(
        "DELETE FROM execution_reservations WHERE token = ?1 AND key = ?2",
        params![token, lease.key.as_str()],
    )? != 1
    {
        return Err(CacheError::CorruptDatabase);
    }
    transaction.commit()?;
    Ok(old)
}

fn verified_component(directory: &HeldDirectory, name: &str, expected: &Component) -> Result<File> {
    if !crate::hashing::is_sha256_digest(&expected.sha256) {
        return Err(corrupt());
    }
    let mut file = directory.open_file(name)?;
    let before = file.metadata()?;
    if before.len() != expected.bytes {
        return Err(corrupt());
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut remaining = expected.bytes;
    while remaining > 0 {
        let capacity =
            usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| corrupt())?;
        let target = buffer.get_mut(..capacity).ok_or_else(corrupt)?;
        let count = file.read(target)?;
        if count == 0 {
            return Err(corrupt());
        }
        remaining -= u64::try_from(count).map_err(|_| corrupt())?;
        hasher.update(buffer.get(..count).ok_or_else(corrupt)?);
    }
    if file.read(buffer.get_mut(..1).ok_or_else(corrupt)?)? != 0 {
        return Err(corrupt());
    }
    let after = file.metadata()?;
    let named = directory.open_file(name)?.metadata()?;
    if !same_content_identity(&before, &after)
        || !same_content_identity(&after, &named)
        || format!("{:x}", hasher.finalize()) != expected.sha256
    {
        return Err(corrupt());
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

fn same_content_identity(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.len() == right.len()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
            && left.nlink() == 1
            && right.nlink() == 1
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len() && left.modified().ok() == right.modified().ok()
    }
}

fn corrupt() -> CacheError {
    CacheError::CorruptEntry("execution checkpoint is corrupt".to_owned())
}
