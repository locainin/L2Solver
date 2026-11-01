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

use crate::job::{JobSnapshot, MemoryBudget, MemoryLease};

use super::{
    Cache, Lease,
    database::{self, Durability},
    error::{CacheError, Result},
    filesystem::HeldDirectory,
    key::StageKey,
    manager::{column_length, now_ns},
    manifest::safe_entry_path,
    memory,
    model::{CheckpointStatus, JOB_SNAPSHOT_VERSION, supports_job_snapshot_version},
    retired,
};

mod cleanup;
mod metadata;
mod update;
pub use metadata::ExecutionGeneration;

const ENVELOPE_VERSION: u32 = 3;
const COMPONENT_NAMES: [&str; 3] = ["graph", "blobs", "executor"];
const MAX_RELATIVE_PATH_BYTES: i64 = 256;
const RESERVATION_BLOCK: u64 = 4096;
const STREAM_BUFFER_BYTES: usize = 8 * 1024;
const WRITER_MEMORY_BYTES: u64 = 3 * 8 * 1024 + 4096;
const HASH_BUFFER_BYTES: usize = 16 * 1024;
const HASH_MEMORY_BYTES: u64 = 16 * 1024 + 4096;

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Component {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    directory: Option<String>,
    bytes: u64,
    sha256: String,
}

#[derive(Serialize)]
struct EnvelopeRef<'a, T: ?Sized> {
    version: u32,
    revision: u64,
    snapshot_version: u32,
    snapshot: &'a JobSnapshot,
    metadata: &'a T,
    components: &'a [Component; 3],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    #[serde(default)]
    revision: Option<u64>,
    snapshot_version: u32,
    snapshot: JobSnapshot,
    metadata: Value,
    components: [Component; 3],
}

const fn envelope_revision(version: u32, revision: Option<u64>) -> Option<u64> {
    match (version, revision) {
        (1, None) => Some(0),
        (2 | ENVELOPE_VERSION, Some(revision)) => Some(revision),
        _ => None,
    }
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
///
/// When a memory budget is attached, the decoded snapshot and metadata remain charged until drop
pub struct ActiveExecution<'lease> {
    generation: ExecutionGeneration,
    snapshot: JobSnapshot,
    metadata: Value,
    graph: File,
    blobs: File,
    executor: File,
    executor_bytes: u64,
    _lease: PhantomData<&'lease Lease>,
    _memory: Option<MemoryLease>,
}

impl std::fmt::Debug for ActiveExecution<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActiveExecution")
            .finish_non_exhaustive()
    }
}

impl ActiveExecution<'_> {
    /// Returns the identity of this verified checkpoint revision and its immutable streams
    #[must_use]
    pub const fn generation(&self) -> &ExecutionGeneration {
        &self.generation
    }

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

    /// Returns the executor stream size verified for this generation
    #[must_use]
    pub const fn executor_bytes(&self) -> u64 {
        self.executor_bytes
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
    /// The caller also accounts for metadata while constructing it inside the callback
    ///
    /// # Errors
    /// Returns an error for memory admission, quota, I/O, integrity, serialization, or database failures
    pub fn save_active<F>(
        &mut self,
        snapshot: &JobSnapshot,
        limits: ExecutionCheckpointLimits,
        write: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut ExecutionWriter) -> Result<Value>,
    {
        self.save_active_generation(snapshot, limits, write)
            .map(|_| ())
    }

    /// Save a generation and return its identity without rereading the Case streams
    ///
    /// The identity can be used to update metadata while the same lease remains held.
    /// The same recipe, memory, and metadata requirements as [`Self::save_active`] apply.
    /// The metadata serializer is called twice and must produce a stable representation
    ///
    /// # Errors
    /// Returns an error for memory, quota, I/O, integrity, serialization, or database failures
    pub fn save_active_generation<F, T>(
        &mut self,
        snapshot: &JobSnapshot,
        limits: ExecutionCheckpointLimits,
        write: F,
    ) -> Result<ExecutionGeneration>
    where
        F: FnOnce(&mut ExecutionWriter) -> Result<T>,
        T: Serialize,
    {
        if !snapshot.is_valid_checkpoint() {
            return Err(CacheError::CorruptCheckpoint);
        }
        self.cache.inner.check_locations()?;
        let memory_budget = self.cache.memory_budget();
        // These buffers are owned by the cache, independently of the caller's codecs
        let _writer_memory = memory::reserve(memory_budget, WRITER_MEMORY_BYTES)?;
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
        let prepared =
            write_generation(&directory, &budget, snapshot, limits, memory_budget, write)?;
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
            &prepared.envelope_json,
            &prepared.snapshot_json,
            prepared.bytes,
        )?;
        if let Some(old) = old {
            // The new pointer is durable before the old generation can be removed
            let _ = retired::cleanup(&self.cache.inner, self.key.as_str(), &old);
        }
        Ok(ExecutionGeneration::new(
            relative,
            prepared.components,
            &prepared.envelope_json,
        ))
    }

    /// Opens only the committed generation and verifies all component hashes before returning
    ///
    /// # Errors
    /// Returns an error when memory admission, limits, paths, metadata, or integrity checks fail
    pub fn load_active(
        &self,
        limits: ExecutionCheckpointLimits,
    ) -> Result<Option<ActiveExecution<'_>>> {
        self.cache.inner.check_locations()?;
        let memory_budget = self.cache.memory_budget();
        let mut connection =
            database::open_connection(&self.cache.inner.state_root, Durability::Checkpoint)?;
        let transaction = connection.transaction()?;
        let rowid = transaction
            .query_row(
                "SELECT rowid FROM executions WHERE key = ?1",
                [self.key.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(rowid) = rowid else {
            return Ok(None);
        };
        let path_len = column_length(&transaction, "executions", "relative_path", rowid)?;
        let envelope_size = column_length(&transaction, "executions", "envelope_json", rowid)?;
        if path_len == 0
            || path_len > u64::try_from(MAX_RELATIVE_PATH_BYTES).map_err(|_| corrupt())?
            || envelope_size > limits.max_metadata_bytes
        {
            return Err(corrupt());
        }
        // Admit the retained decoded envelope and temporary strings before retrieving either
        let retained = memory::reserve(memory_budget, memory::metadata_charge(envelope_size)?)?;
        let transient_bytes = memory::serialized_charge(envelope_size)?
            .checked_add(path_len.checked_mul(2).ok_or(CacheError::SizeOverflow)?)
            .ok_or(CacheError::SizeOverflow)?;
        let transient = memory::reserve(memory_budget, transient_bytes)?;
        let scratch = memory::reserve(memory_budget, HASH_MEMORY_BYTES)?;
        let (relative, json, recorded_bytes): (String, String, i64) = transaction.query_row(
            "SELECT relative_path, envelope_json, bytes FROM executions WHERE rowid = ?1",
            [rowid],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let envelope: Envelope = serde_json::from_str(&json).map_err(|_| corrupt())?;
        if envelope_revision(envelope.version, envelope.revision).is_none()
            || !supports_job_snapshot_version(envelope.snapshot_version)
            || !envelope.snapshot.is_valid_checkpoint()
        {
            return Err(corrupt());
        }
        let streams = verify_streams(
            self,
            &relative,
            &envelope,
            envelope_size,
            recorded_bytes,
            limits,
        )?;
        transaction.commit()?;
        let generation = ExecutionGeneration::new(relative, envelope.components, &json);
        drop(json);
        drop(transient);
        drop(scratch);
        Ok(Some(ActiveExecution {
            generation,
            snapshot: envelope.snapshot,
            metadata: envelope.metadata,
            graph: streams.graph,
            blobs: streams.blobs,
            executor: streams.executor,
            executor_bytes: streams.executor_bytes,
            _lease: PhantomData,
            _memory: retained,
        }))
    }
}

struct VerifiedStreams {
    graph: File,
    blobs: File,
    executor: File,
    executor_bytes: u64,
}

fn verify_streams(
    lease: &Lease,
    relative: &str,
    envelope: &Envelope,
    envelope_size: u64,
    recorded_bytes: i64,
    limits: ExecutionCheckpointLimits,
) -> Result<VerifiedStreams> {
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
    if graph.directory.is_some()
        || blobs.directory.is_some()
        || (envelope.version < 3 && executor.directory.is_some())
    {
        return Err(corrupt());
    }
    let directory = generation_directory(&lease.cache, lease.key.as_str(), relative)?;
    let graph = verified_component(&directory, COMPONENT_NAMES[0], graph)?;
    let blobs = verified_component(&directory, COMPONENT_NAMES[1], blobs)?;
    let executor_bytes = executor.bytes;
    let executor = match &executor.directory {
        Some(name) if valid_cursor_directory(name) => {
            verified_component(&directory.open_child(name)?, COMPONENT_NAMES[2], executor)?
        }
        Some(_) => return Err(corrupt()),
        None => verified_component(&directory, COMPONENT_NAMES[2], executor)?,
    };
    Ok(VerifiedStreams {
        graph,
        blobs,
        executor,
        executor_bytes,
    })
}

struct PreparedGeneration {
    envelope_json: String,
    snapshot_json: String,
    bytes: u64,
    components: [Component; 3],
    _memory: Option<MemoryLease>,
}

fn write_generation<F, T>(
    directory: &HeldDirectory,
    budget: &Rc<RefCell<Budget>>,
    snapshot: &JobSnapshot,
    limits: ExecutionCheckpointLimits,
    memory_budget: Option<&MemoryBudget>,
    write: F,
) -> Result<PreparedGeneration>
where
    F: FnOnce(&mut ExecutionWriter) -> Result<T>,
    T: Serialize,
{
    let component = |name: &str, executor| -> Result<ComponentWriter> {
        Ok(ComponentWriter {
            file: BufWriter::with_capacity(STREAM_BUFFER_BYTES, directory.create_new_file(name)?),
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
        revision: 0,
        snapshot_version: JOB_SNAPSHOT_VERSION,
        snapshot,
        metadata: &metadata,
        components: &components,
    };
    let encoded = memory::json_size_bounded(&envelope, limits.max_metadata_bytes)?;
    let envelope_memory = memory::reserve(memory_budget, memory::checkpoint_charge(encoded)?)?;
    let envelope_json = encode_sized_envelope(&envelope, encoded)?;
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
    Ok(PreparedGeneration {
        envelope_json,
        snapshot_json,
        bytes: total,
        components,
        _memory: envelope_memory,
    })
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
        directory: None,
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
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| io::Error::other("checkpoint metadata allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_envelope<T: Serialize + ?Sized>(
    envelope: &EnvelopeRef<'_, T>,
    limit: u64,
) -> Result<String> {
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

fn encode_sized_envelope<T: Serialize + ?Sized>(
    envelope: &EnvelopeRef<'_, T>,
    expected_bytes: u64,
) -> Result<String> {
    // A caller-provided serializer must not grow after memory has been admitted
    let encoded = match encode_envelope(envelope, expected_bytes) {
        Err(CacheError::MetadataTooLarge { .. }) => {
            return Err(CacheError::InvalidInput(
                "checkpoint metadata changed while serializing",
            ));
        }
        result => result?,
    };
    if u64::try_from(encoded.len()).map_err(|_| CacheError::SizeOverflow)? != expected_bytes {
        return Err(CacheError::InvalidInput(
            "checkpoint metadata changed while serializing",
        ));
    }
    Ok(encoded)
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
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
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

fn valid_cursor_directory(name: &str) -> bool {
    name.strip_prefix("cursor-").is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix.len() <= 64
            && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    })
}

fn generation_directory(cache: &Cache, key: &str, relative: &str) -> Result<HeldDirectory> {
    let path = safe_entry_path(cache.inner.entries.path(), key, relative)?;
    let generation = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(corrupt)?;
    if !generation.starts_with("active-") {
        return Err(corrupt());
    }
    cache.inner.entries.open_child(key)?.open_child(generation)
}

pub(super) use cleanup::cleanup_cursor_debris;
