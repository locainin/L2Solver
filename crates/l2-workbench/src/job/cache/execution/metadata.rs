//! Update bounded execution metadata without rewriting its immutable Case streams

use super::{
    CacheError, CheckpointStatus, Component, Durability, ENVELOPE_VERSION, Envelope, EnvelopeRef,
    ExecutionCheckpointLimits, JOB_SNAPSHOT_VERSION, JobSnapshot, Lease, MAX_RELATIVE_PATH_BYTES,
    MemoryLease, OptionalExtension, Result, TransactionBehavior, column_length, database,
    encode_envelope, envelope_revision, memory, now_ns, params, supports_job_snapshot_version,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Identity of one verified active execution revision and its immutable streams
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionGeneration {
    relative_path: String,
    components: [Component; 3],
    envelope_digest: [u8; 32],
}

impl ExecutionGeneration {
    pub(super) fn new(relative_path: String, components: [Component; 3], envelope: &str) -> Self {
        Self {
            relative_path,
            components,
            envelope_digest: Sha256::digest(envelope.as_bytes()).into(),
        }
    }
}

impl Lease {
    /// Atomically replaces metadata and job progress for one verified generation
    ///
    /// The graph, blob and executor files remain unchanged. The caller must keep the metadata
    /// consistent with those files and must use a generation returned by `load_active` while
    /// holding this lease. A newer stream or metadata revision invalidates the supplied identity.
    /// A successful update advances the supplied identity to the newly committed revision.
    ///
    /// # Errors
    /// Returns an error for a stale or corrupt generation, invalid snapshot, quota, memory,
    /// serialization, or database failure. The previous generation remains authoritative.
    pub fn update_active_metadata(
        &mut self,
        generation: &mut ExecutionGeneration,
        snapshot: &JobSnapshot,
        limits: ExecutionCheckpointLimits,
        metadata: &Value,
    ) -> Result<()> {
        if !snapshot.is_valid_checkpoint() {
            return Err(CacheError::CorruptCheckpoint);
        }
        self.cache.inner.check_locations()?;
        let budget = self.cache.inner.memory_budget();
        let previous = read_previous(self, generation, limits)?;
        let next_revision = previous
            .revision
            .checked_add(1)
            .ok_or(CacheError::SizeOverflow)?;
        let next = EnvelopeRef {
            version: ENVELOPE_VERSION,
            revision: next_revision,
            snapshot_version: JOB_SNAPSHOT_VERSION,
            snapshot,
            metadata,
            components: &generation.components,
        };
        let next_size = memory::json_size(&next)?;
        if next_size > limits.max_metadata_bytes {
            return Err(CacheError::MetadataTooLarge {
                limit_bytes: usize::try_from(limits.max_metadata_bytes).unwrap_or(usize::MAX),
                actual_bytes: usize::try_from(next_size).unwrap_or(usize::MAX),
            });
        }
        let _new_memory = memory::reserve(budget, memory::checkpoint_charge(next_size)?)?;
        let next_json = encode_envelope(&next, limits.max_metadata_bytes)?;
        let snapshot_json = serde_json::to_string(snapshot)?;
        let new_total = previous
            .streams
            .checked_add(next_size)
            .ok_or(CacheError::SizeOverflow)?;
        // Hold the quota lock until the replacement and progress row commit together
        let _quota = if new_total > previous.total {
            self.cache
                .reserve_capacity(&self.key, new_total - previous.total)?
        } else {
            self.cache.inner.quota_lock()?
        };
        commit_metadata(self, &previous, new_total, &next_json, &snapshot_json)?;
        generation.envelope_digest = Sha256::digest(next_json.as_bytes()).into();
        Ok(())
    }
}

struct PreviousEnvelope {
    path: String,
    json: String,
    recorded_bytes: i64,
    streams: u64,
    total: u64,
    revision: u64,
    _memory: Option<MemoryLease>,
}

fn read_previous(
    lease: &Lease,
    generation: &ExecutionGeneration,
    limits: ExecutionCheckpointLimits,
) -> Result<PreviousEnvelope> {
    let mut connection =
        database::open_connection(&lease.cache.inner.state_root, Durability::Checkpoint)?;
    let transaction = connection.transaction()?;
    let rowid = transaction
        .query_row(
            "SELECT rowid FROM executions WHERE key = ?1",
            [lease.key.as_str()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or(CacheError::CorruptCheckpoint)?;
    let path_len = column_length(&transaction, "executions", "relative_path", rowid)?;
    let envelope_len = column_length(&transaction, "executions", "envelope_json", rowid)?;
    if path_len == 0
        || path_len
            > u64::try_from(MAX_RELATIVE_PATH_BYTES).map_err(|_| CacheError::SizeOverflow)?
        || envelope_len > limits.max_metadata_bytes
    {
        return Err(CacheError::CorruptCheckpoint);
    }
    // Admit the previous encoded and decoded envelope before SQLite returns its contents
    let old_charge = memory::serialized_charge(envelope_len)?
        .checked_add(memory::metadata_charge(envelope_len)?)
        .and_then(|bytes| bytes.checked_add(path_len))
        .ok_or(CacheError::SizeOverflow)?;
    let mut admitted = memory::reserve(lease.cache.inner.memory_budget(), old_charge)?;
    let (path, json, recorded_bytes): (String, String, i64) = transaction.query_row(
        "SELECT relative_path, envelope_json, bytes FROM executions WHERE rowid = ?1",
        [rowid],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if <[u8; 32]>::from(Sha256::digest(json.as_bytes())) != generation.envelope_digest {
        return Err(CacheError::CorruptCheckpoint);
    }
    let envelope: Envelope =
        serde_json::from_str(&json).map_err(|_| CacheError::CorruptCheckpoint)?;
    let revision = envelope_revision(&envelope).ok_or(CacheError::CorruptCheckpoint)?;
    if !supports_job_snapshot_version(envelope.snapshot_version)
        || !envelope.snapshot.is_valid_checkpoint()
        || path != generation.relative_path
        || envelope.components != generation.components
    {
        return Err(CacheError::CorruptCheckpoint);
    }
    let [graph, blobs, executor] = &envelope.components;
    let encoded = graph
        .bytes
        .checked_add(blobs.bytes)
        .ok_or(CacheError::SizeOverflow)?;
    let streams = encoded
        .checked_add(executor.bytes)
        .ok_or(CacheError::SizeOverflow)?;
    let total = streams
        .checked_add(envelope_len)
        .ok_or(CacheError::SizeOverflow)?;
    if encoded > limits.max_encoded_bytes
        || executor.bytes > limits.max_executor_bytes
        || u64::try_from(recorded_bytes).ok() != Some(total)
    {
        return Err(CacheError::CorruptCheckpoint);
    }
    drop(envelope);
    transaction.commit()?;
    drop(connection);
    if let Some(memory) = &mut admitted {
        // Only the encoded envelope and path remain live while the new version is prepared
        let retained = memory::serialized_charge(envelope_len)?
            .checked_add(path_len)
            .ok_or(CacheError::SizeOverflow)?;
        memory.try_resize(retained)?;
    }
    Ok(PreviousEnvelope {
        path,
        json,
        recorded_bytes,
        streams,
        total,
        revision,
        _memory: admitted,
    })
}

fn commit_metadata(
    lease: &Lease,
    previous: &PreviousEnvelope,
    new_total: u64,
    next_json: &str,
    snapshot_json: &str,
) -> Result<()> {
    let mut connection =
        database::open_connection(&lease.cache.inner.state_root, Durability::Checkpoint)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let updated = transaction.execute(
            "UPDATE executions SET envelope_json = ?1, bytes = ?2 WHERE key = ?3 AND relative_path = ?4 AND envelope_json = ?5 AND bytes = ?6",
            params![next_json, i64::try_from(new_total).map_err(|_| CacheError::SizeOverflow)?, lease.key.as_str(), previous.path, previous.json, previous.recorded_bytes],
        )?;
    if updated != 1 {
        return Err(CacheError::CorruptCheckpoint);
    }
    let updated = transaction.execute(
            "UPDATE checkpoints SET snapshot_version = ?1, snapshot_json = ?2, updated_ns = ?3 WHERE key = ?4 AND status = ?5",
            params![i64::from(JOB_SNAPSHOT_VERSION), snapshot_json, now_ns(), lease.key.as_str(), CheckpointStatus::Active.to_database()],
        )?;
    if updated != 1 {
        return Err(CacheError::CorruptCheckpoint);
    }
    transaction.commit()?;
    Ok(())
}
