//! Update bounded execution metadata without rewriting its immutable Case streams

use super::{
    CacheError, CheckpointStatus, Component, ENVELOPE_VERSION, Envelope, EnvelopeRef,
    ExecutionCheckpointLimits, JOB_SNAPSHOT_VERSION, JobSnapshot, Lease, MAX_RELATIVE_PATH_BYTES,
    MemoryLease, OptionalExtension, Result, TransactionBehavior, column_length, database,
    encode_sized_envelope, envelope_revision, memory, now_ns, params,
    supports_job_snapshot_version,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Identity of one verified active execution revision and its immutable streams
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionGeneration {
    pub(super) relative_path: String,
    pub(super) components: [Component; 3],
    pub(super) envelope_digest: [u8; 32],
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
    /// The metadata serializer is called twice and must produce a stable representation
    /// The caller accounts for any owned metadata built before this method is invoked
    ///
    /// # Errors
    /// Returns an error for a stale or corrupt generation, invalid snapshot, quota, memory,
    /// serialization, or database failure. The previous generation remains authoritative.
    pub fn update_active_metadata<T: Serialize + ?Sized>(
        &mut self,
        generation: &mut ExecutionGeneration,
        snapshot: &JobSnapshot,
        limits: ExecutionCheckpointLimits,
        metadata: &T,
    ) -> Result<()> {
        if !snapshot.is_valid_checkpoint() {
            return Err(CacheError::CorruptCheckpoint);
        }
        self.cache.inner.check_locations()?;
        let budget = self.cache.memory_budget();
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
        let next_size = memory::json_size_bounded(&next, limits.max_metadata_bytes)?;
        let _new_memory = memory::reserve(budget, memory::checkpoint_charge(next_size)?)?;
        let next_json = encode_sized_envelope(&next, next_size)?;
        let snapshot_json = serde_json::to_string(snapshot)?;
        let new_total = previous
            .streams
            .checked_add(next_size)
            .ok_or(CacheError::SizeOverflow)?;
        // Hold the quota lock until the replacement and progress row commit together
        let _quota = if new_total > previous.total {
            self.cache
                .reserve_capacity(&self.key, new_total - previous.total, budget)?
        } else {
            self.cache.inner.quota_lock()?
        };
        commit_metadata(
            self,
            &previous,
            new_total,
            &next_json,
            &snapshot_json,
            Change::Metadata,
        )?;
        generation.envelope_digest = Sha256::digest(next_json.as_bytes()).into();
        Ok(())
    }
}

pub(super) struct PreviousEnvelope {
    pub(super) path: String,
    pub(super) json: String,
    pub(super) recorded_bytes: i64,
    pub(super) streams: u64,
    pub(super) total: u64,
    pub(super) revision: u64,
    _memory: Option<MemoryLease>,
}

pub(super) fn read_previous(
    lease: &Lease,
    generation: &ExecutionGeneration,
    limits: ExecutionCheckpointLimits,
) -> Result<PreviousEnvelope> {
    let mut connection = database::open_connection(&lease.cache.inner.state_root)?;
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
    let mut admitted = memory::reserve(lease.cache.memory_budget(), old_charge)?;
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
    let revision = envelope_revision(envelope.version, envelope.revision)
        .ok_or(CacheError::CorruptCheckpoint)?;
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

#[derive(Clone, Copy)]
pub(super) enum Change<'a> {
    Metadata,
    Executor {
        incoming_token: &'a str,
        retired_token: &'a str,
        retired_bytes: u64,
    },
}

pub(super) fn commit_metadata(
    lease: &Lease,
    previous: &PreviousEnvelope,
    new_total: u64,
    next_json: &str,
    snapshot_json: &str,
    change: Change<'_>,
) -> Result<()> {
    let mut connection = database::open_connection(&lease.cache.inner.state_root)?;
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
    if let Change::Executor {
        incoming_token,
        retired_token,
        retired_bytes,
    } = change
    {
        // Displaced files remain counted until their removal is durable
        transaction.execute(
            "INSERT INTO execution_reservations(token, key, bytes) VALUES (?1, ?2, ?3)",
            params![
                retired_token,
                lease.key.as_str(),
                i64::try_from(retired_bytes).map_err(|_| CacheError::SizeOverflow)?
            ],
        )?;
        if transaction.execute(
            "DELETE FROM execution_reservations WHERE token = ?1 AND key = ?2",
            params![incoming_token, lease.key.as_str()],
        )? != 1
        {
            return Err(CacheError::CorruptCheckpoint);
        }
    }
    transaction.commit()?;
    Ok(())
}
