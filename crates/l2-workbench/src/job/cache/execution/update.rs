//! Commit a new executor stream while retaining the unchanged immutable Case files

use super::{
    Budget, Cache, CacheError, Component, ComponentWriter, Durability, ENVELOPE_VERSION,
    EnvelopeRef, ExecutionCheckpointLimits, ExecutionGeneration, HeldDirectory,
    JOB_SNAPSHOT_VERSION, JobSnapshot, Lease, Result, STREAM_BUFFER_BYTES, WRITER_MEMORY_BYTES,
    WrittenFile, cleanup, database, encode_sized_envelope, finish_component, generation_directory,
    memory,
    metadata::{Change, commit_metadata, read_previous},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    io::{BufWriter, Write},
    rc::Rc,
};

struct PendingCursor {
    cache: Cache,
    parent: HeldDirectory,
    directory: HeldDirectory,
    name: String,
    token: String,
    commit_attempted: bool,
}

impl Drop for PendingCursor {
    fn drop(&mut self) {
        // An uncertain database commit is resolved from its pointer by the next lease holder
        if self.commit_attempted || cleanup::remove_cursor(&self.parent, &self.name).is_err() {
            return;
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

struct PreparedCursor<T> {
    metadata: T,
    component: Component,
    budget: Rc<RefCell<Budget>>,
    // Keep the synced file descriptor held through the pointer commit
    file: WrittenFile,
}

impl PendingCursor {
    fn new(lease: &Lease, generation: &ExecutionGeneration) -> Result<Self> {
        let parent =
            generation_directory(&lease.cache, lease.key.as_str(), &generation.relative_path)?;
        let (name, directory) = parent.create_private_child("cursor-")?;
        let token = format!("{}/{}", generation.relative_path, name);
        let pending = Self {
            cache: lease.cache.clone(),
            parent,
            directory,
            name,
            token: token.clone(),
            commit_attempted: false,
        };
        lease
            .cache
            .reserve_execution_capacity(&lease.key, &token, 0)?;
        Ok(pending)
    }

    fn write<F, T>(
        &self,
        lease: &Lease,
        limits: ExecutionCheckpointLimits,
        write: F,
    ) -> Result<PreparedCursor<T>>
    where
        F: FnOnce(&mut dyn Write) -> Result<T>,
    {
        let budget = Rc::new(RefCell::new(Budget {
            cache: lease.cache.clone(),
            key: lease.key.clone(),
            token: self.token.clone(),
            limits,
            encoded_bytes: 0,
            executor_bytes: 0,
            available: 0,
            failure: None,
        }));
        let mut writer = ComponentWriter {
            file: BufWriter::with_capacity(
                STREAM_BUFFER_BYTES,
                self.directory.create_new_file("executor")?,
            ),
            hash: Sha256::new(),
            bytes: 0,
            executor: true,
            budget: Rc::clone(&budget),
        };
        let result = write(&mut writer);
        if let Some(error) = budget.borrow_mut().failure.take() {
            return Err(error);
        }
        let metadata = result?;
        let (mut executor, written) = finish_component(writer)?;
        let named = self.directory.open_file("executor")?.metadata()?;
        if !super::same_content_identity(&written.synced_metadata, &named) {
            return Err(CacheError::CorruptCheckpoint);
        }
        executor.directory = Some(self.name.clone());
        Ok(PreparedCursor {
            metadata,
            component: executor,
            budget,
            file: written,
        })
    }
}

impl Lease {
    /// Atomically replace executor state, metadata, and job progress for a verified Case generation
    ///
    /// The graph and blob files are reused without copying or hashing them again
    /// The caller must keep their interpretation unchanged and hold the same exclusive lease
    /// The metadata serializer must remain stable across both encoding passes
    ///
    /// # Errors
    /// Rejects stale generations, exhausted limits, unsafe paths, serialization, I/O, and commit failures
    /// The previous checkpoint remains authoritative until every new file is durable and the transaction commits
    pub fn update_active_executor<F, T>(
        &mut self,
        generation: &mut ExecutionGeneration,
        snapshot: &JobSnapshot,
        limits: ExecutionCheckpointLimits,
        write: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut dyn Write) -> Result<T>,
        T: Serialize,
    {
        if !snapshot.is_valid_checkpoint() {
            return Err(CacheError::CorruptCheckpoint);
        }
        self.cache.inner.check_locations()?;
        let previous = read_previous(self, generation, limits)?;
        self.cache.clear_execution_debris(self.key.as_str())?;
        let budget_memory = self.cache.memory_budget();
        let _writer_memory = memory::reserve(budget_memory, WRITER_MEMORY_BYTES)?;
        let mut pending = PendingCursor::new(self, generation)?;
        let prepared = pending.write(self, limits, write)?;
        let mut components = generation.components.clone();
        let old_executor = std::mem::replace(&mut components[2], prepared.component);
        let revision = previous
            .revision
            .checked_add(1)
            .ok_or(CacheError::SizeOverflow)?;
        let envelope = EnvelopeRef {
            version: ENVELOPE_VERSION,
            revision,
            snapshot_version: JOB_SNAPSHOT_VERSION,
            snapshot,
            metadata: &prepared.metadata,
            components: &components,
        };
        let size = memory::json_size_bounded(&envelope, limits.max_metadata_bytes)?;
        let _envelope_memory = memory::reserve(budget_memory, memory::checkpoint_charge(size)?)?;
        let json = encode_sized_envelope(&envelope, size)?;
        prepared.budget.borrow_mut().reserve(size)?;
        let snapshot_json = serde_json::to_string(snapshot)?;
        let total = previous
            .streams
            .checked_sub(old_executor.bytes)
            .and_then(|bytes| bytes.checked_add(components[2].bytes))
            .and_then(|bytes| bytes.checked_add(size))
            .ok_or(CacheError::SizeOverflow)?;
        pending.directory.sync()?;
        pending.parent.sync()?;
        let retired = format!(
            "{}/{}",
            generation.relative_path,
            old_executor.directory.as_deref().unwrap_or("executor")
        );
        let quota = self.cache.inner.quota_lock()?;
        // Metadata serialization can run caller code, so check the synced file again afterward
        let held = prepared.file.file.metadata()?;
        let named = pending.directory.open_file("executor")?.metadata()?;
        if !super::same_content_identity(&prepared.file.synced_metadata, &held)
            || !super::same_content_identity(&held, &named)
        {
            return Err(CacheError::CorruptCheckpoint);
        }
        pending.commit_attempted = true;
        commit_metadata(
            self,
            &previous,
            total,
            &json,
            &snapshot_json,
            Change::Executor {
                incoming_token: &pending.token,
                retired_token: &retired,
                retired_bytes: old_executor.bytes,
            },
        )?;
        generation.components = components;
        generation.envelope_digest = Sha256::digest(json.as_bytes()).into();
        drop(quota);
        // Cleanup is recoverable maintenance after the new pointer is committed
        let _ = self.cache.clear_execution_debris(self.key.as_str());
        Ok(())
    }
}
