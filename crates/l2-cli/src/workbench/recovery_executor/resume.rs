//! Persist committed scheduler boundaries with their exact Case and work contribution

use super::{
    Case, Executor, RecoveryExecutionError, RecoveryStage, checkpoint,
    execution_state::SchedulerCursor,
};
use crate::arguments::RecoveryOptions;
use l2_workbench::{
    evidence::{CasePrefixBinding, CaseSnapshotLimits, CaseSnapshotUsage},
    job::{
        CacheFallbackKind, CacheStage, Job, JobSnapshot, MemoryBudget, MemoryClass, MemoryLease,
        WorkSnapshot,
        cache::{CacheError, ExecutionCheckpointLimits, ExecutionGeneration, Lease},
    },
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

const METADATA_VERSION: u32 = 1;
const MAX_METADATA_BYTES: u64 = 4 * 1024 * 1024;
const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    version: u32,
    usage: CaseSnapshotUsage,
    work: Option<WorkSnapshot>,
}

struct AdmittedMetadata {
    value: Metadata,
    memory: MemoryLease,
}

#[derive(Serialize)]
struct MetadataRef<'a> {
    version: u32,
    usage: CaseSnapshotUsage,
    work: Option<&'a WorkSnapshot>,
}

enum BudgetOrigin {
    Supplied,
    Discover,
}

/// One exclusively leased recovery stage and its checkpoint storage policy
pub struct RecoveryResume<'lease> {
    lease: &'lease mut Lease,
    case_limits: CaseSnapshotLimits,
    store_limits: ExecutionCheckpointLimits,
    executor_limit: usize,
    session_memory: MemoryBudget,
    budget_origin: BudgetOrigin,
    memory_limit: u64,
    refresh: bool,
    strict: bool,
    disabled: bool,
    last_save: Option<Instant>,
    initial: Option<CasePrefixBinding>,
    generation: Option<ExecutionGeneration>,
    usage: Option<CaseSnapshotUsage>,
    metadata_memory: Option<MemoryLease>,
    #[cfg(test)]
    test_hooks: RelationalTestHooks,
}

#[cfg(test)]
#[derive(Default)]
struct RelationalTestHooks {
    pause_after_relational: Option<std::path::PathBuf>,
    cancel_after_relational_load: bool,
    fail_allocation_during_relational_load: bool,
    restored_relational: Option<u64>,
    forced_inner_limit: Option<(TestCheckpointPart, usize)>,
    forced_generation: Option<ExecutionGeneration>,
    cancel_after_case_snapshot: bool,
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum TestCheckpointPart {
    Cursor,
    Gate,
}

pub(super) struct Loaded {
    pub(super) case: Case,
    pub(super) state: Vec<u8>,
    pub(super) work: Option<WorkSnapshot>,
    pub(super) state_memory: MemoryLease,
}

impl<'lease> RecoveryResume<'lease> {
    pub fn new(
        lease: &'lease mut Lease,
        options: &RecoveryOptions,
        memory: Option<&MemoryBudget>,
    ) -> Self {
        // The executor ceiling bounds checkpoint structure and verification work
        let executor_bytes = options.memory_limit / 8;
        Self {
            lease,
            // Expanded bytes bound the stream; live allocations use the shared ledger
            case_limits: CaseSnapshotLimits::new(options.cache_max_bytes, options.memory_limit),
            store_limits: ExecutionCheckpointLimits {
                max_encoded_bytes: options.cache_max_bytes,
                max_executor_bytes: executor_bytes,
                max_metadata_bytes: MAX_METADATA_BYTES,
            },
            executor_limit: usize::try_from(executor_bytes).unwrap_or(usize::MAX),
            // Keep one ledger even when startup did not attach a shared budget
            session_memory: memory
                .cloned()
                .unwrap_or_else(|| MemoryBudget::new(options.memory_limit)),
            budget_origin: if memory.is_some() {
                BudgetOrigin::Supplied
            } else {
                BudgetOrigin::Discover
            },
            memory_limit: options.memory_limit,
            refresh: options.refresh,
            strict: options.strict_cache,
            disabled: false,
            last_save: None,
            initial: None,
            generation: None,
            usage: None,
            metadata_memory: None,
            #[cfg(test)]
            test_hooks: RelationalTestHooks::default(),
        }
    }

    pub(super) fn prepare(&mut self, initial: &mut Case) -> Result<(), RecoveryExecutionError> {
        if matches!(self.budget_origin, BudgetOrigin::Discover)
            && let Some(existing) = initial
                .memory_budget()
                .or_else(|| self.lease.memory_budget())
        {
            self.session_memory = existing.clone();
        }
        if self
            .session_memory
            .snapshot()
            .map_err(operational_error)?
            .limit_bytes
            > self.memory_limit
        {
            return Err(operational_error(
                l2_workbench::job::MemoryError::IncompatibleWorkingSet,
            ));
        }
        self.lease
            .bind_memory_budget(&self.session_memory)
            .map_err(cache_error)?;
        initial.admit_memory_budget(&self.session_memory)?;
        self.initial = Some(initial.checkpoint_prefix()?);
        Ok(())
    }

    pub(super) fn load(&mut self) -> Result<Option<Loaded>, RecoveryExecutionError> {
        if self.refresh || self.disabled {
            return Ok(None);
        }
        let Some(mut active) = self
            .lease
            .load_active(self.store_limits)
            .map_err(cache_error)?
        else {
            return Ok(None);
        };
        let metadata = admit_metadata(active.metadata(), &self.session_memory)?;
        if metadata.value.version != METADATA_VERSION {
            return Err(cache_error(CacheError::CorruptCheckpoint));
        }
        let generation = active.generation().clone();
        let encoded_bytes = active.executor_bytes();
        let count =
            usize::try_from(encoded_bytes).map_err(|_| cache_error(CacheError::SizeOverflow))?;
        let mut state_memory = self.reserve(encoded_bytes)?;
        let (graph, blobs, state) = active.streams();
        let case = crate::case_snapshot::read_streams(
            graph,
            blobs,
            metadata.value.usage,
            self.case_limits,
            Some(&self.session_memory),
        )
        .map_err(operational)?;
        if !self
            .initial
            .as_ref()
            .ok_or_else(|| cache_error(CacheError::CorruptCheckpoint))?
            .matches(&case)?
        {
            return Err(cache_error(CacheError::CorruptCheckpoint));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(count)
            .map_err(|_| l2_workbench::recovery::RecoveryError::AllocationFailed)?;
        state_memory
            .try_resize(
                u64::try_from(bytes.capacity())
                    .map_err(|_| CacheError::SizeOverflow)
                    .map_err(cache_error)?,
            )
            .map_err(operational_error)?;
        bytes.resize(count, 0);
        state.read_exact(&mut bytes).map_err(operational_error)?;
        drop(active);
        self.generation = Some(generation);
        self.usage = Some(metadata.value.usage);
        self.metadata_memory = Some(metadata.memory);
        self.last_save = Some(Instant::now());
        Ok(Some(Loaded {
            case,
            state: bytes,
            work: metadata.value.work,
            state_memory,
        }))
    }

    pub(super) fn restore_work(
        job: Option<&Job>,
        work: Option<WorkSnapshot>,
    ) -> Result<(), RecoveryExecutionError> {
        match (job, work) {
            (Some(job), Some(work)) => match job.restore_work(work) {
                Ok(()) => {}
                Err(l2_workbench::job::JobError::InvalidWorkSnapshot) => {
                    return Err(cache_error(CacheError::CorruptCheckpoint));
                }
                Err(error) => return Err(error.into()),
            },
            (None, None) => {}
            _ => return Err(cache_error(CacheError::CorruptCheckpoint)),
        }
        Ok(())
    }

    pub(super) fn invalid(
        &mut self,
        error: RecoveryExecutionError,
        job: Option<&Job>,
    ) -> Result<(), RecoveryExecutionError> {
        if self.strict || is_runtime_failure(&error) {
            return Err(error);
        }
        if !matches!(
            error,
            RecoveryExecutionError::Operational { .. }
                | RecoveryExecutionError::Coordinator(
                    l2_workbench::recovery::RecoveryError::InvalidCheckpoint
                )
        ) {
            return Err(error);
        }
        self.disable(
            job,
            CacheFallbackKind::InvalidEntry,
            "active recovery checkpoint could not be restored",
        )
    }

    pub(super) fn due(&self) -> bool {
        !self.disabled
            && self
                .last_save
                .is_none_or(|last| last.elapsed() >= CHECKPOINT_INTERVAL)
    }

    pub(super) fn save(
        &mut self,
        executor: &Executor<'_>,
        cursor: &SchedulerCursor,
    ) -> Result<(), RecoveryExecutionError> {
        if self.disabled {
            return Ok(());
        }
        executor.check_cancelled()?;
        executor.case.validate_memory_budget(&self.session_memory)?;
        if !self
            .initial
            .as_ref()
            .ok_or_else(|| cache_error(CacheError::CorruptCheckpoint))?
            .matches(executor.case)?
        {
            return Err(cache_error(CacheError::CorruptCheckpoint));
        }
        let (snapshot, work) = checkpoint_progress(executor)?;
        let mut codec_error = None;
        let mut saved_usage = None;
        let job = executor.job.as_ref().map(|progress| &progress.job);
        #[cfg(test)]
        let cancel_after_case = std::mem::take(&mut self.test_hooks.cancel_after_case_snapshot);
        let result = self
            .lease
            .save_active_generation(&snapshot, self.store_limits, |writer| {
                let encoded = crate::case_snapshot::with_cancellation(job, |cancellation| {
                    let (graph, blobs, state) = writer.streams();
                    let mut state = cancellation.wrap(state);
                    let usage = crate::case_snapshot::write_streams(
                        graph,
                        blobs,
                        executor.case,
                        self.case_limits,
                        Some(&self.session_memory),
                        cancellation,
                    )?;
                    #[cfg(test)]
                    if cancel_after_case && let Some(job) = job {
                        job.request_cancel();
                    }
                    if let Err(error) = checkpoint::write_with_memory(
                        executor,
                        cursor,
                        &mut state,
                        self.executor_limit,
                        Some(&self.session_memory),
                    ) {
                        codec_error = Some(error);
                        return Err(std::io::Error::other("checkpoint encoding failed").into());
                    }
                    Ok(usage)
                });
                let usage = match encoded {
                    Ok(usage) => usage,
                    Err(error) => {
                        codec_error = Some(codec_failure(error, codec_error.take()));
                        return Err(CacheError::CorruptCheckpoint);
                    }
                };
                saved_usage = Some(usage);
                Ok(MetadataRef {
                    version: METADATA_VERSION,
                    usage,
                    work: work.as_ref(),
                })
            });
        // Cache quotas and I/O errors explain the writer failure more precisely than the codec
        match (result, codec_error) {
            (Err(CacheError::CorruptCheckpoint), Some(error)) => return Err(error),
            (Err(error), _) => return Err(cache_error(error)),
            (Ok(generation), _) => {
                self.generation = Some(generation);
                self.usage = saved_usage;
            }
        }
        self.last_save = Some(Instant::now());
        Ok(())
    }

    pub(super) fn save_incremental(
        &mut self,
        executor: &Executor<'_>,
        cursor: &SchedulerCursor,
    ) -> Result<(), RecoveryExecutionError> {
        if self.disabled {
            return Ok(());
        }
        executor.check_cancelled()?;
        executor.case.validate_memory_budget(&self.session_memory)?;
        let usage = self
            .usage
            .ok_or_else(|| cache_error(CacheError::CorruptCheckpoint))?;
        let generation = self
            .generation
            .as_mut()
            .ok_or_else(|| cache_error(CacheError::CorruptCheckpoint))?;
        let (snapshot, work) = checkpoint_progress(executor)?;
        let executor_limit = self.executor_limit;
        let mut codec_error = None;
        let job = executor.job.as_ref().map(|progress| &progress.job);
        let result =
            self.lease
                .update_active_executor(generation, &snapshot, self.store_limits, |state| {
                    let encoded = crate::case_snapshot::with_cancellation(job, |cancellation| {
                        let mut state = cancellation.wrap(state);
                        if let Err(error) = checkpoint::write_with_memory(
                            executor,
                            cursor,
                            &mut state,
                            executor_limit,
                            Some(&self.session_memory),
                        ) {
                            codec_error = Some(error);
                            return Err(std::io::Error::other("checkpoint encoding failed").into());
                        }
                        Ok(())
                    });
                    if let Err(error) = encoded {
                        codec_error = Some(codec_failure(error, codec_error.take()));
                        return Err(CacheError::CorruptCheckpoint);
                    }
                    Ok(MetadataRef {
                        version: METADATA_VERSION,
                        usage,
                        work: work.as_ref(),
                    })
                });
        match (result, codec_error) {
            (Err(CacheError::CorruptCheckpoint), Some(error)) => return Err(error),
            (Err(error), _) => return Err(cache_error(error)),
            (Ok(()), _) => {}
        }
        self.last_save = Some(Instant::now());
        Ok(())
    }

    pub(super) fn save_or_fallback(
        &mut self,
        executor: &Executor<'_>,
        cursor: &SchedulerCursor,
    ) -> Result<(), RecoveryExecutionError> {
        let result = self.save(executor, cursor);
        self.save_result(executor, result)
    }

    pub(super) fn save_incremental_or_fallback(
        &mut self,
        executor: &Executor<'_>,
        cursor: &SchedulerCursor,
    ) -> Result<(), RecoveryExecutionError> {
        let result = self.save_incremental(executor, cursor);
        self.save_result(executor, result)
    }

    pub(super) fn unrepresentable_or_error(
        &mut self,
        executor: &Executor<'_>,
        error: RecoveryExecutionError,
    ) -> Result<(), RecoveryExecutionError> {
        if self.strict {
            return Err(error);
        }
        self.disable(
            executor.job.as_ref().map(|progress| &progress.job),
            CacheFallbackKind::CommitFailed,
            "active recovery checkpoint could not be saved",
        )
    }

    fn save_result(
        &mut self,
        executor: &Executor<'_>,
        result: Result<(), RecoveryExecutionError>,
    ) -> Result<(), RecoveryExecutionError> {
        match result {
            Ok(()) => Ok(()),
            Err(error)
                if !self.strict
                    && !is_runtime_failure(&error)
                    && matches!(error, RecoveryExecutionError::Operational { .. }) =>
            {
                self.disable(
                    executor.job.as_ref().map(|progress| &progress.job),
                    CacheFallbackKind::CommitFailed,
                    "active recovery checkpoint could not be saved",
                )
            }
            Err(error) => Err(error),
        }
    }

    fn disable(
        &mut self,
        job: Option<&Job>,
        kind: CacheFallbackKind,
        message: &'static str,
    ) -> Result<(), RecoveryExecutionError> {
        if let Some(job) = job {
            job.check_cancelled()?;
            job.record_cache_fallback(CacheStage::Checkpoint, kind, format_args!("{message}"))?;
        }
        self.disabled = true;
        Ok(())
    }

    pub(super) const fn executor_limit(&self) -> usize {
        self.executor_limit
    }

    pub(super) fn session_memory(&self) -> MemoryBudget {
        self.session_memory.clone()
    }

    #[cfg(test)]
    pub(super) const fn wants_populated_checkpoint(&self) -> bool {
        !self.disabled
            && (self.test_hooks.forced_inner_limit.is_some()
                || self.test_hooks.pause_after_relational.is_some())
    }

    #[cfg(test)]
    pub(super) fn check_relational_allocation_test_failure(
        &self,
    ) -> Result<(), RecoveryExecutionError> {
        if self.test_hooks.fail_allocation_during_relational_load {
            return Err(l2_workbench::recovery::RecoveryError::AllocationFailed.into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) const fn fail_allocation_during_relational_load(&mut self) {
        self.test_hooks.fail_allocation_during_relational_load = true;
    }

    #[cfg(test)]
    pub(super) fn relational_restored(
        &mut self,
        count: usize,
        job: Option<&Job>,
    ) -> Result<(), RecoveryExecutionError> {
        self.test_hooks.restored_relational = Some(
            u64::try_from(count)
                .map_err(|_| l2_workbench::recovery::RecoveryError::InvalidCheckpoint)?,
        );
        if self.test_hooks.cancel_after_relational_load {
            let job = job.ok_or(l2_workbench::recovery::RecoveryError::InvalidCheckpoint)?;
            job.request_cancel();
            job.check_cancelled()?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn after_populated_checkpoint(
        &mut self,
        count: usize,
        cached_plans: usize,
        job: Option<&Job>,
        history: Option<&l2_workbench::protocol::RelationalReplayHistory>,
    ) -> Result<(), RecoveryExecutionError> {
        if count > 0
            && cached_plans > 0
            && let Some(path) = self.test_hooks.pause_after_relational.take()
        {
            let job = job.ok_or(l2_workbench::recovery::RecoveryError::InvalidCheckpoint)?;
            let peak = job
                .memory_budget()
                .ok_or(l2_workbench::recovery::RecoveryError::InvalidCheckpoint)?
                .snapshot()
                .map_err(operational_error)?
                .peak_bytes;
            let work = job.work_snapshot()?;
            let history_entries = history
                .map(serde_json::to_value)
                .transpose()
                .map_err(operational_error)?
                .and_then(|value| {
                    value
                        .get("entries")
                        .and_then(serde_json::Value::as_array)
                        .map(Vec::len)
                })
                .unwrap_or(0);
            let marker = serde_json::to_vec(&serde_json::json!({
                    "candidates_examined": count,
                    "cached_plans": cached_plans,
                    "aggregate_peak_bytes": peak,
                    "work_candidates_examined": work.counter(l2_workbench::job::Counter::CandidatesExamined),
                    "work_bytes": work.counter(l2_workbench::job::Counter::Bytes),
                    "history_storage_bytes": history.map_or(0, l2_workbench::protocol::RelationalReplayHistory::storage_bytes),
                    "history_ceiling_bytes": history.map_or(0, l2_workbench::protocol::RelationalReplayHistory::maximum_bytes),
                    "history_entries": history_entries,
                }))
                .map_err(operational_error)?;
            std::fs::write(path, marker).map_err(operational_error)?;
            loop {
                job.check_cancelled()?;
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn pause_after_populated_relational_checkpoint(&mut self, path: std::path::PathBuf) {
        self.test_hooks.pause_after_relational = Some(path);
    }

    #[cfg(test)]
    pub(super) const fn force_inner_checkpoint_limit(
        &mut self,
        part: TestCheckpointPart,
        limit: usize,
    ) {
        self.test_hooks.forced_inner_limit = Some((part, limit));
    }

    #[cfg(test)]
    pub(super) fn forced_boundary_generation(&self) -> Option<ExecutionGeneration> {
        self.test_hooks.forced_generation.clone()
    }

    #[cfg(test)]
    pub(super) fn inner_checkpoint_test_limit(&mut self, part: TestCheckpointPart) -> usize {
        if let Some((forced_part, limit)) = self.test_hooks.forced_inner_limit {
            self.test_hooks.forced_generation = self.generation.clone();
            if part == forced_part {
                return limit;
            }
        }
        self.executor_limit
    }

    #[cfg(test)]
    pub(super) const fn cancel_after_loading_relational_checkpoint(&mut self) {
        self.test_hooks.cancel_after_relational_load = true;
    }

    #[cfg(test)]
    pub(super) const fn cancel_after_next_case_snapshot(&mut self) {
        self.test_hooks.cancel_after_case_snapshot = true;
    }

    #[cfg(test)]
    pub(super) const fn restored_relational_candidates(&self) -> Option<u64> {
        self.test_hooks.restored_relational
    }

    fn reserve(&self, bytes: u64) -> Result<MemoryLease, RecoveryExecutionError> {
        self.session_memory
            .try_reserve(MemoryClass::Executor, bytes)
            .map_err(operational_error)
    }
}

fn is_runtime_failure(error: &RecoveryExecutionError) -> bool {
    use l2_workbench::{
        derivation::DerivationError,
        job::{JobError, MemoryError},
        protocol::{RecordError, RelationalCursorError, RelationalTransformError},
        recovery::RecoveryError,
    };
    crate::memory_error::any_cause(error, |cause| {
        cause.is::<MemoryError>()
            || cause.is::<JobError>()
            || cause.is::<std::collections::TryReserveError>()
            || matches!(
                cause.downcast_ref::<RecoveryError>(),
                Some(RecoveryError::AllocationFailed)
            )
            || matches!(
                cause.downcast_ref::<RecordError>(),
                Some(RecordError::AllocationFailed)
            )
            || matches!(
                cause.downcast_ref::<DerivationError>(),
                Some(DerivationError::AllocationFailed)
            )
            || matches!(
                cause.downcast_ref::<RelationalTransformError>(),
                Some(RelationalTransformError::AllocationFailed)
            )
            || matches!(
                cause.downcast_ref::<RelationalCursorError<RecoveryExecutionError>>(),
                Some(RelationalCursorError::AllocationFailed)
            )
    })
}

fn cache_error(source: CacheError) -> RecoveryExecutionError {
    operational_error(source)
}

fn checkpoint_progress(
    executor: &Executor<'_>,
) -> Result<(JobSnapshot, Option<WorkSnapshot>), RecoveryExecutionError> {
    if let Some(progress) = &executor.job {
        Ok((
            progress.job.checkpoint_snapshot()?,
            Some(progress.job.work_snapshot()?),
        ))
    } else {
        Ok((Job::new("recovery checkpoint").checkpoint_snapshot()?, None))
    }
}

fn admit_metadata(
    value: &serde_json::Value,
    memory: &MemoryBudget,
) -> Result<AdmittedMetadata, RecoveryExecutionError> {
    // The parsed work copy outlives the cache entry's own metadata charge
    let limit = usize::try_from(MAX_METADATA_BYTES).unwrap_or(usize::MAX);
    let (encoded, buffer_memory) = checkpoint::encode(value, limit, Some(memory))?;
    let admission = l2_workbench::job::admit_json(&encoded, memory, MemoryClass::Executor)
        .map_err(|error| match error {
            l2_workbench::job::JsonMemoryError::Memory(error) => operational_error(error),
            l2_workbench::job::JsonMemoryError::InvalidJson { .. }
            | l2_workbench::job::JsonMemoryError::SizeOverflow => {
                cache_error(CacheError::CorruptCheckpoint)
            }
        })?;
    let value =
        serde_json::from_slice(&encoded).map_err(|_| cache_error(CacheError::CorruptCheckpoint))?;
    let metadata = AdmittedMetadata {
        value,
        memory: admission.into_retained(),
    };
    drop(encoded);
    drop(buffer_memory);
    Ok(metadata)
}

fn codec_failure(
    error: Box<dyn std::error::Error>,
    codec_error: Option<RecoveryExecutionError>,
) -> RecoveryExecutionError {
    if error.downcast_ref::<l2_workbench::job::JobError>()
        == Some(&l2_workbench::job::JobError::Cancelled)
    {
        return l2_workbench::job::JobError::Cancelled.into();
    }
    codec_error.unwrap_or_else(|| operational(error))
}

fn operational_error(source: impl std::error::Error + 'static) -> RecoveryExecutionError {
    operational(Box::new(source))
}

fn operational(source: Box<dyn std::error::Error>) -> RecoveryExecutionError {
    RecoveryExecutionError::Operational {
        stage: RecoveryStage::TransformDiscovery,
        source,
    }
}
