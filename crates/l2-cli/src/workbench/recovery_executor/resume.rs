//! Persist committed scheduler boundaries with their exact Case and work contribution

use super::{
    Case, Executor, RecoveryExecutionError, RecoveryStage, checkpoint,
    execution_state::SchedulerCursor,
};
use crate::arguments::RecoveryOptions;
use l2_workbench::{
    evidence::{CasePrefixBinding, CaseSnapshotLimits, CaseSnapshotUsage},
    job::{
        CacheFallbackKind, CacheStage, Job, MemoryBudget, MemoryClass, MemoryLease, WorkSnapshot,
        cache::{CacheError, ExecutionCheckpointLimits, Lease},
    },
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

const METADATA_VERSION: u32 = 1;
const MAX_METADATA_BYTES: u64 = 4 * 1024 * 1024;
const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    version: u32,
    usage: CaseSnapshotUsage,
    work: Option<WorkSnapshot>,
}

/// One exclusively leased recovery stage and its checkpoint storage policy
pub struct RecoveryResume<'lease> {
    lease: &'lease mut Lease,
    case_limits: CaseSnapshotLimits,
    store_limits: ExecutionCheckpointLimits,
    executor_limit: usize,
    refresh: bool,
    strict: bool,
    disabled: bool,
    last_save: Option<Instant>,
    initial: Option<CasePrefixBinding>,
    memory: Option<MemoryBudget>,
}

pub(super) struct Loaded {
    pub(super) case: Case,
    pub(super) state: Vec<u8>,
    pub(super) work: Option<WorkSnapshot>,
    pub(super) state_memory: Option<MemoryLease>,
}

impl<'lease> RecoveryResume<'lease> {
    pub fn new(
        lease: &'lease mut Lease,
        options: &RecoveryOptions,
        memory: Option<&MemoryBudget>,
    ) -> Self {
        // Restoration keeps the native Case alive until the saved generation is validated
        let executor_bytes = options.memory_limit / 8;
        Self {
            lease,
            case_limits: CaseSnapshotLimits::new(options.cache_max_bytes, options.memory_limit / 4),
            store_limits: ExecutionCheckpointLimits {
                max_encoded_bytes: options.cache_max_bytes,
                max_executor_bytes: executor_bytes,
                max_metadata_bytes: MAX_METADATA_BYTES,
            },
            executor_limit: usize::try_from(executor_bytes).unwrap_or(usize::MAX),
            refresh: options.refresh,
            strict: options.strict_cache,
            disabled: false,
            last_save: None,
            initial: None,
            memory: memory.cloned(),
        }
    }

    pub(super) fn prepare(&mut self, initial: &Case) -> Result<(), RecoveryExecutionError> {
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
        let metadata = Metadata::deserialize(active.metadata())
            .map_err(|_| cache_error(CacheError::CorruptCheckpoint))?;
        if metadata.version != METADATA_VERSION {
            return Err(cache_error(CacheError::CorruptCheckpoint));
        }
        let encoded_bytes = active.executor_bytes();
        let count =
            usize::try_from(encoded_bytes).map_err(|_| cache_error(CacheError::SizeOverflow))?;
        let mut state_memory = self.reserve(encoded_bytes)?;
        let (graph, blobs, state) = active.streams();
        let case = crate::case_snapshot::read_streams(
            graph,
            blobs,
            metadata.usage,
            self.case_limits,
            self.memory.as_ref(),
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
        if let Some(memory) = &mut state_memory {
            memory
                .try_resize(
                    u64::try_from(bytes.capacity())
                        .map_err(|_| CacheError::SizeOverflow)
                        .map_err(cache_error)?,
                )
                .map_err(operational_error)?;
        }
        bytes.resize(count, 0);
        state.read_exact(&mut bytes).map_err(operational_error)?;
        drop(active);
        self.last_save = Some(Instant::now());
        Ok(Some(Loaded {
            case,
            state: bytes,
            work: metadata.work,
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
        if self.strict
            || crate::memory_error::find(&error).is_some()
            || matches!(error, RecoveryExecutionError::Job(_))
        {
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
        if !self
            .initial
            .as_ref()
            .ok_or_else(|| cache_error(CacheError::CorruptCheckpoint))?
            .matches(executor.case)?
        {
            return Err(cache_error(CacheError::CorruptCheckpoint));
        }
        let (snapshot, work) = if let Some(progress) = &executor.job {
            (
                progress.job.checkpoint_snapshot()?,
                Some(progress.job.work_snapshot()?),
            )
        } else {
            (Job::new("recovery checkpoint").checkpoint_snapshot()?, None)
        };
        let mut codec_error = None;
        let result = self
            .lease
            .save_active(&snapshot, self.store_limits, |writer| {
                let (mut graph, mut blobs, mut state) = writer.streams();
                let usage = match crate::case_snapshot::write_streams(
                    &mut graph,
                    &mut blobs,
                    executor.case,
                    self.case_limits,
                    self.memory.as_ref(),
                ) {
                    Ok(usage) => usage,
                    Err(error) => {
                        codec_error = Some(operational(error));
                        return Err(CacheError::CorruptCheckpoint);
                    }
                };
                if let Err(error) =
                    checkpoint::write(executor, cursor, &mut state, self.executor_limit)
                {
                    codec_error = Some(error);
                    return Err(CacheError::CorruptCheckpoint);
                }
                Ok(serde_json::to_value(Metadata {
                    version: METADATA_VERSION,
                    usage,
                    work,
                })?)
            });
        // Cache quotas and I/O errors explain the writer failure more precisely than the codec
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
        match self.save(executor, cursor) {
            Ok(()) => Ok(()),
            Err(error)
                if !self.strict
                    && crate::memory_error::find(&error).is_none()
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

    fn reserve(&self, bytes: u64) -> Result<Option<MemoryLease>, RecoveryExecutionError> {
        self.memory
            .as_ref()
            .map(|budget| budget.try_reserve(MemoryClass::Executor, bytes))
            .transpose()
            .map_err(operational_error)
    }
}

fn cache_error(source: CacheError) -> RecoveryExecutionError {
    operational_error(source)
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
