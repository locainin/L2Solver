//! Recover Cases in bounded batches before serial export

mod admission;
mod case_buffer;
mod ordered;

pub(super) use ordered::process_ordered;

use super::{
    coverage::RecoveryCaseKind,
    provenance::cohort_scope,
    recovery_cache::{CachedRecovery, RecoveryContext, recover},
};
use crate::workbench;
use case_buffer::BufferedResult;
use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits},
    investigation::BuildResult,
    job::{Counter, Job, JobError, MemoryBudget, MemoryClass, MemoryError, Phase, PhaseOutcome},
};
use std::{
    error::Error,
    fmt,
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};

// Pending native Cases and completed resident results each have a bounded buffering share
const CASE_BUFFER_DIVISOR: u64 = 4;
const COLLECTION_PHASES: [Phase; 6] = [
    Phase::Reconstruction,
    Phase::NativeExtraction,
    Phase::FramingRecordDiscovery,
    Phase::TransformDiscovery,
    Phase::AssemblyValidation,
    Phase::Expansion,
];

/// Keep collection phases active until analysis and optional extraction both finish
pub(super) struct CollectionPhases<'job> {
    job: Option<&'job Job>,
    active: bool,
}

impl<'job> CollectionPhases<'job> {
    pub(super) fn start(job: Option<&'job Job>) -> Result<Self, Box<dyn Error>> {
        if let Some(job) = job {
            // These phases overlap while Cases move through recovery and expansion
            for (started, phase) in COLLECTION_PHASES.into_iter().enumerate() {
                if let Err(error) = job.start(phase, None) {
                    for started_phase in COLLECTION_PHASES.into_iter().take(started) {
                        let _ = job.finish(started_phase, PhaseOutcome::Failed);
                    }
                    return Err(error.into());
                }
            }
        }
        Ok(Self {
            job,
            active: job.is_some(),
        })
    }

    pub(super) fn finish(mut self, outcome: PhaseOutcome) -> Result<(), Box<dyn Error>> {
        let Some(job) = self.job else {
            self.active = false;
            return Ok(());
        };
        let mut first_error = None;
        for phase in COLLECTION_PHASES {
            if let Err(error) = job.finish(phase, outcome)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        self.active = false;
        first_error.map_or(Ok(()), |error| Err(error.into()))
    }
}

impl Drop for CollectionPhases<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(job) = self.job {
            // Record the current job outcome when an operation exits before normal completion
            let outcome = if job.is_cancelled() {
                PhaseOutcome::Cancelled
            } else {
                PhaseOutcome::Failed
            };
            for phase in COLLECTION_PHASES {
                let _ = job.finish(phase, outcome);
            }
        }
    }
}

/// Set the maximum concurrency; each Case still needs live memory admission
pub(super) fn recovery_worker_count(requested: Option<usize>, available_cpus: usize) -> usize {
    let cpu_limit = available_cpus.max(1);
    let requested = requested.unwrap_or(cpu_limit).max(1);
    requested.min(cpu_limit)
}

/// Release queued native Cases before a CPU-sized batch consumes recovery's working room
pub(super) fn batch_ready(
    queued: usize,
    workers: usize,
    memory: Option<&MemoryBudget>,
) -> Result<bool, MemoryError> {
    if queued == 0 {
        return Ok(false);
    }
    if queued >= workers {
        return Ok(true);
    }
    let Some(memory) = memory else {
        return Ok(false);
    };
    let snapshot = memory.snapshot()?;
    Ok(snapshot.used(MemoryClass::Case) >= snapshot.limit_bytes / CASE_BUFFER_DIVISOR)
}

/// One analyzed Case waiting for its bounded recovery batch
pub(super) struct PendingCase {
    item: workbench::full_source::FullSourceItem,
    kind: RecoveryCaseKind,
    scope: serde_json::Value,
}

impl PendingCase {
    pub(super) fn new(
        item: workbench::full_source::FullSourceItem,
    ) -> Result<Self, Box<dyn Error>> {
        // Keep the strong source identity in the exact scope used by recovery caching
        let (kind, scope) = match &item {
            workbench::full_source::FullSourceItem::Flow(analysis) => (
                RecoveryCaseKind::Flow,
                serde_json::json!({
                    "kind": "flow",
                    "source_id": analysis.flow.source_id,
                    "flow_id": analysis.flow.id,
                    "flow": serde_json::to_value(&analysis.flow)?,
                }),
            ),
            workbench::full_source::FullSourceItem::FlowPage(page) => (
                RecoveryCaseKind::Flow,
                serde_json::json!({
                    "kind": "flow_page",
                    "source_id": page.flow.source_id,
                    "flow_id": page.flow.id,
                    "page_index": page.page_index,
                    "first_packet": page.first_packet,
                    "last_packet": page.last_packet,
                    "selected_records": page.selected_records,
                    "retained_records": page.retained_records,
                    "omitted_records": page.omitted_records,
                    "flow": serde_json::to_value(&page.flow)?,
                }),
            ),
            workbench::full_source::FullSourceItem::Cohort(cohort) => {
                let source_id = cohort
                    .member_flows
                    .first()
                    .ok_or("indexed IP-pair cohort has no member flow")?
                    .source_id
                    .clone();
                (
                    RecoveryCaseKind::Cohort,
                    serde_json::json!({
                        "kind": "cohort",
                        "source_id": source_id,
                        "flow_ids": cohort.member_flows.iter().map(|flow| flow.id).collect::<Vec<_>>(),
                        "split": cohort.split,
                        "cohort_scope": cohort_scope(cohort)?,
                    }),
                )
            }
        };
        Ok(Self { item, kind, scope })
    }

    fn recover(
        &mut self,
        context: &RecoveryContext<'_>,
        memory: Option<&MemoryBudget>,
    ) -> Result<CachedRecovery, WorkerFailure> {
        // Cache work spends the same admitted credit as this Case's recovery
        let worker_cache = context
            .cache
            .zip(memory)
            .map(|(cache, memory)| cache.with_memory_scope(memory))
            .transpose()
            .map_err(|error| classify_worker_error(&error))?;
        let worker_context = RecoveryContext {
            memory,
            cache: worker_cache.as_ref().or(context.cache),
            ..*context
        };
        recover(
            case_mut(&mut self.item),
            self.kind,
            &self.scope,
            &worker_context,
        )
        .map_err(|error| classify_worker_error(error.as_ref()))
    }

    pub(super) const fn progress_counter(&self) -> Option<Counter> {
        match &self.item {
            workbench::full_source::FullSourceItem::Flow(_) => Some(Counter::Flows),
            workbench::full_source::FullSourceItem::FlowPage(_) => None,
            workbench::full_source::FullSourceItem::Cohort(_) => Some(Counter::Cohorts),
        }
    }
}

/// One Case with cached or freshly computed recovery, ready for serial output
pub(super) struct RecoveredCase<R = BuildResult> {
    pub(super) item: workbench::full_source::FullSourceItem<R>,
    pub(super) scope: serde_json::Value,
    pub(super) recovery: CachedRecovery,
}

/// Recover a bounded batch in parallel, then emit each result in source order
pub(super) fn process_case_batch(
    batch: &mut Vec<PendingCase>,
    pool: &rayon::ThreadPool,
    temporary_parent: &Path,
    context: &RecoveryContext<'_>,
    mut emit: impl FnMut(RecoveredCase) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    if batch.is_empty() {
        return Ok(());
    }
    let memory_limit = context
        .memory
        .map(MemoryBudget::snapshot)
        .transpose()?
        .map_or(context.options.memory_limit, |snapshot| {
            snapshot.limit_bytes
        });
    // Later resident results share one quarter of the allowance; emit the earliest directly
    let resident_limit = memory_limit / CASE_BUFFER_DIVISOR / u64::try_from(batch.len())?;
    let snapshot_limits = CaseSnapshotLimits::new(memory_limit, memory_limit);
    let next = AtomicUsize::new(0);
    // Workers finish independently; only small descriptors need to wait for source order
    let items = std::mem::take(batch).into_iter().enumerate().collect();
    process_ordered(
        pool,
        items,
        |(_, pending), active| admission::admit(pending, active, context),
        |(index, mut pending), working_set| {
            let recovery = pending.recover(context, working_set.memory())?;
            let PendingCase {
                mut item, scope, ..
            } = pending;
            let retained_bytes = case_mut(&mut item).charged_memory_bytes().unwrap_or(0);
            let spill = index > next.load(Ordering::Acquire) && retained_bytes > resident_limit;
            let mut observation = None;
            let item = item
                .try_map_result(|result| {
                    let buffered = if spill {
                        BufferedResult::spill(
                            result,
                            temporary_parent,
                            snapshot_limits,
                            working_set.memory(),
                            context.job,
                        )?
                    } else {
                        BufferedResult::Resident(Box::new(result))
                    };
                    observation = context
                        .memory
                        .map(|memory| buffered.observe(memory))
                        .transpose()?;
                    Ok::<_, Box<dyn Error>>(buffered)
                })
                .map_err(|error| classify_worker_error(error.as_ref()))?;
            Ok::<_, WorkerFailure>((
                // Early collection failure must end the observation before dropping its Case
                observation,
                RecoveredCase {
                    item,
                    scope,
                    recovery,
                },
            ))
        },
        |(buffered, case): (_, RecoveredCase<BufferedResult>)| {
            // End the wait before publication; the Case still owns its allocation charges
            drop(buffered);
            let item = case
                .item
                .try_map_result(|result| result.restore(pool, context.memory, context.job))?;
            if let Some(job) = context.job {
                job.check_cancelled()?;
            }
            emit(RecoveredCase {
                item,
                scope: case.scope,
                recovery: case.recovery,
            })?;
            next.fetch_add(1, Ordering::Release);
            Ok(())
        },
    )
}

#[derive(Debug)]
pub(super) struct WorkerFailure {
    message: String,
    cause: Option<WorkerCause>,
}

#[derive(Debug)]
enum WorkerCause {
    Memory(MemoryError),
    Job(JobError),
}

impl fmt::Display for WorkerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for WorkerFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.cause {
            Some(WorkerCause::Memory(error)) => Some(error),
            Some(WorkerCause::Job(error)) => Some(error),
            None => None,
        }
    }
}

pub(super) fn classify_worker_error(error: &(dyn Error + 'static)) -> WorkerFailure {
    WorkerFailure {
        message: error.to_string(),
        // Workers need a sendable cause without flattening cancellation into text
        cause: crate::memory_error::find_map(error, |cause| {
            cause
                .downcast_ref::<MemoryError>()
                .copied()
                .map(WorkerCause::Memory)
                .or_else(|| {
                    cause
                        .downcast_ref::<JobError>()
                        .copied()
                        .map(WorkerCause::Job)
                })
        }),
    }
}

fn case_mut(item: &mut workbench::full_source::FullSourceItem) -> &mut Case {
    match item {
        workbench::full_source::FullSourceItem::Flow(analysis) => &mut analysis.result.case,
        workbench::full_source::FullSourceItem::FlowPage(page) => &mut page.result.case,
        workbench::full_source::FullSourceItem::Cohort(cohort) => &mut cohort.result.case,
    }
}
