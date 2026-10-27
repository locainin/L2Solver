//! Recover Cases in bounded batches before serial export

use super::{
    coverage::RecoveryCaseKind,
    provenance::cohort_scope,
    recovery_cache::{CachedRecovery, RecoveryContext, recover},
};
use crate::workbench;
use l2_workbench::{
    evidence::Case,
    job::{Counter, Job, Phase, PhaseOutcome},
};
use std::{error::Error, io, sync::mpsc};

// A batch holds one bounded Case and active recovery graph per worker
const RECOVERY_WORKER_RESERVATION_BYTES: u64 = 128 * 1024 * 1024;
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

/// Bound parallel recovery by requested workers, available CPUs, and a per-worker reserve
///
/// The memory limit bounds each Case's recovery materialization, not exact process RSS
/// The reserve limits concurrent Case materialization
pub(super) fn recovery_worker_count(
    requested: Option<usize>,
    available_cpus: usize,
    memory_limit_bytes: u64,
) -> usize {
    let cpu_limit = available_cpus.max(1);
    let requested = requested.unwrap_or(cpu_limit).max(1);
    let memory_limit = usize::try_from(memory_limit_bytes / RECOVERY_WORKER_RESERVATION_BYTES)
        .unwrap_or(usize::MAX)
        .max(1);
    requested.min(cpu_limit).min(memory_limit)
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

    pub(super) const fn progress_counter(&self) -> Option<Counter> {
        match &self.item {
            workbench::full_source::FullSourceItem::Flow(_) => Some(Counter::Flows),
            workbench::full_source::FullSourceItem::FlowPage(_) => None,
            workbench::full_source::FullSourceItem::Cohort(_) => Some(Counter::Cohorts),
        }
    }
}

/// One Case with cached or freshly computed recovery, ready for serial output
pub(super) struct RecoveredCase {
    pub(super) item: workbench::full_source::FullSourceItem,
    pub(super) scope: serde_json::Value,
    pub(super) recovery: CachedRecovery,
}

/// Recover a bounded batch in parallel, then emit each result in source order
pub(super) fn process_case_batch(
    batch: &mut Vec<PendingCase>,
    pool: &rayon::ThreadPool,
    context: &RecoveryContext<'_>,
    emit: impl FnMut(RecoveredCase) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    if batch.is_empty() {
        return Ok(());
    }
    if batch.len() > pool.current_num_threads() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recovery batch exceeds the worker count",
        )
        .into());
    }
    // Send finished Cases to the collector while later recovery work is still active
    let items = std::mem::take(batch);
    process_ordered(
        pool,
        items,
        |pending| {
            let PendingCase {
                mut item,
                kind,
                scope,
            } = pending;
            let recovery = recover(case_mut(&mut item), kind, &scope, context)
                .map_err(|error| error.to_string())?;
            Ok(RecoveredCase {
                item,
                scope,
                recovery,
            })
        },
        emit,
    )
}

/// Run a bounded batch and emit its completed prefix in source order
pub(super) fn process_ordered<T: Send, U: Send>(
    pool: &rayon::ThreadPool,
    items: Vec<T>,
    work: impl Fn(T) -> Result<U, String> + Sync,
    mut emit: impl FnMut(U) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    // The collector cannot occupy a worker whose result it needs to receive
    if pool.current_thread_index().is_some() {
        return Err(
            io::Error::other("ordered collection cannot run inside its recovery pool").into(),
        );
    }
    let count = items.len();
    let mut waiting = std::iter::repeat_with(|| None)
        .take(count)
        .collect::<Vec<_>>();
    let (sender, receiver) = mpsc::sync_channel(count);
    pool.in_place_scope_fifo(|scope| {
        for (index, item) in items.into_iter().enumerate() {
            let sender = sender.clone();
            let work = &work;
            scope.spawn_fifo(move |_| {
                // Dropping the receiver ends collection after an error
                let _ = sender.send((index, work(item)));
            });
        }
        drop(sender);
        let outcome = (|| {
            let mut next = 0;
            for _ in 0..count {
                let (index, result) = receiver.recv().map_err(|_| {
                    io::Error::other("recovery worker stopped before producing all results")
                })?;
                let slot = waiting.get_mut(index).ok_or_else(|| {
                    io::Error::other("recovery worker returned an invalid result index")
                })?;
                *slot = Some(result);
                // Release each available prefix Case before waiting for later results
                while let Some(result) = waiting.get_mut(next).and_then(Option::take) {
                    let result = result
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                    emit(result)?;
                    next += 1;
                }
            }
            Ok(())
        })();
        drop(receiver);
        outcome
    })
}

fn case_mut(item: &mut workbench::full_source::FullSourceItem) -> &mut Case {
    match item {
        workbench::full_source::FullSourceItem::Flow(analysis) => &mut analysis.result.case,
        workbench::full_source::FullSourceItem::FlowPage(page) => &mut page.result.case,
        workbench::full_source::FullSourceItem::Cohort(cohort) => &mut cohort.result.case,
    }
}
