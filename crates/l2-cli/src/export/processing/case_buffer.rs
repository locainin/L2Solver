//! Spill completed Case graphs without changing source metadata or publication order

#[cfg(test)]
#[path = "../../../tests/export/case_buffer.rs"]
mod tests;

use l2_workbench::{
    evidence::{CaseSnapshotLimits, CaseSnapshotUsage},
    investigation::BuildResult,
    job::{BufferedCase, Job, MemoryBudget, MemoryError},
};
use std::{error::Error, fs::File, path::Path};

pub(super) enum BufferedResult {
    Resident(Box<BuildResult>),
    Snapshot {
        graph: File,
        blobs: File,
        usage: CaseSnapshotUsage,
        limits: CaseSnapshotLimits,
        complete: bool,
    },
}

impl BufferedResult {
    pub(super) fn observe(&self, memory: &MemoryBudget) -> Result<BufferedCase, MemoryError> {
        match self {
            Self::Resident(result) => {
                memory.observe_buffered_case(result.case.charged_memory_bytes().unwrap_or(0))
            }
            // The writer bounds the combined streams before returning this usage
            Self::Snapshot { usage, .. } => {
                memory.observe_spilled_case(usage.graph_bytes + usage.blob_pack_bytes)
            }
        }
    }

    pub(super) fn spill(
        result: BuildResult,
        directory: &Path,
        limits: CaseSnapshotLimits,
        memory: Option<&MemoryBudget>,
        job: Option<&Job>,
    ) -> Result<Self, Box<dyn Error>> {
        // Keep anonymous descriptors open; no path can be replaced before collection
        let mut graph = tempfile::tempfile_in(directory)?;
        let mut blobs = tempfile::tempfile_in(directory)?;
        let usage = crate::case_snapshot::write_files_cancellable(
            &mut graph,
            &mut blobs,
            &result.case,
            limits,
            memory,
            job,
        )?;
        let complete = result.complete;
        // Release the full graph before placing the completion in the ordered queue
        drop(result);
        Ok(Self::Snapshot {
            graph,
            blobs,
            usage,
            limits,
            complete,
        })
    }

    pub(super) fn restore(
        self,
        pool: &rayon::ThreadPool,
        memory: Option<&MemoryBudget>,
        job: Option<&Job>,
    ) -> Result<BuildResult, Box<dyn Error>> {
        if let Some(job) = job {
            job.check_cancelled()?;
        }
        match self {
            Self::Resident(result) => Ok(*result),
            Self::Snapshot {
                mut graph,
                mut blobs,
                usage,
                limits,
                complete,
            } => {
                // Reuse worker allocation arenas instead of building another graph in the collector
                pool.install(move || {
                    let case = crate::case_snapshot::read_files_cancellable(
                        &mut graph, &mut blobs, usage, limits, memory, job,
                    )
                    .map_err(|error| super::classify_worker_error(error.as_ref()))?;
                    Ok::<_, super::WorkerFailure>(BuildResult { case, complete })
                })
                .map_err(Into::into)
            }
        }
    }
}
