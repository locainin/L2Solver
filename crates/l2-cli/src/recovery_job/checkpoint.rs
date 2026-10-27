//! Durable checkpoints of the shared scheduler job state

use crate::result_directory::ResultIdentity;
use l2_workbench::job::{
    Job, JobError, JobSnapshot, PhaseState,
    cache::{Cache, CacheError, CheckpointStatus, StageKey},
};
use serde_json::json;
use std::{
    error::Error,
    fmt, io,
    sync::mpsc,
    thread::{self, JoinHandle},
    time::Duration,
};

#[derive(Debug)]
pub(super) enum CheckpointError {
    Cache(CacheError),
    // An invalid identity cannot be repaired by skipping the cache
    Identity(CacheError),
    Job(JobError),
    WorkerStart(io::Error),
    WorkerPanicked,
}

impl CheckpointError {
    pub(super) const fn is_cache_failure(&self) -> bool {
        matches!(self, Self::Cache(_) | Self::WorkerStart(_))
    }
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cache(error) | Self::Identity(error) => error.fmt(formatter),
            Self::Job(error) => error.fmt(formatter),
            Self::WorkerStart(error) => {
                write!(formatter, "checkpoint worker could not start: {error}")
            }
            Self::WorkerPanicked => formatter.write_str("checkpoint worker panicked"),
        }
    }
}

impl Error for CheckpointError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Cache(error) | Self::Identity(error) => Some(error),
            Self::Job(error) => Some(error),
            Self::WorkerStart(error) => Some(error),
            Self::WorkerPanicked => None,
        }
    }
}

impl From<CacheError> for CheckpointError {
    fn from(error: CacheError) -> Self {
        Self::Cache(error)
    }
}

impl From<JobError> for CheckpointError {
    fn from(error: JobError) -> Self {
        Self::Job(error)
    }
}

enum WorkerCommand {
    Start,
    Stop,
}

pub(super) struct CheckpointWriter {
    cache: Cache,
    key: StageKey,
    job: Job,
    stop: Option<mpsc::Sender<WorkerCommand>>,
    worker: Option<JoinHandle<Result<(), CheckpointError>>>,
}

impl CheckpointWriter {
    pub(super) fn start(
        cache: &Cache,
        identity: &ResultIdentity,
        job: &Job,
        refresh: bool,
    ) -> Result<Self, CheckpointError> {
        let key = StageKey::new(
            "recovery_job",
            3,
            "l2-recovery-job-v3",
            &json!({"kind": identity.kind, "algorithm_version": identity.algorithm_version,
                "settings": identity.settings}),
            &identity.source,
            &[],
        )
        .map_err(CheckpointError::Identity)?;
        let saved_snapshot = if refresh {
            None
        } else {
            cache.read_checkpoint(&key)?.and_then(|saved| {
                (saved.status == CheckpointStatus::Active).then_some(saved.snapshot)
            })
        };
        let saved_snapshot = saved_snapshot.map(|mut snapshot| {
            // Every stage replays from cache or starts a fresh bounded pass
            for phase in &mut snapshot.phases {
                // Cumulative job counters retain prior work, including evicted stages
                phase.completed = 0;
                phase.elapsed_ms = 0;
                phase.state = PhaseState::Pending;
            }
            snapshot.current_phase = None;
            snapshot
        });
        let initial_snapshot = preview_snapshot(job, saved_snapshot.as_ref())?;
        let (stop, receiver) = mpsc::channel();
        let worker_cache = cache.clone();
        let worker_key = key.clone();
        let worker_job = job.clone();
        let worker = thread::Builder::new()
            .name("l2-checkpoint".into())
            .spawn(move || {
                // Do not observe the live job until restoration has succeeded
                match receiver.recv() {
                    Ok(WorkerCommand::Start) => {}
                    Ok(WorkerCommand::Stop) | Err(_) => return Ok(()),
                }
                loop {
                    match receiver.recv_timeout(Duration::from_secs(1)) {
                        Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            let snapshot = worker_job.checkpoint_snapshot()?;
                            worker_cache.write_checkpoint(
                                &worker_key,
                                &snapshot,
                                CheckpointStatus::Active,
                            )?;
                        }
                    }
                }
                Ok(())
            })
            .map_err(CheckpointError::WorkerStart)?;
        let writer = Self {
            cache: cache.clone(),
            key,
            job: job.clone(),
            stop: Some(stop.clone()),
            worker: Some(worker),
        };
        // A failed worker startup must leave the previous checkpoint untouched
        job.check_cancelled()?;
        writer
            .cache
            .write_checkpoint(&writer.key, &initial_snapshot, CheckpointStatus::Active)?;
        job.check_cancelled()?;
        if let Some(snapshot) = saved_snapshot {
            job.restore(snapshot)?;
        }
        stop.send(WorkerCommand::Start)
            .map_err(|_| CheckpointError::WorkerPanicked)?;
        Ok(writer)
    }

    pub(super) fn finish(mut self, finished: bool) -> Result<(), CheckpointError> {
        self.stop_worker()?;
        self.cache.write_checkpoint(
            &self.key,
            &self.job.checkpoint_snapshot()?,
            if finished {
                CheckpointStatus::Complete
            } else {
                CheckpointStatus::Active
            },
        )?;
        self.cache.checkpoint_wal()?;
        Ok(())
    }

    fn stop_worker(&mut self) -> Result<(), CheckpointError> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(WorkerCommand::Stop);
        }
        if let Some(worker) = self.worker.take() {
            // Keep worker failures distinct from a later cache write
            worker
                .join()
                .map_err(|_| CheckpointError::WorkerPanicked)??;
        }
        Ok(())
    }
}

fn preview_snapshot(
    job: &Job,
    saved: Option<&JobSnapshot>,
) -> Result<JobSnapshot, CheckpointError> {
    let current = job.checkpoint_snapshot()?;
    let Some(saved) = saved else {
        return Ok(current);
    };
    // Match the live restore precondition before constructing a detached preview
    if current.current_phase.is_some()
        || current
            .phases
            .iter()
            .any(|phase| phase.state != PhaseState::Pending)
    {
        return Err(JobError::RestoreAfterStart.into());
    }
    let preview = Job::new("checkpoint preview");
    if current.cancel_requested {
        preview.request_cancel();
    }
    preview.restore(current)?;
    preview.restore(saved.clone())?;
    Ok(preview.checkpoint_snapshot()?)
}

impl Drop for CheckpointWriter {
    fn drop(&mut self) {
        let _ = self.stop_worker();
    }
}

#[cfg(test)]
#[path = "../../tests/recovery_job/checkpoint.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/recovery_job/progress.rs"]
mod progress_tests;
