//! Durable checkpoints of the shared scheduler job state

use crate::result_directory::ResultIdentity;
use l2_workbench::job::{
    Job, PhaseState,
    cache::{Cache, CheckpointStatus, StageKey},
};
use serde_json::json;
use std::{
    error::Error,
    io,
    sync::mpsc,
    thread::{self, JoinHandle},
    time::Duration,
};

pub struct CheckpointWriter {
    cache: Cache,
    key: StageKey,
    job: Job,
    stop: Option<mpsc::Sender<()>>,
    worker: Option<JoinHandle<Result<(), String>>>,
}

impl CheckpointWriter {
    pub fn start(
        cache: &Cache,
        identity: &ResultIdentity,
        job: &Job,
        refresh: bool,
    ) -> Result<Self, Box<dyn Error>> {
        let key = StageKey::new(
            "recovery_job",
            2,
            "l2-recovery-job-v2",
            &json!({"kind": identity.kind, "algorithm_version": identity.algorithm_version,
                "settings": identity.settings}),
            &identity.source,
            &[],
        )?;
        if !refresh
            && let Some(saved) = cache.read_checkpoint(&key)?
            && saved.status == CheckpointStatus::Active
        {
            let mut snapshot = saved.snapshot;
            // Committed stages replay from cache entries during this pipeline pass
            for phase in &mut snapshot.phases {
                phase.state = PhaseState::Pending;
            }
            snapshot.current_phase = None;
            job.restore(snapshot)?;
        }
        cache.write_checkpoint(&key, &job.snapshot()?, CheckpointStatus::Active)?;
        let (stop, receiver) = mpsc::channel();
        let worker_cache = cache.clone();
        let worker_key = key.clone();
        let worker_job = job.clone();
        let worker = thread::Builder::new()
            .name("l2-checkpoint".into())
            .spawn(move || {
                loop {
                    match receiver.recv_timeout(Duration::from_secs(1)) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            let snapshot =
                                worker_job.snapshot().map_err(|error| error.to_string())?;
                            worker_cache
                                .write_checkpoint(&worker_key, &snapshot, CheckpointStatus::Active)
                                .map_err(|error| error.to_string())?;
                        }
                    }
                }
                Ok(())
            })?;
        Ok(Self {
            cache: cache.clone(),
            key,
            job: job.clone(),
            stop: Some(stop),
            worker: Some(worker),
        })
    }

    pub fn finish(mut self, finished: bool) -> Result<(), Box<dyn Error>> {
        self.stop_worker()?;
        self.cache.write_checkpoint(
            &self.key,
            &self.job.snapshot()?,
            if finished {
                CheckpointStatus::Complete
            } else {
                CheckpointStatus::Active
            },
        )?;
        self.cache.checkpoint_wal()?;
        Ok(())
    }

    fn stop_worker(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| io::Error::other("checkpoint worker panicked"))?
                .map_err(io::Error::other)?;
        }
        Ok(())
    }
}

impl Drop for CheckpointWriter {
    fn drop(&mut self) {
        let _ = self.stop_worker();
    }
}

#[cfg(test)]
#[path = "../../tests/recovery_job/checkpoint.rs"]
mod tests;
