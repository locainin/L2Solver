//! Observe kernel memory independently of progress rendering and cache writes

use super::Reader;
use l2_workbench::job::MemoryBudget;
use std::{
    error::Error,
    io,
    path::Path,
    sync::mpsc::{self, Sender},
    thread::{self, JoinHandle},
    time::Duration,
};

const INTERVAL: Duration = Duration::from_millis(250);

pub(in crate::recovery_job) struct Monitor {
    stop: Sender<()>,
    worker: Option<JoinHandle<Result<(), l2_workbench::job::MemoryError>>>,
}

impl Monitor {
    pub(in crate::recovery_job) fn start(memory: &MemoryBudget) -> Result<Self, Box<dyn Error>> {
        // The first observation is ready before recovery can admit a Case
        observe(memory)?;
        let memory = memory.clone();
        let (stop, receiver) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("l2-memory-pressure".to_owned())
            .spawn(move || {
                loop {
                    match receiver.recv_timeout(INTERVAL) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => observe(&memory)?,
                    }
                }
                // Include final publication and cache-cleanup usage in the last snapshot
                observe(&memory)
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }

    pub(in crate::recovery_job) fn finish(mut self) -> Result<(), Box<dyn Error>> {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| io::Error::other("memory observation worker panicked"))??;
        }
        Ok(())
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        // The explicit finish path joins and reports errors; early return only requests stop
        let _ = self.stop.send(());
    }
}

pub(in crate::recovery_job) fn observe(
    memory: &MemoryBudget,
) -> Result<(), l2_workbench::job::MemoryError> {
    // Reopen proc metadata so moving the process between cgroups cannot leave an old path active
    let sample = Reader::open(Path::new("/proc/self")).and_then(|reader| reader.sample());
    memory.observe_system_memory(sample.ok())
}
