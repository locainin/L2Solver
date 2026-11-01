//! Observe kernel memory independently of progress rendering and cache writes

use super::Reader;
use crate::recovery_job::MEMORY_OBSERVATION_INTERVAL;
use l2_workbench::job::MemoryBudget;
use std::{
    error::Error,
    io,
    path::Path,
    sync::mpsc::{self, Sender},
    thread::{self, JoinHandle},
};

pub(in crate::recovery_job) struct Monitor {
    stop: Sender<()>,
    worker: Option<JoinHandle<Result<(), l2_workbench::job::MemoryError>>>,
}

impl Monitor {
    pub(in crate::recovery_job) fn start(memory: &MemoryBudget) -> Result<Self, Box<dyn Error>> {
        // Record the first attempt before recovery can admit a Case, even if the read fails
        observe(memory)?;
        let memory = memory.clone();
        let (stop, receiver) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("l2-memory-pressure".to_owned())
            .spawn(move || {
                loop {
                    match receiver.recv_timeout(MEMORY_OBSERVATION_INTERVAL) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => match observe(&memory) {
                            Ok(()) | Err(l2_workbench::job::MemoryError::SystemObservationBusy) => {
                            }
                            Err(error) => return Err(error),
                        },
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
    memory.try_observe_system_memory_with(|| {
        Reader::open(Path::new("/proc/self")).and_then(|reader| reader.sample())
    })
}
