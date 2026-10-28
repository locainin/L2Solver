//! Admit coordinator encoding capacity before retaining checkpoint bytes

use super::{RecoveryError, RecoveryExecutionError, operational};
use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryLease};
use std::io::{self, Write};

pub(super) struct Buffer {
    pub(super) bytes: Vec<u8>,
    pub(super) failure: Option<RecoveryExecutionError>,
    pub(super) memory: Option<MemoryLease>,
    maximum: usize,
}

impl Buffer {
    pub(super) fn new(
        maximum: usize,
        memory: Option<&MemoryBudget>,
    ) -> Result<Self, RecoveryExecutionError> {
        Ok(Self {
            bytes: Vec::new(),
            failure: None,
            memory: memory
                .map(|budget| budget.try_reserve(MemoryClass::Executor, 0))
                .transpose()
                .map_err(operational)?,
            maximum,
        })
    }

    fn grow(&mut self, required: usize) -> Result<(), RecoveryExecutionError> {
        if required <= self.bytes.capacity() {
            return Ok(());
        }
        // The coordinator writer already checks the total encoded byte limit
        let capacity = required
            .max(self.bytes.capacity().saturating_mul(2))
            .min(self.maximum);
        if let Some(memory) = &mut self.memory {
            // A growing Vec can briefly retain both the old and replacement allocation
            let peak = self
                .bytes
                .capacity()
                .checked_add(capacity)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(RecoveryError::AllocationFailed)?;
            memory.try_resize(peak).map_err(operational)?;
        }
        self.bytes
            .try_reserve_exact(capacity - self.bytes.len())
            .map_err(|_| RecoveryError::AllocationFailed)?;
        if let Some(memory) = &mut self.memory {
            memory
                .try_resize(
                    u64::try_from(self.bytes.capacity())
                        .map_err(|_| RecoveryError::AllocationFailed)?,
                )
                .map_err(operational)?;
        }
        Ok(())
    }
}

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Err(error) = self.grow(self.bytes.len() + bytes.len()) {
            self.failure = Some(error);
            return Err(io::Error::other("checkpoint buffer growth failed"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
