//! Fixed shared-memory admission for copying source-backed artifact ranges

use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryLease};
use std::{error::Error, io};

const MAX_COPY_BUFFER_BYTES: u64 = 16 * 1024;

pub(super) struct PublicationBuffer {
    bytes: Vec<u8>,
    _lease: MemoryLease,
}

impl PublicationBuffer {
    pub(super) fn try_new(memory: &MemoryBudget) -> Result<Self, Box<dyn Error>> {
        // The copy size stays fixed across runs with the same settings
        let requested = MAX_COPY_BUFFER_BYTES;
        let mut lease = memory.try_reserve(MemoryClass::Publication, requested)?;
        let length = usize::try_from(requested)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(io::Error::other)?;
        lease.try_resize(u64::try_from(bytes.capacity())?)?;
        bytes.resize(length, 0);
        Ok(Self {
            bytes,
            _lease: lease,
        })
    }

    pub(super) fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}
