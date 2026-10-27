//! Bounded temporary reference tracking for Case validation

use super::{EvidenceError, memory::CaseMemory};
use crate::job::MemoryLease;

pub(super) struct BlobReferences {
    seen: Vec<bool>,
    count: usize,
    _memory: Option<MemoryLease>,
}

impl BlobReferences {
    pub(super) fn new(count: usize, memory: Option<&CaseMemory>) -> Result<Self, EvidenceError> {
        // One logical byte per blob replaces a hash table of the same indexes
        let requested = u64::try_from(count).map_err(|_| EvidenceError::ArithmeticOverflow {
            field: "blob reference tracking",
        })?;
        let mut lease = memory
            .map(|memory| memory.try_scratch(requested))
            .transpose()?;
        let mut seen = Vec::new();
        seen.try_reserve_exact(count)
            .map_err(|_| EvidenceError::AllocationFailed {
                field: "blob reference tracking",
            })?;
        if let Some(lease) = &mut lease {
            let capacity =
                u64::try_from(seen.capacity()).map_err(|_| EvidenceError::ArithmeticOverflow {
                    field: "blob reference tracking",
                })?;
            lease.try_resize(capacity).map_err(EvidenceError::Memory)?;
        }
        seen.resize(count, false);
        Ok(Self {
            seen,
            count: 0,
            _memory: lease,
        })
    }

    pub(super) fn insert(&mut self, index: usize) -> Result<(), EvidenceError> {
        let seen = self
            .seen
            .get_mut(index)
            .ok_or(EvidenceError::InconsistentResourceCount {
                field: "blob index",
            })?;
        if !*seen {
            *seen = true;
            self.count += 1;
        }
        Ok(())
    }

    pub(super) const fn len(&self) -> usize {
        self.count
    }
}
