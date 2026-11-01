//! Admission for byte buffers owned by the canonical derivation runner

use crate::job::{MemoryError, MemoryLease};
use std::convert::Infallible;

pub(super) trait Admission {
    type Error;
    type Lease;

    fn reserve(&self, bytes: u64) -> Result<Self::Lease, Self::Error>;
    fn resize(&self, lease: &mut Self::Lease, bytes: u64) -> Result<(), Self::Error>;
    fn reject_untracked_operation(&self) -> Result<(), Self::Error>;
    fn finish(self, output: Self::Lease, metadata: Self::Lease);
    fn is_active(&self) -> bool;
}

pub(super) struct Unrestricted;

impl Admission for Unrestricted {
    type Error = Infallible;
    type Lease = ();

    fn reserve(&self, _bytes: u64) -> Result<Self::Lease, Self::Error> {
        Ok(())
    }

    fn resize(&self, _lease: &mut Self::Lease, _bytes: u64) -> Result<(), Self::Error> {
        Ok(())
    }

    fn reject_untracked_operation(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn finish(self, _output: Self::Lease, _metadata: Self::Lease) {}

    fn is_active(&self) -> bool {
        false
    }
}

#[derive(Debug)]
pub(super) enum AdmissionError {
    Memory(MemoryError),
    UnsupportedOperation,
}

pub(super) struct Shared<'a>(pub &'a mut MemoryLease);

impl Admission for Shared<'_> {
    type Error = AdmissionError;
    type Lease = MemoryLease;

    fn reserve(&self, bytes: u64) -> Result<Self::Lease, Self::Error> {
        self.0.try_sibling(bytes).map_err(AdmissionError::Memory)
    }

    fn resize(&self, lease: &mut Self::Lease, bytes: u64) -> Result<(), Self::Error> {
        lease.try_resize(bytes).map_err(AdmissionError::Memory)
    }

    fn reject_untracked_operation(&self) -> Result<(), Self::Error> {
        Err(AdmissionError::UnsupportedOperation)
    }

    fn finish(self, output: Self::Lease, metadata: Self::Lease) {
        self.0.absorb(output);
        self.0.absorb(metadata);
    }

    fn is_active(&self) -> bool {
        true
    }
}

pub(super) enum BufferError<E> {
    Allocation,
    Admission(E),
}

// Fields drop in order so the allocation disappears before its charge
pub(super) struct Buffer<A: Admission> {
    pub bytes: Vec<u8>,
    lease: A::Lease,
}

impl<A: Admission> Buffer<A> {
    pub fn with_capacity(capacity: usize, admission: &A) -> Result<Self, BufferError<A::Error>> {
        let requested = u64::try_from(capacity).map_err(|_| BufferError::Allocation)?;
        let lease = admission
            .reserve(requested)
            .map_err(BufferError::Admission)?;
        let mut buffer = Self {
            bytes: Vec::new(),
            lease,
        };
        // Exact reservation avoids the default Vec growth policy for new buffers
        buffer
            .bytes
            .try_reserve_exact(capacity)
            .map_err(|_| BufferError::Allocation)?;
        let actual = u64::try_from(buffer.bytes.capacity()).map_err(|_| BufferError::Allocation)?;
        // Allocators may provide more capacity than requested, so reconcile at once
        admission
            .resize(&mut buffer.lease, actual)
            .map_err(BufferError::Admission)?;
        Ok(buffer)
    }

    pub const fn from_untracked(bytes: Vec<u8>, lease: A::Lease) -> Self {
        Self { bytes, lease }
    }

    pub fn extend_bounded(
        &mut self,
        source: &[u8],
        maximum: usize,
        admission: &A,
    ) -> Result<(), BufferError<A::Error>> {
        let required = self
            .bytes
            .len()
            .checked_add(source.len())
            .ok_or(BufferError::Allocation)?;
        if required > self.bytes.capacity() {
            if admission.is_active() {
                let next = self
                    .bytes
                    .capacity()
                    .saturating_mul(2)
                    .max(required)
                    .min(maximum);
                // The old and new allocations both remain charged while bytes move
                let mut replacement = Self::with_capacity(next, admission)?;
                replacement.bytes.extend_from_slice(&self.bytes);
                *self = replacement;
            } else {
                self.bytes
                    .try_reserve(source.len())
                    .map_err(|_| BufferError::Allocation)?;
            }
        }
        self.bytes.extend_from_slice(source);
        Ok(())
    }

    pub fn into_parts(self) -> (Vec<u8>, A::Lease) {
        (self.bytes, self.lease)
    }
}
