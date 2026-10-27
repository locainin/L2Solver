//! Shared admission for live publication encoding buffers

use crate::job::{MemoryBudget, MemoryClass, MemoryError, MemoryLease};
use std::{
    cell::{Cell, RefCell},
    io,
};

pub(super) struct Scratch {
    lease: RefCell<Option<MemoryLease>>,
    failure: Cell<Option<MemoryError>>,
}

impl Scratch {
    pub(super) fn new(budget: Option<&MemoryBudget>) -> io::Result<Self> {
        let lease = budget
            .map(|budget| budget.try_reserve(MemoryClass::Publication, 0))
            .transpose()
            .map_err(io::Error::other)?;
        Ok(Self {
            lease: RefCell::new(lease),
            failure: Cell::new(None),
        })
    }

    pub(super) fn claim(&self, bytes: u64) -> io::Result<Charge<'_>> {
        self.grow(bytes, false)?;
        Ok(Charge {
            scratch: self,
            bytes,
        })
    }

    pub(super) fn grow(&self, bytes: u64, optional: bool) -> io::Result<bool> {
        let mut lease = self.lease.borrow_mut();
        let Some(lease) = lease.as_mut() else {
            return Ok(true);
        };
        let total = lease
            .bytes()
            .checked_add(bytes)
            .ok_or_else(|| io::Error::other("publication scratch count overflow"))?;
        match lease.try_resize(total) {
            Ok(()) => Ok(true),
            Err(MemoryError::Limit { .. }) if optional => Ok(false),
            Err(error) => {
                self.failure.set(Some(error));
                Err(io::Error::other(error))
            }
        }
    }

    fn release(&self, bytes: u64) {
        let mut lease = self.lease.borrow_mut();
        if let Some(lease) = lease.as_mut()
            && let Err(error) = lease.try_resize(lease.bytes() - bytes)
        {
            self.failure.set(Some(error));
        }
    }

    pub(super) fn error(
        &self,
        error: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> io::Error {
        self.failure
            .get()
            .map_or_else(|| io::Error::other(error), io::Error::other)
    }

    pub(super) fn check(&self) -> io::Result<()> {
        self.failure
            .get()
            .map_or(Ok(()), |error| Err(io::Error::other(error)))
    }
}

pub(super) struct Charge<'a> {
    scratch: &'a Scratch,
    bytes: u64,
}

impl Charge<'_> {
    pub(super) fn grow(&mut self, bytes: u64, optional: bool) -> io::Result<bool> {
        if !self.scratch.grow(bytes, optional)? {
            return Ok(false);
        }
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| io::Error::other("publication scratch count overflow"))?;
        Ok(true)
    }
}

impl Drop for Charge<'_> {
    fn drop(&mut self) {
        self.scratch.release(self.bytes);
    }
}
