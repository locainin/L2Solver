//! Shared admission for canonical region candidates and proposal reports

use crate::{
    allocation::{VectorAllocationError, reserve_one_with_memory},
    job::{MemoryError, MemoryLease},
    recovery::proposals::{
        ProposalMemoryError, TransformProposalBudget, TransformProposalReport, propose_transforms,
        propose_transforms_with_memory,
    },
};
use std::{convert::Infallible, error::Error, fmt};

#[derive(Debug)]
pub(crate) enum RegionMemoryError {
    Memory(MemoryError),
    Allocation,
}

impl fmt::Display for RegionMemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory(error) => error.fmt(formatter),
            Self::Allocation => formatter.write_str("transform region allocation failed"),
        }
    }
}

impl Error for RegionMemoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            Self::Allocation => None,
        }
    }
}

impl From<MemoryError> for RegionMemoryError {
    fn from(error: MemoryError) -> Self {
        Self::Memory(error)
    }
}

impl From<VectorAllocationError> for RegionMemoryError {
    fn from(error: VectorAllocationError) -> Self {
        match error {
            VectorAllocationError::Memory(error) => Self::Memory(error),
            VectorAllocationError::Allocation => Self::Allocation,
        }
    }
}

impl From<ProposalMemoryError> for RegionMemoryError {
    fn from(error: ProposalMemoryError) -> Self {
        match error {
            ProposalMemoryError::Memory(error) => Self::Memory(error),
            ProposalMemoryError::Allocation => Self::Allocation,
        }
    }
}

pub(super) trait RegionAdmission {
    type Error;
    type Lease;

    fn lease(&self) -> Result<Self::Lease, Self::Error>;
    fn charge(&self, lease: &mut Self::Lease, bytes: usize) -> Result<(), Self::Error>;
    fn reserve_one<T>(
        &self,
        values: &mut Vec<T>,
        lease: &mut Self::Lease,
    ) -> Result<(), Self::Error>;
    fn propose(
        &self,
        input: &[u8],
        budget: TransformProposalBudget,
        lease: &mut Self::Lease,
    ) -> Result<TransformProposalReport, Self::Error>;
    fn absorb(&self, target: &mut Self::Lease, source: Self::Lease);
    fn finish(self, retained: Self::Lease);
}

pub(super) struct Unlimited;

impl RegionAdmission for Unlimited {
    type Error = Infallible;
    type Lease = ();

    fn lease(&self) -> Result<Self::Lease, Self::Error> {
        Ok(())
    }

    fn charge(&self, _lease: &mut Self::Lease, _bytes: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn reserve_one<T>(
        &self,
        _values: &mut Vec<T>,
        _lease: &mut Self::Lease,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn propose(
        &self,
        input: &[u8],
        budget: TransformProposalBudget,
        _lease: &mut Self::Lease,
    ) -> Result<TransformProposalReport, Self::Error> {
        Ok(propose_transforms(input, budget))
    }

    fn absorb(&self, _target: &mut Self::Lease, _source: Self::Lease) {}

    fn finish(self, _retained: Self::Lease) {}
}

pub(super) struct Shared<'a>(pub(super) &'a mut MemoryLease);

impl RegionAdmission for Shared<'_> {
    type Error = RegionMemoryError;
    type Lease = MemoryLease;

    fn lease(&self) -> Result<Self::Lease, Self::Error> {
        self.0.try_sibling(0).map_err(Into::into)
    }

    fn charge(&self, lease: &mut Self::Lease, bytes: usize) -> Result<(), Self::Error> {
        let total = u64::try_from(bytes)
            .ok()
            .and_then(|bytes| lease.bytes().checked_add(bytes))
            .ok_or(RegionMemoryError::Allocation)?;
        lease.try_resize(total).map_err(Into::into)
    }

    fn reserve_one<T>(
        &self,
        values: &mut Vec<T>,
        lease: &mut Self::Lease,
    ) -> Result<(), Self::Error> {
        reserve_one_with_memory(values, lease).map_err(Into::into)
    }

    fn propose(
        &self,
        input: &[u8],
        budget: TransformProposalBudget,
        lease: &mut Self::Lease,
    ) -> Result<TransformProposalReport, Self::Error> {
        propose_transforms_with_memory(input, budget, lease).map_err(Into::into)
    }

    fn absorb(&self, target: &mut Self::Lease, source: Self::Lease) {
        target.absorb(source);
    }

    fn finish(self, retained: Self::Lease) {
        self.0.absorb(retained);
    }
}
