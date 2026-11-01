//! Admit DER inventories and retained values as the parser grows them

use super::{DerError, DerNode};
use crate::job::{MemoryError, MemoryLease};
use std::{fmt, io::Write};

pub(super) trait Admission {
    type Error: From<DerError>;

    fn reserve_node(&mut self, nodes: &mut Vec<DerNode>) -> Result<(), Self::Error>;
    fn copy_preview(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn format_oid(&mut self, value: &impl fmt::Display) -> Result<String, Self::Error>;
}

pub(super) struct Unmetered;

impl Admission for Unmetered {
    type Error = DerError;

    fn reserve_node(&mut self, nodes: &mut Vec<DerNode>) -> Result<(), Self::Error> {
        nodes
            .try_reserve(1)
            .map_err(|_| DerError::AllocationFailure)
    }

    fn copy_preview(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut preview = Vec::new();
        preview
            .try_reserve_exact(bytes.len())
            .map_err(|_| DerError::AllocationFailure)?;
        preview.extend_from_slice(bytes);
        Ok(preview)
    }

    fn format_oid(&mut self, value: &impl fmt::Display) -> Result<String, Self::Error> {
        let mut output = string_with_capacity(formatted_length(value)?)?;
        fmt::write(&mut output, format_args!("{value}"))
            .map_err(|_| DerError::AllocationFailure)?;
        Ok(output)
    }
}

#[derive(Debug)]
pub(in crate::artifact) enum DerMemoryError {
    Format(DerError),
    Memory(MemoryError),
}

impl From<DerError> for DerMemoryError {
    fn from(error: DerError) -> Self {
        Self::Format(error)
    }
}

impl From<MemoryError> for DerMemoryError {
    fn from(error: MemoryError) -> Self {
        Self::Memory(error)
    }
}

pub(super) struct Metered<'a>(pub(super) &'a mut MemoryLease);

impl Admission for Metered<'_> {
    type Error = DerMemoryError;

    fn reserve_node(&mut self, nodes: &mut Vec<DerNode>) -> Result<(), Self::Error> {
        crate::allocation::reserve_one_with_memory(nodes, self.0).map_err(|error| match error {
            crate::allocation::VectorAllocationError::Memory(error) => error.into(),
            crate::allocation::VectorAllocationError::Allocation => {
                DerError::AllocationFailure.into()
            }
        })
    }

    fn copy_preview(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let requested = u64::try_from(bytes.len()).map_err(|_| DerError::AllocationFailure)?;
        let mut pending = self.0.try_sibling(requested)?;
        let mut preview = Vec::new();
        preview
            .try_reserve_exact(bytes.len())
            .map_err(|_| DerError::AllocationFailure)?;
        pending.try_resize(
            u64::try_from(preview.capacity()).map_err(|_| DerError::AllocationFailure)?,
        )?;
        preview.extend_from_slice(bytes);
        self.0.absorb(pending);
        Ok(preview)
    }

    fn format_oid(&mut self, value: &impl fmt::Display) -> Result<String, Self::Error> {
        let length = formatted_length(value)?;
        let requested = u64::try_from(length).map_err(|_| DerError::AllocationFailure)?;
        let mut pending = self.0.try_sibling(requested)?;
        let mut output = string_with_capacity(length)?;
        pending.try_resize(
            u64::try_from(output.capacity()).map_err(|_| DerError::AllocationFailure)?,
        )?;
        fmt::write(&mut output, format_args!("{value}"))
            .map_err(|_| DerError::AllocationFailure)?;
        self.0.absorb(pending);
        Ok(output)
    }
}

fn formatted_length(value: &impl fmt::Display) -> Result<usize, DerError> {
    let mut counter = crate::serialization::CountWriter::new(usize::MAX);
    write!(counter, "{value}").map_err(|_| DerError::AllocationFailure)?;
    Ok(counter.written())
}

fn string_with_capacity(length: usize) -> Result<String, DerError> {
    let mut value = String::new();
    value
        .try_reserve_exact(length)
        .map_err(|_| DerError::AllocationFailure)?;
    Ok(value)
}
