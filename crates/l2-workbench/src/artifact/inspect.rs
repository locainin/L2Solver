use std::{fmt, fmt::Write};

mod admission;

pub(super) use admission::{Admission, array_bytes};

use sha2::{Digest, Sha256};

use super::{
    ArtifactError, ArtifactFormat, ArtifactReport, ArtifactSection, FileMapping,
    MAX_ARTIFACT_BYTES, signatures,
};
use crate::job::{MemoryError, MemoryLease};

#[cfg(test)]
#[path = "../../tests/artifact/inspect_memory.rs"]
mod tests;

const STATIC_LIMITATION: &str = "Header, section, symbol, and import facts are static file observations and do not establish runtime behavior";

/// Inspect a bounded PE or ELF image without executing it
///
/// # Errors
/// Returns an error for unsupported formats, malformed ranges, or resource-limit violations
pub fn inspect(bytes: &[u8]) -> Result<ArtifactReport, ArtifactError> {
    let mut admission = Admission::unlimited();
    inspect_inner(bytes, &mut admission).map_err(legacy_error)
}

#[derive(Debug)]
pub(super) enum InspectMemoryError {
    Format(ArtifactError),
    Memory(MemoryError),
    Allocation,
}

impl fmt::Display for InspectMemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(error) => error.fmt(formatter),
            Self::Memory(error) => error.fmt(formatter),
            Self::Allocation => ArtifactError::AllocationFailure.fmt(formatter),
        }
    }
}

impl std::error::Error for InspectMemoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Format(error) => Some(error),
            Self::Memory(error) => Some(error),
            Self::Allocation => None,
        }
    }
}

impl From<ArtifactError> for InspectMemoryError {
    fn from(error: ArtifactError) -> Self {
        Self::Format(error)
    }
}

const fn legacy_error(error: InspectMemoryError) -> ArtifactError {
    match error {
        InspectMemoryError::Format(error) => error,
        InspectMemoryError::Memory(_) | InspectMemoryError::Allocation => {
            ArtifactError::AllocationFailure
        }
    }
}

/// Inspect with shared admission for retained metadata and temporary parser storage
///
/// The caller keeps the lease until the returned report is dropped. The ledger charges
/// logical buffer capacities and the current Rust B-tree layout, not allocator overhead,
/// process RSS, or allocations internal to third-party libraries
pub(super) fn inspect_with_memory(
    bytes: &[u8],
    memory: &mut MemoryLease,
) -> Result<ArtifactReport, InspectMemoryError> {
    // A sibling keeps the caller's existing charge intact on every failed parse
    let mut admission = Admission {
        scratch: Some(memory.try_sibling(0).map_err(InspectMemoryError::Memory)?),
    };
    let result = inspect_inner(bytes, &mut admission);
    let report = result?;
    let retained = report_bytes(&report)?;
    if let Some(mut scratch) = admission.scratch.take() {
        // Temporary buffers are gone, leaving only the report's owned capacities
        if scratch.bytes() < retained {
            // The report must be dropped before releasing any insufficient charge
            drop(report);
            return Err(InspectMemoryError::Allocation);
        }
        if let Err(error) = scratch.try_resize(retained) {
            drop(report);
            drop(scratch);
            return Err(InspectMemoryError::Memory(error));
        }
        memory.absorb(scratch);
    }
    Ok(report)
}

fn inspect_inner(
    bytes: &[u8],
    admission: &mut Admission,
) -> Result<ArtifactReport, InspectMemoryError> {
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(ArtifactError::ArtifactTooLarge {
            length: bytes.len(),
            maximum: MAX_ARTIFACT_BYTES,
        }
        .into());
    }
    let mut report = match candidate_executable_format(bytes) {
        Some(ArtifactFormat::Elf) => super::elf::parse(bytes, admission)?,
        Some(ArtifactFormat::PortableExecutable) => super::pe::parse(bytes, admission)?,
        None => return Err(ArtifactError::UnsupportedFormat.into()),
    };
    // Reserve the complete digest before formatting so its buffer cannot grow mid-write
    let mut digest = admission.string(64)?;
    write!(&mut digest, "{:x}", Sha256::digest(bytes))
        .map_err(|_| InspectMemoryError::Allocation)?;
    report.sha256 = digest;
    admission.grow_vec(&mut report.limitations, 1)?;
    report.limitations.push(STATIC_LIMITATION);
    Ok(report)
}

/// Select the executable parser indicated by a literal leading signature
#[must_use]
pub fn candidate_executable_format(bytes: &[u8]) -> Option<ArtifactFormat> {
    if bytes.starts_with(signatures::ELF_MAGIC) {
        Some(ArtifactFormat::Elf)
    } else if bytes.starts_with(signatures::MZ_MAGIC) {
        Some(ArtifactFormat::PortableExecutable)
    } else {
        None
    }
}

fn report_bytes(report: &ArtifactReport) -> Result<u64, InspectMemoryError> {
    let mut bytes = report.sha256.capacity();
    for amount in [
        report.architecture.capacity(),
        array_bytes::<ArtifactSection>(report.sections.capacity())?,
        array_bytes::<FileMapping>(report.mappings.capacity())?,
        array_bytes::<super::ArtifactReference>(report.references.capacity())?,
        array_bytes::<&'static str>(report.limitations.capacity())?,
    ] {
        bytes = bytes
            .checked_add(amount)
            .ok_or(InspectMemoryError::Allocation)?;
    }
    for section in &report.sections {
        bytes = bytes
            .checked_add(section.name.capacity())
            .ok_or(InspectMemoryError::Allocation)?;
    }
    for reference in &report.references {
        bytes = bytes
            .checked_add(reference.name.capacity())
            .and_then(|total| {
                total.checked_add(reference.library.as_ref().map_or(0, String::capacity))
            })
            .ok_or(InspectMemoryError::Allocation)?;
    }
    u64::try_from(bytes).map_err(|_| InspectMemoryError::Allocation)
}
