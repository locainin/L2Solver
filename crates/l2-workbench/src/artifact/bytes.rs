use super::inspect::{Admission, InspectMemoryError};
use super::{ArtifactError, ArtifactFormat};

#[derive(Clone, Copy)]
pub(super) enum Endian {
    Little,
    Big,
}

pub(super) fn slice(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], ArtifactError> {
    let end = offset
        .checked_add(length)
        .ok_or(ArtifactError::InvalidRange {
            offset,
            length,
            total: bytes.len(),
        })?;
    bytes.get(offset..end).ok_or(ArtifactError::InvalidRange {
        offset,
        length,
        total: bytes.len(),
    })
}

pub(super) fn u16_at(bytes: &[u8], offset: usize, endian: Endian) -> Result<u16, ArtifactError> {
    let raw = slice(bytes, offset, 2)?;
    let array: [u8; 2] = raw.try_into().map_err(|_| ArtifactError::InvalidRange {
        offset,
        length: 2,
        total: bytes.len(),
    })?;
    Ok(match endian {
        Endian::Little => u16::from_le_bytes(array),
        Endian::Big => u16::from_be_bytes(array),
    })
}

pub(super) fn u32_at(bytes: &[u8], offset: usize, endian: Endian) -> Result<u32, ArtifactError> {
    let raw = slice(bytes, offset, 4)?;
    let array: [u8; 4] = raw.try_into().map_err(|_| ArtifactError::InvalidRange {
        offset,
        length: 4,
        total: bytes.len(),
    })?;
    Ok(match endian {
        Endian::Little => u32::from_le_bytes(array),
        Endian::Big => u32::from_be_bytes(array),
    })
}

pub(super) fn u64_at(bytes: &[u8], offset: usize, endian: Endian) -> Result<u64, ArtifactError> {
    let raw = slice(bytes, offset, 8)?;
    let array: [u8; 8] = raw.try_into().map_err(|_| ArtifactError::InvalidRange {
        offset,
        length: 8,
        total: bytes.len(),
    })?;
    Ok(match endian {
        Endian::Little => u64::from_le_bytes(array),
        Endian::Big => u64::from_be_bytes(array),
    })
}

pub(super) fn usize_from_u64(value: u64, field: &'static str) -> Result<usize, ArtifactError> {
    usize::try_from(value).map_err(|_| ArtifactError::InvalidHeader { field })
}

pub(super) fn range(offset: usize, length: usize, total: usize) -> Result<(), ArtifactError> {
    let end = offset
        .checked_add(length)
        .ok_or(ArtifactError::InvalidRange {
            offset,
            length,
            total,
        })?;
    if end > total {
        return Err(ArtifactError::InvalidRange {
            offset,
            length,
            total,
        });
    }
    Ok(())
}

pub(super) fn c_string(
    bytes: &[u8],
    offset: usize,
    maximum: usize,
    admission: &mut Admission,
) -> Result<(String, usize), InspectMemoryError> {
    let available = bytes.len().saturating_sub(offset).min(maximum);
    let raw = slice(bytes, offset, available)?;
    let end = raw
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(ArtifactError::InvalidName { offset })?;
    let name_bytes = raw
        .get(..end)
        .ok_or(ArtifactError::InvalidName { offset })?;
    let name = admission.lossy_string(name_bytes)?;
    Ok((name, end))
}

pub(super) fn charge_reference_text(
    budget: &mut usize,
    name: &str,
    library: Option<&str>,
) -> Result<(), ArtifactError> {
    let additional = name.len().checked_add(library.map_or(0, str::len)).ok_or(
        ArtifactError::LimitExceeded {
            field: "artifact reference text",
            maximum: super::MAX_REFERENCE_TEXT_BYTES,
        },
    )?;
    let total = budget
        .checked_add(additional)
        .ok_or(ArtifactError::LimitExceeded {
            field: "artifact reference text",
            maximum: super::MAX_REFERENCE_TEXT_BYTES,
        })?;
    if total > super::MAX_REFERENCE_TEXT_BYTES {
        return Err(ArtifactError::LimitExceeded {
            field: "artifact reference text",
            maximum: super::MAX_REFERENCE_TEXT_BYTES,
        });
    }
    *budget = total;
    Ok(())
}

pub(super) fn machine_name(
    format: ArtifactFormat,
    machine: u16,
    admission: &mut Admission,
) -> Result<String, InspectMemoryError> {
    let name = match (format, machine) {
        (ArtifactFormat::Elf, 3) | (ArtifactFormat::PortableExecutable, 0x014c) => "x86",
        (ArtifactFormat::Elf, 62) | (ArtifactFormat::PortableExecutable, 0x8664) => "x86_64",
        (ArtifactFormat::Elf, 40) | (ArtifactFormat::PortableExecutable, 0x01c0) => "arm",
        (ArtifactFormat::Elf, 183) | (ArtifactFormat::PortableExecutable, 0xaa64) => "aarch64",
        (ArtifactFormat::Elf, 20) => "powerpc",
        (ArtifactFormat::Elf, 21) => "powerpc64",
        _ => {
            let prefix = match format {
                ArtifactFormat::Elf => "elf_machine_",
                ArtifactFormat::PortableExecutable => "pe_machine_",
            };
            return admission.number_name(prefix, u64::from(machine), "");
        }
    };
    admission.copy_str(name)
}
