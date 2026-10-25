use super::ArtifactError;

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
) -> Result<(String, usize), ArtifactError> {
    let available = bytes.len().saturating_sub(offset).min(maximum);
    let raw = slice(bytes, offset, available)?;
    let end = raw
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(ArtifactError::InvalidName { offset })?;
    let name_bytes = raw
        .get(..end)
        .ok_or(ArtifactError::InvalidName { offset })?;
    let name = String::from_utf8_lossy(name_bytes).into_owned();
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

pub(super) fn machine_name(format: &'static str, machine: u16) -> String {
    let name = match (format, machine) {
        ("elf", 3) | ("pe", 0x014c) => "x86",
        ("elf", 62) | ("pe", 0x8664) => "x86_64",
        ("elf", 40) | ("pe", 0x01c0) => "arm",
        ("elf", 183) | ("pe", 0xaa64) => "aarch64",
        ("elf", 20) => "powerpc",
        ("elf", 21) => "powerpc64",
        _ => return format!("{format}_machine_{machine}"),
    };
    name.to_owned()
}
