mod sections;

use super::bytes::{Endian, range, slice, u16_at, u32_at, u64_at, usize_from_u64};
use super::inspect::{Admission, InspectMemoryError, array_bytes};
use super::{
    ArtifactError, ArtifactFormat, ArtifactReport, ArtifactSection, EntryPoint, FileMapping,
    MAX_SECTIONS,
};

const ELF_CLASS_32: u8 = 1;
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LITTLE: u8 = 1;
const ELF_DATA_BIG: u8 = 2;
pub(super) const SHT_NOBITS: u32 = 8;
const PT_LOAD: u32 = 1;
const PN_XNUM: u16 = 0xffff;
const SHN_XINDEX: u16 = 0xffff;

#[derive(Clone, Copy)]
pub(super) struct SectionHeader {
    pub name: u32,
    pub section_type: u32,
    pub flags: u64,
    pub address: u64,
    pub offset: usize,
    pub size: usize,
    pub link: u32,
    pub info: u32,
    pub entry_size: usize,
}

pub(super) struct Header {
    pub is_64: bool,
    pub endian: Endian,
    pub machine: u16,
    pub entry: u64,
    pub program_offset: usize,
    pub program_entry_size: usize,
    pub program_count: usize,
    pub section_offset: usize,
    pub section_entry_size: usize,
    pub section_count: usize,
    pub section_string_index: usize,
}

/// Parse ELF headers, sections, load mappings, symbols, and dynamic imports
pub(super) fn parse(
    bytes: &[u8],
    admission: &mut Admission,
) -> Result<ArtifactReport, InspectMemoryError> {
    let header = read_header(bytes)?;
    let section_headers = read_sections(bytes, &header, admission)?;
    let (mut sections, references) = sections::parse(
        bytes,
        &section_headers,
        header.section_string_index,
        header.is_64,
        header.endian,
        admission,
    )?;
    let header_bytes = array_bytes::<SectionHeader>(section_headers.capacity())?;
    // Header records are no longer needed once section metadata is built
    drop(section_headers);
    admission.release(header_bytes)?;
    let mappings = read_programs(bytes, &header, &mut sections, admission)?;
    let entrypoint = if header.entry == 0 {
        None
    } else {
        Some(EntryPoint {
            address: header.entry,
            file_offset: Some(map_address(&mappings, header.entry, 1)?),
        })
    };
    let mut limitations = admission.vec(3)?;
    limitations.extend_from_slice(&[
        "ELF load mappings include only file-backed PT_LOAD bytes",
        "ELF symbol names are displayed as lossy UTF-8 while exact name byte ranges are retained",
    ]);
    Ok(ArtifactReport {
        format: ArtifactFormat::Elf,
        sha256: String::new(),
        machine: header.machine,
        architecture: super::bytes::machine_name(ArtifactFormat::Elf, header.machine, admission)?,
        bitness: if header.is_64 { 64 } else { 32 },
        entrypoint,
        sections,
        mappings,
        references,
        limitations,
    })
}

fn read_header(bytes: &[u8]) -> Result<Header, ArtifactError> {
    let (is_64, endian) = read_encoding(bytes)?;
    let mut header = read_header_fields(bytes, is_64, endian)?;
    resolve_extended_counts(bytes, &mut header)?;
    validate_table_headers(&header)?;
    Ok(header)
}

fn read_encoding(bytes: &[u8]) -> Result<(bool, Endian), ArtifactError> {
    let class = bytes
        .get(4)
        .copied()
        .ok_or(ArtifactError::InvalidHeader { field: "ELF class" })?;
    let data = bytes.get(5).copied().ok_or(ArtifactError::InvalidHeader {
        field: "ELF byte order",
    })?;
    let is_64 = match class {
        ELF_CLASS_32 => false,
        ELF_CLASS_64 => true,
        _ => return Err(ArtifactError::InvalidHeader { field: "ELF class" }),
    };
    let endian = match data {
        ELF_DATA_LITTLE => Endian::Little,
        ELF_DATA_BIG => Endian::Big,
        _ => {
            return Err(ArtifactError::InvalidHeader {
                field: "ELF byte order",
            });
        }
    };
    let header_length = if is_64 { 64 } else { 52 };
    slice(bytes, 0, header_length)?;
    if bytes.get(6) != Some(&1) {
        return Err(ArtifactError::InvalidHeader {
            field: "ELF version",
        });
    }
    Ok((is_64, endian))
}

fn read_header_fields(bytes: &[u8], is_64: bool, endian: Endian) -> Result<Header, ArtifactError> {
    let header_length = if is_64 { 64 } else { 52 };
    let machine = u16_at(bytes, 18, endian)?;
    let entry = word_at(bytes, 24, is_64, endian)?;
    let (program_offset, section_offset) = if is_64 {
        (
            word_at(bytes, 32, true, endian)?,
            word_at(bytes, 40, true, endian)?,
        )
    } else {
        (
            word_at(bytes, 28, false, endian)?,
            word_at(bytes, 32, false, endian)?,
        )
    };
    let (header_size_offset, program_size_offset, program_count_offset) =
        if is_64 { (52, 54, 56) } else { (40, 42, 44) };
    let (section_size_offset, section_count_offset, string_index_offset) =
        if is_64 { (58, 60, 62) } else { (46, 48, 50) };
    let declared_header_size = usize::from(u16_at(bytes, header_size_offset, endian)?);
    if declared_header_size < header_length {
        return Err(ArtifactError::InvalidHeader {
            field: "ELF header size",
        });
    }
    let program_entry_size = usize::from(u16_at(bytes, program_size_offset, endian)?);
    let section_entry_size = usize::from(u16_at(bytes, section_size_offset, endian)?);
    let program_count = usize::from(u16_at(bytes, program_count_offset, endian)?);
    let section_count = usize::from(u16_at(bytes, section_count_offset, endian)?);
    let section_string_index = usize::from(u16_at(bytes, string_index_offset, endian)?);
    Ok(Header {
        is_64,
        endian,
        machine,
        entry,
        program_offset: usize_from_u64(program_offset, "ELF program table offset")?,
        program_entry_size,
        program_count,
        section_offset: usize_from_u64(section_offset, "ELF section table offset")?,
        section_entry_size,
        section_count,
        section_string_index,
    })
}

fn resolve_extended_counts(bytes: &[u8], header: &mut Header) -> Result<(), ArtifactError> {
    let section_zero_needed = (header.section_count == 0 && header.section_offset != 0)
        || (header.program_count == usize::from(PN_XNUM))
        || (header.section_string_index == usize::from(SHN_XINDEX));
    let section_zero = if section_zero_needed {
        if header.section_entry_size < section_header_minimum(header.is_64) {
            return Err(ArtifactError::InvalidHeader {
                field: "extended ELF section header size",
            });
        }
        Some(read_section(
            bytes,
            header.section_offset,
            header.section_entry_size,
            header.is_64,
            header.endian,
        )?)
    } else {
        None
    };
    if header.section_count == 0 && header.section_offset != 0 {
        header.section_count =
            section_zero
                .map(|section| section.size)
                .ok_or(ArtifactError::InvalidHeader {
                    field: "ELF section count",
                })?;
    }
    if header.program_count == usize::from(PN_XNUM) {
        header.program_count = usize::try_from(section_zero.map(|section| section.info).ok_or(
            ArtifactError::InvalidHeader {
                field: "ELF program count",
            },
        )?)
        .map_err(|_| ArtifactError::InvalidHeader {
            field: "ELF program count",
        })?;
    }
    if header.section_string_index == usize::from(SHN_XINDEX) {
        header.section_string_index =
            usize::try_from(section_zero.map(|section| section.link).ok_or(
                ArtifactError::InvalidHeader {
                    field: "ELF string section index",
                },
            )?)
            .map_err(|_| ArtifactError::InvalidHeader {
                field: "ELF string section index",
            })?;
    }
    Ok(())
}

const fn validate_table_headers(header: &Header) -> Result<(), ArtifactError> {
    if header.section_count > MAX_SECTIONS {
        return Err(ArtifactError::LimitExceeded {
            field: "sections",
            maximum: MAX_SECTIONS,
        });
    }
    if header.program_count > MAX_SECTIONS {
        return Err(ArtifactError::LimitExceeded {
            field: "program headers",
            maximum: MAX_SECTIONS,
        });
    }
    if header.program_count > 0 && header.program_entry_size < program_header_minimum(header.is_64)
    {
        return Err(ArtifactError::InvalidHeader {
            field: "ELF program header size",
        });
    }
    if header.section_count > 0 && header.section_entry_size < section_header_minimum(header.is_64)
    {
        return Err(ArtifactError::InvalidHeader {
            field: "ELF section header size",
        });
    }
    Ok(())
}

fn read_sections(
    bytes: &[u8],
    header: &Header,
    admission: &mut Admission,
) -> Result<Vec<SectionHeader>, InspectMemoryError> {
    let table_length = header
        .section_entry_size
        .checked_mul(header.section_count)
        .ok_or(ArtifactError::InvalidHeader {
            field: "ELF section table length",
        })?;
    range(header.section_offset, table_length, bytes.len())?;
    let mut sections = admission.vec(header.section_count)?;
    for index in 0..header.section_count {
        let displacement =
            header
                .section_entry_size
                .checked_mul(index)
                .ok_or(ArtifactError::InvalidHeader {
                    field: "ELF section table offset",
                })?;
        let offset = header.section_offset.checked_add(displacement).ok_or(
            ArtifactError::InvalidHeader {
                field: "ELF section table offset",
            },
        )?;
        sections.push(read_section(
            bytes,
            offset,
            header.section_entry_size,
            header.is_64,
            header.endian,
        )?);
    }
    Ok(sections)
}

fn read_section(
    bytes: &[u8],
    offset: usize,
    entry_size: usize,
    is_64: bool,
    endian: Endian,
) -> Result<SectionHeader, ArtifactError> {
    let minimum = section_header_minimum(is_64);
    if entry_size < minimum {
        return Err(ArtifactError::InvalidHeader {
            field: "ELF section header size",
        });
    }
    slice(bytes, offset, minimum)?;
    if is_64 {
        let file_offset =
            usize_from_u64(u64_at(bytes, offset + 24, endian)?, "ELF section offset")?;
        let size = usize_from_u64(u64_at(bytes, offset + 32, endian)?, "ELF section size")?;
        Ok(SectionHeader {
            name: u32_at(bytes, offset, endian)?,
            section_type: u32_at(bytes, offset + 4, endian)?,
            flags: u64_at(bytes, offset + 8, endian)?,
            address: u64_at(bytes, offset + 16, endian)?,
            offset: file_offset,
            size,
            link: u32_at(bytes, offset + 40, endian)?,
            info: u32_at(bytes, offset + 44, endian)?,
            entry_size: usize_from_u64(
                u64_at(bytes, offset + 56, endian)?,
                "ELF symbol entry size",
            )?,
        })
    } else {
        Ok(SectionHeader {
            name: u32_at(bytes, offset, endian)?,
            section_type: u32_at(bytes, offset + 4, endian)?,
            flags: u64::from(u32_at(bytes, offset + 8, endian)?),
            address: u64::from(u32_at(bytes, offset + 12, endian)?),
            offset: usize::try_from(u32_at(bytes, offset + 16, endian)?).map_err(|_| {
                ArtifactError::InvalidHeader {
                    field: "ELF section offset",
                }
            })?,
            size: usize::try_from(u32_at(bytes, offset + 20, endian)?).map_err(|_| {
                ArtifactError::InvalidHeader {
                    field: "ELF section size",
                }
            })?,
            link: u32_at(bytes, offset + 24, endian)?,
            info: u32_at(bytes, offset + 28, endian)?,
            entry_size: usize::try_from(u32_at(bytes, offset + 36, endian)?).map_err(|_| {
                ArtifactError::InvalidHeader {
                    field: "ELF symbol entry size",
                }
            })?,
        })
    }
}

fn read_programs(
    bytes: &[u8],
    header: &Header,
    sections: &mut Vec<ArtifactSection>,
    admission: &mut Admission,
) -> Result<Vec<FileMapping>, InspectMemoryError> {
    let table_length = header
        .program_entry_size
        .checked_mul(header.program_count)
        .ok_or(ArtifactError::InvalidHeader {
            field: "ELF program table length",
        })?;
    range(header.program_offset, table_length, bytes.len())?;
    let mut mappings = Vec::new();
    for index in 0..header.program_count {
        let offset = header
            .program_entry_size
            .checked_mul(index)
            .and_then(|delta| header.program_offset.checked_add(delta))
            .ok_or(ArtifactError::InvalidHeader {
                field: "ELF program header offset",
            })?;
        let (segment_type, flags, file_offset, address, file_size, memory_size) =
            read_program(bytes, offset, header)?;
        let end = file_offset
            .checked_add(file_size)
            .ok_or(ArtifactError::InvalidHeader {
                field: "ELF segment range",
            })?;
        if end > bytes.len() {
            return Err(ArtifactError::InvalidRange {
                offset: file_offset,
                length: file_size,
                total: bytes.len(),
            }
            .into());
        }
        if segment_type == PT_LOAD {
            if file_size > memory_size {
                return Err(ArtifactError::InvalidHeader {
                    field: "ELF load segment size",
                }
                .into());
            }
            admission.grow_vec(sections, 1)?;
            let name = admission.number_name(
                "LOAD[",
                u64::try_from(index).map_err(|_| InspectMemoryError::Allocation)?,
                "]",
            )?;
            sections.push(ArtifactSection {
                name,
                address,
                file_offset: Some(file_offset),
                file_size,
                memory_size,
                flags,
            });
            if file_size > 0 {
                admission.grow_vec(&mut mappings, 1)?;
                mappings.push(FileMapping {
                    address,
                    file_offset,
                    file_size,
                    flags,
                    executable: flags & 1 != 0,
                });
            }
        }
    }
    Ok(mappings)
}

fn read_program(
    bytes: &[u8],
    offset: usize,
    header: &Header,
) -> Result<(u32, u64, usize, u64, usize, usize), ArtifactError> {
    if header.is_64 {
        Ok((
            u32_at(bytes, offset, header.endian)?,
            u64_at(bytes, offset + 4, header.endian)?,
            usize_from_u64(
                u64_at(bytes, offset + 8, header.endian)?,
                "ELF segment offset",
            )?,
            u64_at(bytes, offset + 16, header.endian)?,
            usize_from_u64(
                u64_at(bytes, offset + 32, header.endian)?,
                "ELF segment file size",
            )?,
            usize_from_u64(
                u64_at(bytes, offset + 40, header.endian)?,
                "ELF segment memory size",
            )?,
        ))
    } else {
        Ok((
            u32_at(bytes, offset, header.endian)?,
            u64::from(u32_at(bytes, offset + 24, header.endian)?),
            usize::try_from(u32_at(bytes, offset + 4, header.endian)?).map_err(|_| {
                ArtifactError::InvalidHeader {
                    field: "ELF segment offset",
                }
            })?,
            u64::from(u32_at(bytes, offset + 8, header.endian)?),
            usize::try_from(u32_at(bytes, offset + 16, header.endian)?).map_err(|_| {
                ArtifactError::InvalidHeader {
                    field: "ELF segment file size",
                }
            })?,
            usize::try_from(u32_at(bytes, offset + 20, header.endian)?).map_err(|_| {
                ArtifactError::InvalidHeader {
                    field: "ELF segment memory size",
                }
            })?,
        ))
    }
}

fn map_address(
    mappings: &[FileMapping],
    address: u64,
    length: usize,
) -> Result<usize, ArtifactError> {
    let length_u64 =
        u64::try_from(length).map_err(|_| ArtifactError::UnmappedAddress { address, length })?;
    let mut offsets = mappings.iter().filter_map(|mapping| {
        let displacement = address.checked_sub(mapping.address)?;
        let end = displacement.checked_add(length_u64)?;
        let file_size = u64::try_from(mapping.file_size).ok()?;
        if end <= file_size {
            usize::try_from(displacement)
                .ok()
                .and_then(|delta| mapping.file_offset.checked_add(delta))
        } else {
            None
        }
    });
    let first = offsets
        .next()
        .ok_or(ArtifactError::UnmappedAddress { address, length })?;
    if offsets.next().is_some() {
        Err(ArtifactError::AmbiguousAddress { address })
    } else {
        Ok(first)
    }
}

fn word_at(bytes: &[u8], offset: usize, is_64: bool, endian: Endian) -> Result<u64, ArtifactError> {
    if is_64 {
        u64_at(bytes, offset, endian)
    } else {
        Ok(u64::from(u32_at(bytes, offset, endian)?))
    }
}

const fn section_header_minimum(is_64: bool) -> usize {
    if is_64 { 64 } else { 40 }
}

const fn program_header_minimum(is_64: bool) -> usize {
    if is_64 { 56 } else { 32 }
}
