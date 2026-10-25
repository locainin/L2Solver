use std::collections::BTreeMap;

use super::super::bytes::{Endian, charge_reference_text, slice, u16_at, u32_at, u64_at};
use super::super::{
    ArtifactError, ArtifactReference, ArtifactReferenceKind, ArtifactSection, FileRange,
    MAX_REFERENCES,
};
use super::{SHT_NOBITS, SectionHeader};

const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_DYNSYM: u32 = 11;
const SHN_UNDEF: u16 = 0;

struct SymbolContext<'a> {
    bytes: &'a [u8],
    headers: &'a [SectionHeader],
    is_64: bool,
    endian: Endian,
}

struct SymbolCollection {
    processed_records: usize,
    text_bytes: usize,
    references: BTreeMap<(u8, String, Option<u64>), ArtifactReference>,
}

pub(super) fn parse(
    bytes: &[u8],
    headers: &[SectionHeader],
    string_index: usize,
    is_64: bool,
    endian: Endian,
) -> Result<(Vec<ArtifactSection>, Vec<ArtifactReference>), ArtifactError> {
    let section_names = string_section(bytes, headers, string_index)?;
    let mut sections = Vec::with_capacity(headers.len());
    for header in headers {
        if header.section_type != SHT_NOBITS {
            slice(bytes, header.offset, header.size)?;
        }
        let name = section_name(section_names, header.name)?;
        sections.push(ArtifactSection {
            name,
            address: header.address,
            file_offset: (header.section_type != SHT_NOBITS).then_some(header.offset),
            file_size: if header.section_type == SHT_NOBITS {
                0
            } else {
                header.size
            },
            memory_size: header.size,
            flags: header.flags,
        });
    }
    let references = parse_symbols(bytes, headers, is_64, endian)?;
    Ok((sections, references))
}

fn string_section<'a>(
    bytes: &'a [u8],
    headers: &[SectionHeader],
    string_index: usize,
) -> Result<Option<(&'a [u8], usize)>, ArtifactError> {
    if string_index == 0 {
        return Ok(None);
    }
    let section = headers
        .get(string_index)
        .ok_or(ArtifactError::InvalidHeader {
            field: "ELF section name table index",
        })?;
    if section.section_type != SHT_STRTAB {
        return Err(ArtifactError::InvalidHeader {
            field: "ELF section name table type",
        });
    }
    Ok(Some((
        slice(bytes, section.offset, section.size)?,
        section.offset,
    )))
}

fn section_name(table: Option<(&[u8], usize)>, offset: u32) -> Result<String, ArtifactError> {
    if offset == 0 {
        return Ok(String::new());
    }
    let Some((table, base)) = table else {
        return Err(ArtifactError::InvalidName { offset: 0 });
    };
    name_from_table(table, base, offset).map(|(name, _, _)| name)
}

fn parse_symbols(
    bytes: &[u8],
    headers: &[SectionHeader],
    is_64: bool,
    endian: Endian,
) -> Result<Vec<ArtifactReference>, ArtifactError> {
    let context = SymbolContext {
        bytes,
        headers,
        is_64,
        endian,
    };
    let mut collection = SymbolCollection {
        processed_records: 0,
        text_bytes: 0,
        references: BTreeMap::new(),
    };
    for section in context
        .headers
        .iter()
        .filter(|section| matches!(section.section_type, SHT_SYMTAB | SHT_DYNSYM))
    {
        parse_symbol_table(&context, &mut collection, section)?;
    }
    Ok(collection.references.into_values().collect())
}

fn parse_symbol_table(
    context: &SymbolContext<'_>,
    collection: &mut SymbolCollection,
    section: &SectionHeader,
) -> Result<(), ArtifactError> {
    let minimum = if context.is_64 { 24 } else { 16 };
    if section.entry_size < minimum || !section.size.is_multiple_of(section.entry_size) {
        return Err(ArtifactError::InvalidHeader {
            field: "ELF symbol entry size",
        });
    }
    let string_index = usize::try_from(section.link).map_err(|_| ArtifactError::InvalidHeader {
        field: "ELF symbol string table index",
    })?;
    let string_header = context
        .headers
        .get(string_index)
        .ok_or(ArtifactError::InvalidHeader {
            field: "ELF symbol string table index",
        })?;
    if string_header.section_type != SHT_STRTAB {
        return Err(ArtifactError::InvalidHeader {
            field: "ELF symbol string table type",
        });
    }
    let strings = slice(context.bytes, string_header.offset, string_header.size)?;
    let count = section.size / section.entry_size;
    collection.processed_records =
        collection
            .processed_records
            .checked_add(count)
            .ok_or(ArtifactError::LimitExceeded {
                field: "symbol records",
                maximum: MAX_REFERENCES,
            })?;
    if collection.processed_records > MAX_REFERENCES {
        return Err(ArtifactError::LimitExceeded {
            field: "symbol records",
            maximum: MAX_REFERENCES,
        });
    }
    for index in 0..count {
        let record_offset = section
            .entry_size
            .checked_mul(index)
            .and_then(|delta| section.offset.checked_add(delta))
            .ok_or(ArtifactError::InvalidHeader {
                field: "ELF symbol table offset",
            })?;
        let (name_index, address, section_index) =
            read_symbol(context.bytes, record_offset, context.is_64, context.endian)?;
        if name_index == 0 {
            continue;
        }
        let (name, name_offset, name_length) =
            name_from_table(strings, string_header.offset, name_index)?;
        if name.is_empty() {
            continue;
        }
        add_symbol_reference(
            collection,
            name,
            FileRange {
                offset: record_offset,
                length: minimum,
            },
            FileRange {
                offset: name_offset,
                length: name_length,
            },
            address,
            section_index == SHN_UNDEF,
        )?;
    }
    Ok(())
}

fn add_symbol_reference(
    collection: &mut SymbolCollection,
    name: String,
    record_range: FileRange,
    name_range: FileRange,
    address: u64,
    is_import: bool,
) -> Result<(), ArtifactError> {
    let kind = if is_import {
        ArtifactReferenceKind::Import
    } else {
        ArtifactReferenceKind::Symbol
    };
    let address = (address != 0).then_some(address);
    let key = (reference_kind_key(kind), name.clone(), address);
    if collection.references.contains_key(&key) {
        return Ok(());
    }
    charge_reference_text(&mut collection.text_bytes, &name, None)?;
    collection.references.insert(
        key,
        ArtifactReference {
            name,
            library: None,
            library_range: None,
            kind,
            record_range,
            name_range: Some(name_range),
            address,
        },
    );
    Ok(())
}

fn read_symbol(
    bytes: &[u8],
    offset: usize,
    is_64: bool,
    endian: Endian,
) -> Result<(u32, u64, u16), ArtifactError> {
    if is_64 {
        Ok((
            u32_at(bytes, offset, endian)?,
            u64_at(bytes, offset + 8, endian)?,
            u16_at(bytes, offset + 6, endian)?,
        ))
    } else {
        Ok((
            u32_at(bytes, offset, endian)?,
            u64::from(u32_at(bytes, offset + 4, endian)?),
            u16_at(bytes, offset + 14, endian)?,
        ))
    }
}

fn name_from_table(
    table: &[u8],
    table_offset: usize,
    name_index: u32,
) -> Result<(String, usize, usize), ArtifactError> {
    let local_offset = usize::try_from(name_index).map_err(|_| ArtifactError::InvalidName {
        offset: table_offset,
    })?;
    let rest = table
        .get(local_offset..)
        .ok_or_else(|| ArtifactError::InvalidName {
            offset: table_offset.saturating_add(local_offset),
        })?;
    let length = rest
        .iter()
        .take(4_096)
        .position(|byte| *byte == 0)
        .ok_or_else(|| ArtifactError::InvalidName {
            offset: table_offset.saturating_add(local_offset),
        })?;
    let name =
        String::from_utf8_lossy(
            rest.get(..length)
                .ok_or_else(|| ArtifactError::InvalidName {
                    offset: table_offset.saturating_add(local_offset),
                })?,
        )
        .into_owned();
    let offset = table_offset
        .checked_add(local_offset)
        .ok_or(ArtifactError::InvalidName {
            offset: table_offset,
        })?;
    Ok((name, offset, length))
}

const fn reference_kind_key(kind: ArtifactReferenceKind) -> u8 {
    match kind {
        ArtifactReferenceKind::Symbol => 0,
        ArtifactReferenceKind::Import => 1,
    }
}
