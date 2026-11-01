use super::bytes::{Endian, c_string, charge_reference_text, range, slice, u16_at, u32_at, u64_at};
use super::inspect::{Admission, InspectMemoryError, array_bytes};
use super::{
    ArtifactError, ArtifactFormat, ArtifactReference, ArtifactReferenceKind, ArtifactReport,
    ArtifactSection, EntryPoint, FileMapping, FileRange, MAX_REFERENCES, MAX_SECTIONS,
};

const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";
const PE32_MAGIC: u16 = 0x010b;
const PE64_MAGIC: u16 = 0x020b;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const MAX_IMPORT_NAME_BYTES: usize = 4_096;
const IMPORT_DIRECTORY: usize = 1;
const EXPORT_DIRECTORY: usize = 0;
const RETAINED_DIRECTORY_COUNT: usize = 2;
const IMPORT_DESCRIPTOR_BYTES: usize = 20;

#[derive(Clone, Copy)]
struct DataDirectory {
    rva: u32,
    size: u32,
}

struct PeImage {
    is_64: bool,
    machine: u16,
    image_base: u64,
    entry_rva: u32,
    directories: Vec<DataDirectory>,
    sections: Vec<ArtifactSection>,
    mappings: Vec<FileMapping>,
}

struct CoffHeader {
    machine: u16,
    section_count: usize,
    optional_offset: usize,
    optional_size: usize,
    section_table_offset: usize,
}

struct OptionalHeader {
    is_64: bool,
    image_base: u64,
    entry_rva: u32,
    size_of_headers: usize,
    directories: Vec<DataDirectory>,
}

struct ImportReferences<'a> {
    remaining: usize,
    text_bytes: &'a mut usize,
    records: &'a mut Vec<ArtifactReference>,
}

/// Parse PE headers, sections, exports, and imports
pub(super) fn parse(
    bytes: &[u8],
    admission: &mut Admission,
) -> Result<ArtifactReport, InspectMemoryError> {
    let image = read_image(bytes, admission)?;
    let mut reference_text_bytes = 0_usize;
    let mut references = parse_exports(bytes, &image, &mut reference_text_bytes, admission)?;
    let remaining_references = MAX_REFERENCES.saturating_sub(references.len());
    let mut imports = parse_imports(
        bytes,
        &image,
        remaining_references,
        &mut reference_text_bytes,
        admission,
    )?;
    if references.is_empty() {
        let empty_bytes = array_bytes::<ArtifactReference>(references.capacity())?;
        drop(references);
        admission.release(empty_bytes)?;
        // A PE without exports can keep the import buffer directly
        references = imports;
    } else {
        admission.grow_vec(&mut references, imports.len())?;
        references.append(&mut imports);
        let import_bytes = array_bytes::<ArtifactReference>(imports.capacity())?;
        drop(imports);
        admission.release(import_bytes)?;
    }
    let entrypoint = if image.entry_rva == 0 {
        None
    } else {
        let address = image
            .image_base
            .checked_add(u64::from(image.entry_rva))
            .ok_or(ArtifactError::InvalidHeader {
                field: "PE entry address",
            })?;
        let file_offset = map_address(&image, address, 1, true)?;
        Some(EntryPoint {
            address,
            file_offset: Some(file_offset),
        })
    };
    let directory_bytes = array_bytes::<DataDirectory>(image.directories.capacity())?;
    // The report keeps sections and mappings, while directory records can be dropped
    drop(image.directories);
    admission.release(directory_bytes)?;
    let mut limitations = admission.vec(3)?;
    limitations.extend_from_slice(&[
        "PE import and export names are static table observations and do not establish executed behavior",
        "PE section mappings include file-backed raw bytes only",
    ]);
    Ok(ArtifactReport {
        format: ArtifactFormat::PortableExecutable,
        sha256: String::new(),
        machine: image.machine,
        architecture: super::bytes::machine_name(
            ArtifactFormat::PortableExecutable,
            image.machine,
            admission,
        )?,
        bitness: if image.is_64 { 64 } else { 32 },
        entrypoint,
        sections: image.sections,
        mappings: image.mappings,
        references,
        limitations,
    })
}

fn read_image(bytes: &[u8], admission: &mut Admission) -> Result<PeImage, InspectMemoryError> {
    let coff = read_coff_header(bytes)?;
    let optional =
        read_optional_header(bytes, coff.optional_offset, coff.optional_size, admission)?;
    let (sections, mappings) = read_sections(
        bytes,
        coff.section_table_offset,
        coff.section_count,
        optional.image_base,
        optional.size_of_headers,
        admission,
    )?;
    Ok(PeImage {
        is_64: optional.is_64,
        machine: coff.machine,
        image_base: optional.image_base,
        entry_rva: optional.entry_rva,
        directories: optional.directories,
        sections,
        mappings,
    })
}

fn read_coff_header(bytes: &[u8]) -> Result<CoffHeader, ArtifactError> {
    let pe_header_offset = usize::try_from(u32_at(bytes, 0x3c, Endian::Little)?).map_err(|_| {
        ArtifactError::InvalidHeader {
            field: "PE header offset",
        }
    })?;
    if slice(bytes, pe_header_offset, PE_SIGNATURE.len())? != PE_SIGNATURE {
        return Err(ArtifactError::InvalidHeader {
            field: "PE signature",
        });
    }
    let coff_offset =
        pe_header_offset
            .checked_add(PE_SIGNATURE.len())
            .ok_or(ArtifactError::InvalidHeader {
                field: "PE COFF header offset",
            })?;
    slice(bytes, coff_offset, 20)?;
    let machine = u16_at(bytes, coff_offset, Endian::Little)?;
    let section_count = usize::from(u16_at(bytes, coff_offset + 2, Endian::Little)?);
    if section_count > MAX_SECTIONS {
        return Err(ArtifactError::LimitExceeded {
            field: "PE sections",
            maximum: MAX_SECTIONS,
        });
    }
    let optional_size = usize::from(u16_at(bytes, coff_offset + 16, Endian::Little)?);
    let optional_offset = coff_offset
        .checked_add(20)
        .ok_or(ArtifactError::InvalidHeader {
            field: "PE optional header offset",
        })?;
    let optional_end =
        optional_offset
            .checked_add(optional_size)
            .ok_or(ArtifactError::InvalidHeader {
                field: "PE optional header offset",
            })?;
    Ok(CoffHeader {
        machine,
        section_count,
        optional_offset,
        optional_size,
        section_table_offset: optional_end,
    })
}

fn read_optional_header(
    bytes: &[u8],
    optional_offset: usize,
    optional_size: usize,
    admission: &mut Admission,
) -> Result<OptionalHeader, InspectMemoryError> {
    slice(bytes, optional_offset, optional_size)?;
    let magic = u16_at(bytes, optional_offset, Endian::Little)?;
    let (is_64, directory_offset, directory_count_offset, base_optional_size) = match magic {
        PE32_MAGIC => (false, 96_usize, 92_usize, 96_usize),
        PE64_MAGIC => (true, 112_usize, 108_usize, 112_usize),
        _ => {
            return Err(ArtifactError::InvalidHeader {
                field: "PE optional header magic",
            }
            .into());
        }
    };
    if optional_size < base_optional_size {
        return Err(ArtifactError::InvalidHeader {
            field: "PE optional header size",
        }
        .into());
    }
    let entry_rva = u32_at(bytes, optional_offset + 16, Endian::Little)?;
    let image_base = if is_64 {
        u64_at(bytes, optional_offset + 24, Endian::Little)?
    } else {
        u64::from(u32_at(bytes, optional_offset + 28, Endian::Little)?)
    };
    let size_of_headers = usize::try_from(u32_at(bytes, optional_offset + 60, Endian::Little)?)
        .map_err(|_| ArtifactError::InvalidHeader {
            field: "PE headers size",
        })?;
    if size_of_headers == 0 || size_of_headers > bytes.len() {
        return Err(ArtifactError::InvalidHeader {
            field: "PE headers size",
        }
        .into());
    }
    let directories = read_directories(
        bytes,
        optional_offset,
        optional_size,
        directory_offset,
        directory_count_offset,
        admission,
    )?;
    Ok(OptionalHeader {
        is_64,
        image_base,
        entry_rva,
        size_of_headers,
        directories,
    })
}

fn read_directories(
    bytes: &[u8],
    optional_offset: usize,
    optional_size: usize,
    directory_offset: usize,
    directory_count_offset: usize,
    admission: &mut Admission,
) -> Result<Vec<DataDirectory>, InspectMemoryError> {
    let directory_count = usize::try_from(u32_at(
        bytes,
        optional_offset + directory_count_offset,
        Endian::Little,
    )?)
    .map_err(|_| ArtifactError::InvalidHeader {
        field: "PE directory count",
    })?;
    let available_directory_bytes =
        optional_size
            .checked_sub(directory_offset)
            .ok_or(ArtifactError::InvalidHeader {
                field: "PE directory table",
            })?;
    let available_directory_count = available_directory_bytes / 8;
    if directory_count > available_directory_count {
        return Err(ArtifactError::InvalidHeader {
            field: "PE directory count",
        }
        .into());
    }
    let retained_count = directory_count.min(RETAINED_DIRECTORY_COUNT);
    let mut directories = admission.vec(retained_count)?;
    for index in 0..retained_count {
        let offset = optional_offset
            .checked_add(directory_offset)
            .and_then(|base| base.checked_add(index.checked_mul(8)?))
            .ok_or(ArtifactError::InvalidHeader {
                field: "PE directory offset",
            })?;
        directories.push(DataDirectory {
            rva: u32_at(bytes, offset, Endian::Little)?,
            size: u32_at(bytes, offset + 4, Endian::Little)?,
        });
    }
    Ok(directories)
}

fn read_sections(
    bytes: &[u8],
    table_offset: usize,
    count: usize,
    image_base: u64,
    size_of_headers: usize,
    admission: &mut Admission,
) -> Result<(Vec<ArtifactSection>, Vec<FileMapping>), InspectMemoryError> {
    let table_size = count.checked_mul(40).ok_or(ArtifactError::InvalidHeader {
        field: "PE section table size",
    })?;
    range(table_offset, table_size, bytes.len())?;
    let mut sections = admission.vec(count)?;
    let mut mappings = Vec::new();
    for index in 0..count {
        let offset = table_offset
            .checked_add(index.checked_mul(40).ok_or(ArtifactError::InvalidHeader {
                field: "PE section header offset",
            })?)
            .ok_or(ArtifactError::InvalidHeader {
                field: "PE section header offset",
            })?;
        let (section, mapping) = read_section(bytes, offset, image_base, admission)?;
        sections.push(section);
        if let Some(mapping) = mapping {
            admission.grow_vec(&mut mappings, 1)?;
            mappings.push(mapping);
        }
    }
    if size_of_headers > 0 {
        admission.grow_vec(&mut mappings, 1)?;
        mappings.push(FileMapping {
            address: image_base,
            file_offset: 0,
            file_size: size_of_headers,
            flags: 0,
            executable: false,
        });
    }
    Ok((sections, mappings))
}

fn read_section(
    bytes: &[u8],
    offset: usize,
    image_base: u64,
    admission: &mut Admission,
) -> Result<(ArtifactSection, Option<FileMapping>), InspectMemoryError> {
    let raw_name = slice(bytes, offset, 8)?;
    let name_length = raw_name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(raw_name.len());
    let name_bytes = raw_name
        .get(..name_length)
        .ok_or(ArtifactError::InvalidRange {
            offset,
            length: name_length,
            total: bytes.len(),
        })?;
    let name = admission.lossy_string(name_bytes)?;
    let memory_size =
        usize::try_from(u32_at(bytes, offset + 8, Endian::Little)?).map_err(|_| {
            ArtifactError::InvalidHeader {
                field: "PE virtual section size",
            }
        })?;
    let virtual_address = u64::from(u32_at(bytes, offset + 12, Endian::Little)?);
    let file_size = usize::try_from(u32_at(bytes, offset + 16, Endian::Little)?).map_err(|_| {
        ArtifactError::InvalidHeader {
            field: "PE raw section size",
        }
    })?;
    let file_offset =
        usize::try_from(u32_at(bytes, offset + 20, Endian::Little)?).map_err(|_| {
            ArtifactError::InvalidHeader {
                field: "PE raw section offset",
            }
        })?;
    let flags = u64::from(u32_at(bytes, offset + 36, Endian::Little)?);
    let address = image_base
        .checked_add(virtual_address)
        .ok_or(ArtifactError::InvalidHeader {
            field: "PE section address",
        })?;
    if file_size > 0 {
        range(file_offset, file_size, bytes.len())?;
    } else if file_offset > bytes.len() {
        return Err(ArtifactError::InvalidRange {
            offset: file_offset,
            length: 0,
            total: bytes.len(),
        }
        .into());
    }
    let mapping = (file_size > 0).then_some(FileMapping {
        address,
        file_offset,
        file_size,
        flags,
        executable: flags & u64::from(IMAGE_SCN_MEM_EXECUTE) != 0,
    });
    Ok((
        ArtifactSection {
            name,
            address,
            file_offset: (file_size > 0).then_some(file_offset),
            file_size,
            memory_size,
            flags,
        },
        mapping,
    ))
}

fn parse_imports(
    bytes: &[u8],
    image: &PeImage,
    reference_limit: usize,
    reference_text_bytes: &mut usize,
    admission: &mut Admission,
) -> Result<Vec<ArtifactReference>, InspectMemoryError> {
    let Some((directory_offset, descriptor_count)) = import_directory(image)? else {
        return Ok(Vec::new());
    };
    let mut references = Vec::new();
    let mut terminated = false;
    for index in 0..descriptor_count {
        let offset = directory_offset
            .checked_add(index.checked_mul(IMPORT_DESCRIPTOR_BYTES).ok_or(
                ArtifactError::InvalidHeader {
                    field: "PE import descriptor offset",
                },
            )?)
            .ok_or(ArtifactError::InvalidHeader {
                field: "PE import descriptor offset",
            })?;
        let descriptor = slice(bytes, offset, IMPORT_DESCRIPTOR_BYTES)?;
        if descriptor.iter().all(|byte| *byte == 0) {
            terminated = true;
            break;
        }
        let original_thunk = u32_at(bytes, offset, Endian::Little)?;
        let name_rva = u32_at(bytes, offset + 12, Endian::Little)?;
        let first_thunk = u32_at(bytes, offset + 16, Endian::Little)?;
        if name_rva == 0 || first_thunk == 0 {
            return Err(ArtifactError::InvalidHeader {
                field: "PE import descriptor",
            }
            .into());
        }
        let name_offset = rva_to_offset(image, name_rva, 1)?;
        let (library, library_length) =
            c_string(bytes, name_offset, MAX_IMPORT_NAME_BYTES, admission)?;
        let thunk_rva = if original_thunk == 0 {
            first_thunk
        } else {
            original_thunk
        };
        let remaining_records = reference_limit.saturating_sub(references.len());
        let mut import_references = ImportReferences {
            remaining: remaining_records,
            text_bytes: reference_text_bytes,
            records: &mut references,
        };
        parse_thunks(
            bytes,
            image,
            thunk_rva,
            &library,
            FileRange {
                offset: name_offset,
                length: library_length,
            },
            &mut import_references,
            admission,
        )?;
        let library_bytes = library.capacity();
        drop(library);
        admission.release(library_bytes)?;
    }
    if !terminated {
        return Err(ArtifactError::InvalidHeader {
            field: "PE import terminator",
        }
        .into());
    }
    Ok(references)
}

fn import_directory(image: &PeImage) -> Result<Option<(usize, usize)>, InspectMemoryError> {
    let Some(directory) = image.directories.get(IMPORT_DIRECTORY).copied() else {
        return Ok(None);
    };
    if directory.rva == 0 && directory.size == 0 {
        return Ok(None);
    }
    let directory_size =
        usize::try_from(directory.size).map_err(|_| ArtifactError::InvalidHeader {
            field: "PE import directory size",
        })?;
    if directory_size < IMPORT_DESCRIPTOR_BYTES || directory_size % IMPORT_DESCRIPTOR_BYTES != 0 {
        return Err(ArtifactError::InvalidHeader {
            field: "PE import directory size",
        }
        .into());
    }
    let directory_offset = rva_to_offset(image, directory.rva, directory_size)?;
    let descriptor_count = directory_size / IMPORT_DESCRIPTOR_BYTES;
    Ok(Some((directory_offset, descriptor_count)))
}

fn parse_thunks(
    bytes: &[u8],
    image: &PeImage,
    thunk_rva: u32,
    library: &str,
    library_range: FileRange,
    output: &mut ImportReferences<'_>,
    admission: &mut Admission,
) -> Result<(), InspectMemoryError> {
    let width = if image.is_64 { 8_usize } else { 4_usize };
    let ordinal_mask = if image.is_64 {
        1_u64 << 63
    } else {
        1_u64 << 31
    };
    for index in 0..=output.remaining {
        let displacement = index
            .checked_mul(width)
            .ok_or(ArtifactError::InvalidHeader {
                field: "PE thunk offset",
            })?;
        let rva = u32::try_from(displacement)
            .ok()
            .and_then(|delta| thunk_rva.checked_add(delta))
            .ok_or(ArtifactError::InvalidHeader {
                field: "PE thunk RVA",
            })?;
        let offset = rva_to_offset(image, rva, width)?;
        let value = if image.is_64 {
            u64_at(bytes, offset, Endian::Little)?
        } else {
            u64::from(u32_at(bytes, offset, Endian::Little)?)
        };
        if value == 0 {
            return Ok(());
        }
        if index == output.remaining {
            return Err(ArtifactError::LimitExceeded {
                field: "PE import thunks",
                maximum: MAX_REFERENCES,
            }
            .into());
        }
        let (name, name_range) = if value & ordinal_mask != 0 {
            let ordinal = value & 0xffff;
            (admission.number_name("#", ordinal, "")?, None)
        } else {
            let name_rva = u32::try_from(value).map_err(|_| ArtifactError::InvalidHeader {
                field: "PE import name RVA",
            })?;
            let hint_offset = rva_to_offset(image, name_rva, 2)?;
            let name_offset = hint_offset
                .checked_add(2)
                .ok_or(ArtifactError::InvalidHeader {
                    field: "PE import name offset",
                })?;
            let (name, name_length) =
                c_string(bytes, name_offset, MAX_IMPORT_NAME_BYTES, admission)?;
            (
                name,
                Some(FileRange {
                    offset: name_offset,
                    length: name_length,
                }),
            )
        };
        charge_reference_text(output.text_bytes, &name, Some(library))?;
        let retained_library = admission.copy_str(library)?;
        admission.grow_vec(output.records, 1)?;
        output.records.push(ArtifactReference {
            name,
            library: Some(retained_library),
            library_range: Some(library_range),
            kind: ArtifactReferenceKind::Import,
            record_range: FileRange {
                offset,
                length: width,
            },
            name_range,
            address: None,
        });
    }
    Err(ArtifactError::LimitExceeded {
        field: "PE import thunks",
        maximum: MAX_REFERENCES,
    }
    .into())
}

fn parse_exports(
    bytes: &[u8],
    image: &PeImage,
    reference_text_bytes: &mut usize,
    admission: &mut Admission,
) -> Result<Vec<ArtifactReference>, InspectMemoryError> {
    let Some(exports) = export_table(bytes, image)? else {
        return Ok(Vec::new());
    };
    let mut references = admission.vec(exports.name_count)?;
    for index in 0..exports.name_count {
        references.push(parse_export(
            bytes,
            image,
            &exports,
            index,
            reference_text_bytes,
            admission,
        )?);
    }
    Ok(references)
}

struct ExportTable {
    function_count: usize,
    name_count: usize,
    functions_rva: u32,
    names_rva: u32,
    ordinals_rva: u32,
}

fn export_table(bytes: &[u8], image: &PeImage) -> Result<Option<ExportTable>, ArtifactError> {
    let Some(directory) = image.directories.get(EXPORT_DIRECTORY).copied() else {
        return Ok(None);
    };
    if directory.rva == 0 && directory.size == 0 {
        return Ok(None);
    }
    if directory.size < 40 {
        return Err(ArtifactError::InvalidHeader {
            field: "PE export directory size",
        });
    }
    let offset = rva_to_offset(image, directory.rva, 40)?;
    let function_count =
        usize::try_from(u32_at(bytes, offset + 20, Endian::Little)?).map_err(|_| {
            ArtifactError::InvalidHeader {
                field: "PE export function count",
            }
        })?;
    let name_count =
        usize::try_from(u32_at(bytes, offset + 24, Endian::Little)?).map_err(|_| {
            ArtifactError::InvalidHeader {
                field: "PE export name count",
            }
        })?;
    if name_count > MAX_REFERENCES || function_count > MAX_REFERENCES {
        return Err(ArtifactError::LimitExceeded {
            field: "PE export records",
            maximum: MAX_REFERENCES,
        });
    }
    Ok(Some(ExportTable {
        function_count,
        name_count,
        functions_rva: u32_at(bytes, offset + 28, Endian::Little)?,
        names_rva: u32_at(bytes, offset + 32, Endian::Little)?,
        ordinals_rva: u32_at(bytes, offset + 36, Endian::Little)?,
    }))
}

fn parse_export(
    bytes: &[u8],
    image: &PeImage,
    exports: &ExportTable,
    index: usize,
    reference_text_bytes: &mut usize,
    admission: &mut Admission,
) -> Result<ArtifactReference, InspectMemoryError> {
    let index_u32 = u32::try_from(index).map_err(|_| ArtifactError::InvalidHeader {
        field: "PE export name index",
    })?;
    let name_pointer_rva = indexed_rva(exports.names_rva, index_u32, 4, "PE export name pointer")?;
    let record_offset = rva_to_offset(image, name_pointer_rva, 4)?;
    let export_name_rva = u32_at(bytes, record_offset, Endian::Little)?;
    let name_offset = rva_to_offset(image, export_name_rva, 1)?;
    let (name, name_length) = c_string(bytes, name_offset, MAX_IMPORT_NAME_BYTES, admission)?;
    charge_reference_text(reference_text_bytes, &name, None)?;
    let ordinal_index = indexed_rva(
        exports.ordinals_rva,
        index_u32,
        2,
        "PE export ordinal index",
    )?;
    let ordinal_offset = rva_to_offset(image, ordinal_index, 2)?;
    let function_index = usize::from(u16_at(bytes, ordinal_offset, Endian::Little)?);
    if function_index >= exports.function_count {
        return Err(ArtifactError::InvalidHeader {
            field: "PE export ordinal",
        }
        .into());
    }
    let function_index =
        u32::try_from(function_index).map_err(|_| ArtifactError::InvalidHeader {
            field: "PE export function index",
        })?;
    let function_index_rva = indexed_rva(
        exports.functions_rva,
        function_index,
        4,
        "PE export function index",
    )?;
    let function_offset = rva_to_offset(image, function_index_rva, 4)?;
    let function_rva = u32_at(bytes, function_offset, Endian::Little)?;
    Ok(ArtifactReference {
        name,
        library: None,
        library_range: None,
        kind: ArtifactReferenceKind::Symbol,
        record_range: FileRange {
            offset: record_offset,
            length: 4,
        },
        name_range: Some(FileRange {
            offset: name_offset,
            length: name_length,
        }),
        address: image.image_base.checked_add(u64::from(function_rva)),
    })
}

fn indexed_rva(
    base: u32,
    index: u32,
    width: u32,
    field: &'static str,
) -> Result<u32, ArtifactError> {
    let displacement = index
        .checked_mul(width)
        .ok_or(ArtifactError::InvalidHeader { field })?;
    base.checked_add(displacement)
        .ok_or(ArtifactError::InvalidHeader { field })
}

fn rva_to_offset(image: &PeImage, rva: u32, length: usize) -> Result<usize, ArtifactError> {
    let address =
        image
            .image_base
            .checked_add(u64::from(rva))
            .ok_or(ArtifactError::InvalidHeader {
                field: "PE RVA address",
            })?;
    map_address(image, address, length, false)
}

fn map_address(
    image: &PeImage,
    address: u64,
    length: usize,
    executable_only: bool,
) -> Result<usize, ArtifactError> {
    let length_u64 =
        u64::try_from(length).map_err(|_| ArtifactError::UnmappedAddress { address, length })?;
    let mut offsets = image.mappings.iter().filter_map(|mapping| {
        if executable_only && !mapping.executable {
            return None;
        }
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
