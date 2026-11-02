use std::io::{Cursor, Read, Seek};

use crate::job::{MemoryError, MemoryLease};
use crc32fast::hash as crc32;
use flate2::read::DeflateDecoder;
use zip::read::{ArchiveOffset, Config};
use zip::{ZipArchive, ZipReadOptions};

use super::admission::ZipAdmission;
use super::model::{
    ZipArtifactEntry, ZipArtifactEntryMetadata, ZipArtifactError, ZipArtifactLimits,
    ZipArtifactOmission, ZipArtifactOmissionReason, ZipArtifactReport, ZipEntryDataFailure,
    ZipMemoryError, ZipReadError, ZipReaderBudget, ZipReaderLimits,
};
use super::view::{Patch, Reader, View, ViewFailure};

const STORED_METHOD: u16 = 0;
const DEFLATE_METHOD: u16 = 8;
const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
const ZIP64_EOCD_SIGNATURE: &[u8; 4] = b"PK\x06\x06";
const ZIP64_LOCATOR_SIGNATURE: &[u8; 4] = b"PK\x06\x07";
const CENTRAL_FILE_HEADER_SIGNATURE: u32 = 0x0201_4b50;
const CENTRAL_DIGITAL_SIGNATURE: u32 = 0x0505_4b50;
const CENTRAL_ARCHIVE_EXTRA_SIGNATURE: u32 = 0x0806_4b50;
const CENTRAL_FILE_HEADER_SIZE: usize = 46;
const EOCD_FIXED_SIZE: usize = 22;
const ZIP64_LOCATOR_SIZE: usize = 20;
const ZIP64_EOCD_MIN_SIZE: u64 = 44;
const MAX_EOCD_COMMENT_SIZE: usize = 65_535;
const ZIP64_SCAN_BLOCK_BYTES: usize = 64 * 1024;

/// Inspect one ZIP archive using the default bounded limits
///
/// # Errors
/// Returns an error if archive structure or operational limits are invalid
pub fn inspect_zip(bytes: &[u8]) -> Result<ZipArtifactReport, ZipArtifactError> {
    inspect_zip_with_limits(bytes, ZipArtifactLimits::default())
}

/// Inspect one top-level ZIP archive using caller-selected bounded limits
///
/// # Errors
/// Returns an error if limits or archive structure are invalid
pub fn inspect_zip_with_limits(
    bytes: &[u8],
    limits: ZipArtifactLimits,
) -> Result<ZipArtifactReport, ZipArtifactError> {
    inspect_zip_at_depth(bytes, limits, 0)
}

/// Report whether the bytes contain a ZIP end record ending at the object boundary
///
/// This recognizes archives with a prepended executable or other self-extracting
/// stub without treating an unrelated embedded `PK` marker as a complete archive.
#[must_use]
pub fn has_zip_end_record(bytes: &[u8]) -> bool {
    let view = View::new(Cursor::new(bytes), bytes.len(), usize::MAX);
    !matches!(find_eocd(&view), EocdSelection::None)
}

pub(in crate::artifact) fn has_zip_end_record_with_memory(
    bytes: &[u8],
    memory: &MemoryLease,
) -> Result<bool, MemoryError> {
    let charge = u64::try_from(scan_scratch_bytes(bytes.len()))
        .map_err(|_| MemoryError::ObservationOverflow)?;
    // The tail and a ZIP64 search buffer can exist at the same time
    let _scratch = memory.try_sibling(charge)?;
    Ok(has_zip_end_record(bytes))
}

/// Inspect a ZIP archive at a known nested depth
///
/// # Errors
/// Returns an error if limits or archive structure are invalid
pub fn inspect_zip_at_depth(
    bytes: &[u8],
    limits: ZipArtifactLimits,
    depth: usize,
) -> Result<ZipArtifactReport, ZipArtifactError> {
    inspect_zip_at_depth_inner(bytes, limits, depth, None)
}

/// Inspect a ZIP archive while consuming a shared operation-wide expansion budget
///
/// The declared expanded size is charged before extraction, so failed CRC or
/// decompression checks cannot make the same work available to another archive
/// in the operation
///
/// # Errors
/// Returns an error if archive structure or operational limits are invalid
pub fn inspect_zip_at_depth_with_operation_budget(
    bytes: &[u8],
    limits: ZipArtifactLimits,
    depth: usize,
    operation_budget_remaining: &mut usize,
) -> Result<ZipArtifactReport, ZipArtifactError> {
    inspect_zip_at_depth_inner(bytes, limits, depth, Some(operation_budget_remaining))
}

/// Inspect a ZIP while reserving member output in a caller-owned live-memory lease
///
/// The lease must outlive the returned report and every moved member buffer
/// Parser-owned buffers are charged; ZIP library metadata and decoder backend allocations are not
///
/// # Errors
/// Returns archive, allocation, or shared-memory admission failures
pub fn inspect_zip_at_depth_with_memory(
    bytes: &[u8],
    limits: ZipArtifactLimits,
    depth: usize,
    operation_budget_remaining: &mut usize,
    memory: &mut MemoryLease,
) -> Result<ZipArtifactReport, ZipMemoryError> {
    inspect_zip_slice(
        bytes,
        limits,
        depth,
        Some(operation_budget_remaining),
        Some(memory),
    )
    .map_err(|error| match error {
        ZipReadError::Memory(error) => ZipMemoryError::Memory(error),
        ZipReadError::Format(error) => ZipMemoryError::Archive(error),
        _ => ZipMemoryError::Archive(ZipArtifactError::InvalidArchive),
    })
}

/// Inspect a stable seekable archive using its already verified source digest
///
/// The source remains unchanged throughout this call. Metadata reads, directory bytes,
/// expanded output and archive depth are subject to separate caller-selected limits.
///
/// # Errors
/// Returns a structural, resource, digest, or source I/O failure
pub fn inspect_zip_from_reader_with_source_sha256(
    reader: &mut (impl Read + Seek),
    source_length: usize,
    source_sha256: &str,
    limits: ZipReaderLimits,
    depth: usize,
    budget: &mut ZipReaderBudget,
) -> Result<ZipArtifactReport, ZipReadError> {
    inspect_zip_reader(
        reader,
        source_length,
        source_sha256,
        limits,
        depth,
        budget,
        None,
    )
}

/// Inspect a seekable ZIP while reserving member output against one shared lease
///
/// The lease must outlive the returned report and every moved member buffer
/// Parser-owned buffers are charged; ZIP library metadata and decoder backend allocations are not
///
/// # Errors
/// Returns source, archive, work, allocation, or shared-memory admission failures
pub fn inspect_zip_from_reader_with_source_sha256_and_memory(
    reader: &mut (impl Read + Seek),
    source_length: usize,
    source_sha256: &str,
    limits: ZipReaderLimits,
    depth: usize,
    budget: &mut ZipReaderBudget,
    memory: &mut MemoryLease,
) -> Result<ZipArtifactReport, ZipReadError> {
    inspect_zip_reader(
        reader,
        source_length,
        source_sha256,
        limits,
        depth,
        budget,
        Some(memory),
    )
}

fn inspect_zip_reader(
    reader: &mut (impl Read + Seek),
    source_length: usize,
    source_sha256: &str,
    limits: ZipReaderLimits,
    depth: usize,
    budget: &mut ZipReaderBudget,
    memory: Option<&mut MemoryLease>,
) -> Result<ZipArtifactReport, ZipReadError> {
    if !crate::hashing::is_sha256_digest(source_sha256) {
        return Err(ZipReadError::InvalidSourceDigest);
    }
    let mut admission = ZipAdmission::new(memory, scan_scratch_bytes(source_length))?;
    let view = View::new(reader, source_length, budget.read_bytes_remaining);
    let result = inspect_view(
        &view,
        source_sha256,
        limits.archive,
        depth,
        Some(&mut budget.expanded_bytes_remaining),
        limits.max_directory_bytes,
        &mut admission,
    );
    budget.read_bytes_remaining = view.remaining();
    if let Some(failure) = view.take_failure() {
        let error = match failure {
            ViewFailure::Io(error) => ZipReadError::Io(error),
            ViewFailure::WorkLimit {
                requested,
                remaining,
            } => ZipReadError::WorkLimit {
                requested,
                remaining,
            },
            ViewFailure::Allocation => ZipReadError::Format(ZipArtifactError::AllocationFailure),
        };
        drop(result);
        return admission.finish(Err(error));
    }
    admission.finish(result)
}

fn inspect_zip_at_depth_inner(
    bytes: &[u8],
    limits: ZipArtifactLimits,
    depth: usize,
    operation_budget_remaining: Option<&mut usize>,
) -> Result<ZipArtifactReport, ZipArtifactError> {
    inspect_zip_slice(bytes, limits, depth, operation_budget_remaining, None).map_err(|error| {
        match error {
            ZipReadError::Format(error) => error,
            _ => ZipArtifactError::InvalidArchive,
        }
    })
}

fn inspect_zip_slice(
    bytes: &[u8],
    limits: ZipArtifactLimits,
    depth: usize,
    operation_budget_remaining: Option<&mut usize>,
    memory: Option<&mut MemoryLease>,
) -> Result<ZipArtifactReport, ZipReadError> {
    let mut admission = ZipAdmission::new(memory, scan_scratch_bytes(bytes.len()))?;
    let view = View::new(Cursor::new(bytes), bytes.len(), usize::MAX);
    let result = inspect_view(
        &view,
        &crate::sha256(bytes),
        limits,
        depth,
        operation_budget_remaining,
        usize::MAX,
        &mut admission,
    );
    if view.take_failure().is_some() {
        drop(result);
        return admission.finish(Err(ZipReadError::Format(
            ZipArtifactError::AllocationFailure,
        )));
    }
    admission.finish(result)
}

fn inspect_view<R: Read + Seek>(
    bytes: &View<R>,
    source_sha256: &str,
    limits: ZipArtifactLimits,
    depth: usize,
    mut operation_budget_remaining: Option<&mut usize>,
    max_directory_bytes: usize,
    admission: &mut ZipAdmission<'_>,
) -> Result<ZipArtifactReport, ZipReadError> {
    validate_limits(limits).map_err(ZipReadError::Format)?;
    if bytes.len() > limits.max_archive_bytes {
        return Err(ZipReadError::Format(ZipArtifactError::ArchiveTooLarge {
            length: bytes.len(),
            maximum: limits.max_archive_bytes,
        }));
    }
    // The declared count is checked before the ZIP library allocates records
    let declared_entry_count = declared_entry_count(bytes).map_err(ZipReadError::Format)?;
    let entry_count = usize::try_from(declared_entry_count).map_err(|_| {
        ZipReadError::Format(ZipArtifactError::EntryCountOutOfRange {
            count: declared_entry_count,
        })
    })?;
    if depth > limits.max_depth {
        return limited_report(
            bytes,
            source_sha256,
            depth,
            entry_count,
            ZipArtifactOmissionReason::DepthLimit,
        )
        .map_err(ZipReadError::Format);
    }
    if entry_count > limits.max_entries {
        return limited_report(
            bytes,
            source_sha256,
            depth,
            entry_count,
            ZipArtifactOmissionReason::EntryCountLimit,
        )
        .map_err(ZipReadError::Format);
    }
    let directory = declared_directory_layout(bytes, entry_count).map_err(ZipReadError::Format)?;
    let zip64_metadata = directory.zip64_record_offset.map_or(0, |start| {
        directory
            .eocd_offset
            .saturating_sub(ZIP64_LOCATOR_SIZE)
            .saturating_sub(start)
    });
    let metadata_bytes = directory
        .size
        .saturating_add(u64::try_from(zip64_metadata).unwrap_or(u64::MAX));
    if metadata_bytes > u64::try_from(max_directory_bytes).unwrap_or(u64::MAX) {
        return Err(ZipReadError::DirectoryLimit {
            length: metadata_bytes,
            maximum: max_directory_bytes,
        });
    }
    admission.reserve_metadata(entry_count, metadata_bytes)?;
    let PreparedArchive {
        mut archive,
        metadata_entries,
        member_failures,
    } = prepare_archive(bytes, entry_count, directory).map_err(ZipReadError::Format)?;
    // Reserve eligible output before member extraction consumes operation work
    if admission.is_active() {
        let (output_bytes, uses_deflate) = planned_member_outputs(
            &metadata_entries,
            limits,
            operation_budget_remaining.as_deref().copied(),
        )?;
        admission.reserve_output(output_bytes, uses_deflate)?;
    }
    let mut report = empty_report(bytes, source_sha256, depth, entry_count);
    report
        .entries
        .try_reserve_exact(entry_count)
        .map_err(|_| ZipReadError::Format(ZipArtifactError::AllocationFailure))?;
    for (index, metadata) in metadata_entries.into_iter().enumerate() {
        inspect_member(
            &mut archive,
            metadata,
            member_failures.get(index).copied().flatten(),
            limits,
            &mut report,
            &mut operation_budget_remaining,
        )
        .map_err(ZipReadError::Format)?;
    }
    Ok(report)
}

fn scan_scratch_bytes(length: usize) -> usize {
    let tail = length.min(MAX_EOCD_COMMENT_SIZE + EOCD_FIXED_SIZE);
    // A ZIP64 locator can lead to a second live buffer while the tail is held
    let zip64 = length
        .checked_sub(EOCD_FIXED_SIZE + ZIP64_LOCATOR_SIZE)
        .map_or(0, |bytes| bytes.clamp(4, ZIP64_SCAN_BLOCK_BYTES));
    tail + zip64
}

fn planned_member_outputs(
    entries: &[ZipArtifactEntryMetadata],
    limits: ZipArtifactLimits,
    mut remaining: Option<usize>,
) -> Result<(usize, bool), ZipReadError> {
    let mut total = 0_usize;
    let mut uses_deflate = false;
    for metadata in entries {
        if omission_reason(metadata, limits, total, remaining).is_some() {
            continue;
        }
        let bytes = usize::try_from(metadata.expanded_size)
            .map_err(|_| ZipReadError::Format(ZipArtifactError::InvalidArchive))?;
        total += bytes;
        uses_deflate |= metadata.compression_method == DEFLATE_METHOD;
        if let Some(remaining) = &mut remaining {
            *remaining -= bytes;
        }
    }
    Ok((total, uses_deflate))
}

fn inspect_member(
    archive: &mut ZipArchive<impl Read + Seek>,
    metadata: ZipArtifactEntryMetadata,
    structural_failure: Option<ZipEntryDataFailure>,
    limits: ZipArtifactLimits,
    report: &mut ZipArtifactReport,
    operation_budget_remaining: &mut Option<&mut usize>,
) -> Result<(), ZipArtifactError> {
    let operation_remaining = operation_budget_remaining.as_deref().copied();
    if let Some(reason) = omission_reason(
        &metadata,
        limits,
        report.expanded_work_byte_count,
        operation_remaining,
    ) {
        record_omission(report, reason, 1)?;
        report.entries.push(ZipArtifactEntry {
            metadata,
            content: None,
            omission: Some(reason),
        });
        return Ok(());
    }

    let work_bytes =
        usize::try_from(metadata.expanded_size).map_err(|_| ZipArtifactError::InvalidArchive)?;
    // Charge before extraction so a failed member stays charged
    report.expanded_work_byte_count += work_bytes;
    if let Some(remaining) = operation_budget_remaining.as_deref_mut() {
        *remaining -= work_bytes;
    }
    let (content, omission) = match extract_entry(archive, &metadata, structural_failure) {
        Ok(expanded) => {
            report.expanded_byte_count += expanded.len();
            report.extracted_entry_count += 1;
            (Some(expanded), None)
        }
        Err(failure) => {
            // Member data errors stay local so later directory entries can still be read
            let reason = ZipArtifactOmissionReason::EntryDataFailure {
                index: metadata.index,
                failure,
            };
            record_omission(report, reason, 1)?;
            (None, Some(reason))
        }
    };
    report.entries.push(ZipArtifactEntry {
        metadata,
        content,
        omission,
    });
    Ok(())
}

struct PreparedArchive<'a, R> {
    archive: ZipArchive<Reader<'a, R>>,
    metadata_entries: Vec<ZipArtifactEntryMetadata>,
    member_failures: Vec<Option<ZipEntryDataFailure>>,
}

#[derive(Clone, Copy)]
struct DirectoryLayout {
    start: u64,
    size: u64,
    relative_offset: u64,
    eocd_offset: usize,
    zip64_record_offset: Option<usize>,
}

fn prepare_archive<R: Read + Seek>(
    bytes: &View<R>,
    entry_count: usize,
    directory: DirectoryLayout,
) -> Result<PreparedArchive<'_, R>, ZipArtifactError> {
    let patches = normalized_reader_patches(bytes, directory)?;
    // The checked directory already fixes the archive prefix, avoiding a full-source search
    let archive_offset = directory
        .start
        .checked_sub(directory.relative_offset)
        .ok_or(ZipArtifactError::InvalidArchive)?;
    let config = Config {
        archive_offset: ArchiveOffset::Known(archive_offset),
    };
    let mut archive = ZipArchive::with_config(config, Reader::new(bytes, patches))
        .map_err(|_| ZipArtifactError::InvalidArchive)?;
    if archive.len() != entry_count {
        return Err(ZipArtifactError::InvalidArchive);
    }
    // Overlapping entries make otherwise valid members depend on conflicting byte ranges
    if archive
        .has_overlapping_entries()
        .map_err(|_| ZipArtifactError::InvalidArchive)?
    {
        return Err(ZipArtifactError::InvalidArchive);
    }
    let directory_start = directory.start;
    let mut metadata_entries = Vec::new();
    metadata_entries
        .try_reserve_exact(entry_count)
        .map_err(|_| ZipArtifactError::AllocationFailure)?;
    for index in 0..entry_count {
        metadata_entries.push(archive_entry_metadata(&mut archive, index)?);
    }
    let mut member_failures = Vec::new();
    member_failures
        .try_reserve_exact(entry_count)
        .map_err(|_| ZipArtifactError::AllocationFailure)?;
    member_failures.resize(entry_count, None);
    let mut member_ranges = Vec::new();
    member_ranges
        .try_reserve_exact(entry_count)
        .map_err(|_| ZipArtifactError::AllocationFailure)?;
    for (index, metadata) in metadata_entries.iter().enumerate() {
        let Some(layout) = member_layout(bytes, metadata, directory_start) else {
            continue;
        };
        if let Some(failure) = layout.failure {
            let slot = member_failures
                .get_mut(index)
                .ok_or(ZipArtifactError::InvalidArchive)?;
            *slot = Some(failure);
        }
        member_ranges.push((layout.range, index, layout.has_descriptor));
    }
    flag_descriptor_overlaps(&mut member_ranges, &mut member_failures);
    Ok(PreparedArchive {
        archive,
        metadata_entries,
        member_failures,
    })
}

fn validate_central_directory(
    bytes: &View<impl Read + Seek>,
    directory_start: u64,
    directory_size: u64,
    expected_entries: usize,
) -> Result<(), ZipArtifactError> {
    let start = usize::try_from(directory_start).map_err(|_| ZipArtifactError::InvalidArchive)?;
    let size = usize::try_from(directory_size).map_err(|_| ZipArtifactError::InvalidArchive)?;
    let end = start
        .checked_add(size)
        .filter(|end| *end <= bytes.len())
        .ok_or(ZipArtifactError::InvalidArchive)?;
    let mut cursor = start;
    let mut observed_entries = 0_usize;

    // Walk record boundaries so signature-like bytes inside names and comments cannot affect the count
    while cursor < end {
        let signature = read_u32(bytes, cursor).ok_or(ZipArtifactError::InvalidArchive)?;
        let record_size = match signature {
            CENTRAL_FILE_HEADER_SIGNATURE => {
                observed_entries = observed_entries
                    .checked_add(1)
                    .ok_or(ZipArtifactError::InvalidArchive)?;
                central_file_header_size(bytes, cursor)?
            }
            CENTRAL_DIGITAL_SIGNATURE => central_variable_record_size(bytes, cursor, 6, 4, false)?,
            CENTRAL_ARCHIVE_EXTRA_SIGNATURE => {
                // The archive-extra record is optional, singular, and precedes all member headers
                if cursor != start {
                    return Err(ZipArtifactError::InvalidArchive);
                }
                central_variable_record_size(bytes, cursor, 8, 4, true)?
            }
            _ => return Err(ZipArtifactError::InvalidArchive),
        };
        let next = cursor
            .checked_add(record_size)
            .filter(|next| *next <= end)
            .ok_or(ZipArtifactError::InvalidArchive)?;
        if signature == CENTRAL_DIGITAL_SIGNATURE && next != end {
            return Err(ZipArtifactError::InvalidArchive);
        }
        cursor = next;
    }

    if cursor != end || observed_entries != expected_entries {
        return Err(ZipArtifactError::InvalidArchive);
    }
    Ok(())
}

fn central_file_header_size(
    bytes: &View<impl Read + Seek>,
    offset: usize,
) -> Result<usize, ZipArtifactError> {
    let name_length = read_u16(
        bytes,
        offset
            .checked_add(28)
            .ok_or(ZipArtifactError::InvalidArchive)?,
    )
    .map(usize::from)
    .ok_or(ZipArtifactError::InvalidArchive)?;
    let extra_length = read_u16(
        bytes,
        offset
            .checked_add(30)
            .ok_or(ZipArtifactError::InvalidArchive)?,
    )
    .map(usize::from)
    .ok_or(ZipArtifactError::InvalidArchive)?;
    let comment_length = read_u16(
        bytes,
        offset
            .checked_add(32)
            .ok_or(ZipArtifactError::InvalidArchive)?,
    )
    .map(usize::from)
    .ok_or(ZipArtifactError::InvalidArchive)?;
    CENTRAL_FILE_HEADER_SIZE
        .checked_add(name_length)
        .and_then(|size| size.checked_add(extra_length))
        .and_then(|size| size.checked_add(comment_length))
        .ok_or(ZipArtifactError::InvalidArchive)
}

fn central_variable_record_size(
    bytes: &View<impl Read + Seek>,
    offset: usize,
    fixed_size: usize,
    length_offset: usize,
    wide_length: bool,
) -> Result<usize, ZipArtifactError> {
    let field_offset = offset
        .checked_add(length_offset)
        .ok_or(ZipArtifactError::InvalidArchive)?;
    let payload_size = if wide_length {
        read_u32(bytes, field_offset).map(|length| usize::try_from(length).ok())
    } else {
        read_u16(bytes, field_offset).map(|length| Some(usize::from(length)))
    }
    .flatten()
    .ok_or(ZipArtifactError::InvalidArchive)?;
    fixed_size
        .checked_add(payload_size)
        .ok_or(ZipArtifactError::InvalidArchive)
}

fn validate_limits(limits: ZipArtifactLimits) -> Result<(), ZipArtifactError> {
    for (field, requested) in [
        ("archive bytes", limits.max_archive_bytes),
        ("entries", limits.max_entries),
        ("entry expanded bytes", limits.max_entry_expanded_bytes),
    ] {
        if requested == 0 {
            return Err(ZipArtifactError::InvalidLimits { field });
        }
    }
    // A zero aggregate budget still permits structure checks and empty members
    Ok(())
}

fn empty_report(
    bytes: &View<impl Read + Seek>,
    source_sha256: &str,
    depth: usize,
    entry_count: usize,
) -> ZipArtifactReport {
    ZipArtifactReport {
        archive_sha256: source_sha256.to_owned(),
        archive_size: bytes.len(),
        depth,
        entry_count,
        extracted_entry_count: 0,
        expanded_byte_count: 0,
        expanded_work_byte_count: 0,
        omitted_entry_count: 0,
        entries: Vec::new(),
        omissions: Vec::new(),
    }
}

fn limited_report(
    bytes: &View<impl Read + Seek>,
    source_sha256: &str,
    depth: usize,
    entry_count: usize,
    reason: ZipArtifactOmissionReason,
) -> Result<ZipArtifactReport, ZipArtifactError> {
    let mut report = empty_report(bytes, source_sha256, depth, entry_count);
    record_omission(&mut report, reason, entry_count)?;
    Ok(report)
}

fn declared_entry_count(bytes: &View<impl Read + Seek>) -> Result<u64, ZipArtifactError> {
    let eocd_offset = match find_eocd(bytes) {
        EocdSelection::None => return Err(ZipArtifactError::InvalidArchive),
        EocdSelection::Ambiguous => return Err(ZipArtifactError::AmbiguousEndRecords),
        EocdSelection::Unique(offset) => offset,
    };
    let disk_number = read_u16(bytes, eocd_offset + 4).ok_or(ZipArtifactError::InvalidArchive)?;
    let directory_disk =
        read_u16(bytes, eocd_offset + 6).ok_or(ZipArtifactError::InvalidArchive)?;
    let entries_on_disk =
        read_u16(bytes, eocd_offset + 8).ok_or(ZipArtifactError::InvalidArchive)?;
    let total_entries =
        read_u16(bytes, eocd_offset + 10).ok_or(ZipArtifactError::InvalidArchive)?;
    let directory_size =
        read_u32(bytes, eocd_offset + 12).ok_or(ZipArtifactError::InvalidArchive)?;
    let directory_offset =
        read_u32(bytes, eocd_offset + 16).ok_or(ZipArtifactError::InvalidArchive)?;
    if disk_number != 0 || directory_disk != 0 {
        return Err(ZipArtifactError::InvalidArchive);
    }

    let has_zip64_markers = entries_on_disk == u16::MAX
        || total_entries == u16::MAX
        || directory_size == u32::MAX
        || directory_offset == u32::MAX;
    if !has_zip64_markers {
        if entries_on_disk != total_entries {
            return Err(ZipArtifactError::InvalidArchive);
        }
        return Ok(u64::from(total_entries));
    }

    let zip64_entries = zip64_entry_count(bytes, eocd_offset)?;
    if (entries_on_disk != u16::MAX && u64::from(entries_on_disk) != zip64_entries)
        || (total_entries != u16::MAX && u64::from(total_entries) != zip64_entries)
    {
        return Err(ZipArtifactError::InvalidArchive);
    }
    Ok(zip64_entries)
}

fn declared_directory_layout(
    bytes: &View<impl Read + Seek>,
    entry_count: usize,
) -> Result<DirectoryLayout, ZipArtifactError> {
    let eocd_offset = match find_eocd(bytes) {
        EocdSelection::None => return Err(ZipArtifactError::InvalidArchive),
        EocdSelection::Ambiguous => return Err(ZipArtifactError::AmbiguousEndRecords),
        EocdSelection::Unique(offset) => offset,
    };
    let fields = read_eocd_fields(bytes, eocd_offset).ok_or(ZipArtifactError::InvalidArchive)?;
    let (size, relative_offset) = plausible_directory_fields(bytes, eocd_offset, fields)
        .ok_or(ZipArtifactError::InvalidArchive)?;
    let optional_zip64 = zip64_record_before_eocd(bytes, eocd_offset);
    if size == 0 {
        let end = optional_zip64.unwrap_or(eocd_offset);
        let start = u64::try_from(end).map_err(|_| ZipArtifactError::InvalidArchive)?;
        validate_central_directory(bytes, start, size, entry_count)?;
        return Ok(DirectoryLayout {
            start,
            size,
            relative_offset,
            eocd_offset,
            zip64_record_offset: optional_zip64,
        });
    }
    let candidate_ends = [
        (eocd_offset, None),
        (optional_zip64.unwrap_or(eocd_offset), optional_zip64),
    ];
    let mut selected = None;
    for (candidate_index, (end, zip64_record_offset)) in candidate_ends.into_iter().enumerate() {
        if candidate_index == 1 && zip64_record_offset.is_none() {
            continue;
        }
        let Some(start) = u64::try_from(end)
            .ok()
            .and_then(|end| end.checked_sub(size))
        else {
            continue;
        };
        if validate_central_directory(bytes, start, size, entry_count).is_err() {
            continue;
        }
        if selected.is_some() {
            return Err(ZipArtifactError::InvalidArchive);
        }
        selected = Some(DirectoryLayout {
            start,
            size,
            relative_offset,
            eocd_offset,
            zip64_record_offset,
        });
    }
    selected.ok_or(ZipArtifactError::InvalidArchive)
}

fn normalized_reader_patches(
    bytes: &View<impl Read + Seek>,
    directory: DirectoryLayout,
) -> Result<Vec<Patch>, ZipArtifactError> {
    let start = usize::try_from(directory.start).map_err(|_| ZipArtifactError::InvalidArchive)?;
    if read_u32(bytes, start) != Some(CENTRAL_ARCHIVE_EXTRA_SIGNATURE) {
        return Ok(Vec::new());
    }
    let extra_size = u64::try_from(central_variable_record_size(bytes, start, 8, 4, true)?)
        .map_err(|_| ZipArtifactError::InvalidArchive)?;
    let size = directory
        .size
        .checked_sub(extra_size)
        .ok_or(ZipArtifactError::InvalidArchive)?;
    let offset = directory
        .relative_offset
        .checked_add(extra_size)
        .ok_or(ZipArtifactError::InvalidArchive)?;
    let fields =
        read_eocd_fields(bytes, directory.eocd_offset).ok_or(ZipArtifactError::InvalidArchive)?;
    let mut patches = Vec::new();
    patches
        .try_reserve_exact(4)
        .map_err(|_| ZipArtifactError::AllocationFailure)?;
    if fields.directory_size != u32::MAX {
        patches.push(Patch {
            offset: directory.eocd_offset + 12,
            bytes: u32::try_from(size)
                .map_err(|_| ZipArtifactError::InvalidArchive)?
                .to_le_bytes()
                .to_vec(),
        });
    }
    if fields.directory_offset != u32::MAX {
        patches.push(Patch {
            offset: directory.eocd_offset + 16,
            bytes: u32::try_from(offset)
                .map_err(|_| ZipArtifactError::InvalidArchive)?
                .to_le_bytes()
                .to_vec(),
        });
    }
    if let Some(record_offset) = directory.zip64_record_offset {
        patches.push(Patch {
            offset: record_offset + 40,
            bytes: size.to_le_bytes().to_vec(),
        });
        patches.push(Patch {
            offset: record_offset + 48,
            bytes: offset.to_le_bytes().to_vec(),
        });
    }
    Ok(patches)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EocdSelection {
    None,
    Unique(usize),
    Ambiguous,
}

fn find_eocd(bytes: &View<impl Read + Seek>) -> EocdSelection {
    let Some(max_scan_size) = EOCD_FIXED_SIZE.checked_add(MAX_EOCD_COMMENT_SIZE) else {
        return EocdSelection::None;
    };
    let scan_start = bytes.len().saturating_sub(max_scan_size);
    let Some(scan) = bytes.get(scan_start..bytes.len()) else {
        return EocdSelection::None;
    };

    // ZIP comments can contain a second end-aligned record, so retain every plausible interpretation
    let mut selected = None;
    for (relative_offset, signature) in scan.windows(EOCD_SIGNATURE.len()).enumerate() {
        if signature != EOCD_SIGNATURE {
            continue;
        }
        let Some(offset) = scan_start.checked_add(relative_offset) else {
            continue;
        };
        let Some(comment_size) = offset
            .checked_add(20)
            .and_then(|field| read_u16(bytes, field))
            .map(usize::from)
        else {
            continue;
        };
        let Some(record_end) = offset
            .checked_add(EOCD_FIXED_SIZE)
            .and_then(|end| end.checked_add(comment_size))
        else {
            continue;
        };
        if record_end != bytes.len() || !plausible_eocd(bytes, offset) {
            continue;
        }
        if selected.is_some() {
            return EocdSelection::Ambiguous;
        }
        selected = Some(offset);
    }
    selected.map_or(EocdSelection::None, EocdSelection::Unique)
}

fn plausible_eocd(bytes: &View<impl Read + Seek>, offset: usize) -> bool {
    let Some(fields) = read_eocd_fields(bytes, offset) else {
        return false;
    };
    let Some((directory_size, directory_offset)) =
        plausible_directory_fields(bytes, offset, fields)
    else {
        return false;
    };
    directory_offset
        .checked_add(directory_size)
        .is_some_and(|end| end <= u64::try_from(offset).unwrap_or(u64::MAX))
}

#[derive(Clone, Copy)]
struct EocdFields {
    entries_on_disk: u16,
    total_entries: u16,
    directory_size: u32,
    directory_offset: u32,
}

fn read_eocd_fields(bytes: &View<impl Read + Seek>, offset: usize) -> Option<EocdFields> {
    let disk_number = read_u16(bytes, offset.checked_add(4)?)?;
    let directory_disk = read_u16(bytes, offset.checked_add(6)?)?;
    if disk_number != 0 || directory_disk != 0 {
        return None;
    }
    Some(EocdFields {
        entries_on_disk: read_u16(bytes, offset.checked_add(8)?)?,
        total_entries: read_u16(bytes, offset.checked_add(10)?)?,
        directory_size: read_u32(bytes, offset.checked_add(12)?)?,
        directory_offset: read_u32(bytes, offset.checked_add(16)?)?,
    })
}

fn plausible_directory_fields(
    bytes: &View<impl Read + Seek>,
    eocd_offset: usize,
    fields: EocdFields,
) -> Option<(u64, u64)> {
    let has_zip64_markers = fields.entries_on_disk == u16::MAX
        || fields.total_entries == u16::MAX
        || fields.directory_size == u32::MAX
        || fields.directory_offset == u32::MAX;
    if !has_zip64_markers {
        return (fields.entries_on_disk == fields.total_entries).then_some((
            u64::from(fields.directory_size),
            u64::from(fields.directory_offset),
        ));
    }

    let count = zip64_entry_count(bytes, eocd_offset).ok()?;
    if (fields.entries_on_disk != u16::MAX && u64::from(fields.entries_on_disk) != count)
        || (fields.total_entries != u16::MAX && u64::from(fields.total_entries) != count)
    {
        return None;
    }
    zip64_directory_fields(bytes, eocd_offset, fields)
}

fn zip64_directory_fields(
    bytes: &View<impl Read + Seek>,
    eocd_offset: usize,
    fields: EocdFields,
) -> Option<(u64, u64)> {
    if fields.directory_size != u32::MAX && fields.directory_offset != u32::MAX {
        return Some((
            u64::from(fields.directory_size),
            u64::from(fields.directory_offset),
        ));
    }
    let locator_offset = eocd_offset.checked_sub(ZIP64_LOCATOR_SIZE)?;
    let record_offset = find_zip64_record_offset(bytes, locator_offset)?;
    let zip64_size = read_u64(bytes, record_offset.checked_add(40)?)?;
    let zip64_offset = read_u64(bytes, record_offset.checked_add(48)?)?;
    Some((
        if fields.directory_size == u32::MAX {
            zip64_size
        } else {
            u64::from(fields.directory_size)
        },
        if fields.directory_offset == u32::MAX {
            zip64_offset
        } else {
            u64::from(fields.directory_offset)
        },
    ))
}

fn find_zip64_record_offset(
    bytes: &View<impl Read + Seek>,
    locator_offset: usize,
) -> Option<usize> {
    let direct = read_u64(bytes, locator_offset.checked_add(8)?)
        .and_then(|offset| usize::try_from(offset).ok())
        .filter(|offset| zip64_record_entry_count(bytes, *offset, locator_offset).is_some());
    if direct.is_some() {
        return direct;
    }
    let mut end = locator_offset;
    while end > 0 {
        let start = end.saturating_sub(ZIP64_SCAN_BLOCK_BYTES);
        let scan = bytes.get(start..end)?;
        for (relative, signature) in scan.windows(ZIP64_EOCD_SIGNATURE.len()).enumerate().rev() {
            let offset = start.checked_add(relative)?;
            if signature == ZIP64_EOCD_SIGNATURE
                && zip64_record_entry_count(bytes, offset, locator_offset).is_some()
            {
                return Some(offset);
            }
        }
        if start == 0 {
            break;
        }
        end = start.checked_add(ZIP64_EOCD_SIGNATURE.len() - 1)?;
    }
    None
}

fn zip64_record_before_eocd(bytes: &View<impl Read + Seek>, eocd_offset: usize) -> Option<usize> {
    let locator_offset = eocd_offset.checked_sub(ZIP64_LOCATOR_SIZE)?;
    if bytes.get(locator_offset..locator_offset.checked_add(4)?)? != ZIP64_LOCATOR_SIGNATURE {
        return None;
    }
    let disk_number = read_u32(bytes, locator_offset.checked_add(4)?)?;
    let disk_count = read_u32(bytes, locator_offset.checked_add(16)?)?;
    if disk_number != 0 || disk_count != 1 {
        return None;
    }
    find_zip64_record_offset(bytes, locator_offset)
}

fn zip64_entry_count(
    bytes: &View<impl Read + Seek>,
    eocd_offset: usize,
) -> Result<u64, ZipArtifactError> {
    let record_offset =
        zip64_record_before_eocd(bytes, eocd_offset).ok_or(ZipArtifactError::InvalidArchive)?;
    read_u64(bytes, record_offset + 32).ok_or(ZipArtifactError::InvalidArchive)
}

fn zip64_record_entry_count(
    bytes: &View<impl Read + Seek>,
    record_offset: usize,
    locator_offset: usize,
) -> Option<u64> {
    if bytes.get(record_offset..record_offset.checked_add(4)?)? != ZIP64_EOCD_SIGNATURE {
        return None;
    }
    let record_size = read_u64(bytes, record_offset.checked_add(4)?)?;
    if record_size < ZIP64_EOCD_MIN_SIZE {
        return None;
    }
    let record_size = usize::try_from(record_size).ok()?;
    let record_end = record_offset.checked_add(12)?.checked_add(record_size)?;
    if record_end != locator_offset {
        return None;
    }

    let disk_number = read_u32(bytes, record_offset.checked_add(16)?)?;
    let directory_disk = read_u32(bytes, record_offset.checked_add(20)?)?;
    let entries_on_disk = read_u64(bytes, record_offset.checked_add(24)?)?;
    let entry_count = read_u64(bytes, record_offset.checked_add(32)?)?;
    (disk_number == 0 && directory_disk == 0 && entries_on_disk == entry_count)
        .then_some(entry_count)
}

struct MemberLayout {
    range: std::ops::Range<u64>,
    failure: Option<ZipEntryDataFailure>,
    has_descriptor: bool,
}

fn member_layout(
    bytes: &View<impl Read + Seek>,
    metadata: &ZipArtifactEntryMetadata,
    directory_start: u64,
) -> Option<MemberLayout> {
    let header_start = usize::try_from(metadata.local_header_offset).ok()?;
    let header_end = header_start.checked_add(30)?;
    if bytes.get(header_start..header_start.checked_add(4)?)? != b"PK\x03\x04" {
        return None;
    }
    let flags = read_u16(bytes, header_start.checked_add(6)?)?;
    let local_compressed_size = read_u32(bytes, header_start.checked_add(18)?)?;
    let local_expanded_size = read_u32(bytes, header_start.checked_add(22)?)?;
    let name_length = usize::from(read_u16(bytes, header_start.checked_add(26)?)?);
    let extra_length = usize::from(read_u16(bytes, header_start.checked_add(28)?)?);
    let extra_start = header_end.checked_add(name_length)?;
    let data_start = extra_start.checked_add(extra_length)?;
    let data_end = data_start.checked_add(usize::try_from(metadata.compressed_size).ok()?)?;
    let has_descriptor = flags & (1 << 3) != 0;
    let mut end = data_end;
    let mut failure = None;

    if has_descriptor {
        let zip64 = local_compressed_size == u32::MAX
            || local_expanded_size == u32::MAX
            || metadata.compressed_size > u64::from(u32::MAX)
            || metadata.expanded_size > u64::from(u32::MAX)
            || local_extra_has_zip64(bytes, extra_start, extra_length);
        let (descriptor_end, descriptor_failure) =
            descriptor_boundary(bytes, data_end, metadata, zip64);
        end = descriptor_end;
        failure = descriptor_failure;
        if u64::try_from(end).ok()? > directory_start {
            end = usize::try_from(directory_start).ok()?;
            failure = Some(ZipEntryDataFailure::DataDescriptorMismatch);
        }
    }

    Some(MemberLayout {
        range: u64::try_from(header_start).ok()?..u64::try_from(end).ok()?,
        failure,
        has_descriptor,
    })
}

fn local_extra_has_zip64(bytes: &View<impl Read + Seek>, mut offset: usize, length: usize) -> bool {
    let Some(extra_end) = offset.checked_add(length) else {
        return false;
    };
    while offset < extra_end {
        let Some(field_id) = read_u16(bytes, offset) else {
            return false;
        };
        let Some(field_length) = read_u16(bytes, offset.saturating_add(2)).map(usize::from) else {
            return false;
        };
        if field_id == 0x0001 {
            return true;
        }
        let Some(next) = offset
            .checked_add(4)
            .and_then(|field| field.checked_add(field_length))
        else {
            return false;
        };
        if next > extra_end {
            return false;
        }
        offset = next;
    }
    false
}

fn descriptor_boundary(
    bytes: &View<impl Read + Seek>,
    offset: usize,
    metadata: &ZipArtifactEntryMetadata,
    zip64: bool,
) -> (usize, Option<ZipEntryDataFailure>) {
    let has_signature = read_u32(bytes, offset) == Some(0x0807_4b50);
    let unsigned_match = descriptor_matches(bytes, offset, metadata, zip64, false);
    let signed_match = if has_signature {
        descriptor_matches(bytes, offset, metadata, zip64, true)
    } else {
        None
    };
    let (length, failure) = match (unsigned_match, signed_match) {
        (Some(unsigned_end), None) => (unsigned_end.saturating_sub(offset), None),
        (None, Some(signed_end)) => (signed_end.saturating_sub(offset), None),
        (Some(unsigned_end), Some(signed_end)) => (
            unsigned_end.max(signed_end).saturating_sub(offset),
            Some(ZipEntryDataFailure::DataDescriptorMismatch),
        ),
        (None, None) => {
            let length = match (zip64, has_signature) {
                (false, false) => 12,
                (false, true) => 16,
                (true, false) => 20,
                (true, true) => 24,
            };
            (length, Some(ZipEntryDataFailure::DataDescriptorMismatch))
        }
    };
    let end = offset
        .checked_add(length)
        .unwrap_or(bytes.len())
        .min(bytes.len());
    (end, failure)
}

fn descriptor_matches(
    bytes: &View<impl Read + Seek>,
    offset: usize,
    metadata: &ZipArtifactEntryMetadata,
    zip64: bool,
    signed: bool,
) -> Option<usize> {
    if signed && read_u32(bytes, offset)? != 0x0807_4b50 {
        return None;
    }
    let fields = offset.checked_add(if signed { 4 } else { 0 })?;
    let crc32 = read_u32(bytes, fields)?;
    if crc32 != metadata.crc32 {
        return None;
    }
    let size_fields = fields.checked_add(4)?;
    let (compressed_size, expanded_size, length) = if zip64 {
        (
            read_u64(bytes, size_fields)?,
            read_u64(bytes, size_fields.checked_add(8)?)?,
            if signed { 24 } else { 20 },
        )
    } else {
        (
            u64::from(read_u32(bytes, size_fields)?),
            u64::from(read_u32(bytes, size_fields.checked_add(4)?)?),
            if signed { 16 } else { 12 },
        )
    };
    if compressed_size != metadata.compressed_size || expanded_size != metadata.expanded_size {
        return None;
    }
    offset.checked_add(length)
}

fn flag_descriptor_overlaps(
    ranges: &mut [(std::ops::Range<u64>, usize, bool)],
    failures: &mut [Option<ZipEntryDataFailure>],
) {
    ranges.sort_unstable_by_key(|(range, _, _)| (range.start, range.end));
    for left_index in 0..ranges.len() {
        let Some((left_range, left_entry, left_has_descriptor)) = ranges.get(left_index) else {
            continue;
        };
        for (right_range, right_entry, right_has_descriptor) in ranges
            .iter()
            .skip(left_index.saturating_add(1))
            .take_while(|(range, _, _)| range.start < left_range.end)
        {
            let descriptor_involved = *left_has_descriptor || *right_has_descriptor;
            let left_starts_before_right_ends = left_range.start < right_range.end;
            let right_starts_before_left_ends = right_range.start < left_range.end;
            if descriptor_involved && left_starts_before_right_ends && right_starts_before_left_ends
            {
                if *left_has_descriptor && let Some(failure) = failures.get_mut(*left_entry) {
                    failure.get_or_insert(ZipEntryDataFailure::DataDescriptorOverlap);
                }
                if *right_has_descriptor && let Some(failure) = failures.get_mut(*right_entry) {
                    failure.get_or_insert(ZipEntryDataFailure::DataDescriptorOverlap);
                }
            }
        }
    }
}

fn read_u16(bytes: &View<impl Read + Seek>, offset: usize) -> Option<u16> {
    bytes.array(offset).map(u16::from_le_bytes)
}

fn read_u32(bytes: &View<impl Read + Seek>, offset: usize) -> Option<u32> {
    bytes.array(offset).map(u32::from_le_bytes)
}

fn read_u64(bytes: &View<impl Read + Seek>, offset: usize) -> Option<u64> {
    bytes.array(offset).map(u64::from_le_bytes)
}

fn archive_entry_metadata(
    archive: &mut ZipArchive<impl Read + Seek>,
    index: usize,
) -> Result<ZipArtifactEntryMetadata, ZipArtifactError> {
    let file = archive
        .by_index_raw(index)
        .map_err(|_| ZipArtifactError::InvalidArchive)?;
    // Keep the path as raw metadata and never use it to create a filesystem location
    let mut raw_name = Vec::new();
    raw_name
        .try_reserve_exact(file.name_raw().len())
        .map_err(|_| ZipArtifactError::AllocationFailure)?;
    raw_name.extend_from_slice(file.name_raw());
    Ok(ZipArtifactEntryMetadata {
        index,
        raw_name,
        is_directory: file.is_dir(),
        compression_method: file.compression().into_compression().as_u16(),
        encrypted: file.encrypted(),
        compressed_size: file.compressed_size(),
        expanded_size: file.size(),
        crc32: file.crc32(),
        local_header_offset: file.header_start(),
        unix_mode: file.unix_mode(),
    })
}

const fn is_supported_method(method: u16) -> bool {
    matches!(method, STORED_METHOD | DEFLATE_METHOD)
}

fn omission_reason(
    metadata: &ZipArtifactEntryMetadata,
    limits: ZipArtifactLimits,
    expanded_work_so_far: usize,
    operation_remaining: Option<usize>,
) -> Option<ZipArtifactOmissionReason> {
    if metadata.encrypted {
        return Some(ZipArtifactOmissionReason::Encrypted);
    }
    // Preserve the feature omission reason before considering the byte budgets
    if !is_supported_method(metadata.compression_method) {
        return Some(ZipArtifactOmissionReason::UnsupportedCompression {
            method: metadata.compression_method,
        });
    }
    if metadata.expanded_size > usize_as_u64(limits.max_entry_expanded_bytes) {
        return Some(ZipArtifactOmissionReason::EntryExpandedByteLimit);
    }
    let remaining_total = limits.max_total_expanded_bytes - expanded_work_so_far;
    if operation_remaining.is_some_and(|remaining| {
        remaining <= remaining_total && metadata.expanded_size > usize_as_u64(remaining)
    }) {
        return Some(ZipArtifactOmissionReason::OperationExpandedByteLimit);
    }
    if metadata.expanded_size > usize_as_u64(remaining_total) {
        return Some(ZipArtifactOmissionReason::TotalExpandedByteLimit);
    }
    None
}

fn extract_entry(
    archive: &mut ZipArchive<impl Read + Seek>,
    metadata: &ZipArtifactEntryMetadata,
    structural_failure: Option<ZipEntryDataFailure>,
) -> Result<Vec<u8>, ZipEntryDataFailure> {
    let index = metadata.index;
    let expanded_size =
        usize::try_from(metadata.expanded_size).map_err(|_| ZipEntryDataFailure::SizeMismatch)?;

    // Validate this member independently so one inconsistent header does not hide later evidence
    let validated = archive
        .by_index_with_options(
            index,
            ZipReadOptions::new().enforce_header_consistency(true),
        )
        .map_err(|_| ZipEntryDataFailure::InvalidEntryHeader)?;
    drop(validated);
    if let Some(failure) = structural_failure {
        return Err(failure);
    }

    let bytes = match metadata.compression_method {
        STORED_METHOD => {
            if metadata.compressed_size != metadata.expanded_size {
                return Err(ZipEntryDataFailure::SizeMismatch);
            }
            let mut file = archive
                .by_index_raw(index)
                .map_err(|_| ZipEntryDataFailure::InvalidEntryHeader)?;
            read_exact_expanded(&mut file, expanded_size)?
        }
        DEFLATE_METHOD => {
            let file = archive
                .by_index_raw(index)
                .map_err(|_| ZipEntryDataFailure::InvalidEntryHeader)?;
            let mut decoder = DeflateDecoder::new(file);
            // Decoder read errors identify a malformed compressed stream
            let expanded =
                read_exact_expanded(&mut decoder, expanded_size).map_err(
                    |failure| match failure {
                        ZipEntryDataFailure::ReadFailure => {
                            ZipEntryDataFailure::DecompressionFailure
                        }
                        other => other,
                    },
                )?;
            // A valid deflate stream must consume the complete compressed member
            if decoder.total_in() != metadata.compressed_size {
                return Err(ZipEntryDataFailure::SizeMismatch);
            }
            expanded
        }
        _ => return Err(ZipEntryDataFailure::InvalidEntryHeader),
    };

    if crc32(&bytes) != metadata.crc32 {
        return Err(ZipEntryDataFailure::CrcMismatch);
    }
    Ok(bytes)
}

fn read_exact_expanded<R: Read>(
    reader: &mut R,
    expanded_size: usize,
) -> Result<Vec<u8>, ZipEntryDataFailure> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(expanded_size)
        .map_err(|_| ZipEntryDataFailure::AllocationFailure)?;
    let mut remaining = expanded_size;
    let mut buffer = [0_u8; 8_192];

    while remaining > 0 {
        let request = remaining.min(buffer.len());
        let chunk = buffer
            .get_mut(..request)
            .ok_or(ZipEntryDataFailure::SizeMismatch)?;
        let count = reader
            .read(chunk)
            .map_err(|_| ZipEntryDataFailure::ReadFailure)?;
        if count == 0 {
            return Err(ZipEntryDataFailure::SizeMismatch);
        }
        let bytes = buffer
            .get(..count)
            .ok_or(ZipEntryDataFailure::SizeMismatch)?;
        output.extend_from_slice(bytes);
        remaining -= count;
    }

    // Probe once after the declared output length to detect understated size metadata
    let mut trailing_byte = [0_u8; 1];
    if reader
        .read(&mut trailing_byte)
        .map_err(|_| ZipEntryDataFailure::ReadFailure)?
        > 0
    {
        return Err(ZipEntryDataFailure::SizeMismatch);
    }
    Ok(output)
}

fn record_omission(
    report: &mut ZipArtifactReport,
    reason: ZipArtifactOmissionReason,
    count: usize,
) -> Result<(), ZipArtifactError> {
    if count == 0 {
        return Ok(());
    }
    report.omitted_entry_count += count;
    if let Some(existing) = report
        .omissions
        .iter_mut()
        .find(|omission| omission.reason == reason)
    {
        existing.count += count;
    } else {
        report
            .omissions
            .try_reserve(1)
            .map_err(|_| ZipArtifactError::AllocationFailure)?;
        report.omissions.push(ZipArtifactOmission { reason, count });
    }
    Ok(())
}

fn usize_as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
