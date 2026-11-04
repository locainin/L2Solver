use super::common::{
    EndpointImportError, MAX_ENDPOINT_RECORDS, error, read_bytes, read_u8, read_u16, read_u32,
    read_u64, source_range,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fmt,
    io::{self, Cursor, ErrorKind, Read, Seek, SeekFrom},
};

const UPDATE_SEQUENCE_OFFSET: usize = 4;
const UPDATE_SEQUENCE_COUNT_OFFSET: usize = 6;
const FILE_RECORD_HEADER_SIZE: usize = 48;
const NTFS_SECTOR_SIZE: usize = 512;
const MAX_MFT_DETAIL_BYTES: usize = 16 * 1024 * 1024;
const ATTRIBUTE_STANDARD_INFORMATION: u32 = 0x10;
const ATTRIBUTE_FILE_NAME: u32 = 0x30;
const ATTRIBUTE_END: u32 = u32::MAX;

/// Four FILETIME values read from one NTFS timestamp attribute
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MftTimestampSet {
    /// Creation time in raw 100-nanosecond ticks since 1601-01-01 UTC
    pub creation: u64,
    /// Last data modification time in raw FILETIME ticks
    pub modified: u64,
    /// Last MFT record change time in raw FILETIME ticks
    pub record_changed: u64,
    /// Last access time in raw FILETIME ticks
    pub accessed: u64,
}

/// One filename attribute with its independent timestamps and exact raw range
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MftFileName {
    /// Parent file reference number from `$FILE_NAME`
    pub parent_file_reference: u64,
    /// Exact decoded NTFS filename component
    pub name: String,
    /// Namespace value stored in `$FILE_NAME`
    pub namespace: u8,
    /// Four FILETIME values stored in `$FILE_NAME`
    pub timestamps: MftTimestampSet,
    /// Full attribute range in the source MFT bytes
    pub source_range: crate::evidence::SourceRange,
}

/// One validated MFT file record with timestamps from its separate attributes
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MftRecord {
    /// Record number retained in the FILE record header
    pub record_number: u32,
    /// Sequence-qualified file reference used by NTFS directory entries
    pub file_reference: u64,
    /// Base record reference for an extension record, or zero
    pub base_file_reference: u64,
    /// FILE record flags retained without behavioral interpretation
    pub flags: u16,
    /// `$STANDARD_INFORMATION` timestamps, when present in this record
    pub standard_information: Option<MftTimestampSet>,
    /// Every resident `$FILE_NAME` attribute retained in source order
    pub file_names: Vec<MftFileName>,
    /// Any timestamp value that differs from a filename attribute
    pub timestamps_differ_from_file_name: bool,
    /// Exact FILE record range in the original MFT byte stream
    pub source_range: crate::evidence::SourceRange,
    /// Exact `$STANDARD_INFORMATION` attribute range, when present
    pub standard_information_range: Option<crate::evidence::SourceRange>,
}

/// Bounded MFT parse with source identity and explicit output omissions
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MftReport {
    /// SHA-256 identity of the exact MFT input bytes
    pub source_sha256: String,
    /// Exact input size in bytes
    pub source_length: u64,
    /// Record size read from the first FILE record
    pub record_size: u32,
    /// Valid FILE records encountered, including records omitted from output
    pub records_seen: u64,
    /// All-zero record slots encountered
    pub empty_slots: u64,
    /// Valid records omitted after the retained-record or source-byte limits
    pub omitted_records: u64,
    /// Valid records sent to a visitor instead of retained in `records`
    pub streamed_records: u64,
    /// Records retained with exact source ranges
    pub records: Vec<MftRecord>,
    /// Records whose `$STANDARD_INFORMATION` values differ from a filename attribute
    pub timestamp_differences: u64,
    /// Records beyond the bounded file-reference uniqueness check
    pub reference_checks_omitted: u64,
    /// False when details or identity checks were omitted
    pub complete: bool,
    /// Limits on what these records establish
    pub limitations: Vec<String>,
}

/// Parse raw consecutive NTFS MFT FILE records
///
/// Multi-sector update sequence fixups are checked before attributes are read
/// The report keeps timestamps in their original FILETIME tick units
///
/// # Errors
/// Rejects malformed record sizes, update sequence arrays, attributes, and names
pub fn parse_mft(bytes: &[u8]) -> Result<MftReport, EndpointImportError> {
    parse_mft_reader(Cursor::new(bytes))
}

/// Parse raw MFT records from a reader with bounded per-record memory
///
/// The complete stream is hashed while only a bounded number of records are retained
///
/// # Errors
/// Rejects malformed records, partial slots, or reader failures
pub fn parse_mft_reader<R: Read>(mut reader: R) -> Result<MftReport, EndpointImportError> {
    let mut next_header = read_record_header(&mut reader)?;
    let first_header = next_header
        .as_ref()
        .ok_or_else(|| error("MFT input does not begin with a FILE record"))?;
    let (record_size, record_size_field) = record_size_from_header(first_header)?;
    let mut report = empty_report(record_size_field);
    let mut hasher = Sha256::new();
    let mut source_length = 0_u64;
    let mut record_offset = 0_usize;
    let mut retained_bytes = 0_usize;
    let mut references = HashSet::new();
    while let Some(header) = next_header.take() {
        let raw = read_stream_record(&mut reader, header, record_size, &mut hasher)?;
        source_length = source_length
            .checked_add(
                u64::try_from(record_size).map_err(|_| error("MFT record size exceeds u64"))?,
            )
            .ok_or_else(|| error("MFT source length overflows u64"))?;
        if raw.iter().all(|byte| *byte == 0) {
            report.empty_slots = report.empty_slots.saturating_add(1);
        } else {
            let fixed = apply_fixups(&raw)?;
            let record = parse_record(&fixed, record_offset, "")?;
            check_reference(&mut references, &mut report, record.file_reference)?;
            report.records_seen = report.records_seen.saturating_add(1);
            if record.timestamps_differ_from_file_name {
                report.timestamp_differences = report.timestamp_differences.saturating_add(1);
            }
            retain_record(&mut report, record, &mut retained_bytes);
        }
        record_offset = record_offset
            .checked_add(record_size)
            .ok_or_else(|| error("MFT record offset overflows"))?;
        next_header = read_record_header(&mut reader)?;
    }
    report.source_sha256 = format!("sha256:{:x}", hasher.finalize());
    report.source_length = source_length;
    assign_source_identity(&mut report);
    report.complete = report.omitted_records == 0 && report.reference_checks_omitted == 0;
    Ok(report)
}

/// Stream every valid MFT record after hashing and validating the source
///
/// The reader is rewound after hashing. A second digest detects source changes during parsing
///
/// # Errors
/// Rejects malformed records, source changes, reader failures, or visitor write failures
pub fn visit_mft_records<R, F>(reader: &mut R, mut visitor: F) -> Result<MftReport, MftVisitError>
where
    R: Read + Seek,
    F: FnMut(&MftRecord) -> io::Result<()>,
{
    let (expected_source, expected_length) = hash_reader(reader)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|read_error| source_read_error(&read_error))?;
    let mut next_header = read_record_header(reader).map_err(MftVisitError::Source)?;
    let first_header = next_header.as_ref().ok_or_else(|| {
        MftVisitError::Source(error("MFT input does not begin with a FILE record"))
    })?;
    let (record_size, record_size_field) =
        record_size_from_header(first_header).map_err(MftVisitError::Source)?;
    let mut report = empty_report(record_size_field);
    report.source_sha256.clone_from(&expected_source);
    report.source_length = expected_length;
    let mut second_hasher = Sha256::new();
    let mut second_length = 0_u64;
    let mut record_offset = 0_usize;
    let mut references = HashSet::new();
    while let Some(header) = next_header.take() {
        let raw = read_stream_record(reader, header, record_size, &mut second_hasher)
            .map_err(MftVisitError::Source)?;
        second_length =
            checked_mft_length(second_length, record_size).map_err(MftVisitError::Source)?;
        visit_record(
            &raw,
            record_offset,
            &expected_source,
            &mut references,
            &mut report,
            &mut visitor,
        )?;
        record_offset = record_offset
            .checked_add(record_size)
            .ok_or_else(|| MftVisitError::Source(error("MFT record offset overflows")))?;
        next_header = read_record_header(reader).map_err(MftVisitError::Source)?;
    }
    let second_source = format!("sha256:{:x}", second_hasher.finalize());
    if second_length != expected_length || second_source != expected_source {
        return Err(MftVisitError::SourceChanged);
    }
    report.complete = report.reference_checks_omitted == 0;
    Ok(report)
}

/// Failure while parsing an MFT source or writing one streamed record
#[derive(Debug)]
pub enum MftVisitError {
    /// The input did not satisfy native MFT structure or I/O rules
    Source(EndpointImportError),
    /// The source changed after its digest was calculated
    SourceChanged,
    /// The caller could not accept the next streamed record
    Visitor(io::Error),
}

impl fmt::Display for MftVisitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(source_error) => source_error.fmt(formatter),
            Self::SourceChanged => formatter.write_str("MFT source changed during parsing"),
            Self::Visitor(visitor_error) => visitor_error.fmt(formatter),
        }
    }
}

impl std::error::Error for MftVisitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(source_error) => Some(source_error),
            Self::SourceChanged => None,
            Self::Visitor(visitor_error) => Some(visitor_error),
        }
    }
}

fn hash_reader<R: Read + Seek>(reader: &mut R) -> Result<(String, u64), MftVisitError> {
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|read_error| source_read_error(&read_error))?;
    let mut hasher = Sha256::new();
    let mut source_length = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|read_error| source_read_error(&read_error))?;
        if count == 0 {
            break;
        }
        let bytes = buffer
            .get(..count)
            .ok_or_else(|| MftVisitError::Source(error("MFT hash read range is invalid")))?;
        hasher.update(bytes);
        source_length = source_length
            .checked_add(
                u64::try_from(count)
                    .map_err(|_| MftVisitError::Source(error("MFT hash length exceeds u64")))?,
            )
            .ok_or_else(|| MftVisitError::Source(error("MFT source length overflows u64")))?;
    }
    Ok((format!("sha256:{:x}", hasher.finalize()), source_length))
}

fn source_read_error(read_error: &io::Error) -> MftVisitError {
    MftVisitError::Source(error(&format!("MFT source read failed: {read_error}")))
}

fn checked_mft_length(length: u64, record_size: usize) -> Result<u64, EndpointImportError> {
    length
        .checked_add(u64::try_from(record_size).map_err(|_| error("MFT record size exceeds u64"))?)
        .ok_or_else(|| error("MFT source length overflows u64"))
}

fn visit_record<F>(
    raw: &[u8],
    offset: usize,
    source: &str,
    references: &mut HashSet<u64>,
    report: &mut MftReport,
    visitor: &mut F,
) -> Result<(), MftVisitError>
where
    F: FnMut(&MftRecord) -> io::Result<()>,
{
    if raw.iter().all(|byte| *byte == 0) {
        report.empty_slots = report.empty_slots.saturating_add(1);
        return Ok(());
    }
    let fixed = apply_fixups(raw).map_err(MftVisitError::Source)?;
    let record = parse_record(&fixed, offset, source).map_err(MftVisitError::Source)?;
    check_reference(references, report, record.file_reference).map_err(MftVisitError::Source)?;
    report.records_seen = report.records_seen.saturating_add(1);
    report.streamed_records = report.streamed_records.saturating_add(1);
    if record.timestamps_differ_from_file_name {
        report.timestamp_differences = report.timestamp_differences.saturating_add(1);
    }
    visitor(&record).map_err(MftVisitError::Visitor)
}

fn check_reference(
    references: &mut HashSet<u64>,
    report: &mut MftReport,
    reference: u64,
) -> Result<(), EndpointImportError> {
    if references.len() >= MAX_ENDPOINT_RECORDS {
        report.reference_checks_omitted = report.reference_checks_omitted.saturating_add(1);
    } else if !references.insert(reference) {
        return Err(error("MFT file reference number is duplicated"));
    }
    Ok(())
}

fn read_record_header<R: Read>(
    reader: &mut R,
) -> Result<Option<[u8; FILE_RECORD_HEADER_SIZE]>, EndpointImportError> {
    let mut header = [0_u8; FILE_RECORD_HEADER_SIZE];
    let mut read_length = 0_usize;
    while read_length < header.len() {
        let destination = header
            .get_mut(read_length..)
            .ok_or_else(|| error("MFT header read range is invalid"))?;
        match reader.read(destination) {
            Ok(0) if read_length == 0 => return Ok(None),
            Ok(0) => return Err(error("MFT input ends within a record header")),
            Ok(count) => {
                read_length = read_length
                    .checked_add(count)
                    .ok_or_else(|| error("MFT header read length overflows"))?;
            }
            Err(read_error) if read_error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(error("MFT header read failed")),
        }
    }
    Ok(Some(header))
}

fn record_size_from_header(
    header: &[u8; FILE_RECORD_HEADER_SIZE],
) -> Result<(usize, u32), EndpointImportError> {
    if read_bytes(header, 0, 4)? != b"FILE" {
        return Err(error("MFT input does not begin with a FILE record"));
    }
    let record_size_field = read_u32(header, 28)?;
    let record_size = usize::try_from(record_size_field)
        .map_err(|_| error("MFT record size exceeds the platform limit"))?;
    if !(NTFS_SECTOR_SIZE..=65_536).contains(&record_size) || !record_size.is_power_of_two() {
        return Err(error("MFT record size is invalid"));
    }
    Ok((record_size, record_size_field))
}

fn read_stream_record<R: Read>(
    reader: &mut R,
    header: [u8; FILE_RECORD_HEADER_SIZE],
    record_size: usize,
    hasher: &mut Sha256,
) -> Result<Vec<u8>, EndpointImportError> {
    let mut record = vec![0_u8; record_size];
    let header_region = record
        .get_mut(..FILE_RECORD_HEADER_SIZE)
        .ok_or_else(|| error("MFT record header destination is invalid"))?;
    header_region.copy_from_slice(&header);
    let body = record
        .get_mut(FILE_RECORD_HEADER_SIZE..)
        .ok_or_else(|| error("MFT record body destination is invalid"))?;
    reader
        .read_exact(body)
        .map_err(|_| error("MFT input ends within a record body"))?;
    hasher.update(&record);
    Ok(record)
}

fn empty_report(record_size: u32) -> MftReport {
    MftReport {
        source_sha256: String::new(),
        source_length: 0,
        record_size,
        records_seen: 0,
        empty_slots: 0,
        omitted_records: 0,
        streamed_records: 0,
        records: Vec::new(),
        timestamp_differences: 0,
        reference_checks_omitted: 0,
        complete: true,
        limitations: vec![
            "Different NTFS timestamp copies are independent file-state observations; they do not prove a deliberate timestamp change".to_owned(),
            "Buffered record details use bounded count and source-byte limits; omitted records are counted".to_owned(),
            "File-reference uniqueness is checked only for the first bounded set of records".to_owned(),
            "The raw MFT bytes and their acquisition history are not authenticated by this parser".to_owned(),
        ],
    }
}

fn assign_source_identity(report: &mut MftReport) {
    for record in &mut report.records {
        record.source_range.source.clone_from(&report.source_sha256);
        if let Some(range) = record.standard_information_range.as_mut() {
            range.source.clone_from(&report.source_sha256);
        }
        for file_name in &mut record.file_names {
            file_name
                .source_range
                .source
                .clone_from(&report.source_sha256);
        }
    }
}

fn retain_record(report: &mut MftReport, record: MftRecord, retained_bytes: &mut usize) {
    let record_bytes = usize::try_from(record.source_range.length);
    if report.records.len() < MAX_ENDPOINT_RECORDS
        && let Ok(record_bytes) = record_bytes
        && record_bytes <= MAX_MFT_DETAIL_BYTES.saturating_sub(*retained_bytes)
    {
        *retained_bytes = retained_bytes.saturating_add(record_bytes);
        report.records.push(record);
    } else {
        report.omitted_records = report.omitted_records.saturating_add(1);
    }
}

fn apply_fixups(raw: &[u8]) -> Result<Vec<u8>, EndpointImportError> {
    if read_bytes(raw, 0, 4)? != b"FILE" {
        return Err(error("MFT record signature is invalid"));
    }
    let array_offset = usize::from(read_u16(raw, UPDATE_SEQUENCE_OFFSET)?);
    let count = usize::from(read_u16(raw, UPDATE_SEQUENCE_COUNT_OFFSET)?);
    let first_attribute = usize::from(read_u16(raw, 20)?);
    validate_fixup_shape(raw.len(), array_offset, count, first_attribute)?;
    let sequence = read_u16(raw, array_offset)?;
    let mut fixed = raw.to_vec();
    for sector_index in 1..count {
        let trailer = sector_index
            .checked_mul(NTFS_SECTOR_SIZE)
            .and_then(|value| value.checked_sub(2))
            .ok_or_else(|| error("MFT update sequence trailer offset overflows"))?;
        if read_u16(raw, trailer)? != sequence {
            return Err(error("MFT update sequence trailer does not match"));
        }
        let replacement_offset = array_offset
            .checked_add(
                sector_index
                    .checked_mul(2)
                    .ok_or_else(|| error("MFT update sequence replacement offset overflows"))?,
            )
            .ok_or_else(|| error("MFT update sequence replacement offset overflows"))?;
        let replacement = read_bytes(raw, replacement_offset, 2)?;
        let target = fixed
            .get_mut(trailer..trailer + 2)
            .ok_or_else(|| error("MFT update sequence target exceeds record"))?;
        target.copy_from_slice(replacement);
    }
    Ok(fixed)
}

fn validate_fixup_shape(
    record_size: usize,
    array_offset: usize,
    count: usize,
    first_attribute: usize,
) -> Result<(), EndpointImportError> {
    let array_length = count
        .checked_mul(2)
        .ok_or_else(|| error("MFT update sequence array length overflows"))?;
    let array_end = array_offset
        .checked_add(array_length)
        .ok_or_else(|| error("MFT update sequence array range overflows"))?;
    if count != record_size / NTFS_SECTOR_SIZE + 1
        || array_offset < FILE_RECORD_HEADER_SIZE
        || array_end > record_size
        || array_end > first_attribute
    {
        return Err(error("MFT update sequence array is invalid"));
    }
    Ok(())
}

fn parse_record(
    record: &[u8],
    offset: usize,
    source: &str,
) -> Result<MftRecord, EndpointImportError> {
    validate_record_header(record)?;
    let record_number = read_u32(record, 44)?;
    let sequence = u64::from(read_u16(record, 16)?);
    let file_reference = sequence
        .checked_shl(48)
        .and_then(|prefix| prefix.checked_add(u64::from(record_number)))
        .ok_or_else(|| error("MFT file reference number overflows"))?;
    let mut parsed = ParsedAttributes::default();
    parse_attributes(record, source, offset, &mut parsed)?;
    let differs = timestamps_differ(parsed.standard_information.as_ref(), &parsed.file_names);
    Ok(MftRecord {
        record_number,
        file_reference,
        base_file_reference: read_u64(record, 32)?,
        flags: read_u16(record, 22)?,
        standard_information: parsed.standard_information,
        file_names: parsed.file_names,
        timestamps_differ_from_file_name: differs,
        source_range: source_range(source, offset, record.len())?,
        standard_information_range: parsed.standard_information_range,
    })
}

fn validate_record_header(record: &[u8]) -> Result<(), EndpointImportError> {
    if read_bytes(record, 0, 4)? != b"FILE" {
        return Err(error("MFT record signature is invalid"));
    }
    let first_attribute = usize::from(read_u16(record, 20)?);
    let bytes_in_use = usize::try_from(read_u32(record, 24)?)
        .map_err(|_| error("MFT bytes-in-use value exceeds the platform limit"))?;
    let bytes_allocated = usize::try_from(read_u32(record, 28)?)
        .map_err(|_| error("MFT allocated size exceeds the platform limit"))?;
    if bytes_allocated != record.len()
        || first_attribute < FILE_RECORD_HEADER_SIZE
        || !first_attribute.is_multiple_of(8)
        || bytes_in_use > record.len()
        || first_attribute
            .checked_add(4)
            .is_none_or(|end| end > bytes_in_use)
    {
        return Err(error("MFT record header sizes are inconsistent"));
    }
    Ok(())
}

#[derive(Default)]
struct ParsedAttributes {
    standard_information: Option<MftTimestampSet>,
    standard_information_range: Option<crate::evidence::SourceRange>,
    file_names: Vec<MftFileName>,
}

fn parse_attributes(
    record: &[u8],
    source: &str,
    record_offset: usize,
    parsed: &mut ParsedAttributes,
) -> Result<(), EndpointImportError> {
    let mut cursor = usize::from(read_u16(record, 20)?);
    let end = usize::try_from(read_u32(record, 24)?)
        .map_err(|_| error("MFT bytes-in-use value exceeds the platform limit"))?;
    let mut terminated = false;
    while cursor < end {
        let attribute_type = read_u32(record, cursor)?;
        if attribute_type == ATTRIBUTE_END {
            terminated = true;
            break;
        }
        let length = usize::try_from(read_u32(record, cursor + 4)?)
            .map_err(|_| error("MFT attribute length exceeds the platform limit"))?;
        validate_attribute(record, cursor, length)?;
        parse_known_attribute(
            record,
            source,
            record_offset,
            cursor,
            length,
            attribute_type,
            parsed,
        )?;
        cursor = cursor
            .checked_add(length)
            .ok_or_else(|| error("MFT attribute offset overflows"))?;
    }
    if !terminated {
        return Err(error("MFT attribute end marker is missing"));
    }
    Ok(())
}

fn validate_attribute(
    record: &[u8],
    offset: usize,
    length: usize,
) -> Result<(), EndpointImportError> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| error("MFT attribute range overflows"))?;
    let bytes_in_use = usize::try_from(read_u32(record, 24)?)
        .map_err(|_| error("MFT bytes-in-use value exceeds the platform limit"))?;
    if length < 16 || end > record.len() || end > bytes_in_use {
        return Err(error("MFT attribute range or length is invalid"));
    }
    let name_length = usize::from(read_u16(record, offset + 9)?);
    if name_length > 0 {
        let name_offset = usize::from(read_u16(record, offset + 10)?);
        let name_bytes = name_length
            .checked_mul(2)
            .ok_or_else(|| error("MFT attribute name length overflows"))?;
        let name_end = name_offset
            .checked_add(name_bytes)
            .ok_or_else(|| error("MFT attribute name range overflows"))?;
        if name_offset < 16 || name_end > length {
            return Err(error("MFT attribute name range is invalid"));
        }
    }
    Ok(())
}

fn parse_known_attribute(
    record: &[u8],
    source: &str,
    record_offset: usize,
    offset: usize,
    length: usize,
    attribute_type: u32,
    parsed: &mut ParsedAttributes,
) -> Result<(), EndpointImportError> {
    if !matches!(
        attribute_type,
        ATTRIBUTE_STANDARD_INFORMATION | ATTRIBUTE_FILE_NAME
    ) {
        return Ok(());
    }
    if length < 24 {
        return Err(error("MFT resident attribute header is truncated"));
    }
    if read_bytes(record, offset + 8, 1)? != [0] {
        return Err(error("nonresident MFT timestamp attribute is unsupported"));
    }
    let value_length = usize::try_from(read_u32(record, offset + 16)?)
        .map_err(|_| error("MFT resident value length exceeds the platform limit"))?;
    let value_offset = usize::from(read_u16(record, offset + 20)?);
    let value = resident_value(record, offset, length, value_offset, value_length)?;
    if attribute_type == ATTRIBUTE_STANDARD_INFORMATION {
        store_standard_information(source, record_offset, offset, length, value, parsed)
    } else {
        parse_filename_attribute(source, record_offset, offset, length, value, parsed)
    }
}

fn resident_value(
    record: &[u8],
    attribute_offset: usize,
    attribute_length: usize,
    value_offset: usize,
    value_length: usize,
) -> Result<&[u8], EndpointImportError> {
    if value_offset < 24 {
        return Err(error("MFT resident attribute value offset is invalid"));
    }
    let relative_end = value_offset
        .checked_add(value_length)
        .ok_or_else(|| error("MFT resident attribute value range overflows"))?;
    if relative_end > attribute_length {
        return Err(error("MFT resident attribute value exceeds its attribute"));
    }
    read_bytes(record, attribute_offset + value_offset, value_length)
}

fn store_standard_information(
    source: &str,
    record_offset: usize,
    offset: usize,
    length: usize,
    value: &[u8],
    parsed: &mut ParsedAttributes,
) -> Result<(), EndpointImportError> {
    if value.len() < 32 || parsed.standard_information.is_some() {
        return Err(error(
            "MFT standard-information value is duplicated or truncated",
        ));
    }
    parsed.standard_information = Some(read_timestamps(value, 0)?);
    parsed.standard_information_range = Some(source_range(source, record_offset + offset, length)?);
    Ok(())
}

fn parse_filename_attribute(
    source: &str,
    record_offset: usize,
    offset: usize,
    length: usize,
    value: &[u8],
    parsed: &mut ParsedAttributes,
) -> Result<(), EndpointImportError> {
    if value.len() < 66 {
        return Err(error("MFT file-name value is truncated"));
    }
    let name_length = usize::from(read_u8(value, 64)?);
    let namespace = read_u8(value, 65)?;
    let name_bytes = name_length
        .checked_mul(2)
        .ok_or_else(|| error("MFT filename length overflows"))?;
    let encoded_name = read_bytes(value, 66, name_bytes)?;
    let name = decode_utf16(encoded_name)?;
    parsed.file_names.push(MftFileName {
        parent_file_reference: read_u64(value, 0)?,
        name,
        namespace,
        timestamps: read_timestamps(value, 8)?,
        source_range: source_range(source, record_offset + offset, length)?,
    });
    Ok(())
}

fn read_timestamps(bytes: &[u8], offset: usize) -> Result<MftTimestampSet, EndpointImportError> {
    Ok(MftTimestampSet {
        creation: read_u64(bytes, offset)?,
        modified: read_u64(bytes, offset + 8)?,
        record_changed: read_u64(bytes, offset + 16)?,
        accessed: read_u64(bytes, offset + 24)?,
    })
}

fn decode_utf16(bytes: &[u8]) -> Result<String, EndpointImportError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(error("MFT filename has an odd byte length"));
    }
    let words = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect::<Vec<_>>();
    String::from_utf16(&words).map_err(|_| error("MFT filename has invalid UTF-16"))
}

fn timestamps_differ(
    standard_information: Option<&MftTimestampSet>,
    file_names: &[MftFileName],
) -> bool {
    standard_information.is_some_and(|standard| {
        file_names.iter().any(|file_name| {
            standard.creation != file_name.timestamps.creation
                || standard.modified != file_name.timestamps.modified
                || standard.record_changed != file_name.timestamps.record_changed
                || standard.accessed != file_name.timestamps.accessed
        })
    })
}
