use super::common::{
    EndpointImportError, MAX_ENDPOINT_RECORDS, error, read_bytes, read_u16, read_u32, read_u64,
    read_u128, source_id, source_length, source_range,
};
use serde::Serialize;

const USN_V2_HEADER_SIZE: usize = 60;
const USN_V3_HEADER_SIZE: usize = 76;
const USN_BUFFER_PREFIX_SIZE: usize = 8;

/// File reference identity format used by one USN record version
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsnFileReference {
    /// 64-bit NTFS file reference in a version 2 record
    V2(u64),
    /// 128-bit file identifier in a version 3 record
    V3(u128),
}

/// One validated USN change-journal record
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UsnRecord {
    /// USN record major version
    pub major_version: u16,
    /// USN record minor version
    pub minor_version: u16,
    /// File identifier in the record's native width
    pub file_reference: UsnFileReference,
    /// Parent file identifier in the record's native width
    pub parent_file_reference: UsnFileReference,
    /// Nonnegative sequence number within the volume journal
    pub usn: u64,
    /// Timestamp stored as raw FILETIME ticks since 1601-01-01 UTC
    pub filetime_ticks: u64,
    /// Reason flags retained without inferring a process or user
    pub reason: u32,
    /// Source information flags retained as raw provider data
    pub source_info: u32,
    /// File attributes retained as raw provider data
    pub file_attributes: u32,
    /// Exact filename component stored in the record
    pub file_name: String,
    /// Exact record range in the original source bytes
    pub source_range: crate::evidence::SourceRange,
}

/// An unsupported but safely skipped USN record version
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UsnUnsupportedRecord {
    /// Major version found in the record header
    pub major_version: u16,
    /// Minor version found in the record header
    pub minor_version: u16,
    /// Exact skipped record range in the source bytes
    pub source_range: crate::evidence::SourceRange,
}

/// Bounded native USN parse with ordering and unsupported-version accounting
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UsnReport {
    /// SHA-256 identity of the exact journal bytes
    pub source_sha256: String,
    /// Exact input size in bytes
    pub source_length: u64,
    /// Optional next-USN value from a `DeviceIoControl` output buffer
    pub next_usn: Option<u64>,
    /// Parsed V2 and V3 records in source order
    pub records: Vec<UsnRecord>,
    /// Unsupported versions with exact source ranges
    pub unsupported: Vec<UsnUnsupportedRecord>,
    /// Number of unsupported records omitted after the detail limit
    pub omitted_unsupported: u64,
    /// Number of valid records omitted after the detail limit
    pub omitted_records: u64,
    /// Number of descending or duplicate USN values in source order
    pub nonmonotonic_usn_records: u64,
    /// Trailing zero bytes after the last complete record
    pub trailing_zero_bytes: u64,
    /// False when unsupported or over-limit record detail was encountered
    pub complete: bool,
    /// Limits on what the journal records establish
    pub limitations: Vec<String>,
}

/// Parse a raw sequence of USN V2 and V3 records
///
/// # Errors
/// Rejects truncated records, invalid ranges, and malformed UTF-16 names
pub fn parse_usn_records(bytes: &[u8]) -> Result<UsnReport, EndpointImportError> {
    parse_usn_at(bytes, 0, None)
}

/// Parse a `DeviceIoControl` journal buffer with its leading `NextUsn` value
///
/// # Errors
/// Rejects buffers shorter than the required eight-byte prefix or malformed records
pub fn parse_usn_device_buffer(bytes: &[u8]) -> Result<UsnReport, EndpointImportError> {
    if bytes.len() < USN_BUFFER_PREFIX_SIZE {
        return Err(error(
            "USN device buffer is shorter than its next-USN prefix",
        ));
    }
    let next_usn = read_u64(bytes, 0)?;
    parse_usn_at(bytes, USN_BUFFER_PREFIX_SIZE, Some(next_usn))
}

fn parse_usn_at(
    bytes: &[u8],
    mut cursor: usize,
    next_usn: Option<u64>,
) -> Result<UsnReport, EndpointImportError> {
    let source = source_id(bytes);
    let mut report = empty_report(&source, bytes, next_usn)?;
    let mut previous_usn = None;
    while cursor < bytes.len() {
        if trailing_zero_region(bytes, cursor) {
            report.trailing_zero_bytes = u64::try_from(bytes.len() - cursor)
                .map_err(|_| error("USN trailing-byte count exceeds u64"))?;
            break;
        }
        let record_size = usize::try_from(read_u32(bytes, cursor)?)
            .map_err(|_| error("USN record length exceeds the platform limit"))?;
        let version = read_version(bytes, cursor, record_size)?;
        let record_range = source_range(&source, cursor, record_size)?;
        if version.0 == 2 || version.0 == 3 {
            let record = parse_supported_record(bytes, cursor, record_size, version, record_range)?;
            if previous_usn.is_some_and(|previous| record.usn <= previous) {
                report.nonmonotonic_usn_records = report.nonmonotonic_usn_records.saturating_add(1);
            }
            previous_usn = Some(record.usn);
            retain_record(&mut report, record);
        } else {
            report.complete = false;
            retain_unsupported(&mut report, version, record_range);
        }
        cursor = cursor
            .checked_add(record_size)
            .ok_or_else(|| error("USN record offset overflows"))?;
    }
    Ok(report)
}

fn empty_report(
    source: &str,
    bytes: &[u8],
    next_usn: Option<u64>,
) -> Result<UsnReport, EndpointImportError> {
    Ok(UsnReport {
        source_sha256: source.to_owned(),
        source_length: source_length(bytes)?,
        next_usn,
        records: Vec::new(),
        unsupported: Vec::new(),
        omitted_unsupported: 0,
        omitted_records: 0,
        nonmonotonic_usn_records: 0,
        trailing_zero_bytes: 0,
        complete: true,
        limitations: vec![
            "USN reason flags do not identify the process or user that caused a change".to_owned(),
            "USN timestamps describe journal logging time, not a complete history of file timestamp values".to_owned(),
            "The journal bytes and their acquisition history are not authenticated by this parser".to_owned(),
        ],
    })
}

fn trailing_zero_region(bytes: &[u8], cursor: usize) -> bool {
    bytes
        .get(cursor..)
        .is_some_and(|tail| tail.iter().all(|byte| *byte == 0))
}

fn read_version(
    bytes: &[u8],
    offset: usize,
    record_size: usize,
) -> Result<(u16, u16), EndpointImportError> {
    if record_size < 8
        || offset
            .checked_add(record_size)
            .is_none_or(|end| end > bytes.len())
    {
        return Err(error("USN record length is truncated or too small"));
    }
    Ok((read_u16(bytes, offset + 4)?, read_u16(bytes, offset + 6)?))
}

fn parse_supported_record(
    bytes: &[u8],
    offset: usize,
    record_size: usize,
    version: (u16, u16),
    range: crate::evidence::SourceRange,
) -> Result<UsnRecord, EndpointImportError> {
    let raw = read_bytes(bytes, offset, record_size)?;
    let fixed_size = if version.0 == 2 {
        USN_V2_HEADER_SIZE
    } else {
        USN_V3_HEADER_SIZE
    };
    if record_size < fixed_size {
        return Err(error("USN record is shorter than its fixed header"));
    }
    let (file_reference, parent_file_reference, fields_offset) =
        read_file_references(raw, version.0)?;
    let name_length = usize::from(read_u16(raw, fields_offset + 32)?);
    let name_offset = usize::from(read_u16(raw, fields_offset + 34)?);
    validate_name_range(record_size, fixed_size, name_offset, name_length)?;
    let encoded_name = read_bytes(raw, name_offset, name_length)?;
    Ok(UsnRecord {
        major_version: version.0,
        minor_version: version.1,
        file_reference,
        parent_file_reference,
        usn: read_nonnegative_usn(raw, fields_offset)?,
        filetime_ticks: read_u64(raw, fields_offset + 8)?,
        reason: read_u32(raw, fields_offset + 16)?,
        source_info: read_u32(raw, fields_offset + 20)?,
        file_attributes: read_u32(raw, fields_offset + 28)?,
        file_name: decode_utf16(encoded_name)?,
        source_range: range,
    })
}

fn read_file_references(
    record: &[u8],
    major_version: u16,
) -> Result<(UsnFileReference, UsnFileReference, usize), EndpointImportError> {
    if major_version == 2 {
        Ok((
            UsnFileReference::V2(read_u64(record, 8)?),
            UsnFileReference::V2(read_u64(record, 16)?),
            24,
        ))
    } else {
        Ok((
            UsnFileReference::V3(read_u128(record, 8)?),
            UsnFileReference::V3(read_u128(record, 24)?),
            40,
        ))
    }
}

fn read_nonnegative_usn(record: &[u8], offset: usize) -> Result<u64, EndpointImportError> {
    let raw = read_bytes(record, offset, 8)?;
    let array = raw
        .try_into()
        .map_err(|_| error("USN sequence number is truncated"))?;
    let value = i64::from_le_bytes(array);
    u64::try_from(value).map_err(|_| error("USN sequence number is negative"))
}

fn validate_name_range(
    record_size: usize,
    fixed_size: usize,
    name_offset: usize,
    name_length: usize,
) -> Result<(), EndpointImportError> {
    let end = name_offset
        .checked_add(name_length)
        .ok_or_else(|| error("USN filename range overflows"))?;
    if name_offset < fixed_size || end > record_size || !name_length.is_multiple_of(2) {
        return Err(error("USN filename range or length is invalid"));
    }
    Ok(())
}

fn decode_utf16(bytes: &[u8]) -> Result<String, EndpointImportError> {
    let words = bytes
        .chunks_exact(2)
        .map(|pair| {
            let raw = pair
                .try_into()
                .map_err(|_| error("USN filename word is truncated"))?;
            Ok(u16::from_le_bytes(raw))
        })
        .collect::<Result<Vec<_>, EndpointImportError>>()?;
    String::from_utf16(&words).map_err(|_| error("USN filename has invalid UTF-16"))
}

fn retain_record(report: &mut UsnReport, record: UsnRecord) {
    if report.records.len() < MAX_ENDPOINT_RECORDS {
        report.records.push(record);
    } else {
        report.omitted_records = report.omitted_records.saturating_add(1);
        report.complete = false;
    }
}

fn retain_unsupported(
    report: &mut UsnReport,
    version: (u16, u16),
    range: crate::evidence::SourceRange,
) {
    if report.unsupported.len() < MAX_ENDPOINT_RECORDS {
        report.unsupported.push(UsnUnsupportedRecord {
            major_version: version.0,
            minor_version: version.1,
            source_range: range,
        });
    } else {
        report.omitted_unsupported = report.omitted_unsupported.saturating_add(1);
    }
}
