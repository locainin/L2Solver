use super::common::{
    EndpointImportError, MAX_ENDPOINT_RECORDS, error, read_bytes, read_u16, read_u32, read_u64,
    source_id, source_length, source_range,
};
use crc32fast::Hasher;
use serde::Serialize;

const FILE_HEADER_SIZE: usize = 4096;
const CHUNK_SIZE: usize = 65_536;
const CHUNK_HEADER_SIZE: usize = 512;
const FILE_SIGNATURE: &[u8; 8] = b"ElfFile\0";
const CHUNK_SIGNATURE: &[u8; 8] = b"ElfChnk\0";
const RECORD_SIGNATURE: &[u8; 4] = b"**\0\0";

/// `BinXML` content parsing state for an EVTX envelope report
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvtxBinXmlStatus {
    /// Event record framing was checked, but the `BinXML` payload was not decoded
    NotParsed,
}

/// One validated EVTX chunk header and its original byte range
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvtxChunk {
    /// Zero-based chunk position after the EVTX file header
    pub index: u64,
    /// First event record identifier stated by the chunk header
    pub first_record_id: u64,
    /// Last event record identifier stated by the chunk header
    pub last_record_id: u64,
    /// Exact chunk range in the source file
    pub source_range: crate::evidence::SourceRange,
}

/// One EVTX record envelope without interpreted event content
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvtxRecordEnvelope {
    /// EVTX record identifier
    pub record_id: u64,
    /// Logged time in raw FILETIME ticks since 1601-01-01 UTC
    pub filetime_ticks: u64,
    /// Exact EVTX record range in the source file
    pub source_range: crate::evidence::SourceRange,
    /// Raw `BinXML` byte range, retained as uninterpreted source content
    pub binxml_range: crate::evidence::SourceRange,
}

/// Validated EVTX file and chunk envelopes with explicit `BinXML` limits
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvtxReport {
    /// SHA-256 identity of the exact EVTX input bytes
    pub source_sha256: String,
    /// Exact input size in bytes
    pub source_length: u64,
    /// Header chunk count read from the file
    pub chunk_count: u16,
    /// Chunks retained with exact source ranges
    pub chunks: Vec<EvtxChunk>,
    /// Valid event records encountered, including records omitted from output
    pub records_seen: u64,
    /// Record envelopes retained with exact source ranges
    pub records: Vec<EvtxRecordEnvelope>,
    /// Valid records omitted after the detail limit
    pub omitted_records: u64,
    /// Valid chunks omitted after the detail limit
    pub omitted_chunks: u64,
    /// State of the record content parser
    pub binxml_status: EvtxBinXmlStatus,
    /// False when record envelopes or chunks were omitted
    pub complete: bool,
    /// Limits on format interpretation and source authenticity
    pub limitations: Vec<String>,
}

/// Validate an EVTX file header, chunk checksums, and record envelopes
///
/// Record payloads are kept as raw `BinXML` ranges and are not decoded as events
///
/// # Errors
/// Rejects invalid header or chunk checksums, lengths, signatures, and framing
pub fn parse_evtx_envelope(bytes: &[u8]) -> Result<EvtxReport, EndpointImportError> {
    validate_file_shape(bytes)?;
    validate_file_header(bytes)?;
    let chunk_count = read_u16(bytes, 42)?;
    let mut report = empty_report(bytes, chunk_count)?;
    for index in 0..usize::from(chunk_count) {
        let offset = FILE_HEADER_SIZE
            .checked_add(
                index
                    .checked_mul(CHUNK_SIZE)
                    .ok_or_else(|| error("EVTX chunk offset overflows"))?,
            )
            .ok_or_else(|| error("EVTX chunk offset overflows"))?;
        parse_chunk(bytes, offset, index, &mut report)?;
    }
    report.complete = report.omitted_chunks == 0 && report.omitted_records == 0;
    Ok(report)
}

fn validate_file_shape(bytes: &[u8]) -> Result<(), EndpointImportError> {
    if bytes.len() < FILE_HEADER_SIZE
        || !(bytes.len() - FILE_HEADER_SIZE).is_multiple_of(CHUNK_SIZE)
    {
        return Err(error(
            "EVTX input has a truncated file header or partial chunk",
        ));
    }
    if read_bytes(bytes, 0, FILE_SIGNATURE.len())? != FILE_SIGNATURE {
        return Err(error("EVTX file signature is invalid"));
    }
    let declared_chunks = usize::from(read_u16(bytes, 42)?);
    let actual_chunks = (bytes.len() - FILE_HEADER_SIZE) / CHUNK_SIZE;
    if declared_chunks != actual_chunks {
        return Err(error("EVTX header chunk count does not match file length"));
    }
    Ok(())
}

fn validate_file_header(bytes: &[u8]) -> Result<(), EndpointImportError> {
    if read_u32(bytes, 32)? != 128
        || read_u16(bytes, 40)?
            != u16::try_from(FILE_HEADER_SIZE).map_err(|_| error("EVTX header size exceeds u16"))?
    {
        return Err(error("EVTX file header sizes are unsupported"));
    }
    let declared_crc = read_u32(bytes, 124)?;
    let computed_crc = crc(read_bytes(bytes, 0, 120)?);
    if declared_crc != computed_crc {
        return Err(error("EVTX file header CRC does not match"));
    }
    Ok(())
}

fn empty_report(bytes: &[u8], chunk_count: u16) -> Result<EvtxReport, EndpointImportError> {
    Ok(EvtxReport {
        source_sha256: source_id(bytes),
        source_length: source_length(bytes)?,
        chunk_count,
        chunks: Vec::new(),
        records_seen: 0,
        records: Vec::new(),
        omitted_records: 0,
        omitted_chunks: 0,
        binxml_status: EvtxBinXmlStatus::NotParsed,
        complete: true,
        limitations: vec![
            "EVTX chunk and record envelopes are validated; BinXML event content is not parsed".to_owned(),
            "EVTX structure and checksums do not authenticate the event publisher or acquisition history".to_owned(),
        ],
    })
}

fn parse_chunk(
    bytes: &[u8],
    chunk_offset: usize,
    index: usize,
    report: &mut EvtxReport,
) -> Result<(), EndpointImportError> {
    let chunk = read_bytes(bytes, chunk_offset, CHUNK_SIZE)?;
    validate_chunk_signature(chunk)?;
    let free_offset = usize::try_from(read_u32(chunk, 48)?)
        .map_err(|_| error("EVTX free-space offset exceeds the platform limit"))?;
    validate_chunk_ranges(chunk, free_offset)?;
    validate_chunk_checksums(chunk, free_offset)?;
    let records = parse_records(chunk, chunk_offset, free_offset, report)?;
    validate_last_record_pointer(chunk, records.last().map(|item| item.0))?;
    validate_chunk_ids(chunk, &records)?;
    retain_chunk(chunk, chunk_offset, index, report)?;
    Ok(())
}

fn validate_chunk_signature(chunk: &[u8]) -> Result<(), EndpointImportError> {
    if read_bytes(chunk, 0, CHUNK_SIGNATURE.len())? != CHUNK_SIGNATURE {
        return Err(error("EVTX chunk signature is invalid"));
    }
    if read_u32(chunk, 40)? != 128 {
        return Err(error("EVTX chunk header size is unsupported"));
    }
    Ok(())
}

fn validate_chunk_ranges(chunk: &[u8], free_offset: usize) -> Result<(), EndpointImportError> {
    let last_record_offset = usize::try_from(read_u32(chunk, 44)?)
        .map_err(|_| error("EVTX last-record offset exceeds the platform limit"))?;
    if free_offset < CHUNK_HEADER_SIZE
        || free_offset > chunk.len()
        || (last_record_offset != 0
            && (last_record_offset < CHUNK_HEADER_SIZE || last_record_offset >= free_offset))
    {
        return Err(error("EVTX chunk record offsets are invalid"));
    }
    Ok(())
}

fn validate_chunk_checksums(chunk: &[u8], free_offset: usize) -> Result<(), EndpointImportError> {
    let records_crc = read_u32(chunk, 52)?;
    let actual_records_crc = crc(read_bytes(
        chunk,
        CHUNK_HEADER_SIZE,
        free_offset - CHUNK_HEADER_SIZE,
    )?);
    if records_crc != actual_records_crc {
        return Err(error("EVTX chunk record CRC does not match"));
    }
    let header_crc = read_u32(chunk, 124)?;
    let actual_header_crc = crc_parts(
        read_bytes(chunk, 0, 120)?,
        read_bytes(chunk, 128, CHUNK_HEADER_SIZE - 128)?,
    );
    if header_crc != actual_header_crc {
        return Err(error("EVTX chunk header CRC does not match"));
    }
    Ok(())
}

fn parse_records(
    chunk: &[u8],
    chunk_offset: usize,
    free_offset: usize,
    report: &mut EvtxReport,
) -> Result<Vec<(usize, u64)>, EndpointImportError> {
    let mut offsets = Vec::new();
    let mut cursor = CHUNK_HEADER_SIZE;
    while record_signature_at(chunk, cursor, free_offset)? {
        let record = parse_record(chunk, chunk_offset, cursor, free_offset, report)?;
        offsets.push((cursor, record.record_id));
        cursor = cursor
            .checked_add(
                usize::try_from(record.source_range.length)
                    .map_err(|_| error("EVTX record length exceeds the platform limit"))?,
            )
            .ok_or_else(|| error("EVTX record offset overflows"))?;
    }
    if cursor < free_offset
        && chunk
            .get(cursor..free_offset)
            .is_some_and(|remaining| remaining.iter().any(|byte| *byte != 0))
    {
        return Err(error(
            "EVTX chunk contains unsupported bytes outside record envelopes",
        ));
    }
    Ok(offsets)
}

fn record_signature_at(
    chunk: &[u8],
    offset: usize,
    free_offset: usize,
) -> Result<bool, EndpointImportError> {
    if offset
        .checked_add(RECORD_SIGNATURE.len())
        .is_none_or(|end| end > free_offset)
    {
        return Ok(false);
    }
    Ok(read_bytes(chunk, offset, RECORD_SIGNATURE.len())? == RECORD_SIGNATURE)
}

fn parse_record(
    chunk: &[u8],
    chunk_offset: usize,
    offset: usize,
    free_offset: usize,
    report: &mut EvtxReport,
) -> Result<EvtxRecordEnvelope, EndpointImportError> {
    let record_size = usize::try_from(read_u32(chunk, offset + 4)?)
        .map_err(|_| error("EVTX record size exceeds the platform limit"))?;
    let end = offset
        .checked_add(record_size)
        .ok_or_else(|| error("EVTX record range overflows"))?;
    if record_size < 32 || end > free_offset {
        return Err(error("EVTX record size exceeds its chunk"));
    }
    if read_u32(chunk, end - 4)?
        != u32::try_from(record_size).map_err(|_| error("EVTX record size exceeds u32"))?
    {
        return Err(error("EVTX record trailing size does not match"));
    }
    let record_offset = chunk_offset
        .checked_add(offset)
        .ok_or_else(|| error("EVTX record source offset overflows"))?;
    let content_length = record_size
        .checked_sub(28)
        .ok_or_else(|| error("EVTX record content length underflows"))?;
    let record = EvtxRecordEnvelope {
        record_id: read_u64(chunk, offset + 8)?,
        filetime_ticks: read_u64(chunk, offset + 16)?,
        source_range: source_range(&report.source_sha256, record_offset, record_size)?,
        binxml_range: source_range(&report.source_sha256, record_offset + 24, content_length)?,
    };
    report.records_seen = report.records_seen.saturating_add(1);
    if report.records.len() < MAX_ENDPOINT_RECORDS {
        report.records.push(record.clone());
    } else {
        report.omitted_records = report.omitted_records.saturating_add(1);
    }
    Ok(record)
}

fn validate_last_record_pointer(
    chunk: &[u8],
    last_record: Option<usize>,
) -> Result<(), EndpointImportError> {
    let declared = usize::try_from(read_u32(chunk, 44)?)
        .map_err(|_| error("EVTX last-record offset exceeds the platform limit"))?;
    if last_record.unwrap_or(0) != declared {
        return Err(error(
            "EVTX last-record offset does not match record framing",
        ));
    }
    Ok(())
}

fn validate_chunk_ids(chunk: &[u8], records: &[(usize, u64)]) -> Result<(), EndpointImportError> {
    let Some((_, first_id)) = records.first() else {
        return Ok(());
    };
    let last_id = records
        .last()
        .map(|(_, record_id)| *record_id)
        .ok_or_else(|| error("EVTX record index is inconsistent"))?;
    if read_u64(chunk, 24)? != *first_id || read_u64(chunk, 32)? != last_id {
        return Err(error(
            "EVTX chunk record identifiers disagree with record headers",
        ));
    }
    if records.windows(2).any(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_some_and(|(first, second)| first.1 >= second.1)
    }) {
        return Err(error("EVTX record identifiers are not strictly increasing"));
    }
    Ok(())
}

fn retain_chunk(
    chunk: &[u8],
    chunk_offset: usize,
    index: usize,
    report: &mut EvtxReport,
) -> Result<(), EndpointImportError> {
    if report.chunks.len() >= MAX_ENDPOINT_RECORDS {
        report.omitted_chunks = report.omitted_chunks.saturating_add(1);
        return Ok(());
    }
    report.chunks.push(EvtxChunk {
        index: u64::try_from(index).map_err(|_| error("EVTX chunk index exceeds u64"))?,
        first_record_id: read_u64(chunk, 24)?,
        last_record_id: read_u64(chunk, 32)?,
        source_range: source_range(&report.source_sha256, chunk_offset, chunk.len())?,
    });
    Ok(())
}

fn crc(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

fn crc_parts(first: &[u8], second: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(first);
    hasher.update(second);
    hasher.finalize()
}
