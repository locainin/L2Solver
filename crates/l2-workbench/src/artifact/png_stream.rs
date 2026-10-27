//! Shared bounded PNG structural scan for slices and streams

use std::{
    fmt,
    io::{self, Read},
};

use super::{FileRange, PNG_SIGNATURE, PngError, PngLimits};

const READ_BUFFER_BYTES: usize = 16 * 1024;
const IHDR_LENGTH: usize = 13;

/// One CRC-checked chunk described by ranges relative to the start of the input
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PngRangeChunk {
    /// Four-byte chunk type code
    pub type_code: [u8; 4],
    /// Complete chunk including its length, type, payload, and CRC
    pub chunk_range: FileRange,
    /// Exact four-byte length field
    pub length_range: FileRange,
    /// Exact four-byte type field
    pub type_range: FileRange,
    /// Exact chunk payload
    pub payload_range: FileRange,
    /// Exact four-byte CRC field
    pub crc_range: FileRange,
    /// CRC value stored in the input
    pub stored_crc32: u32,
}

/// CRC-checked chunk ranges and the boundary following IEND
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PngRangeReport {
    /// Chunk ranges in source order, including IHDR and IEND
    pub chunks: Vec<PngRangeChunk>,
    /// Bytes following IEND in the declared input range
    pub bytes_after_iend_range: FileRange,
}

/// A structural rejection or an underlying reader failure
#[derive(Debug)]
pub enum PngReadError {
    /// The input failed a PNG structural check or resource limit
    Format(PngError),
    /// The reader failed or ended before the declared input length
    Io(io::Error),
}

impl fmt::Display for PngReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(error) => error.fmt(formatter),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PngReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Format(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

impl From<PngError> for PngReadError {
    fn from(error: PngError) -> Self {
        Self::Format(error)
    }
}

impl From<io::Error> for PngReadError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Validate PNG structure using bounded reads without retaining chunk payloads
///
/// The reader starts at the input's first byte. The scanner stops immediately after IEND,
/// leaving any trailing bytes unread. Returned ranges are relative to that starting byte.
/// The caller must keep the source stable and separately enforce any aggregate work limit.
///
/// # Errors
/// Returns a structural or resource error, or an I/O error from the supplied reader
pub fn parse_png_from_reader(
    reader: &mut impl Read,
    source_length: usize,
    limits: PngLimits,
) -> Result<PngRangeReport, PngReadError> {
    if limits.max_input_bytes == 0 || limits.max_chunks == 0 {
        return Err(PngError::InvalidLimits.into());
    }
    if source_length > limits.max_input_bytes {
        return Err(PngError::InputTooLarge {
            length: source_length,
            maximum: limits.max_input_bytes,
        }
        .into());
    }
    if source_length < PNG_SIGNATURE.len() {
        return Err(PngError::InvalidSignature.into());
    }
    let mut signature = [0_u8; PNG_SIGNATURE.len()];
    reader.read_exact(&mut signature)?;
    if signature != PNG_SIGNATURE {
        return Err(PngError::InvalidSignature.into());
    }

    let mut cursor = PNG_SIGNATURE.len();
    let mut chunks = Vec::new();
    let mut buffer = [0_u8; READ_BUFFER_BYTES];
    loop {
        if cursor == source_length {
            return Err(PngError::MissingIend.into());
        }
        if chunks.len() >= limits.max_chunks {
            return Err(PngError::TooManyChunks {
                maximum: limits.max_chunks,
            }
            .into());
        }
        let (chunk, end) = read_chunk(
            reader,
            source_length,
            cursor,
            chunks.is_empty(),
            &mut buffer,
        )?;
        let is_iend = chunk.type_code == *b"IEND";
        chunks
            .try_reserve(1)
            .map_err(|_| PngError::AllocationFailure)?;
        chunks.push(chunk);
        if is_iend {
            return Ok(PngRangeReport {
                chunks,
                bytes_after_iend_range: FileRange {
                    offset: end,
                    length: source_length - end,
                },
            });
        }
        cursor = end;
    }
}

fn read_chunk(
    reader: &mut impl Read,
    source_length: usize,
    cursor: usize,
    is_first: bool,
    buffer: &mut [u8],
) -> Result<(PngRangeChunk, usize), PngReadError> {
    let type_offset = cursor.checked_add(4).ok_or(PngError::TruncatedChunk)?;
    if type_offset > source_length {
        return Err(PngError::TruncatedChunk.into());
    }
    let mut field = [0_u8; 4];
    reader.read_exact(&mut field)?;
    let payload_length =
        usize::try_from(u32::from_be_bytes(field)).map_err(|_| PngError::TruncatedChunk)?;
    let payload_offset = type_offset.checked_add(4).ok_or(PngError::TruncatedChunk)?;
    let crc_offset = payload_offset
        .checked_add(payload_length)
        .ok_or(PngError::TruncatedChunk)?;
    let end = crc_offset.checked_add(4).ok_or(PngError::TruncatedChunk)?;
    if payload_offset > source_length {
        return Err(PngError::TruncatedChunk.into());
    }
    reader.read_exact(&mut field)?;
    let type_code = field;
    validate_type_code(type_code)?;
    if end > source_length {
        return Err(PngError::TruncatedChunk.into());
    }

    // Only a fixed-size buffer is needed to verify even a large chunk's CRC
    let mut crc = crc32fast::Hasher::new();
    crc.update(&type_code);
    let mut remaining = payload_length;
    while remaining > 0 {
        let count = remaining.min(buffer.len());
        let part = buffer.get_mut(..count).ok_or(PngError::TruncatedChunk)?;
        reader.read_exact(part)?;
        crc.update(part);
        remaining -= count;
    }
    reader.read_exact(&mut field)?;
    let stored_crc32 = u32::from_be_bytes(field);
    if crc.finalize() != stored_crc32 {
        return Err(PngError::InvalidChecksum { type_code }.into());
    }
    validate_chunk(type_code, payload_length, is_first)?;
    Ok((
        PngRangeChunk {
            type_code,
            chunk_range: FileRange {
                offset: cursor,
                length: end - cursor,
            },
            length_range: FileRange {
                offset: cursor,
                length: 4,
            },
            type_range: FileRange {
                offset: type_offset,
                length: 4,
            },
            payload_range: FileRange {
                offset: payload_offset,
                length: payload_length,
            },
            crc_range: FileRange {
                offset: crc_offset,
                length: 4,
            },
            stored_crc32,
        },
        end,
    ))
}

fn validate_type_code(type_code: [u8; 4]) -> Result<(), PngError> {
    let [first, second, third, fourth] = type_code;
    if ![first, second, third, fourth]
        .iter()
        .all(u8::is_ascii_alphabetic)
        || !third.is_ascii_uppercase()
    {
        return Err(PngError::InvalidChunkType { type_code });
    }
    Ok(())
}

fn validate_chunk(type_code: [u8; 4], length: usize, is_first: bool) -> Result<(), PngError> {
    if is_first {
        if type_code != *b"IHDR" {
            return Err(PngError::IhdrNotFirst);
        }
        if length != IHDR_LENGTH {
            return Err(PngError::InvalidIhdrLength);
        }
    } else if type_code == *b"IHDR" {
        return Err(PngError::RepeatedIhdr);
    }
    if type_code == *b"IEND" && length != 0 {
        return Err(PngError::InvalidIendLength);
    }
    Ok(())
}
