use core::fmt;

use super::FileRange;

/// The fixed byte prefix present at the start of every PNG file
pub const PNG_SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

const MAX_PNG_BYTES: usize = 16 * 1024 * 1024;
const MAX_PNG_CHUNKS: usize = 65_536;
const IHDR_LENGTH: usize = 13;

/// Input and metadata limits for one PNG structural scan
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PngLimits {
    /// Largest input slice accepted by the parser
    pub max_input_bytes: usize,
    /// Largest number of chunks retained from the PNG stream
    pub max_chunks: usize,
}

impl Default for PngLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: MAX_PNG_BYTES,
            max_chunks: MAX_PNG_CHUNKS,
        }
    }
}

/// One CRC-checked PNG chunk and the exact ranges that support its fields
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PngChunk<'a> {
    /// Four-byte chunk type code
    pub type_code: [u8; 4],
    /// Complete chunk range including length, type, payload, and CRC
    pub chunk_range: FileRange,
    /// Exact four-byte length field
    pub length_range: FileRange,
    /// Exact four-byte type code field
    pub type_range: FileRange,
    /// Exact payload range, excluding the length, type code, and CRC
    pub payload_range: FileRange,
    /// Exact four-byte CRC field
    pub crc_range: FileRange,
    /// Borrowed chunk payload bytes
    pub payload: &'a [u8],
    /// CRC value stored in the source chunk
    pub stored_crc32: u32,
}

impl PngChunk<'_> {
    /// Whether the first type-code letter marks this as a critical chunk
    #[must_use]
    pub const fn is_critical(&self) -> bool {
        let [first, ..] = self.type_code;
        first.is_ascii_uppercase()
    }

    /// Whether the second type-code letter marks this as private
    #[must_use]
    pub const fn is_private(&self) -> bool {
        let [_, second, ..] = self.type_code;
        second.is_ascii_lowercase()
    }

    /// Whether the fourth type-code letter marks safe-to-copy semantics
    #[must_use]
    pub const fn is_safe_to_copy(&self) -> bool {
        let [_, _, _, fourth] = self.type_code;
        fourth.is_ascii_lowercase()
    }
}

/// CRC-checked PNG chunk envelopes and bytes preserved after the IEND boundary
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PngReport<'a> {
    /// CRC-checked chunks in source order, including IHDR and IEND
    pub chunks: Vec<PngChunk<'a>>,
    /// Exact source bytes following the IEND chunk
    pub bytes_after_iend: &'a [u8],
    /// Exact source range following the IEND chunk
    pub bytes_after_iend_range: FileRange,
}

impl<'a> PngReport<'a> {
    /// Find chunks whose payload begins with the PNG signature
    ///
    /// The chunk type is not consulted, so private and unknown chunks are
    /// included when their payload bytes contain a nested PNG prefix
    pub fn nested_png_chunks(&self) -> impl Iterator<Item = &PngChunk<'a>> {
        self.chunks
            .iter()
            .filter(|chunk| chunk.payload.starts_with(&PNG_SIGNATURE))
    }
}

/// Invalid, incomplete, or over-budget PNG structure
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PngError {
    /// The parser received invalid or zero-valued resource limits
    InvalidLimits,
    /// The input exceeded its configured size ceiling
    InputTooLarge { length: usize, maximum: usize },
    /// The required eight-byte PNG signature was missing
    InvalidSignature,
    /// A chunk length, type, payload, or CRC extended beyond the input
    TruncatedChunk,
    /// The input contained more chunks than allowed by the configured ceiling
    TooManyChunks { maximum: usize },
    /// A chunk type was not four ASCII letters or violated a type-bit rule
    InvalidChunkType { type_code: [u8; 4] },
    /// A chunk CRC did not match the type code and payload bytes
    InvalidChecksum { type_code: [u8; 4] },
    /// IHDR was not the first chunk in the stream
    IhdrNotFirst,
    /// IHDR appeared more than once
    RepeatedIhdr,
    /// IHDR did not contain its required fixed-size payload
    InvalidIhdrLength,
    /// IEND did not have an empty payload
    InvalidIendLength,
    /// The stream ended before an IEND chunk was found
    MissingIend,
}

impl fmt::Display for PngError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("PNG parser limits must be positive"),
            Self::InputTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "PNG input has {length} bytes; maximum is {maximum}"
                )
            }
            Self::InvalidSignature => formatter.write_str("invalid PNG signature"),
            Self::TruncatedChunk => formatter.write_str("truncated PNG chunk"),
            Self::TooManyChunks { maximum } => {
                write!(formatter, "PNG chunk count exceeds maximum {maximum}")
            }
            Self::InvalidChunkType { type_code } => {
                write!(formatter, "invalid PNG chunk type {type_code:?}")
            }
            Self::InvalidChecksum { type_code } => {
                write!(formatter, "PNG chunk {type_code:?} has an invalid CRC")
            }
            Self::IhdrNotFirst => formatter.write_str("PNG IHDR must be the first chunk"),
            Self::RepeatedIhdr => formatter.write_str("PNG contains more than one IHDR chunk"),
            Self::InvalidIhdrLength => formatter.write_str("PNG IHDR payload must have 13 bytes"),
            Self::InvalidIendLength => formatter.write_str("PNG IEND payload must be empty"),
            Self::MissingIend => formatter.write_str("PNG stream has no IEND chunk"),
        }
    }
}

impl std::error::Error for PngError {}

/// Parse bounded PNG chunk envelopes while borrowing payloads from the input
///
/// This structural scan does not validate image-data presence, ordering, or decoding
///
/// # Errors
/// Returns an error for malformed signatures, chunk boundaries, type codes,
/// checksums, the checked IHDR/IEND boundaries, or exceeded limits
pub fn parse_png(bytes: &[u8], limits: PngLimits) -> Result<PngReport<'_>, PngError> {
    validate_limits(bytes, limits)?;

    if bytes.get(..PNG_SIGNATURE.len()) != Some(PNG_SIGNATURE.as_slice()) {
        return Err(PngError::InvalidSignature);
    }

    let mut chunks = Vec::new();
    let mut cursor = PNG_SIGNATURE.len();

    loop {
        if cursor == bytes.len() {
            return Err(PngError::MissingIend);
        }
        if chunks.len() >= limits.max_chunks {
            return Err(PngError::TooManyChunks {
                maximum: limits.max_chunks,
            });
        }

        let (chunk, chunk_end) = parse_chunk(bytes, cursor, chunks.is_empty())?;
        let is_iend = chunk.type_code == *b"IEND";
        chunks.push(chunk);

        if is_iend {
            let bytes_after_iend = bytes.get(chunk_end..).ok_or(PngError::TruncatedChunk)?;
            return Ok(PngReport {
                chunks,
                bytes_after_iend,
                bytes_after_iend_range: FileRange {
                    offset: chunk_end,
                    length: bytes_after_iend.len(),
                },
            });
        }

        cursor = chunk_end;
    }
}

fn parse_chunk(
    bytes: &[u8],
    cursor: usize,
    is_first_chunk: bool,
) -> Result<(PngChunk<'_>, usize), PngError> {
    // A chunk starts with a big-endian payload length followed by four type bytes
    let length = read_u32(bytes, cursor)?;
    let length_usize = usize::try_from(length).map_err(|_| PngError::TruncatedChunk)?;
    let type_offset = cursor.checked_add(4).ok_or(PngError::TruncatedChunk)?;
    let payload_offset = type_offset.checked_add(4).ok_or(PngError::TruncatedChunk)?;
    let payload_end = payload_offset
        .checked_add(length_usize)
        .ok_or(PngError::TruncatedChunk)?;
    let crc_offset = payload_end;
    let chunk_end = crc_offset.checked_add(4).ok_or(PngError::TruncatedChunk)?;

    // Every field range is checked before it is borrowed or read
    let type_slice = bytes
        .get(type_offset..payload_offset)
        .ok_or(PngError::TruncatedChunk)?;
    let type_code: [u8; 4] = type_slice
        .try_into()
        .map_err(|_| PngError::TruncatedChunk)?;
    validate_type_code(type_code)?;
    let payload = bytes
        .get(payload_offset..payload_end)
        .ok_or(PngError::TruncatedChunk)?;
    let stored_crc32 = read_u32(bytes, crc_offset)?;

    // PNG CRC covers the type and payload, but excludes length and stored CRC
    let mut checksum = crc32fast::Hasher::new();
    checksum.update(&type_code);
    checksum.update(payload);
    if checksum.finalize() != stored_crc32 {
        return Err(PngError::InvalidChecksum { type_code });
    }

    // IHDR is the single required first chunk; IEND closes the parsed stream
    if is_first_chunk {
        if type_code != *b"IHDR" {
            return Err(PngError::IhdrNotFirst);
        }
        if length_usize != IHDR_LENGTH {
            return Err(PngError::InvalidIhdrLength);
        }
    } else if type_code == *b"IHDR" {
        return Err(PngError::RepeatedIhdr);
    }

    if type_code == *b"IEND" && length_usize != 0 {
        return Err(PngError::InvalidIendLength);
    }

    let chunk = PngChunk {
        type_code,
        chunk_range: FileRange {
            offset: cursor,
            length: chunk_end - cursor,
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
            length: length_usize,
        },
        crc_range: FileRange {
            offset: crc_offset,
            length: 4,
        },
        payload,
        stored_crc32,
    };

    Ok((chunk, chunk_end))
}

const fn validate_limits(bytes: &[u8], limits: PngLimits) -> Result<(), PngError> {
    if limits.max_input_bytes == 0 || limits.max_chunks == 0 {
        return Err(PngError::InvalidLimits);
    }
    if bytes.len() > limits.max_input_bytes {
        return Err(PngError::InputTooLarge {
            length: bytes.len(),
            maximum: limits.max_input_bytes,
        });
    }
    Ok(())
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

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PngError> {
    let end = offset.checked_add(4).ok_or(PngError::TruncatedChunk)?;
    let raw = bytes.get(offset..end).ok_or(PngError::TruncatedChunk)?;
    let array: [u8; 4] = raw.try_into().map_err(|_| PngError::TruncatedChunk)?;
    Ok(u32::from_be_bytes(array))
}
