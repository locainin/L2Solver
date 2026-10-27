use core::fmt;

use super::FileRange;

/// The fixed byte prefix present at the start of every PNG file
pub const PNG_SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

const MAX_PNG_BYTES: usize = 16 * 1024 * 1024;
const MAX_PNG_CHUNKS: usize = 65_536;

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
    /// Bounded chunk metadata could not be allocated
    AllocationFailure,
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
            Self::AllocationFailure => formatter.write_str("PNG chunk metadata allocation failed"),
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
    let mut reader = std::io::Cursor::new(bytes);
    let parsed = super::png_stream::parse_png_from_reader(&mut reader, bytes.len(), limits)
        .map_err(|error| match error {
            super::png_stream::PngReadError::Format(error) => error,
            super::png_stream::PngReadError::Io(_) => PngError::TruncatedChunk,
        })?;
    let mut chunks = Vec::new();
    chunks
        .try_reserve_exact(parsed.chunks.len())
        .map_err(|_| PngError::AllocationFailure)?;
    for chunk in parsed.chunks {
        let end = chunk
            .payload_range
            .offset
            .checked_add(chunk.payload_range.length)
            .ok_or(PngError::TruncatedChunk)?;
        let payload = bytes
            .get(chunk.payload_range.offset..end)
            .ok_or(PngError::TruncatedChunk)?;
        chunks.push(PngChunk {
            type_code: chunk.type_code,
            chunk_range: chunk.chunk_range,
            length_range: chunk.length_range,
            type_range: chunk.type_range,
            payload_range: chunk.payload_range,
            crc_range: chunk.crc_range,
            payload,
            stored_crc32: chunk.stored_crc32,
        });
    }
    let bytes_after_iend = bytes
        .get(parsed.bytes_after_iend_range.offset..)
        .ok_or(PngError::TruncatedChunk)?;
    Ok(PngReport {
        chunks,
        bytes_after_iend,
        bytes_after_iend_range: parsed.bytes_after_iend_range,
    })
}
