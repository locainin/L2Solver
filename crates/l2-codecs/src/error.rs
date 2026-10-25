//! Structural decoder errors

use std::fmt;

/// The structural errors returned before an LLDP data unit can be represented
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The supplied byte slice exceeds the decoder input budget
    FrameTooLong { length: usize, max: usize },
    /// A TLV header ended before its two-byte header was complete
    TruncatedHeader { offset: usize, available: usize },
    /// A TLV value ended before its advertised length was available
    TruncatedValue {
        offset: usize,
        kind: u8,
        declared: usize,
        available: usize,
    },
    /// The LLDPDU ended without an End of LLDPDU TLV
    MissingEnd { offset: usize },
    /// An End of LLDPDU TLV advertised a nonzero value length
    NonZeroEndLength { offset: usize, length: usize },
    /// The number of retained non-End TLVs exceeded the parser budget
    TooManyTlvs { max: usize },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLong { length, max } => {
                write!(f, "LLDPDU is {length} bytes, maximum is {max}")
            }
            Self::TruncatedHeader { offset, available } => write!(
                f,
                "truncated LLDP TLV header at offset {offset}: {available} byte(s) available"
            ),
            Self::TruncatedValue {
                offset,
                kind,
                declared,
                available,
            } => write!(
                f,
                "truncated LLDP TLV type {kind} at offset {offset}: declared {declared} byte(s), {available} available"
            ),
            Self::MissingEnd { offset } => {
                write!(f, "missing LLDP End TLV at offset {offset}")
            }
            Self::NonZeroEndLength { offset, length } => write!(
                f,
                "LLDP End TLV at offset {offset} has nonzero length {length}"
            ),
            Self::TooManyTlvs { max } => {
                write!(f, "LLDPDU contains more than {max} non-End TLVs")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Errors returned by the canonical LLDP encoder
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The reconstructed LLDP data unit exceeds the bounded input policy
    FrameTooLong { length: usize, max: usize },
    /// The caller did not provide enough output space
    BufferTooShort { needed: usize, available: usize },
    /// The decoded model is not semantically valid for canonical encoding
    InvalidSemantic,
    /// A retained TLV value cannot fit the nine-bit LLDP length field
    TlvValueTooLong { kind: u8, length: usize, max: usize },
    /// The retained non-End TLV count exceeds the bounded model
    TooManyTlvs { max: usize },
    /// The TLV type is outside the seven-bit LLDP type range
    InvalidTlvKind { kind: u8 },
    /// A checked output-length calculation could not be represented
    LengthOverflow,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLong { length, max } => {
                write!(f, "encoded LLDPDU is {length} bytes, maximum is {max}")
            }
            Self::BufferTooShort { needed, available } => write!(
                f,
                "LLDP output buffer is too short: need {needed} bytes, have {available}"
            ),
            Self::InvalidSemantic => {
                f.write_str("LLDPDU mandatory fields are not semantically valid")
            }
            Self::TlvValueTooLong { kind, length, max } => write!(
                f,
                "LLDP TLV type {kind} has {length} value bytes, maximum is {max}"
            ),
            Self::TooManyTlvs { max } => {
                write!(f, "LLDPDU contains more than {max} non-End TLVs")
            }
            Self::InvalidTlvKind { kind } => {
                write!(
                    f,
                    "LLDP TLV type {kind} is outside the seven-bit type range"
                )
            }
            Self::LengthOverflow => f.write_str("encoded LLDPDU length overflowed"),
        }
    }
}

impl std::error::Error for EncodeError {}
