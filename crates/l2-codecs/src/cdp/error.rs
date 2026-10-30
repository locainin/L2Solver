//! Structural and semantic CDP decoding errors

use core::fmt;

/// A CDP packet failed framing, checksum, identity, or policy limits
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CdpError {
    /// The input exceeds the maximum CDP size in an IEEE 802.3 payload
    FrameTooLong { length: usize, max: usize },
    /// The fixed four-byte CDP header is incomplete
    TruncatedHeader { available: usize },
    /// Only CDP versions 1 and 2 are supported
    UnsupportedVersion { version: u8 },
    /// The CDP checksum is incorrect
    InvalidChecksum,
    /// The caller's TLV count limit was exceeded
    TooManyTlvs { max: usize },
    /// A TLV header ended before its four bytes were complete
    TruncatedTlvHeader { offset: usize, available: usize },
    /// A TLV length was smaller than its own header
    InvalidTlvLength { offset: usize, length: usize },
    /// A TLV value ended before its declared length
    TruncatedTlvValue {
        offset: usize,
        declared: usize,
        available: usize,
    },
    /// A device or port identity was empty or above the caller's limit
    InvalidIdentity {
        kind: u16,
        length: usize,
        max: usize,
    },
    /// A device or port identity occurred more than once
    DuplicateIdentity { kind: u16 },
    /// A required device or port identity was absent
    MissingIdentity { kind: u16 },
}

impl fmt::Display for CdpError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLong { length, max } => {
                write!(output, "CDP packet length {length} exceeds {max}")
            }
            Self::TruncatedHeader { available } => {
                write!(output, "CDP header is truncated at {available} bytes")
            }
            Self::UnsupportedVersion { version } => {
                write!(output, "unsupported CDP version {version}")
            }
            Self::InvalidChecksum => output.write_str("invalid CDP checksum"),
            Self::TooManyTlvs { max } => write!(output, "CDP TLV count exceeds {max}"),
            Self::TruncatedTlvHeader { offset, available } => write!(
                output,
                "CDP TLV header at {offset} has only {available} bytes"
            ),
            Self::InvalidTlvLength { offset, length } => {
                write!(output, "CDP TLV at {offset} has invalid length {length}")
            }
            Self::TruncatedTlvValue {
                offset,
                declared,
                available,
            } => write!(
                output,
                "CDP TLV at {offset} declares {declared} value bytes but {available} remain"
            ),
            Self::InvalidIdentity { kind, length, max } => write!(
                output,
                "CDP identity TLV {kind} has invalid size {length}, maximum {max}"
            ),
            Self::DuplicateIdentity { kind } => {
                write!(output, "CDP identity TLV {kind} is duplicated")
            }
            Self::MissingIdentity { kind } => write!(output, "CDP identity TLV {kind} is missing"),
        }
    }
}

impl std::error::Error for CdpError {}
