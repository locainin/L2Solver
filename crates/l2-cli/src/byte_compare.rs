//! Exact comparison of two explicitly selected captured byte ranges

use serde::Serialize;
use std::{error::Error, fmt};

/// Maximum byte offset accepted by the capture comparison interface
pub const MAX_BYTE_OFFSET: usize = 65_535;
/// Maximum length of either selected byte range
pub const MAX_SELECTED_BYTES: usize = 65_535;
/// Maximum repeating XOR key length accepted for verification
pub const MAX_XOR_KEY_BYTES: usize = 256;
/// Maximum number of contiguous unequal spans retained in a report
pub const MAX_REPORTED_SPANS: usize = 128;

/// Explicit offsets and optional range length for comparing two packet buffers
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompareOptions<'key> {
    pub left_offset: usize,
    pub right_offset: usize,
    /// `None` selects each packet's complete remainder independently
    pub length: Option<usize>,
    /// A supplied key is checked as-is and is never inferred from the bytes
    pub xor_key: Option<&'key [u8]>,
}

/// One run of unequal byte values in the common selected prefix
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DifferenceSpan {
    /// Offset relative to the beginning of each selected range
    pub offset: usize,
    pub length: usize,
}

/// Result of checking a caller-supplied repeating XOR relation
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum XorStatus {
    /// Every selected byte pair matches the supplied key relation
    Verified,
    /// The supplied relation failed at the reported number of byte positions
    Mismatch { differing_bytes: usize },
    /// The selected ranges cannot be checked together
    NotComparable,
}

/// Bounded exact differences between two selected ranges
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ByteComparison {
    /// Number of byte positions compared in both selected ranges
    pub compared_length: usize,
    /// Unequal values in the common prefix; unequal tails are counted separately
    pub differing_bytes: usize,
    pub spans: Vec<DifferenceSpan>,
    pub spans_truncated: bool,
    pub left_tail_length: usize,
    pub right_tail_length: usize,
    pub xor_verification: Option<XorStatus>,
}

/// Invalid offsets, selected ranges, or caller-supplied XOR key sizes
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompareError {
    OffsetTooLarge {
        side: &'static str,
        offset: usize,
    },
    OffsetOutOfBounds {
        side: &'static str,
        offset: usize,
        length: usize,
    },
    InvalidRangeLength {
        length: usize,
    },
    RangeOutOfBounds {
        side: &'static str,
        offset: usize,
        length: usize,
        available: usize,
    },
    SelectionTooLong {
        side: &'static str,
        length: usize,
    },
    InvalidXorKeyLength {
        length: usize,
    },
}

impl fmt::Display for CompareError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OffsetTooLarge { side, offset } => {
                write!(output, "{side} offset {offset} exceeds {MAX_BYTE_OFFSET}")
            }
            Self::OffsetOutOfBounds {
                side,
                offset,
                length,
            } => {
                write!(
                    output,
                    "{side} offset {offset} exceeds captured packet length {length}"
                )
            }
            Self::InvalidRangeLength { length } => write!(
                output,
                "selected range length must be from 1 to {MAX_SELECTED_BYTES}, got {length}"
            ),
            Self::RangeOutOfBounds {
                side,
                offset,
                length,
                available,
            } => write!(
                output,
                "{side} range offset {offset} plus length {length} exceeds captured packet length {available}"
            ),
            Self::SelectionTooLong { side, length } => write!(
                output,
                "{side} selected range length {length} exceeds {MAX_SELECTED_BYTES}"
            ),
            Self::InvalidXorKeyLength { length } => write!(
                output,
                "XOR key must contain 1 to {MAX_XOR_KEY_BYTES} bytes, got {length}"
            ),
        }
    }
}

impl Error for CompareError {}

/// Compare explicit byte ranges without inferring a transform or packet pairing
///
/// The default range uses each packet's full remainder, so unequal tails are kept
/// separate. A supplied XOR key is checked from index zero in each selected range
/// and is never searched for or derived from the compared data
///
/// # Errors
/// Returns an error for offsets, requested lengths, or XOR key lengths outside bounds
pub fn compare(
    left_packet: &[u8],
    right_packet: &[u8],
    options: CompareOptions<'_>,
) -> Result<ByteComparison, CompareError> {
    let left = selected_range(left_packet, options.left_offset, options.length, "left")?;
    let right = selected_range(right_packet, options.right_offset, options.length, "right")?;
    validate_key(options.xor_key)?;

    let compared_length = left.len().min(right.len());
    let mut differing_bytes = 0;
    let mut spans = Vec::with_capacity(MAX_REPORTED_SPANS.min(compared_length));
    let mut spans_truncated = false;
    let mut current_start = None;

    // Count every mismatch even after the presentation span ceiling is reached
    for (offset, (left_byte, right_byte)) in left
        .iter()
        .zip(right.iter())
        .take(compared_length)
        .enumerate()
    {
        if left_byte == right_byte {
            finish_span(&mut current_start, offset, &mut spans, &mut spans_truncated);
        } else {
            differing_bytes += 1;
            current_start.get_or_insert(offset);
        }
    }
    finish_span(
        &mut current_start,
        compared_length,
        &mut spans,
        &mut spans_truncated,
    );

    let xor_verification = options.xor_key.map(|key| {
        if left.len() != right.len() || left.is_empty() {
            return XorStatus::NotComparable;
        }
        let mut differing_bytes = 0;
        // The validated nonempty key cycles from index zero in the selected range
        for ((left_byte, right_byte), key_byte) in
            left.iter().zip(right.iter()).zip(key.iter().cycle())
        {
            let expected_right = *left_byte ^ *key_byte;
            if *right_byte != expected_right {
                differing_bytes += 1;
            }
        }
        if differing_bytes == 0 {
            XorStatus::Verified
        } else {
            XorStatus::Mismatch { differing_bytes }
        }
    });

    Ok(ByteComparison {
        compared_length,
        differing_bytes,
        spans,
        spans_truncated,
        left_tail_length: left.len() - compared_length,
        right_tail_length: right.len() - compared_length,
        xor_verification,
    })
}

fn selected_range<'packet>(
    packet: &'packet [u8],
    offset: usize,
    length: Option<usize>,
    side: &'static str,
) -> Result<&'packet [u8], CompareError> {
    if offset > MAX_BYTE_OFFSET {
        return Err(CompareError::OffsetTooLarge { side, offset });
    }
    // Keep the remainder as the canonical selection boundary for both range modes
    let remainder = packet
        .get(offset..)
        .ok_or(CompareError::OffsetOutOfBounds {
            side,
            offset,
            length: packet.len(),
        })?;

    let Some(length) = length else {
        if remainder.len() > MAX_SELECTED_BYTES {
            return Err(CompareError::SelectionTooLong {
                side,
                length: remainder.len(),
            });
        }
        return Ok(remainder);
    };

    if !(1..=MAX_SELECTED_BYTES).contains(&length) {
        return Err(CompareError::InvalidRangeLength { length });
    }
    remainder
        .get(..length)
        .ok_or(CompareError::RangeOutOfBounds {
            side,
            offset,
            length,
            available: packet.len(),
        })
}

fn validate_key(key: Option<&[u8]>) -> Result<(), CompareError> {
    if let Some(key) = key
        && !(1..=MAX_XOR_KEY_BYTES).contains(&key.len())
    {
        return Err(CompareError::InvalidXorKeyLength { length: key.len() });
    }
    Ok(())
}

fn finish_span(
    current_start: &mut Option<usize>,
    end: usize,
    spans: &mut Vec<DifferenceSpan>,
    truncated: &mut bool,
) {
    let Some(start) = current_start.take() else {
        return;
    };
    if spans.len() == MAX_REPORTED_SPANS {
        *truncated = true;
        return;
    }
    spans.push(DifferenceSpan {
        offset: start,
        length: end - start,
    });
}
