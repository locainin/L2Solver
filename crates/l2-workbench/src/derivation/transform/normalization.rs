//! Bounded text normalization for independently retained byte observations

use super::{Admission, Buffer, OutputBudget, TransformError, check_output_size};
use crate::{
    derivation::{
        StepFailure,
        memory::{AdmissionError, Shared},
    },
    job::{MemoryError, MemoryLease},
};
use std::{error::Error, fmt};

// Recognized named references and Unicode scalar numbers fit within this window
const MAX_REFERENCE_BYTES: usize = 16;

/// Conservative input-byte work bound for removing CR and decoding references
#[must_use]
pub const fn normalization_work_bound(input_length: usize) -> Option<usize> {
    // Include the CR pass, bounded reference lookahead, numeric validation, and both outputs
    input_length.checked_mul(8)
}

/// A rejected normalization step or shared-memory reservation
#[derive(Debug)]
pub enum NormalizationError {
    Step(StepFailure),
    Memory(MemoryError),
}

impl fmt::Display for NormalizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Step(error) => write!(formatter, "normalization failed: {error:?}"),
            Self::Memory(error) => error.fmt(formatter),
        }
    }
}

impl Error for NormalizationError {}

/// Normalize while charging both live buffers to the caller's shared-memory budget
///
/// Removes CR and decodes semicolon-terminated amp, lt, gt, quot, apos, decimal,
/// and hexadecimal references. Unsupported or malformed references remain unchanged.
/// The caller must retain the lease while the returned vector is live. On failure,
/// the caller's incoming charge is unchanged.
///
/// # Errors
/// Returns an allocation or memory admission failure
pub fn normalize_message_with_memory(
    input: &[u8],
    memory: &mut MemoryLease,
) -> Result<Vec<u8>, NormalizationError> {
    let mut retained = memory.try_sibling(0).map_err(NormalizationError::Memory)?;
    let budget = OutputBudget {
        remaining_intermediate: input.len(),
        max_output: input.len(),
        max_intermediate: input.len(),
        max_key_bytes: 0,
    };
    let (output, lease) = {
        let admission = Shared(&mut retained);
        let without_cr =
            remove_carriage_returns(input, budget, &admission).map_err(admitted_error)?;
        let output =
            decode_entities(&without_cr.bytes, budget, &admission).map_err(admitted_error)?;
        output.into_parts()
    };
    retained.absorb(lease);
    memory.absorb(retained);
    Ok(output)
}

const fn admitted_error(error: TransformError<AdmissionError>) -> NormalizationError {
    match error {
        TransformError::Step(error) => NormalizationError::Step(error),
        TransformError::Admission(AdmissionError::Memory(error)) => {
            NormalizationError::Memory(error)
        }
        TransformError::Admission(AdmissionError::UnsupportedOperation) => {
            NormalizationError::Step(StepFailure::AllocationFailed)
        }
    }
}

pub(super) fn remove_carriage_returns<A: Admission>(
    input: &[u8],
    budget: OutputBudget,
    admission: &A,
) -> Result<Buffer<A>, TransformError<A::Error>> {
    let mut output = Buffer::with_capacity(input.len(), admission)?;
    output
        .bytes
        .extend(input.iter().copied().filter(|byte| *byte != b'\r'));
    check_output_size(output.bytes.len(), budget)?;
    Ok(output)
}

pub(super) fn decode_entities<A: Admission>(
    input: &[u8],
    budget: OutputBudget,
    admission: &A,
) -> Result<Buffer<A>, TransformError<A::Error>> {
    let mut output = Buffer::with_capacity(input.len(), admission)?;
    let mut position = 0;
    while let Some(byte) = input.get(position).copied() {
        if byte == b'&'
            && let Some((reference_len, decoded)) = input.get(position..).and_then(reference)
        {
            let mut bytes = [0; 4];
            output
                .bytes
                .extend_from_slice(decoded.encode_utf8(&mut bytes).as_bytes());
            position += reference_len;
            continue;
        }
        output.bytes.push(byte);
        position += 1;
    }
    check_output_size(output.bytes.len(), budget)?;
    Ok(output)
}

fn reference(input: &[u8]) -> Option<(usize, char)> {
    // A second ampersand starts another reference and stops this bounded lookahead
    let end = input
        .iter()
        .copied()
        .enumerate()
        .take(MAX_REFERENCE_BYTES)
        .skip(1)
        .take_while(|(_, byte)| *byte != b'&')
        .find_map(|(index, byte)| (byte == b';').then_some(index))?;
    let body = input.get(1..end)?;
    let value = match body {
        b"amp" => '&',
        b"lt" => '<',
        b"gt" => '>',
        b"quot" => '"',
        b"apos" => '\'',
        _ => numeric_reference(body)?,
    };
    Some((end + 1, value))
}

fn numeric_reference(body: &[u8]) -> Option<char> {
    let number = body.strip_prefix(b"#")?;
    let (digits, radix) = number
        .strip_prefix(b"x")
        .or_else(|| number.strip_prefix(b"X"))
        .map_or((number, 10), |hex| (hex, 16));
    if digits.is_empty()
        || !digits.iter().all(|byte| match radix {
            16 => byte.is_ascii_hexdigit(),
            _ => byte.is_ascii_digit(),
        })
    {
        return None;
    }
    let code = u32::from_str_radix(std::str::from_utf8(digits).ok()?, radix).ok()?;
    let code = match code {
        0 => 0xfffd,
        0x80 => 0x20ac,
        0x82 => 0x201a,
        0x83 => 0x0192,
        0x84 => 0x201e,
        0x85 => 0x2026,
        0x86 => 0x2020,
        0x87 => 0x2021,
        0x88 => 0x02c6,
        0x89 => 0x2030,
        0x8a => 0x0160,
        0x8b => 0x2039,
        0x8c => 0x0152,
        0x8e => 0x017d,
        0x91 => 0x2018,
        0x92 => 0x2019,
        0x93 => 0x201c,
        0x94 => 0x201d,
        0x95 => 0x2022,
        0x96 => 0x2013,
        0x97 => 0x2014,
        0x98 => 0x02dc,
        0x99 => 0x2122,
        0x9a => 0x0161,
        0x9b => 0x203a,
        0x9c => 0x0153,
        0x9e => 0x017e,
        0x9f => 0x0178,
        other => other,
    };
    Some(char::from_u32(code).unwrap_or('\u{fffd}'))
}
