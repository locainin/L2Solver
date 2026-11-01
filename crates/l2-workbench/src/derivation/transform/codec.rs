use super::super::{Base64Alphabet, Base64Padding, HexCase, StepFailure};
use super::{OutputBudget, check_output_size};
use base64::{
    Engine, alphabet,
    engine::{
        DecodePaddingMode,
        general_purpose::{GeneralPurpose, GeneralPurposeConfig},
    },
};

pub(super) fn hex_decode(input: &[u8], budget: OutputBudget) -> Result<Vec<u8>, StepFailure> {
    if !input.len().is_multiple_of(2) {
        return Err(StepFailure::InvalidHexLength {
            length: input.len(),
        });
    }
    let output_length = input.len() / 2;
    check_output_size(output_length, budget)?;
    let mut output = Vec::with_capacity(output_length);
    for (pair_index, pair) in input.chunks_exact(2).enumerate() {
        let decoded =
            pair.iter()
                .copied()
                .enumerate()
                .try_fold(0_u8, |value, (nibble_offset, byte)| {
                    let nibble =
                        crate::hex::decode_nibble(byte).ok_or(StepFailure::InvalidHexDigit {
                            offset: pair_index * 2 + nibble_offset,
                        })?;
                    Ok((value << 4) | nibble)
                })?;
        output.push(decoded);
    }
    Ok(output)
}

pub(super) fn hex_encode(
    input: &[u8],
    case: HexCase,
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    let output_length = input
        .len()
        .checked_mul(2)
        .ok_or(StepFailure::OutputLimitExceeded {
            limit: budget.max_output,
        })?;
    check_output_size(output_length, budget)?;
    let mut output = Vec::with_capacity(output_length);
    for byte in input.iter().copied() {
        output.push(hex_digit(byte >> 4, case));
        output.push(hex_digit(byte & 0x0f, case));
    }
    Ok(output)
}

const fn hex_digit(nibble: u8, case: HexCase) -> u8 {
    if nibble < 10 {
        b'0' + nibble
    } else {
        match case {
            HexCase::Upper => b'A' + nibble - 10,
            HexCase::Lower => b'a' + nibble - 10,
        }
    }
}

pub(super) fn base64_encode(
    input: &[u8],
    alphabet: Base64Alphabet,
    padding: Base64Padding,
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    let complete_groups = input.len() / 3;
    let remainder = input.len() % 3;
    let output_length = if padding == Base64Padding::Required {
        input
            .len()
            .div_ceil(3)
            .checked_mul(4)
            .ok_or(StepFailure::OutputLimitExceeded {
                limit: budget.max_output,
            })?
    } else {
        complete_groups
            .checked_mul(4)
            .ok_or(StepFailure::OutputLimitExceeded {
                limit: budget.max_output,
            })?
            + match remainder {
                1 => 2,
                2 => 3,
                _ => 0,
            }
    };
    check_output_size(output_length, budget)?;
    Ok(base64_engine(alphabet, padding).encode(input).into_bytes())
}

pub(super) fn base64_decode(
    input: &[u8],
    alphabet: Base64Alphabet,
    padding: Base64Padding,
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    // Bound the decoder's possible output before its internal allocation
    let complete_groups = input.len() / 4;
    let remainder = input.len() % 4;
    let estimate = complete_groups
        .checked_mul(3)
        .and_then(|length| {
            length.checked_add(match remainder {
                2 => 1,
                3 => 2,
                _ => 0,
            })
        })
        .and_then(|length| {
            let padding = usize::from(input.last() == Some(&b'='))
                + usize::from(input.get(input.len().saturating_sub(2)) == Some(&b'='));
            length.checked_sub(padding)
        })
        .ok_or(StepFailure::InvalidBase64)?;
    check_output_size(estimate, budget)?;
    let decoded = base64_engine(alphabet, padding)
        .decode(input)
        .map_err(|_| StepFailure::InvalidBase64)?;
    check_output_size(decoded.len(), budget)?;
    Ok(decoded)
}

pub(in crate::derivation) fn base64_engine(
    alphabet_kind: Base64Alphabet,
    padding: Base64Padding,
) -> GeneralPurpose {
    let alphabet = match alphabet_kind {
        Base64Alphabet::Standard => &alphabet::STANDARD,
        Base64Alphabet::UrlSafe => &alphabet::URL_SAFE,
    };
    let decode_mode = match padding {
        Base64Padding::Required => DecodePaddingMode::RequireCanonical,
        Base64Padding::Forbidden => DecodePaddingMode::RequireNone,
    };
    let config = GeneralPurposeConfig::new()
        .with_encode_padding(padding == Base64Padding::Required)
        .with_decode_padding_mode(decode_mode);
    GeneralPurpose::new(alphabet, config)
}
