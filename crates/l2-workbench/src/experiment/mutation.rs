use super::{MAX_OUTPUT_BYTES, Mutation, MutationFailure};

pub(super) fn apply(input: &[u8], mutation: &Mutation) -> Result<Vec<u8>, MutationFailure> {
    match mutation {
        Mutation::FlipBit { offset, bit } => flip_bit(input, *offset, *bit),
        Mutation::XorRange {
            offset,
            length,
            key_hex,
        } => xor_range(input, *offset, *length, key_hex),
        Mutation::Insert { offset, bytes_hex } => insert(input, *offset, bytes_hex),
        Mutation::Delete { offset, length } => delete(input, *offset, *length),
        Mutation::Truncate { length } => truncate(input, *length),
    }
}

fn flip_bit(input: &[u8], offset: usize, bit: u8) -> Result<Vec<u8>, MutationFailure> {
    if u32::from(bit) >= u8::BITS {
        return Err(MutationFailure::InvalidBit);
    }
    let Some(mask) = 1_u8.checked_shl(u32::from(bit)) else {
        return Err(MutationFailure::InvalidBit);
    };
    if offset >= input.len() {
        return Err(MutationFailure::RangeOutOfBounds);
    }
    let mut output = copy_bytes(input)?;
    let Some(byte) = output.get_mut(offset) else {
        return Err(MutationFailure::RangeOutOfBounds);
    };
    *byte ^= mask;
    Ok(output)
}

fn xor_range(
    input: &[u8],
    offset: usize,
    length: usize,
    key_hex: &str,
) -> Result<Vec<u8>, MutationFailure> {
    if length == 0 {
        return Err(MutationFailure::EmptyRange);
    }
    if key_hex.is_empty() || key_hex.len() > 2 * 256 {
        return Err(MutationFailure::InvalidKeyLength);
    }
    let key = decode_hex(key_hex)?;
    let end = offset
        .checked_add(length)
        .ok_or(MutationFailure::RangeOutOfBounds)?;
    if input.get(offset..end).is_none() {
        return Err(MutationFailure::RangeOutOfBounds);
    }
    let mut output = copy_bytes(input)?;
    let Some(selected) = output.get_mut(offset..end) else {
        return Err(MutationFailure::RangeOutOfBounds);
    };
    // The nonempty, bounded hex input above decodes to a nonempty key
    for (byte, key_byte) in selected.iter_mut().zip(key.iter().cycle()) {
        *byte ^= *key_byte;
    }
    Ok(output)
}

fn insert(input: &[u8], offset: usize, bytes_hex: &str) -> Result<Vec<u8>, MutationFailure> {
    if bytes_hex.len() > 2 * MAX_OUTPUT_BYTES {
        return Err(MutationFailure::OutputTooLarge);
    }
    let inserted = decode_hex(bytes_hex)?;
    if inserted.is_empty() {
        return Err(MutationFailure::EmptyRange);
    }
    if offset > input.len() {
        return Err(MutationFailure::RangeOutOfBounds);
    }
    let output_length = input
        .len()
        .checked_add(inserted.len())
        .ok_or(MutationFailure::OutputTooLarge)?;
    if output_length > MAX_OUTPUT_BYTES {
        return Err(MutationFailure::OutputTooLarge);
    }
    let prefix = input
        .get(..offset)
        .ok_or(MutationFailure::RangeOutOfBounds)?;
    let suffix = input
        .get(offset..)
        .ok_or(MutationFailure::RangeOutOfBounds)?;
    let mut output = reserve(output_length)?;
    output.extend_from_slice(prefix);
    output.extend_from_slice(&inserted);
    output.extend_from_slice(suffix);
    Ok(output)
}

fn delete(input: &[u8], offset: usize, length: usize) -> Result<Vec<u8>, MutationFailure> {
    if length == 0 {
        return Err(MutationFailure::EmptyRange);
    }
    let end = offset
        .checked_add(length)
        .ok_or(MutationFailure::RangeOutOfBounds)?;
    if input.get(offset..end).is_none() {
        return Err(MutationFailure::RangeOutOfBounds);
    }
    let output_length = input.len() - length;
    let prefix = input
        .get(..offset)
        .ok_or(MutationFailure::RangeOutOfBounds)?;
    let suffix = input.get(end..).ok_or(MutationFailure::RangeOutOfBounds)?;
    let mut output = reserve(output_length)?;
    output.extend_from_slice(prefix);
    output.extend_from_slice(suffix);
    Ok(output)
}

fn truncate(input: &[u8], length: usize) -> Result<Vec<u8>, MutationFailure> {
    let prefix = input
        .get(..length)
        .ok_or(MutationFailure::InvalidTruncateLength)?;
    copy_bytes(prefix)
}

fn copy_bytes(input: &[u8]) -> Result<Vec<u8>, MutationFailure> {
    let mut output = reserve(input.len())?;
    output.extend_from_slice(input);
    Ok(output)
}

fn reserve(length: usize) -> Result<Vec<u8>, MutationFailure> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| MutationFailure::AllocationFailed)?;
    Ok(output)
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, MutationFailure> {
    if !hex.len().is_multiple_of(2) {
        return Err(MutationFailure::InvalidHex);
    }
    let mut output = reserve(hex.len() / 2)?;
    for &[high, low] in hex.as_bytes().as_chunks::<2>().0 {
        let Some(high) = crate::hex::decode_nibble(high) else {
            return Err(MutationFailure::InvalidHex);
        };
        let Some(low) = crate::hex::decode_nibble(low) else {
            return Err(MutationFailure::InvalidHex);
        };
        output.push((high << 4) | low);
    }
    Ok(output)
}
