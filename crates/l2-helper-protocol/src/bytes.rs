use crate::ProtocolError;

// Fixed-width fields share one checked byte boundary across both wire layouts
pub fn read_array<const LENGTH: usize>(
    input: &[u8],
    offset: usize,
) -> Result<[u8; LENGTH], ProtocolError> {
    let end = offset
        .checked_add(LENGTH)
        .ok_or(ProtocolError::LengthOverflow)?;
    let bytes = input.get(offset..end).ok_or(ProtocolError::InputTooShort {
        needed: end,
        available: input.len(),
    })?;
    bytes
        .try_into()
        .map_err(|_| ProtocolError::InternalEncodingInvariant)
}

pub fn write_at(output: &mut [u8], offset: usize, bytes: &[u8]) -> Result<(), ProtocolError> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or(ProtocolError::LengthOverflow)?;
    let destination = output
        .get_mut(offset..end)
        .ok_or(ProtocolError::InternalEncodingInvariant)?;
    destination.copy_from_slice(bytes);
    Ok(())
}
