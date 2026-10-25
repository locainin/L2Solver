/// Read one byte without relying on an unchecked index
pub fn read_u8(input: &[u8], offset: usize) -> Option<u8> {
    input.get(offset).copied()
}

/// Read one network-order 16-bit value without slicing past the input
pub fn read_u16(input: &[u8], offset: usize) -> Option<u16> {
    let (bytes, _) = input.get(offset..)?.split_first_chunk::<2>()?;
    let [high, low] = *bytes;
    Some(u16::from_be_bytes([high, low]))
}

/// Read one network-order 32-bit value without reading past the input
pub fn read_u32(input: &[u8], offset: usize) -> Option<u32> {
    let (bytes, _) = input.get(offset..)?.split_first_chunk::<4>()?;
    Some(u32::from_be_bytes(*bytes))
}

/// Borrow a checked subrange without allocating or panicking
pub fn take(input: &[u8], offset: usize, length: usize) -> Option<&[u8]> {
    let end = offset.checked_add(length)?;
    input.get(offset..end)
}
