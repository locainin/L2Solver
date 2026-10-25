/// Decode an unsigned integer from one through eight bytes
pub fn decode_unsigned(bytes: &[u8], little_endian: bool) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }

    // This bound keeps shifts and accumulation within the eight bytes of u64
    if little_endian {
        Some(
            bytes
                .iter()
                .copied()
                .enumerate()
                .fold(0_u64, |value, (index, byte)| {
                    value | (u64::from(byte) << (index * 8))
                }),
        )
    } else {
        Some(
            bytes
                .iter()
                .copied()
                .fold(0_u64, |value, byte| (value << 8) | u64::from(byte)),
        )
    }
}
