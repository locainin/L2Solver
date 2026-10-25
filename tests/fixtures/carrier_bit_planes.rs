pub(super) fn printable_bit_planes() -> Result<[u8; 40], std::array::TryFromSliceError> {
    let first = *b"EARLY";
    let later = *b"LATER";
    let encoded = first
        .into_iter()
        .zip(later)
        .flat_map(|(first_byte, later_byte)| {
            (0..8)
                .rev()
                .map(move |shift| (((first_byte >> shift) & 1) << 7) | ((later_byte >> shift) & 1))
        })
        .collect::<Vec<_>>();
    encoded.as_slice().try_into()
}
