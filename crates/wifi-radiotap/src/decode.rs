use crate::{
    Channel, DecodeError, MAX_PRESENCE_WORDS, RadiotapFields, RadiotapFlags, RadiotapFrame,
};

const MIN_HEADER_LENGTH: usize = 8;

/// Decode a radiotap envelope and retain the exact following 802.11 bytes
///
/// # Errors
///
/// Returns [`DecodeError`] when the envelope is truncated, declares an invalid
/// header length, exceeds the presence-word budget, or has an invalid layout
pub fn decode(input: &[u8]) -> Result<RadiotapFrame<'_>, DecodeError> {
    // The fixed prefix must exist before any declared length is trusted
    require(input, 4, "header prefix")?;
    let version = read_u8(input, 0, "version")?;
    if version != 0 {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let declared = usize::from(read_u16(input, 2, "header length")?);
    if declared < MIN_HEADER_LENGTH {
        return Err(DecodeError::InvalidHeaderLength {
            declared,
            minimum: MIN_HEADER_LENGTH,
        });
    }
    require(input, declared, "declared header")?;

    // Presence words define both field order and the start of field data
    let (presence, count, fields_offset) = presence_words(input, declared)?;
    let parsed = parse_fields(input, declared, &presence, count, fields_offset)?;
    let header = input
        .get(..declared)
        .ok_or_else(|| DecodeError::truncated("header", declared, input.len()))?;
    let wifi = input
        .get(declared..)
        .ok_or_else(|| DecodeError::truncated("payload", declared, input.len()))?;
    Ok(RadiotapFrame::new(
        header,
        wifi,
        parsed.fields,
        parsed.unsupported.is_none(),
        parsed.unsupported,
    ))
}

fn presence_words(
    input: &[u8],
    declared: usize,
) -> Result<([u32; MAX_PRESENCE_WORDS], usize, usize), DecodeError> {
    let mut words = [0_u32; MAX_PRESENCE_WORDS];
    let mut count = 0_usize;
    let mut offset = 4_usize;
    loop {
        // A hard word limit prevents unbounded extension chains
        if count == MAX_PRESENCE_WORDS {
            return Err(DecodeError::PresenceWordLimit {
                maximum: MAX_PRESENCE_WORDS,
            });
        }
        let word = read_u32_bounded(input, offset, declared, "presence word")?;
        let slot = words.get_mut(count).ok_or(DecodeError::PresenceWordLimit {
            maximum: MAX_PRESENCE_WORDS,
        })?;
        *slot = word;
        count += 1;
        offset = offset
            .checked_add(4)
            .ok_or(DecodeError::InvalidFieldLayout { field: 31 })?;
        if word & 0x8000_0000 == 0 {
            return Ok((words, count, offset));
        }
    }
}

struct ParsedFields {
    fields: RadiotapFields,
    unsupported: Option<u16>,
}

fn parse_fields(
    input: &[u8],
    declared: usize,
    words: &[u32; MAX_PRESENCE_WORDS],
    count: usize,
    mut offset: usize,
) -> Result<ParsedFields, DecodeError> {
    let mut fields = RadiotapFields::new();
    for (word_index, word) in words.iter().take(count).enumerate() {
        for local_bit in 0_u8..31 {
            if word & (1_u32 << u32::from(local_bit)) == 0 {
                continue;
            }
            let absolute = word_index
                .checked_mul(32)
                .and_then(|base| base.checked_add(usize::from(local_bit)))
                .ok_or(DecodeError::InvalidFieldLayout { field: u16::MAX })?;
            let field = u16::try_from(absolute)
                .map_err(|_| DecodeError::InvalidFieldLayout { field: u16::MAX })?;
            let Some((alignment, size)) = layout(field) else {
                // An unknown size makes every following field offset uncertain
                return Ok(ParsedFields {
                    fields,
                    unsupported: Some(field),
                });
            };
            // Radiotap alignment is relative to the start of this header
            offset = align(offset, alignment, field)?;
            // Declared header length and captured length are independent bounds
            require_bounded(input, offset, size, declared, "field")?;
            fields = apply_field(fields, input, offset, field)?;
            offset = offset
                .checked_add(size)
                .ok_or(DecodeError::InvalidFieldLayout { field })?;
        }
    }
    Ok(ParsedFields {
        fields,
        unsupported: None,
    })
}

const fn layout(field: u16) -> Option<(usize, usize)> {
    match field {
        0 => Some((8, 8)),
        1 | 2 | 5 | 6 | 10 | 11 | 12 | 13 | 17 | 26 => Some((1, 1)),
        3 | 27 => Some((2, 4)),
        4 | 7 | 8 | 9 | 14 | 15 => Some((2, 2)),
        19 => Some((1, 3)),
        20 => Some((4, 8)),
        21 | 23 | 24 => Some((2, 12)),
        22 => Some((8, 12)),
        _ => None,
    }
}

fn apply_field(
    fields: RadiotapFields,
    input: &[u8],
    offset: usize,
    field: u16,
) -> Result<RadiotapFields, DecodeError> {
    // Known but unused fields still consume their declared layout above
    match field {
        0 => Ok(fields.with_tsft(read_u64(input, offset, "TSFT")?)),
        1 => Ok(fields.with_flags(RadiotapFlags::new(read_u8(input, offset, "flags")?))),
        2 => Ok(fields.with_rate_500kbps(read_u8(input, offset, "rate")?)),
        3 => Ok(fields.with_channel(Channel::new(
            read_u16(input, offset, "channel frequency")?,
            read_u16(input, offset + 2, "channel flags")?,
        ))),
        5 => Ok(fields.with_signal_dbm(read_i8(input, offset, "signal")?)),
        6 => Ok(fields.with_noise_dbm(read_i8(input, offset, "noise")?)),
        11 => Ok(fields.with_antenna(read_u8(input, offset, "antenna")?)),
        14 => Ok(fields.with_rx_flags(read_u16(input, offset, "RX flags")?)),
        15 => Ok(fields.with_tx_flags(read_u16(input, offset, "TX flags")?)),
        26 => Ok(fields.with_zero_length_psdu(read_u8(input, offset, "zero-length PSDU")?)),
        _ => Ok(fields),
    }
}

fn align(offset: usize, alignment: usize, field: u16) -> Result<usize, DecodeError> {
    let remainder = offset % alignment;
    let padding = if remainder == 0 {
        0
    } else {
        alignment - remainder
    };
    offset
        .checked_add(padding)
        .ok_or(DecodeError::InvalidFieldLayout { field })
}

fn require_bounded(
    input: &[u8],
    offset: usize,
    size: usize,
    declared: usize,
    context: &'static str,
) -> Result<(), DecodeError> {
    // Both limits matter when a capture truncates a declared header
    let end = offset
        .checked_add(size)
        .ok_or(DecodeError::InvalidFieldLayout { field: u16::MAX })?;
    if end > declared || end > input.len() {
        return Err(DecodeError::truncated(
            context,
            end,
            declared.min(input.len()),
        ));
    }
    Ok(())
}

const fn require(input: &[u8], needed: usize, context: &'static str) -> Result<(), DecodeError> {
    if input.len() < needed {
        return Err(DecodeError::truncated(context, needed, input.len()));
    }
    Ok(())
}

fn read_u8(input: &[u8], offset: usize, context: &'static str) -> Result<u8, DecodeError> {
    input
        .get(offset)
        .copied()
        .ok_or_else(|| DecodeError::truncated(context, offset.saturating_add(1), input.len()))
}

fn read_i8(input: &[u8], offset: usize, context: &'static str) -> Result<i8, DecodeError> {
    Ok(i8::from_ne_bytes([read_u8(input, offset, context)?]))
}

fn read_u16(input: &[u8], offset: usize, context: &'static str) -> Result<u16, DecodeError> {
    let bytes: [u8; 2] = read_array(input, offset, context)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32_bounded(
    input: &[u8],
    offset: usize,
    declared: usize,
    context: &'static str,
) -> Result<u32, DecodeError> {
    require_bounded(input, offset, 4, declared, context)?;
    let bytes: [u8; 4] = read_array(input, offset, context)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(input: &[u8], offset: usize, context: &'static str) -> Result<u64, DecodeError> {
    let bytes: [u8; 8] = read_array(input, offset, context)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_array<const N: usize>(
    input: &[u8],
    offset: usize,
    context: &'static str,
) -> Result<[u8; N], DecodeError> {
    // All multibyte reads use exact checked slices instead of pointer casts
    let end = offset
        .checked_add(N)
        .ok_or(DecodeError::InvalidFieldLayout { field: u16::MAX })?;
    let bytes = input
        .get(offset..end)
        .ok_or_else(|| DecodeError::truncated(context, end, input.len()))?;
    bytes
        .try_into()
        .map_err(|_| DecodeError::InvalidFieldLayout { field: u16::MAX })
}
