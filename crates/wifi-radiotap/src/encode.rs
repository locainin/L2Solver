use crate::{Channel, EncodeError, RadiotapFields};

const HEADER_LENGTH: usize = 8;

pub fn encoded_len(fields: &RadiotapFields) -> Result<usize, EncodeError> {
    let mut offset = HEADER_LENGTH;
    for (present, alignment, size) in layouts(fields) {
        if present {
            offset = advance(offset, alignment, size)?;
        }
    }
    Ok(offset)
}

/// Encode the supported radiotap fields in canonical field order
///
/// # Errors
///
/// Returns [`EncodeError`] when the output is too short or the encoded length
/// cannot be represented by the radiotap header
pub fn encode(fields: &RadiotapFields, output: &mut [u8]) -> Result<usize, EncodeError> {
    let length = encoded_len(fields)?;
    if output.len() < length {
        return Err(EncodeError::OutputTooSmall {
            needed: length,
            available: output.len(),
        });
    }
    let target = output.get_mut(..length).ok_or(EncodeError::InternalRange)?;
    target.fill(0);
    write_array(target, 2, &u16_length(length)?.to_le_bytes())?;
    write_array(target, 4, &presence_mask(fields).to_le_bytes())?;

    let mut writer = FieldWriter::new(target);
    if let Some(value) = fields.tsft() {
        writer.write(8, &value.to_le_bytes())?;
    }
    if let Some(value) = fields.flags() {
        writer.write(1, &[value.raw()])?;
    }
    if let Some(value) = fields.rate_500kbps() {
        writer.write(1, &[value])?;
    }
    if let Some(value) = fields.channel() {
        writer.write_channel(value)?;
    }
    if let Some(value) = fields.signal_dbm() {
        writer.write(1, &value.to_ne_bytes())?;
    }
    if let Some(value) = fields.noise_dbm() {
        writer.write(1, &value.to_ne_bytes())?;
    }
    if let Some(value) = fields.antenna() {
        writer.write(1, &[value])?;
    }
    if let Some(value) = fields.rx_flags() {
        writer.write(2, &value.to_le_bytes())?;
    }
    if let Some(value) = fields.tx_flags() {
        writer.write(2, &value.to_le_bytes())?;
    }
    if let Some(value) = fields.zero_length_psdu() {
        writer.write(1, &[value])?;
    }
    Ok(length)
}

struct FieldWriter<'a> {
    output: &'a mut [u8],
    offset: usize,
}

impl<'a> FieldWriter<'a> {
    const fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            offset: HEADER_LENGTH,
        }
    }

    fn write(&mut self, alignment: usize, bytes: &[u8]) -> Result<(), EncodeError> {
        self.offset = aligned(self.offset, alignment)?;
        write_array(self.output, self.offset, bytes)?;
        self.offset = self
            .offset
            .checked_add(bytes.len())
            .ok_or(EncodeError::LengthOverflow)?;
        Ok(())
    }

    fn write_channel(&mut self, channel: Channel) -> Result<(), EncodeError> {
        let mut bytes = [0_u8; 4];
        write_array(&mut bytes, 0, &channel.frequency_mhz().to_le_bytes())?;
        write_array(&mut bytes, 2, &channel.flags().to_le_bytes())?;
        self.write(2, &bytes)
    }
}

const fn layouts(fields: &RadiotapFields) -> [(bool, usize, usize); 10] {
    [
        (fields.tsft().is_some(), 8, 8),
        (fields.flags().is_some(), 1, 1),
        (fields.rate_500kbps().is_some(), 1, 1),
        (fields.channel().is_some(), 2, 4),
        (fields.signal_dbm().is_some(), 1, 1),
        (fields.noise_dbm().is_some(), 1, 1),
        (fields.antenna().is_some(), 1, 1),
        (fields.rx_flags().is_some(), 2, 2),
        (fields.tx_flags().is_some(), 2, 2),
        (fields.zero_length_psdu().is_some(), 1, 1),
    ]
}

const fn presence_mask(fields: &RadiotapFields) -> u32 {
    let mut mask = 0_u32;
    if fields.tsft().is_some() {
        mask |= 1 << 0;
    }
    if fields.flags().is_some() {
        mask |= 1 << 1;
    }
    if fields.rate_500kbps().is_some() {
        mask |= 1 << 2;
    }
    if fields.channel().is_some() {
        mask |= 1 << 3;
    }
    if fields.signal_dbm().is_some() {
        mask |= 1 << 5;
    }
    if fields.noise_dbm().is_some() {
        mask |= 1 << 6;
    }
    if fields.antenna().is_some() {
        mask |= 1 << 11;
    }
    if fields.rx_flags().is_some() {
        mask |= 1 << 14;
    }
    if fields.tx_flags().is_some() {
        mask |= 1 << 15;
    }
    if fields.zero_length_psdu().is_some() {
        mask |= 1 << 26;
    }
    mask
}

fn advance(offset: usize, alignment: usize, size: usize) -> Result<usize, EncodeError> {
    aligned(offset, alignment)?
        .checked_add(size)
        .ok_or(EncodeError::LengthOverflow)
}

fn aligned(offset: usize, alignment: usize) -> Result<usize, EncodeError> {
    let remainder = offset % alignment;
    let padding = if remainder == 0 {
        0
    } else {
        alignment - remainder
    };
    offset
        .checked_add(padding)
        .ok_or(EncodeError::LengthOverflow)
}

fn u16_length(length: usize) -> Result<u16, EncodeError> {
    u16::try_from(length).map_err(|_| EncodeError::LengthOverflow)
}

fn write_array(output: &mut [u8], offset: usize, bytes: &[u8]) -> Result<(), EncodeError> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or(EncodeError::LengthOverflow)?;
    let target = output
        .get_mut(offset..end)
        .ok_or(EncodeError::InternalRange)?;
    target.copy_from_slice(bytes);
    Ok(())
}
