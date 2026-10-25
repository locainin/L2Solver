pub mod common;

use common::pcapng::{ByteOrder, section_header_without_options};
use l2_pcap::{MAX_BLOCK_LENGTH, MAX_INPUT_BYTES, PcapNgReader};
use std::io::{self, Read};

struct ExactBudgetCapture {
    position: u64,
    total: u64,
    section: Vec<u8>,
    full_region: u64,
    final_block_length: u64,
}

impl ExactBudgetCapture {
    fn new() -> Self {
        let section = section_header_without_options(ByteOrder::Little, -1);
        let section_length = u64::try_from(section.len()).unwrap_or(u64::MAX);
        let remaining = MAX_INPUT_BYTES.saturating_sub(section_length);
        let block_length = u64::try_from(MAX_BLOCK_LENGTH).unwrap_or(u64::MAX);
        let full_blocks = remaining / block_length;
        let full_region = full_blocks.saturating_mul(block_length);
        let final_block_length = remaining.saturating_sub(full_region);
        Self {
            position: 0,
            total: MAX_INPUT_BYTES,
            section,
            full_region,
            final_block_length,
        }
    }

    fn block_length_and_offset(&self, position: u64) -> (u64, u64) {
        let section_length = u64::try_from(self.section.len()).unwrap_or(u64::MAX);
        let relative = position.saturating_sub(section_length);
        let full_length = u64::try_from(MAX_BLOCK_LENGTH).unwrap_or(u64::MAX);
        if relative < self.full_region {
            (full_length, relative % full_length)
        } else {
            (self.final_block_length, relative - self.full_region)
        }
    }

    fn write_block_range(
        destination: &mut [u8],
        block_length: u64,
        block_offset: u64,
    ) -> io::Result<()> {
        let length =
            u32::try_from(block_length).map_err(|error| io::Error::other(error.to_string()))?;
        let mut header = [0; 8];
        header[..4].copy_from_slice(&0x8000_0001_u32.to_le_bytes());
        header[4..].copy_from_slice(&length.to_le_bytes());
        let mut written = 0_usize;
        let destination_length = u64::try_from(destination.len())
            .map_err(|error| io::Error::other(error.to_string()))?;
        while u64::try_from(written).unwrap_or(u64::MAX) < destination_length {
            let offset = block_offset + u64::try_from(written).unwrap_or(u64::MAX);
            let Some(destination_tail) = destination.get_mut(written..) else {
                return Err(io::Error::other("PCAPNG budget destination range"));
            };
            let destination_tail_length = u64::try_from(destination_tail.len())
                .map_err(|error| io::Error::other(error.to_string()))?;
            if offset < 8 {
                let count = usize::try_from((8 - offset).min(destination_tail_length))
                    .map_err(|error| io::Error::other(error.to_string()))?;
                let source = header
                    .get(usize::try_from(offset).unwrap_or(usize::MAX)..)
                    .and_then(|value| value.get(..count))
                    .ok_or_else(|| io::Error::other("PCAPNG budget header range"))?;
                let target = destination_tail
                    .get_mut(..count)
                    .ok_or_else(|| io::Error::other("PCAPNG budget target range"))?;
                target.copy_from_slice(source);
                written += count;
            } else if offset < block_length.saturating_sub(4) {
                let count = usize::try_from(
                    (block_length.saturating_sub(4) - offset).min(destination_tail_length),
                )
                .map_err(|error| io::Error::other(error.to_string()))?;
                let target = destination_tail
                    .get_mut(..count)
                    .ok_or_else(|| io::Error::other("PCAPNG budget body range"))?;
                target.fill(0);
                written += count;
            } else {
                let trailer = length.to_le_bytes();
                let count = usize::try_from((block_length - offset).min(destination_tail_length))
                    .map_err(|error| io::Error::other(error.to_string()))?;
                let source = trailer
                    .get(usize::try_from(offset - (block_length - 4)).unwrap_or(usize::MAX)..)
                    .and_then(|value| value.get(..count))
                    .ok_or_else(|| io::Error::other("PCAPNG budget trailer range"))?;
                let target = destination_tail
                    .get_mut(..count)
                    .ok_or_else(|| io::Error::other("PCAPNG budget trailer target range"))?;
                target.copy_from_slice(source);
                written += count;
            }
        }
        Ok(())
    }
}

impl Read for ExactBudgetCapture {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let available = self.total.saturating_sub(self.position);
        let requested =
            u64::try_from(buffer.len()).map_err(|error| io::Error::other(error.to_string()))?;
        let count = usize::try_from(available.min(requested))
            .map_err(|error| io::Error::other(error.to_string()))?;
        if count == 0 {
            return Ok(0);
        }

        let mut written = 0_usize;
        while written < count {
            let section_length = u64::try_from(self.section.len())
                .map_err(|error| io::Error::other(error.to_string()))?;
            if self.position < section_length {
                let source_offset = usize::try_from(self.position)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                let available_section = self.section.len().saturating_sub(source_offset);
                let copy_count = available_section.min(count - written);
                let source = self
                    .section
                    .get(source_offset..source_offset + copy_count)
                    .ok_or_else(|| io::Error::other("PCAPNG budget section range"))?;
                let target = buffer
                    .get_mut(written..written + copy_count)
                    .ok_or_else(|| io::Error::other("PCAPNG budget target range"))?;
                target.copy_from_slice(source);
                self.position += u64::try_from(copy_count)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                written += copy_count;
            } else {
                let (block_length, block_offset) = self.block_length_and_offset(self.position);
                let remaining = usize::try_from(block_length.saturating_sub(block_offset))
                    .map_err(|error| io::Error::other(error.to_string()))?;
                let copy_count = remaining.min(count - written);
                let target = buffer
                    .get_mut(written..written + copy_count)
                    .ok_or_else(|| io::Error::other("PCAPNG budget target range"))?;
                Self::write_block_range(target, block_length, block_offset)?;
                self.position += u64::try_from(copy_count)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                written += copy_count;
            }
        }
        Ok(count)
    }
}

#[test]
fn accepts_exact_input_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = PcapNgReader::new(ExactBudgetCapture::new())?;
    assert!(reader.next_packet()?.is_none());
    assert!(matches!(reader.next_packet(), Ok(None)));
    Ok(())
}
