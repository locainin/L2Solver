use std::io::Read;

// Test builders keep byte-order details beside the cases that exercise them
#[derive(Clone, Copy)]
pub enum ByteOrder {
    Little,
    Big,
}

#[derive(Clone, Copy)]
pub struct CaptureConfig {
    pub order: ByteOrder,
    pub nanoseconds: bool,
    pub snaplen: u32,
    pub network: u32,
}

#[derive(Clone, Copy)]
pub struct PacketConfig<'a> {
    pub seconds: u32,
    pub fraction: u32,
    pub bytes: &'a [u8],
    pub original_len: u32,
}

pub fn push_u16(output: &mut Vec<u8>, value: u16, order: ByteOrder) {
    let bytes = match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    output.extend_from_slice(&bytes);
}

pub fn push_u32(output: &mut Vec<u8>, value: u32, order: ByteOrder) {
    let bytes = match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    output.extend_from_slice(&bytes);
}

#[must_use]
pub fn global_header(order: ByteOrder, nanoseconds: bool, snaplen: u32, network: u32) -> Vec<u8> {
    let magic = match (order, nanoseconds) {
        (ByteOrder::Little, false) => [0xd4, 0xc3, 0xb2, 0xa1],
        (ByteOrder::Big, false) => [0xa1, 0xb2, 0xc3, 0xd4],
        (ByteOrder::Little, true) => [0x4d, 0x3c, 0xb2, 0xa1],
        (ByteOrder::Big, true) => [0xa1, 0xb2, 0x3c, 0x4d],
    };

    let mut output = Vec::with_capacity(24);
    output.extend_from_slice(&magic);
    push_u16(&mut output, 2, order);
    push_u16(&mut output, 4, order);
    // These fields are reserved and must be ignored by a reader
    push_u32(&mut output, 0x1122_3344, order);
    push_u32(&mut output, 0x5566_7788, order);
    push_u32(&mut output, snaplen, order);
    push_u32(&mut output, network, order);
    output
}

#[must_use]
pub fn record_header(
    order: ByteOrder,
    seconds: u32,
    fraction: u32,
    captured_len: u32,
    original_len: u32,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(16);
    push_u32(&mut output, seconds, order);
    push_u32(&mut output, fraction, order);
    push_u32(&mut output, captured_len, order);
    push_u32(&mut output, original_len, order);
    output
}

/// # Panics
///
/// Panics when the fixture payload length does not fit in a 32-bit capture length.
#[must_use]
pub fn one_packet(capture: CaptureConfig, packet: PacketConfig<'_>) -> Vec<u8> {
    let CaptureConfig {
        order,
        nanoseconds,
        snaplen,
        network,
    } = capture;
    let PacketConfig {
        seconds,
        fraction,
        bytes,
        original_len,
    } = packet;
    assert!(
        u32::try_from(bytes.len()).is_ok(),
        "fixture length must fit in u32"
    );
    let captured_len = u32::try_from(bytes.len()).unwrap_or_default();
    let mut output = global_header(order, nanoseconds, snaplen, network);
    output.extend_from_slice(&record_header(
        order,
        seconds,
        fraction,
        captured_len,
        original_len,
    ));
    output.extend_from_slice(bytes);
    output
}

#[must_use]
pub fn prefix(bytes: &[u8], length: usize) -> &[u8] {
    bytes.get(..length).unwrap_or_default()
}

/// Replaces one equal-length range in a byte fixture.
///
/// # Errors
///
/// Returns an error when the requested range is outside the fixture or its length differs from the replacement.
pub fn replace_bytes(
    bytes: &mut [u8],
    start: usize,
    end: usize,
    replacement: &[u8],
) -> Result<(), &'static str> {
    let destination = bytes
        .get_mut(start..end)
        .ok_or("fixture range is out of bounds")?;
    if destination.len() != replacement.len() {
        return Err("fixture replacement length differs from its range");
    }
    destination.copy_from_slice(replacement);
    Ok(())
}

// Generate the large boundary input without keeping a multi-megabyte fixture
pub struct BoundaryCapture {
    pub position: u64,
    pub total: u64,
    pub full_record_total: u64,
    pub full_region: u64,
    pub final_captured: u32,
}

impl BoundaryCapture {
    #[must_use]
    pub fn new(extra_byte: bool) -> Self {
        let full_record_total = u64::from(l2_pcap::MAX_FRAME_LENGTH) + 16;
        let available = l2_pcap::MAX_INPUT_BYTES - 24;
        let full_records = available / full_record_total;
        let full_region = full_records * full_record_total;
        let final_record_total = available - full_region;
        let final_captured = u32::try_from(final_record_total - 16).unwrap_or_default();
        let extra = u64::from(extra_byte);
        Self {
            position: 0,
            total: l2_pcap::MAX_INPUT_BYTES + extra,
            full_record_total,
            full_region,
            final_captured,
        }
    }

    #[must_use]
    pub fn record_header(captured: u32) -> [u8; 16] {
        let mut header = [0; 16];
        let bytes = captured.to_le_bytes();
        if let Some(destination) = header.get_mut(8..12) {
            destination.copy_from_slice(&bytes);
        }
        if let Some(destination) = header.get_mut(12..16) {
            destination.copy_from_slice(&bytes);
        }
        header
    }

    fn advance(&mut self, count: usize) -> std::io::Result<()> {
        let count =
            u64::try_from(count).map_err(|error| std::io::Error::other(error.to_string()))?;
        self.position = self
            .position
            .checked_add(count)
            .ok_or_else(|| std::io::Error::other("boundary fixture position overflow"))?;
        Ok(())
    }
}

impl Read for BoundaryCapture {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        const GLOBAL: [u8; 24] = [
            0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];

        if buffer.is_empty() {
            return Ok(0);
        }
        let available = self.total.saturating_sub(self.position);
        let requested = u64::try_from(buffer.len())
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let count = usize::try_from(available.min(requested))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        if count == 0 {
            return Ok(0);
        }

        let mut written = 0;
        while written < count {
            // The optional byte is only exposed after the accepted budget
            if self.position >= l2_pcap::MAX_INPUT_BYTES {
                let remaining = count - written;
                if let Some(destination) = buffer.get_mut(written..written + remaining) {
                    destination.fill(0);
                }
                self.advance(remaining)?;
                written += remaining;
                continue;
            }

            if self.position < 24 {
                let offset = usize::try_from(self.position)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                let available = 24 - offset;
                let copy_count = (count - written).min(available);
                let source = GLOBAL
                    .get(offset..offset + copy_count)
                    .ok_or_else(|| std::io::Error::other("global fixture range"))?;
                let destination = buffer
                    .get_mut(written..written + copy_count)
                    .ok_or_else(|| std::io::Error::other("destination fixture range"))?;
                destination.copy_from_slice(source);
                self.advance(copy_count)?;
                written += copy_count;
                continue;
            }

            let relative = self.position - 24;
            let (record_offset, captured) = if relative < self.full_region {
                (relative % self.full_record_total, l2_pcap::MAX_FRAME_LENGTH)
            } else {
                (relative - self.full_region, self.final_captured)
            };
            let record_total = u64::from(captured) + 16;

            if record_offset < 16 {
                let header = Self::record_header(captured);
                let offset = usize::try_from(record_offset)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                let available = 16 - offset;
                let copy_count = (count - written).min(available);
                let source = header
                    .get(offset..offset + copy_count)
                    .ok_or_else(|| std::io::Error::other("record fixture range"))?;
                let destination = buffer
                    .get_mut(written..written + copy_count)
                    .ok_or_else(|| std::io::Error::other("destination fixture range"))?;
                destination.copy_from_slice(source);
                self.advance(copy_count)?;
                written += copy_count;
            } else {
                let available = record_total - record_offset;
                let available = usize::try_from(available)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                let copy_count = (count - written).min(available);
                let destination = buffer
                    .get_mut(written..written + copy_count)
                    .ok_or_else(|| std::io::Error::other("destination fixture range"))?;
                destination.fill(0);
                self.advance(copy_count)?;
                written += copy_count;
            }
        }
        Ok(count)
    }
}
