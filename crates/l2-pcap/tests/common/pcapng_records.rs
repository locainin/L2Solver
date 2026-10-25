// Minimal wire records keep limit tests independent of option and metadata fixtures
#[derive(Clone, Copy)]
pub enum ByteOrder {
    Little,
    Big,
}

pub fn put_u16(output: &mut Vec<u8>, value: u16, order: ByteOrder) {
    let bytes = match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    output.extend_from_slice(&bytes);
}

pub fn put_u32(output: &mut Vec<u8>, value: u32, order: ByteOrder) {
    let bytes = match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    output.extend_from_slice(&bytes);
}

pub fn put_u64(output: &mut Vec<u8>, value: u64, order: ByteOrder) {
    let bytes = match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    output.extend_from_slice(&bytes);
}

#[must_use]
pub fn section_header_without_options(order: ByteOrder, section_length: i64) -> Vec<u8> {
    let mut body = Vec::new();
    put_u32(&mut body, 0x1a2b_3c4d, order);
    put_u16(&mut body, 1, order);
    put_u16(&mut body, 0, order);
    put_u64(
        &mut body,
        u64::from_ne_bytes(section_length.to_ne_bytes()),
        order,
    );
    block(order, 0x0a0d_0d0a, &body)
}

#[must_use]
pub fn interface_without_options(order: ByteOrder, snaplen: u32) -> Vec<u8> {
    let mut body = Vec::new();
    put_u16(&mut body, 1, order);
    put_u16(&mut body, 0, order);
    put_u32(&mut body, snaplen, order);
    block(order, 1, &body)
}

#[must_use]
pub fn enhanced_packet_without_options(
    order: ByteOrder,
    interface_id: u32,
    timestamp: u64,
    bytes: &[u8],
    original_len: u32,
) -> Vec<u8> {
    let padding = (4 - bytes.len() % 4) % 4;
    let mut body = Vec::new();
    put_u32(&mut body, interface_id, order);
    let timestamp_high = u32::try_from(timestamp >> 32).unwrap_or_default();
    put_u32(&mut body, timestamp_high, order);
    let timestamp_low = u32::try_from(timestamp & u64::from(u32::MAX)).unwrap_or_default();
    put_u32(&mut body, timestamp_low, order);
    put_u32(
        &mut body,
        u32::try_from(bytes.len()).unwrap_or_default(),
        order,
    );
    put_u32(&mut body, original_len, order);
    body.extend_from_slice(bytes);
    // Packet alignment belongs to the block body even when no options follow
    body.resize(body.len() + padding, 0);
    block(order, 6, &body)
}

#[must_use]
pub fn block(order: ByteOrder, block_type: u32, body: &[u8]) -> Vec<u8> {
    let total = u32::try_from(body.len() + 12).unwrap_or_default();
    let mut output = Vec::with_capacity(usize::try_from(total).unwrap_or_default());
    put_u32(&mut output, block_type, order);
    put_u32(&mut output, total, order);
    output.extend_from_slice(body);
    put_u32(&mut output, total, order);
    output
}
