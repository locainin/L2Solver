#[path = "pcapng_records.rs"]
mod records;

pub use records::{
    ByteOrder, block, enhanced_packet_without_options, interface_without_options,
    section_header_without_options,
};
use records::{put_u16, put_u32, put_u64};

use l2_capture::CapturedFrame;
use l2_pcap::{Error, PcapNgReader};
use std::io::Read;

#[must_use]
pub fn option(order: ByteOrder, code: u16, value: &[u8]) -> Vec<u8> {
    let padding = (4 - value.len() % 4) % 4;
    let mut output = Vec::with_capacity(4 + value.len() + padding);
    put_u16(&mut output, code, order);
    put_u16(
        &mut output,
        u16::try_from(value.len()).unwrap_or_default(),
        order,
    );
    output.extend_from_slice(value);
    output.resize(output.len() + padding, 0);
    output
}

#[must_use]
pub fn options(order: ByteOrder, values: &[(u16, &[u8])]) -> Vec<u8> {
    let mut output = Vec::new();
    for (code, value) in values {
        output.extend_from_slice(&option(order, *code, value));
    }
    output.extend_from_slice(&option(order, 0, &[]));
    output
}

#[must_use]
pub fn section_header(order: ByteOrder, section_length: i64) -> Vec<u8> {
    section_header_with_options(order, section_length, &[])
}

#[must_use]
pub fn section_header_with_options(
    order: ByteOrder,
    section_length: i64,
    values: &[(u16, &[u8])],
) -> Vec<u8> {
    let mut body = Vec::new();
    put_u32(&mut body, 0x1a2b_3c4d, order);
    put_u16(&mut body, 1, order);
    put_u16(&mut body, 0, order);
    put_u64(
        &mut body,
        u64::from_ne_bytes(section_length.to_ne_bytes()),
        order,
    );
    body.extend_from_slice(&options(order, values));
    block(order, 0x0a0d_0d0a, &body)
}

#[must_use]
pub fn interface(order: ByteOrder, snaplen: u32, values: &[(u16, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    put_u16(&mut body, 1, order);
    put_u16(&mut body, 0, order);
    put_u32(&mut body, snaplen, order);
    body.extend_from_slice(&options(order, values));
    block(order, 1, &body)
}

#[must_use]
pub fn enhanced_packet(
    order: ByteOrder,
    interface_id: u32,
    timestamp: u64,
    bytes: &[u8],
    original_len: u32,
    values: &[(u16, &[u8])],
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
    body.resize(body.len() + padding, 0);
    body.extend_from_slice(&options(order, values));
    block(order, 6, &body)
}

#[must_use]
pub fn packet_block(
    order: ByteOrder,
    interface_id: u16,
    drops_count: u16,
    timestamp: u64,
    bytes: &[u8],
    original_len: u32,
    values: &[(u16, &[u8])],
) -> Vec<u8> {
    let padding = (4 - bytes.len() % 4) % 4;
    let mut body = Vec::new();
    put_u16(&mut body, interface_id, order);
    put_u16(&mut body, drops_count, order);
    put_u32(
        &mut body,
        u32::try_from(timestamp >> 32).unwrap_or_default(),
        order,
    );
    put_u32(
        &mut body,
        u32::try_from(timestamp & u64::from(u32::MAX)).unwrap_or_default(),
        order,
    );
    put_u32(
        &mut body,
        u32::try_from(bytes.len()).unwrap_or_default(),
        order,
    );
    put_u32(&mut body, original_len, order);
    body.extend_from_slice(bytes);
    body.resize(body.len() + padding, 0);
    body.extend_from_slice(&options(order, values));
    block(order, 2, &body)
}

#[must_use]
pub fn packet_block_without_options(
    order: ByteOrder,
    interface_id: u16,
    drops_count: u16,
    timestamp: u64,
    bytes: &[u8],
    captured_len: u32,
    original_len: u32,
) -> Vec<u8> {
    let padding = (4 - bytes.len() % 4) % 4;
    let mut body = Vec::new();
    put_u16(&mut body, interface_id, order);
    put_u16(&mut body, drops_count, order);
    put_u32(
        &mut body,
        u32::try_from(timestamp >> 32).unwrap_or_default(),
        order,
    );
    put_u32(
        &mut body,
        u32::try_from(timestamp & u64::from(u32::MAX)).unwrap_or_default(),
        order,
    );
    put_u32(&mut body, captured_len, order);
    put_u32(&mut body, original_len, order);
    body.extend_from_slice(bytes);
    body.resize(body.len() + padding, 0);
    block(order, 2, &body)
}

#[must_use]
pub fn simple_packet(order: ByteOrder, bytes: &[u8], original_len: u32) -> Vec<u8> {
    let padding = (4 - bytes.len() % 4) % 4;
    let mut body = Vec::new();
    put_u32(&mut body, original_len, order);
    body.extend_from_slice(bytes);
    body.resize(body.len() + padding, 0);
    block(order, 3, &body)
}

/// Read one frame or return the reader's error
///
/// # Errors
///
/// Returns the underlying PCAPNG reader error, or a terminal error when the
/// capture ends before a packet block
pub fn first_frame(reader: &mut PcapNgReader<impl Read>) -> Result<CapturedFrame, Error> {
    reader.next_packet()?.ok_or(Error::ReaderTerminated)
}
