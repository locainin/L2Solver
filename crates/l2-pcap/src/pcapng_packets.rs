//! Packet-block decoding for the bounded PCAPNG reader.

use l2_capture::{
    CaptureLocator, CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus,
    FrameError, MAX_FRAME_LENGTH, TimestampSource,
};

use crate::{
    Error,
    header::{ByteOrder, decode_u32},
    pcapng_blocks::{
        BLOCK_TRAILER_LENGTH, ENHANCED_PACKET_BLOCK, ENHANCED_PACKET_MIN_LENGTH, PACKET_BLOCK,
        PACKET_BLOCK_MIN_LENGTH, SIMPLE_PACKET_BLOCK, SIMPLE_PACKET_MIN_LENGTH, read_u16, read_u32,
    },
    pcapng_model::{InterfaceDescription, PcapNgOption},
    pcapng_options::{OptionScope, parse_options},
};

const PACKET_DATA_START: usize = 28;

#[derive(Clone, Copy)]
struct PacketFields {
    block_type: u32,
    timestamp_ticks: u64,
    captured_length: u32,
    original_length: u32,
}

pub struct DecodedPacketBlock {
    pub frame: CapturedFrame,
    pub drops_count: u16,
}

/// Decode one Enhanced Packet Block against the interfaces in the active section.
pub fn decode_enhanced_packet(
    bytes: &[u8],
    order: ByteOrder,
    section: u32,
    interfaces: &[InterfaceDescription],
    block_offset: u64,
) -> Result<CapturedFrame, Error> {
    if bytes.len() < ENHANCED_PACKET_MIN_LENGTH {
        return Err(Error::InvalidBlockLength {
            block_type: ENHANCED_PACKET_BLOCK,
            length: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        });
    }
    let interface_index = read_u32(bytes, 8, order)?;
    let interface = interface(interfaces, section, interface_index)?;
    let timestamp_high = read_u32(bytes, 12, order)?;
    let timestamp_low = read_u32(bytes, 16, order)?;
    // The two fields are ordered high-word then low-word in both byte orders
    let timestamp_ticks = (u64::from(timestamp_high) << 32) + u64::from(timestamp_low);
    let captured_length = read_u32(bytes, 20, order)?;
    let original_length = read_u32(bytes, 24, order)?;
    decode_packet(
        bytes,
        order,
        interface,
        block_offset,
        PacketFields {
            block_type: ENHANCED_PACKET_BLOCK,
            timestamp_ticks,
            captured_length,
            original_length,
        },
    )
}

/// Decode one obsolete Packet Block using the active section's interface table.
pub fn decode_packet_block(
    bytes: &[u8],
    order: ByteOrder,
    section: u32,
    interfaces: &[InterfaceDescription],
    block_offset: u64,
) -> Result<DecodedPacketBlock, Error> {
    if bytes.len() < PACKET_BLOCK_MIN_LENGTH {
        return Err(invalid_packet_length(PACKET_BLOCK, bytes));
    }
    let interface_index = u32::from(read_u16(bytes, 8, order)?);
    let drops_count = read_u16(bytes, 10, order)?;
    let interface = interface(interfaces, section, interface_index)?;
    let timestamp_high = read_u32(bytes, 12, order)?;
    let timestamp_low = read_u32(bytes, 16, order)?;
    // The timestamp uses the same high-word then low-word encoding as an EPB
    let timestamp_ticks = (u64::from(timestamp_high) << 32) + u64::from(timestamp_low);
    let captured_length = read_u32(bytes, 20, order)?;
    let original_length = read_u32(bytes, 24, order)?;
    let frame = decode_packet(
        bytes,
        order,
        interface,
        block_offset,
        PacketFields {
            block_type: PACKET_BLOCK,
            timestamp_ticks,
            captured_length,
            original_length,
        },
    )?;
    Ok(DecodedPacketBlock { frame, drops_count })
}

fn interface(
    interfaces: &[InterfaceDescription],
    section: u32,
    interface_index: u32,
) -> Result<&InterfaceDescription, Error> {
    interfaces
        .get(
            usize::try_from(interface_index).map_err(|_| Error::UnknownInterface {
                section,
                index: interface_index,
            })?,
        )
        .ok_or(Error::UnknownInterface {
            section,
            index: interface_index,
        })
}

fn decode_packet(
    bytes: &[u8],
    order: ByteOrder,
    interface: &InterfaceDescription,
    block_offset: u64,
    packet: PacketFields,
) -> Result<CapturedFrame, Error> {
    validate_packet_lengths(
        packet.captured_length,
        packet.original_length,
        interface.snaplen,
    )?;
    let captured_length =
        usize::try_from(packet.captured_length).map_err(|_| Error::LengthOverflow {
            length: packet.captured_length,
        })?;
    let (data_end, body_end) = packet_bounds(packet.block_type, bytes, captured_length)?;
    let option_scope = if packet.block_type == PACKET_BLOCK {
        OptionScope::PacketBlock
    } else {
        OptionScope::EnhancedPacket
    };
    let options = parse_options(
        packet.block_type,
        bytes
            .get(data_end..body_end)
            .ok_or(Error::InvalidHeaderLayout)?,
        option_scope,
        order,
    )?;
    let (direction, fcs) = packet_flags(&options, interface, order)?;
    let packet_bytes = bytes
        .get(PACKET_DATA_START..PACKET_DATA_START + captured_length)
        .ok_or(Error::InvalidHeaderLayout)?
        .to_vec();
    let timestamp = CaptureTimestamp::new(
        packet.timestamp_ticks,
        interface.timestamp_resolution,
        interface.timestamp_offset_seconds,
        TimestampSource::CaptureFile,
    );
    let metadata = CaptureMetadata::new(
        interface.id,
        packet.original_length,
        Some(CaptureLocator::PcapNg {
            block_offset,
            data_offset: block_offset
                .checked_add(
                    u64::try_from(PACKET_DATA_START).map_err(|_| Error::InvalidHeaderLayout)?,
                )
                .ok_or(Error::InvalidHeaderLayout)?,
            block_type: packet.block_type,
        }),
        Some(timestamp),
        direction,
        None,
        fcs,
    )
    .with_link_type(interface.link_type);
    let metadata = match interface.linux_interface() {
        Some(identity) => metadata.with_linux_interface(identity),
        None => metadata,
    };
    CapturedFrame::new(packet_bytes, metadata).map_err(Error::from)
}

fn packet_bounds(
    block_type: u32,
    bytes: &[u8],
    captured_length: usize,
) -> Result<(usize, usize), Error> {
    let data_end = PACKET_DATA_START
        .checked_add(padded_length(captured_length)?)
        .ok_or_else(|| invalid_packet_length(block_type, bytes))?;
    let body_end = bytes
        .len()
        .checked_sub(BLOCK_TRAILER_LENGTH)
        .ok_or_else(|| invalid_packet_length(block_type, bytes))?;
    if data_end > body_end {
        return Err(invalid_packet_length(block_type, bytes));
    }
    // Alignment bytes are bounded independently from the captured frame
    let unpadded_end = PACKET_DATA_START
        .checked_add(captured_length)
        .ok_or(Error::InvalidHeaderLayout)?;
    let _frame_padding = bytes
        .get(unpadded_end..data_end)
        .ok_or(Error::InvalidHeaderLayout)?;
    Ok((data_end, body_end))
}

fn invalid_packet_length(block_type: u32, bytes: &[u8]) -> Error {
    Error::InvalidBlockLength {
        block_type,
        length: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
    }
}

/// Decode one Simple Packet Block using its section's implicit interface.
pub fn decode_simple_packet(
    bytes: &[u8],
    order: ByteOrder,
    interfaces: &[InterfaceDescription],
    block_offset: u64,
) -> Result<CapturedFrame, Error> {
    if bytes.len() < SIMPLE_PACKET_MIN_LENGTH {
        return Err(Error::InvalidBlockLength {
            block_type: SIMPLE_PACKET_BLOCK,
            length: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        });
    }
    let Some(interface) = interfaces.first() else {
        return Err(Error::SimplePacketWithoutInterface);
    };
    let original_length = read_u32(bytes, 8, order)?;
    let captured_length = if interface.snaplen == 0 {
        original_length
    } else {
        original_length.min(interface.snaplen)
    };
    validate_packet_lengths(captured_length, original_length, interface.snaplen)?;
    let captured_length = usize::try_from(captured_length).map_err(|_| Error::LengthOverflow {
        length: captured_length,
    })?;
    let padded_length = padded_length(captured_length)?;
    let data_start: usize = 12;
    let data_end =
        data_start
            .checked_add(padded_length)
            .ok_or_else(|| Error::InvalidBlockLength {
                block_type: SIMPLE_PACKET_BLOCK,
                length: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            })?;
    let body_end = bytes
        .len()
        .checked_sub(BLOCK_TRAILER_LENGTH)
        .ok_or_else(|| Error::InvalidBlockLength {
            block_type: SIMPLE_PACKET_BLOCK,
            length: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        })?;
    if data_end != body_end {
        return Err(Error::InvalidBlockLength {
            block_type: SIMPLE_PACKET_BLOCK,
            length: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        });
    }
    // Simple packet alignment bytes are not part of the captured frame
    let _frame_padding = bytes
        .get(data_start + captured_length..data_end)
        .ok_or(Error::InvalidHeaderLayout)?;
    let packet_bytes = bytes
        .get(data_start..data_start + captured_length)
        .ok_or(Error::InvalidHeaderLayout)?
        .to_vec();
    let metadata = CaptureMetadata::new(
        interface.id,
        original_length,
        Some(CaptureLocator::PcapNg {
            block_offset,
            data_offset: block_offset
                .checked_add(u64::try_from(data_start).map_err(|_| Error::InvalidHeaderLayout)?)
                .ok_or(Error::InvalidHeaderLayout)?,
            block_type: SIMPLE_PACKET_BLOCK,
        }),
        None,
        Direction::Unknown,
        None,
        interface.fcs_status().map_err(Error::from)?,
    )
    .with_link_type(interface.link_type);
    let metadata = match interface.linux_interface() {
        Some(identity) => metadata.with_linux_interface(identity),
        None => metadata,
    };
    CapturedFrame::new(packet_bytes, metadata).map_err(Error::from)
}

fn validate_packet_lengths(
    captured_length: u32,
    original_length: u32,
    snaplen: u32,
) -> Result<(), Error> {
    if captured_length > u32::try_from(MAX_FRAME_LENGTH).unwrap_or(u32::MAX) {
        return Err(Error::Frame(FrameError::FrameTooLong {
            length: usize::try_from(captured_length).unwrap_or(usize::MAX),
            max: MAX_FRAME_LENGTH,
        }));
    }
    if snaplen != 0 && captured_length > snaplen {
        return Err(Error::InvalidCapturedLength {
            captured: captured_length,
            snaplen,
        });
    }
    if original_length < captured_length {
        return Err(Error::InvalidOriginalLength {
            captured: captured_length,
            original: original_length,
        });
    }
    Ok(())
}

fn packet_flags(
    options: &[PcapNgOption],
    interface: &InterfaceDescription,
    order: ByteOrder,
) -> Result<(Direction, FcsStatus), Error> {
    let mut direction = Direction::Unknown;
    let mut fcs = interface.fcs_status().map_err(Error::from)?;
    for option in options {
        if option.code != 2 {
            continue;
        }
        let value: [u8; 4] = option
            .value
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidHeaderLayout)?;
        let flags = decode_u32(value, order);
        if flags & 0x0000_f000 != 0 {
            return Err(Error::InvalidPacketFlags { flags });
        }
        direction = match flags & 0x03 {
            0 => Direction::Unknown,
            1 => Direction::Inbound,
            2 => Direction::Outbound,
            _ => return Err(Error::InvalidPacketFlags { flags }),
        };
        let fcs_length =
            u8::try_from((flags >> 5) & 0x0f).map_err(|_| Error::InvalidPacketFlags { flags })?;
        // An EPB flags option is an explicit per-packet override. A zero
        // length means that packet FCS information is unavailable, so it
        // must not inherit an interface declaration. With no option, the
        // inherited interface value remains unchanged.
        fcs = if fcs_length == 0 {
            FcsStatus::Unknown
        } else {
            FcsStatus::present(fcs_length).map_err(Error::from)?
        };
    }
    Ok((direction, fcs))
}

fn padded_length(length: usize) -> Result<usize, Error> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(|| Error::LengthOverflow {
            length: u32::try_from(length).unwrap_or(u32::MAX),
        })
}
