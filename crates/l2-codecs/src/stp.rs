//! Bounded passive STP, TCN, and RSTP BPDU decoding

use crate::MAX_FRAME_LEN;
use crate::stp_error::{StpContext, StpError};
use crate::stp_model::{
    BridgeId, PortId, StpBpduType, StpFlags, StpFrame, StpLlcHeader, StpTimers, StpVersion,
};

const LLC_HEADER_LEN: usize = 3;
const BPDU_HEADER_LEN: usize = 4;
const CONFIGURATION_BPDU_LEN: usize = 35;
const RSTP_BPDU_LEN: usize = 36;
const STP_PROTOCOL_IDENTIFIER: u16 = 0;
const LLC_DSAP: u8 = 0x42;
const LLC_SSAP: u8 = 0x42;
const LLC_CONTROL: u8 = 0x03;
const STP_VERSION: u8 = 0;
const RSTP_VERSION: u8 = 2;
const CONFIGURATION_TYPE: u8 = 0;
const TCN_TYPE: u8 = 0x80;
const RSTP_TYPE: u8 = 2;

/// Decode a raw or 802.2 LLC-encapsulated STP/RSTP BPDU
///
/// The decoder accepts either the BPDU beginning with its two-byte protocol
/// identifier or the same bytes preceded by the standard three-byte STP LLC
/// header. Configuration, topology-change, and baseline RSTP layouts are
/// represented. MSTP, PVST extensions, and other version-specific extensions
/// remain explicit unsupported input
///
/// # Errors
///
/// Returns [`StpError`] when fixed fields are truncated, a header value is not
/// supported, or a recognized extension falls outside the implemented layout
pub fn decode_stp(input: &[u8]) -> Result<StpFrame<'_>, StpError> {
    if input.len() > MAX_FRAME_LEN {
        return Err(StpError::FrameTooLong {
            length: input.len(),
            max: MAX_FRAME_LEN,
        });
    }

    let (bpdu, llc) = split_llc(input)?;
    if bpdu.len() < BPDU_HEADER_LEN {
        return Err(StpError::Truncated {
            context: StpContext::CommonHeader,
            needed: BPDU_HEADER_LEN,
            available: bpdu.len(),
        });
    }

    let protocol_identifier = read_u16(bpdu, 0, StpContext::CommonHeader)?;
    if protocol_identifier != STP_PROTOCOL_IDENTIFIER {
        return Err(StpError::InvalidProtocolIdentifier {
            value: protocol_identifier,
        });
    }
    let version_id = read_u8(bpdu, 2, StpContext::CommonHeader)?;
    let type_id = read_u8(bpdu, 3, StpContext::CommonHeader)?;

    match (version_id, type_id) {
        (STP_VERSION, CONFIGURATION_TYPE) => decode_configuration(input, bpdu, llc),
        (STP_VERSION, TCN_TYPE) => decode_tcn(input, bpdu, llc),
        (RSTP_VERSION, RSTP_TYPE) => decode_rstp(input, bpdu, llc),
        (STP_VERSION | RSTP_VERSION, _) => Err(StpError::UnsupportedType {
            version: version_id,
            value: type_id,
        }),
        _ => Err(StpError::UnsupportedVersion { value: version_id }),
    }
}

fn split_llc(input: &[u8]) -> Result<(&[u8], Option<StpLlcHeader>), StpError> {
    if input.first().copied() != Some(LLC_DSAP) {
        return Ok((input, None));
    }

    let Some(header) = input.get(..LLC_HEADER_LEN) else {
        return Err(StpError::Truncated {
            context: StpContext::LlcHeader,
            needed: LLC_HEADER_LEN,
            available: input.len(),
        });
    };
    let Some((&dsap, rest)) = header.split_first() else {
        return Err(StpError::Truncated {
            context: StpContext::LlcHeader,
            needed: LLC_HEADER_LEN,
            available: input.len(),
        });
    };
    let Some((&ssap, control_slice)) = rest.split_first() else {
        return Err(StpError::Truncated {
            context: StpContext::LlcHeader,
            needed: LLC_HEADER_LEN,
            available: input.len(),
        });
    };
    let Some(&control) = control_slice.first() else {
        return Err(StpError::Truncated {
            context: StpContext::LlcHeader,
            needed: LLC_HEADER_LEN,
            available: input.len(),
        });
    };
    if (dsap, ssap, control) != (LLC_DSAP, LLC_SSAP, LLC_CONTROL) {
        return Err(StpError::InvalidLlc {
            dsap,
            ssap,
            control,
        });
    }
    Ok((
        input.get(LLC_HEADER_LEN..).unwrap_or_default(),
        Some(StpLlcHeader {
            dsap,
            ssap,
            control,
        }),
    ))
}

fn decode_configuration<'input>(
    input: &'input [u8],
    bpdu: &'input [u8],
    llc: Option<StpLlcHeader>,
) -> Result<StpFrame<'input>, StpError> {
    let fields = parse_tree_fields(bpdu, CONFIGURATION_BPDU_LEN)?;
    Ok(StpFrame {
        raw: fields.raw,
        wire: input,
        llc,
        protocol_identifier: STP_PROTOCOL_IDENTIFIER,
        version: StpVersion::Stp,
        version_id: STP_VERSION,
        bpdu_type: StpBpduType::Configuration,
        type_id: CONFIGURATION_TYPE,
        flags: fields.flags,
        root: Some(fields.root),
        cost: Some(fields.cost),
        bridge: Some(fields.bridge),
        port: Some(fields.port),
        timers: Some(fields.timers),
        version_1_length: None,
        padding: fields.padding,
    })
}

fn decode_tcn<'input>(
    input: &'input [u8],
    bpdu: &'input [u8],
    llc: Option<StpLlcHeader>,
) -> Result<StpFrame<'input>, StpError> {
    let raw = take(bpdu, 0, BPDU_HEADER_LEN, StpContext::CommonHeader)?;
    Ok(StpFrame {
        raw,
        wire: input,
        llc,
        protocol_identifier: STP_PROTOCOL_IDENTIFIER,
        version: StpVersion::Stp,
        version_id: STP_VERSION,
        bpdu_type: StpBpduType::TopologyChange,
        type_id: TCN_TYPE,
        flags: StpFlags::from_wire(0),
        root: None,
        cost: None,
        bridge: None,
        port: None,
        timers: None,
        version_1_length: None,
        padding: bpdu.get(BPDU_HEADER_LEN..).unwrap_or_default(),
    })
}

fn decode_rstp<'input>(
    input: &'input [u8],
    bpdu: &'input [u8],
    llc: Option<StpLlcHeader>,
) -> Result<StpFrame<'input>, StpError> {
    let fields = parse_tree_fields(bpdu, RSTP_BPDU_LEN)?;
    let version_1_length = *take(bpdu, 35, 1, StpContext::RapidExtension)?
        .first()
        .ok_or(StpError::Truncated {
            context: StpContext::RapidExtension,
            needed: RSTP_BPDU_LEN,
            available: bpdu.len(),
        })?;
    if version_1_length != 0 {
        return Err(StpError::UnsupportedExtension {
            version: RSTP_VERSION,
            length: version_1_length,
        });
    }

    Ok(StpFrame {
        raw: fields.raw,
        wire: input,
        llc,
        protocol_identifier: STP_PROTOCOL_IDENTIFIER,
        version: StpVersion::Rstp,
        version_id: RSTP_VERSION,
        bpdu_type: StpBpduType::Rapid,
        type_id: RSTP_TYPE,
        flags: fields.flags,
        root: Some(fields.root),
        cost: Some(fields.cost),
        bridge: Some(fields.bridge),
        port: Some(fields.port),
        timers: Some(fields.timers),
        version_1_length: Some(version_1_length),
        padding: bpdu.get(RSTP_BPDU_LEN..).unwrap_or_default(),
    })
}

struct TreeFields<'input> {
    raw: &'input [u8],
    flags: StpFlags,
    root: BridgeId,
    cost: u32,
    bridge: BridgeId,
    port: PortId,
    timers: StpTimers,
    padding: &'input [u8],
}

fn parse_tree_fields(bpdu: &[u8], required_len: usize) -> Result<TreeFields<'_>, StpError> {
    // Read each field independently so truncation diagnostics identify the
    // first missing field instead of hiding it behind the total body length
    let flags = StpFlags::from_wire(read_u8(bpdu, 4, StpContext::ConfigurationBody)?);
    let root = read_bridge_id(bpdu, 5)?;
    let cost = read_u32(bpdu, 13, StpContext::ConfigurationBody)?;
    let bridge = read_bridge_id(bpdu, 17)?;
    let port = PortId::from_wire(read_u16(bpdu, 25, StpContext::ConfigurationBody)?);
    let timers = StpTimers {
        message_age: read_u16(bpdu, 27, StpContext::ConfigurationBody)?,
        max_age: read_u16(bpdu, 29, StpContext::ConfigurationBody)?,
        hello_time: read_u16(bpdu, 31, StpContext::ConfigurationBody)?,
        forward_delay: read_u16(bpdu, 33, StpContext::ConfigurationBody)?,
    };
    // The field reads above establish that the recognized layout is present
    let raw = take(bpdu, 0, required_len, StpContext::ConfigurationBody)?;
    Ok(TreeFields {
        raw,
        flags,
        root,
        cost,
        bridge,
        port,
        timers,
        padding: bpdu.get(required_len..).unwrap_or_default(),
    })
}

fn read_bridge_id(input: &[u8], offset: usize) -> Result<BridgeId, StpError> {
    let [p0, p1, m0, m1, m2, m3, m4, m5] =
        take_fixed::<8>(input, offset, StpContext::ConfigurationBody)?;
    Ok(BridgeId::from_wire(
        u16::from_be_bytes([p0, p1]),
        [m0, m1, m2, m3, m4, m5],
    ))
}

fn read_u8(input: &[u8], offset: usize, context: StpContext) -> Result<u8, StpError> {
    let [value] = take_fixed::<1>(input, offset, context)?;
    Ok(value)
}

fn read_u16(input: &[u8], offset: usize, context: StpContext) -> Result<u16, StpError> {
    let [first, second] = take_fixed::<2>(input, offset, context)?;
    Ok(u16::from_be_bytes([first, second]))
}

fn read_u32(input: &[u8], offset: usize, context: StpContext) -> Result<u32, StpError> {
    let [a, b, c, d] = take_fixed::<4>(input, offset, context)?;
    Ok(u32::from_be_bytes([a, b, c, d]))
}

fn take_fixed<const LENGTH: usize>(
    input: &[u8],
    offset: usize,
    context: StpContext,
) -> Result<[u8; LENGTH], StpError> {
    let end = offset.checked_add(LENGTH).ok_or(StpError::Truncated {
        context,
        needed: usize::MAX,
        available: input.len(),
    })?;
    let Some(bytes) = input.get(offset..end) else {
        return Err(StpError::Truncated {
            context,
            needed: end,
            available: input.len(),
        });
    };
    <[u8; LENGTH]>::try_from(bytes).map_err(|_| StpError::Truncated {
        context,
        needed: end,
        available: input.len(),
    })
}

fn take(
    input: &[u8],
    offset: usize,
    length: usize,
    context: StpContext,
) -> Result<&[u8], StpError> {
    let end = offset.checked_add(length).ok_or(StpError::Truncated {
        context,
        needed: usize::MAX,
        available: input.len(),
    })?;
    input.get(offset..end).ok_or(StpError::Truncated {
        context,
        needed: end,
        available: input.len(),
    })
}
