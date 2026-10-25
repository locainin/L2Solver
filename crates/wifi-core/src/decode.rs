use crate::{
    ControlSubtype, DataSubtype, DecodeError, FrameControl, FrameKind, MacAddress,
    ManagementSubtype, WifiFrame, model::HeaderFields,
};

const FRAME_CONTROL_LENGTH: usize = 2;
const MANAGEMENT_HEADER_LENGTH: usize = 24;
const DATA_HEADER_LENGTH: usize = 24;

/// Decode one raw IEEE 802.11 MAC frame without allocating
///
/// # Errors
///
/// Returns [`DecodeError`] when the frame is truncated, has an unsupported
/// protocol version, or contains a header layout that cannot be represented
pub fn decode(input: &[u8]) -> Result<WifiFrame<'_>, DecodeError> {
    // Frame control is little-endian on the captured wire
    let raw = read_u16(input, 0, "frame control")?;
    let version =
        u8::try_from(raw & 0x0003).map_err(|_| DecodeError::InvalidLayout("protocol version"))?;
    if version != 0 {
        return Err(DecodeError::UnsupportedVersion(version));
    }

    let type_bits =
        u8::try_from((raw >> 2) & 0x0003).map_err(|_| DecodeError::InvalidLayout("frame type"))?;
    let subtype = u8::try_from((raw >> 4) & 0x000f)
        .map_err(|_| DecodeError::InvalidLayout("frame subtype"))?;
    let kind = frame_kind(type_bits, subtype);
    let control = FrameControl::new(raw, kind);

    // Each frame class owns its real header-width rules
    match kind {
        FrameKind::Management(_) => decode_management(input, control),
        FrameKind::Control(control_subtype) => decode_control(input, control, control_subtype),
        FrameKind::Data(data_subtype) => decode_data(input, control, data_subtype),
        FrameKind::Extension(_) => decode_extension(input, control),
    }
}

const fn frame_kind(type_bits: u8, subtype: u8) -> FrameKind {
    match type_bits {
        0 => FrameKind::Management(ManagementSubtype::from_wire(subtype)),
        1 => FrameKind::Control(ControlSubtype::from_wire(subtype)),
        2 => FrameKind::Data(DataSubtype::from_wire_nibble(subtype)),
        _ => FrameKind::Extension(subtype),
    }
}

fn decode_management(input: &[u8], control: FrameControl) -> Result<WifiFrame<'_>, DecodeError> {
    let mut header_length = MANAGEMENT_HEADER_LENGTH;
    let mut fields = three_address_fields(input)?;

    // Ordered management frames may carry an HT control field
    if control.order() {
        fields.ht_control = Some(read_u32(input, header_length, "HT control")?);
        header_length += 4;
    }
    let body = body_from(input, header_length, "management header")?;
    Ok(WifiFrame::new(input, body, control, fields))
}

fn decode_control(
    input: &[u8],
    control: FrameControl,
    subtype: ControlSubtype,
) -> Result<WifiFrame<'_>, DecodeError> {
    // Control subtypes do not share one common MAC header width
    let required = match subtype {
        ControlSubtype::PsPoll
        | ControlSubtype::Rts
        | ControlSubtype::CfEnd
        | ControlSubtype::CfEndCfAck => 16,
        ControlSubtype::Cts | ControlSubtype::Ack | ControlSubtype::Other(_) => 10,
        ControlSubtype::BlockAckRequest => 20,
        ControlSubtype::BlockAck => 28,
    };
    require_length(input, required, "control header")?;

    let receiver = Some(read_mac(input, 4, "control receiver")?);
    // Short ACK and CTS forms carry no transmitter address
    let transmitter = match subtype {
        ControlSubtype::PsPoll
        | ControlSubtype::Rts
        | ControlSubtype::BlockAckRequest
        | ControlSubtype::BlockAck
        | ControlSubtype::CfEnd
        | ControlSubtype::CfEndCfAck => Some(read_mac(input, 10, "control transmitter")?),
        ControlSubtype::Cts | ControlSubtype::Ack | ControlSubtype::Other(_) => None,
    };
    let fields = HeaderFields {
        receiver,
        transmitter,
        ..HeaderFields::default()
    };
    let body = body_from(input, required, "control header")?;
    Ok(WifiFrame::new(input, body, control, fields))
}

fn decode_data(
    input: &[u8],
    control: FrameControl,
    subtype: DataSubtype,
) -> Result<WifiFrame<'_>, DecodeError> {
    let mut fields = three_address_fields(input)?;
    let mut header_length = DATA_HEADER_LENGTH;

    // Wireless distribution links add a fourth address only in both-DS mode
    if control.to_ds() && control.from_ds() {
        fields.address4 = Some(read_mac(input, header_length, "fourth address")?);
        header_length += 6;
    }
    // QoS data extends the header before the body begins
    if subtype.has_qos() {
        fields.qos_control = Some(read_u16(input, header_length, "QoS control")?);
        header_length += 2;
    }
    // Ordered QoS frames place HT control after QoS control
    if subtype.has_qos() && control.order() {
        fields.ht_control = Some(read_u32(input, header_length, "HT control")?);
        header_length += 4;
    }

    let body = body_from(input, header_length, "data header")?;
    Ok(WifiFrame::new(input, body, control, fields))
}

fn decode_extension(input: &[u8], control: FrameControl) -> Result<WifiFrame<'_>, DecodeError> {
    // Extension bodies stay opaque until a bounded subtype codec exists
    let body = body_from(input, 4, "extension header")?;
    Ok(WifiFrame::new(
        input,
        body,
        control,
        HeaderFields::default(),
    ))
}

fn three_address_fields(input: &[u8]) -> Result<HeaderFields, DecodeError> {
    // One length check protects every fixed three-address field below
    require_length(input, MANAGEMENT_HEADER_LENGTH, "three-address header")?;
    Ok(HeaderFields {
        receiver: Some(read_mac(input, 4, "receiver address")?),
        transmitter: Some(read_mac(input, 10, "transmitter address")?),
        address3: Some(read_mac(input, 16, "third address")?),
        sequence_control: Some(read_u16(input, 22, "sequence control")?),
        ..HeaderFields::default()
    })
}

fn body_from<'a>(
    input: &'a [u8],
    offset: usize,
    context: &'static str,
) -> Result<&'a [u8], DecodeError> {
    input
        .get(offset..)
        .ok_or_else(|| DecodeError::truncated(context, offset, input.len()))
}

const fn require_length(
    input: &[u8],
    needed: usize,
    context: &'static str,
) -> Result<(), DecodeError> {
    if input.len() < needed {
        return Err(DecodeError::truncated(context, needed, input.len()));
    }
    Ok(())
}

fn read_u16(input: &[u8], offset: usize, context: &'static str) -> Result<u16, DecodeError> {
    let bytes: [u8; 2] = read_array(input, offset, context)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(input: &[u8], offset: usize, context: &'static str) -> Result<u32, DecodeError> {
    let bytes: [u8; 4] = read_array(input, offset, context)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_mac(input: &[u8], offset: usize, context: &'static str) -> Result<MacAddress, DecodeError> {
    let octets: [u8; 6] = read_array(input, offset, context)?;
    Ok(MacAddress::new(octets))
}

fn read_array<const N: usize>(
    input: &[u8],
    offset: usize,
    context: &'static str,
) -> Result<[u8; N], DecodeError> {
    // Checked addition keeps hostile offsets from wrapping the slice range
    let end = offset
        .checked_add(N)
        .ok_or(DecodeError::InvalidLayout(context))?;
    let bytes = input
        .get(offset..end)
        .ok_or_else(|| DecodeError::truncated(context, end, input.len()))?;
    bytes
        .try_into()
        .map_err(|_| DecodeError::InvalidLayout(context))
}

const _: () = assert!(FRAME_CONTROL_LENGTH == 2);
