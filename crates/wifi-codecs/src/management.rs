use crate::{
    ActionBody, AssociationRequestBody, AssociationResponseBody, AuthenticationBody, BeaconBody,
    ElementsBody, ManagementBody, ManagementError, ManagementFrame, ReasonBody,
    ReassociationRequestBody, element::parse_elements,
};
use wifi_core::{FrameKind, MacAddress, ManagementSubtype, WifiFrame};

/// Decode the body of one unprotected management frame
///
/// # Errors
///
/// Returns [`ManagementError`] when the frame is not an unprotected management
/// frame or its fixed fields or information elements are malformed
pub fn parse_management<'a>(frame: &WifiFrame<'a>) -> Result<ManagementFrame<'a>, ManagementError> {
    let FrameKind::Management(subtype) = frame.kind() else {
        return Err(ManagementError::NotManagement);
    };
    if frame.control().protected() {
        return Err(ManagementError::ProtectedBody);
    }
    let bytes = frame.body();
    let body = match subtype {
        ManagementSubtype::Beacon => ManagementBody::Beacon(parse_beacon(bytes)?),
        ManagementSubtype::ProbeResponse => ManagementBody::ProbeResponse(parse_beacon(bytes)?),
        ManagementSubtype::ProbeRequest => {
            ManagementBody::ProbeRequest(ElementsBody::new(parse_elements(bytes)?))
        }
        ManagementSubtype::AssociationRequest => {
            ManagementBody::AssociationRequest(parse_association_request(bytes)?)
        }
        ManagementSubtype::AssociationResponse => {
            ManagementBody::AssociationResponse(parse_association_response(bytes)?)
        }
        ManagementSubtype::ReassociationRequest => {
            ManagementBody::ReassociationRequest(parse_reassociation_request(bytes)?)
        }
        ManagementSubtype::ReassociationResponse => {
            ManagementBody::ReassociationResponse(parse_association_response(bytes)?)
        }
        ManagementSubtype::Authentication => {
            ManagementBody::Authentication(parse_authentication(bytes)?)
        }
        ManagementSubtype::Disassociation => ManagementBody::Disassociation(parse_reason(bytes)?),
        ManagementSubtype::Deauthentication => {
            ManagementBody::Deauthentication(parse_reason(bytes)?)
        }
        ManagementSubtype::Action => ManagementBody::Action(parse_action(bytes)?),
        ManagementSubtype::Other(_) => ManagementBody::Other(bytes),
    };
    Ok(ManagementFrame::new(subtype, body))
}

fn parse_beacon(bytes: &[u8]) -> Result<BeaconBody<'_>, ManagementError> {
    require(bytes, 12, "beacon fixed fields")?;
    Ok(BeaconBody::new(
        read_u64(bytes, 0, "beacon timestamp")?,
        read_u16(bytes, 8, "beacon interval")?,
        read_u16(bytes, 10, "beacon capability")?,
        parse_elements(tail(bytes, 12, "beacon elements")?)?,
    ))
}

fn parse_association_request(bytes: &[u8]) -> Result<AssociationRequestBody<'_>, ManagementError> {
    require(bytes, 4, "association request")?;
    Ok(AssociationRequestBody {
        capability: read_u16(bytes, 0, "association capability")?,
        listen_interval: read_u16(bytes, 2, "association listen interval")?,
        elements: parse_elements(tail(bytes, 4, "association elements")?)?,
    })
}

fn parse_association_response(
    bytes: &[u8],
) -> Result<AssociationResponseBody<'_>, ManagementError> {
    require(bytes, 6, "association response")?;
    Ok(AssociationResponseBody {
        capability: read_u16(bytes, 0, "association capability")?,
        status: read_u16(bytes, 2, "association status")?,
        association_id: read_u16(bytes, 4, "association ID")?,
        elements: parse_elements(tail(bytes, 6, "association elements")?)?,
    })
}

fn parse_reassociation_request(
    bytes: &[u8],
) -> Result<ReassociationRequestBody<'_>, ManagementError> {
    require(bytes, 10, "reassociation request")?;
    Ok(ReassociationRequestBody {
        capability: read_u16(bytes, 0, "reassociation capability")?,
        listen_interval: read_u16(bytes, 2, "reassociation listen interval")?,
        current_access_point: read_mac(bytes, 4, "current access point")?,
        elements: parse_elements(tail(bytes, 10, "reassociation elements")?)?,
    })
}

fn parse_authentication(bytes: &[u8]) -> Result<AuthenticationBody<'_>, ManagementError> {
    require(bytes, 6, "authentication")?;
    Ok(AuthenticationBody {
        algorithm: read_u16(bytes, 0, "authentication algorithm")?,
        sequence: read_u16(bytes, 2, "authentication sequence")?,
        status: read_u16(bytes, 4, "authentication status")?,
        elements: parse_elements(tail(bytes, 6, "authentication elements")?)?,
    })
}

fn parse_reason(bytes: &[u8]) -> Result<ReasonBody<'_>, ManagementError> {
    require(bytes, 2, "reason code")?;
    Ok(ReasonBody {
        reason: read_u16(bytes, 0, "reason code")?,
        trailing: tail(bytes, 2, "reason trailing bytes")?,
    })
}

fn parse_action(bytes: &[u8]) -> Result<ActionBody<'_>, ManagementError> {
    require(bytes, 2, "action header")?;
    Ok(ActionBody {
        category: read_byte(bytes, 0, "action category")?,
        action: read_byte(bytes, 1, "action code")?,
        payload: tail(bytes, 2, "action payload")?,
    })
}

const fn require(
    bytes: &[u8],
    needed: usize,
    context: &'static str,
) -> Result<(), ManagementError> {
    if bytes.len() < needed {
        return Err(ManagementError::truncated_body(
            context,
            needed,
            bytes.len(),
        ));
    }
    Ok(())
}

fn tail<'a>(
    bytes: &'a [u8],
    offset: usize,
    context: &'static str,
) -> Result<&'a [u8], ManagementError> {
    bytes
        .get(offset..)
        .ok_or_else(|| ManagementError::truncated_body(context, offset, bytes.len()))
}

fn read_byte(bytes: &[u8], offset: usize, context: &'static str) -> Result<u8, ManagementError> {
    bytes
        .get(offset)
        .copied()
        .ok_or_else(|| ManagementError::truncated_body(context, offset + 1, bytes.len()))
}

fn read_u16(bytes: &[u8], offset: usize, context: &'static str) -> Result<u16, ManagementError> {
    let value: [u8; 2] = read_array(bytes, offset, context)?;
    Ok(u16::from_le_bytes(value))
}

fn read_u64(bytes: &[u8], offset: usize, context: &'static str) -> Result<u64, ManagementError> {
    let value: [u8; 8] = read_array(bytes, offset, context)?;
    Ok(u64::from_le_bytes(value))
}

fn read_mac(
    bytes: &[u8],
    offset: usize,
    context: &'static str,
) -> Result<MacAddress, ManagementError> {
    let value: [u8; 6] = read_array(bytes, offset, context)?;
    Ok(MacAddress::new(value))
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
    context: &'static str,
) -> Result<[u8; N], ManagementError> {
    let end = offset
        .checked_add(N)
        .ok_or(ManagementError::LengthOverflow)?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| ManagementError::truncated_body(context, end, bytes.len()))?;
    value
        .try_into()
        .map_err(|_| ManagementError::LengthOverflow)
}
