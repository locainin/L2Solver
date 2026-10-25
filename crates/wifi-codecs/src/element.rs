use crate::{ElementKind, InformationElement, MAX_INFORMATION_ELEMENTS, ManagementError};

pub fn parse_elements(input: &[u8]) -> Result<Vec<InformationElement<'_>>, ManagementError> {
    let mut elements = Vec::new();
    let mut offset = 0_usize;
    while offset < input.len() {
        if elements.len() == MAX_INFORMATION_ELEMENTS {
            return Err(ManagementError::ElementLimit {
                maximum: MAX_INFORMATION_ELEMENTS,
            });
        }
        let id = read_byte(input, offset)?;
        let length_offset = offset
            .checked_add(1)
            .ok_or(ManagementError::LengthOverflow)?;
        let length = usize::from(read_byte(input, length_offset)?);
        let value_offset = offset
            .checked_add(2)
            .ok_or(ManagementError::LengthOverflow)?;
        let end = value_offset
            .checked_add(length)
            .ok_or(ManagementError::LengthOverflow)?;
        let bytes = input
            .get(value_offset..end)
            .ok_or(ManagementError::TruncatedElement {
                offset,
                needed: end,
                available: input.len(),
            })?;
        let kind = classify(id, bytes)?;
        elements.push(InformationElement::new(id, bytes, kind));
        offset = end;
    }
    Ok(elements)
}

fn read_byte(input: &[u8], offset: usize) -> Result<u8, ManagementError> {
    input
        .get(offset)
        .copied()
        .ok_or_else(|| ManagementError::TruncatedElement {
            offset,
            needed: offset.saturating_add(1),
            available: input.len(),
        })
}

fn classify(id: u8, bytes: &[u8]) -> Result<ElementKind, ManagementError> {
    let kind = match id {
        0 => ElementKind::Ssid,
        1 => ElementKind::SupportedRates,
        3 => ElementKind::DsParameter,
        7 => ElementKind::Country,
        11 => ElementKind::BssLoad,
        45 => ElementKind::HtCapabilities,
        48 => ElementKind::Rsn,
        50 => ElementKind::ExtendedSupportedRates,
        52 => ElementKind::NeighborReport,
        54 => ElementKind::MobilityDomain,
        61 => ElementKind::HtOperation,
        127 => ElementKind::ExtendedCapabilities,
        191 => ElementKind::VhtCapabilities,
        192 => ElementKind::VhtOperation,
        221 => vendor_kind(bytes),
        244 => ElementKind::RsnExtension,
        255 => extension_kind(bytes)?,
        other => ElementKind::Unknown(other),
    };
    Ok(kind)
}

fn vendor_kind(bytes: &[u8]) -> ElementKind {
    match bytes.get(..4) {
        Some([0x00, 0x50, 0xf2, 1]) => ElementKind::Wpa,
        Some([0x00, 0x50, 0xf2, 4]) => ElementKind::Wps,
        _ => ElementKind::VendorSpecific,
    }
}

fn extension_kind(bytes: &[u8]) -> Result<ElementKind, ManagementError> {
    let extension = bytes
        .first()
        .copied()
        .ok_or(ManagementError::InvalidElement {
            id: 255,
            reason: "extension ID is missing",
        })?;
    Ok(match extension {
        35 => ElementKind::HeCapabilities,
        36 => ElementKind::HeOperation,
        106 => ElementKind::EhtOperation,
        108 => ElementKind::EhtCapabilities,
        other => ElementKind::Extension(other),
    })
}
