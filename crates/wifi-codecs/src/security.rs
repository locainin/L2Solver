use crate::{
    AkmSuite, CipherSuite, ElementKind, InformationElement, MAX_SECURITY_LIST_ENTRIES, PmfMode,
    SecurityError, SecurityProfile, SecurityProtocol,
};

/// Decode a bounded RSN or WPA security element
///
/// # Errors
///
/// Returns [`SecurityError`] when the element has the wrong type, is truncated,
/// exceeds a list budget, or contains an unsupported or invalid security layout
pub fn parse_security(element: &InformationElement<'_>) -> Result<SecurityProfile, SecurityError> {
    // The outer element decides whether WPA vendor bytes need removal
    let (protocol, bytes) = match element.kind() {
        ElementKind::Rsn => (SecurityProtocol::Rsn, element.bytes()),
        ElementKind::Wpa => (
            SecurityProtocol::WpaLegacy,
            element
                .bytes()
                .get(4..)
                .ok_or_else(|| SecurityError::Truncated {
                    context: "WPA vendor prefix",
                    needed: 4,
                    available: element.bytes().len(),
                })?,
        ),
        _ => return Err(SecurityError::WrongElement),
    };
    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u16("security version")?;
    if version != 1 {
        return Err(SecurityError::UnsupportedVersion(version));
    }
    let group_cipher = cipher(cursor.read_suite("group cipher")?);
    let pairwise_ciphers = parse_ciphers(&mut cursor)?;
    let akms = parse_akms(&mut cursor)?;
    let pmf = parse_tail(&mut cursor, protocol)?;
    Ok(SecurityProfile::new(
        protocol,
        group_cipher,
        pairwise_ciphers,
        akms,
        pmf,
    ))
}

fn parse_ciphers(cursor: &mut Cursor<'_>) -> Result<Vec<CipherSuite>, SecurityError> {
    // Validate the count before reserving memory from untrusted input
    let count = list_count(cursor, "pairwise cipher")?;
    let mut suites = Vec::with_capacity(count);
    for _ in 0..count {
        suites.push(cipher(cursor.read_suite("pairwise cipher")?));
    }
    Ok(suites)
}

fn parse_akms(cursor: &mut Cursor<'_>) -> Result<Vec<AkmSuite>, SecurityError> {
    // AKM lists use the same bounded count rule as cipher lists
    let count = list_count(cursor, "AKM")?;
    let mut suites = Vec::with_capacity(count);
    for _ in 0..count {
        suites.push(akm(cursor.read_suite("AKM")?));
    }
    Ok(suites)
}

fn list_count(cursor: &mut Cursor<'_>, context: &'static str) -> Result<usize, SecurityError> {
    let count = usize::from(cursor.read_u16(context)?);
    if count == 0 {
        return Err(SecurityError::EmptySuiteList(context));
    }
    if count > MAX_SECURITY_LIST_ENTRIES {
        return Err(SecurityError::ListLimit {
            context,
            count,
            maximum: MAX_SECURITY_LIST_ENTRIES,
        });
    }
    Ok(count)
}

fn parse_tail(
    cursor: &mut Cursor<'_>,
    protocol: SecurityProtocol,
) -> Result<PmfMode, SecurityError> {
    if protocol == SecurityProtocol::WpaLegacy {
        // WPA may append one two-byte capabilities field after its AKM list
        if cursor.remaining() == 2 {
            let _ = cursor.read_u16("WPA capabilities")?;
        }
        ensure_empty(cursor)?;
        return Ok(PmfMode::Disabled);
    }
    if cursor.remaining() == 0 {
        return Ok(PmfMode::Disabled);
    }
    let capabilities = cursor.read_u16("RSN capabilities")?;
    let capable = capabilities & 0x0080 != 0;
    let required = capabilities & 0x0040 != 0;
    // Required PMF without capable PMF is internally inconsistent
    if required && !capable {
        return Err(SecurityError::InvalidPmf);
    }
    parse_optional_pmkids(cursor)?;
    if required {
        Ok(PmfMode::Required)
    } else if capable {
        Ok(PmfMode::Capable)
    } else {
        Ok(PmfMode::Disabled)
    }
}

fn parse_optional_pmkids(cursor: &mut Cursor<'_>) -> Result<(), SecurityError> {
    if cursor.remaining() == 0 {
        return Ok(());
    }
    let count = usize::from(cursor.read_u16("PMKID count")?);
    if count > MAX_SECURITY_LIST_ENTRIES {
        return Err(SecurityError::ListLimit {
            context: "PMKID",
            count,
            maximum: MAX_SECURITY_LIST_ENTRIES,
        });
    }
    // Each PMKID is exactly sixteen bytes on the wire
    let bytes = count.checked_mul(16).ok_or(SecurityError::LengthOverflow)?;
    cursor.skip(bytes, "PMKID list")?;
    if cursor.remaining() == 4 {
        let _ = cursor.read_suite("group management cipher")?;
    }
    ensure_empty(cursor)
}

const fn ensure_empty(cursor: &Cursor<'_>) -> Result<(), SecurityError> {
    if cursor.remaining() != 0 {
        return Err(SecurityError::TrailingBytes(cursor.remaining()));
    }
    Ok(())
}

const fn cipher(selector: [u8; 4]) -> CipherSuite {
    // Unknown selectors remain evidence for future registry assignments
    match selector {
        [0x00, 0x0f, 0xac, 0] | [0x00, 0x50, 0xf2, 0] => CipherSuite::UseGroup,
        [0x00, 0x0f, 0xac, 1] | [0x00, 0x50, 0xf2, 1] => CipherSuite::Wep40,
        [0x00, 0x0f, 0xac, 2] | [0x00, 0x50, 0xf2, 2] => CipherSuite::Tkip,
        [0x00, 0x0f, 0xac, 4] | [0x00, 0x50, 0xf2, 4] => CipherSuite::Ccmp128,
        [0x00, 0x0f, 0xac, 5] | [0x00, 0x50, 0xf2, 5] => CipherSuite::Wep104,
        [0x00, 0x0f, 0xac, 6] => CipherSuite::BipCmac128,
        [0x00, 0x0f, 0xac, 8] => CipherSuite::Gcmp128,
        [0x00, 0x0f, 0xac, 9] => CipherSuite::Gcmp256,
        [0x00, 0x0f, 0xac, 10] => CipherSuite::Ccmp256,
        other => CipherSuite::Unknown(other),
    }
}

const fn akm(selector: [u8; 4]) -> AkmSuite {
    // Unknown selectors are preserved instead of becoming malformed input
    match selector {
        [0x00, 0x0f, 0xac, 1] | [0x00, 0x50, 0xf2, 1] => AkmSuite::Ieee8021x,
        [0x00, 0x0f, 0xac, 2] | [0x00, 0x50, 0xf2, 2] => AkmSuite::Psk,
        [0x00, 0x0f, 0xac, 3] => AkmSuite::FtIeee8021x,
        [0x00, 0x0f, 0xac, 4] => AkmSuite::FtPsk,
        [0x00, 0x0f, 0xac, 8] => AkmSuite::Sae,
        [0x00, 0x0f, 0xac, 9] => AkmSuite::FtSae,
        [0x00, 0x0f, 0xac, 11] => AkmSuite::SuiteB,
        [0x00, 0x0f, 0xac, 12] => AkmSuite::SuiteB192,
        [0x00, 0x0f, 0xac, 18] => AkmSuite::Owe,
        other => AkmSuite::Unknown(other),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn read_u16(&mut self, context: &'static str) -> Result<u16, SecurityError> {
        let value: [u8; 2] = self.read_array(context)?;
        Ok(u16::from_le_bytes(value))
    }

    fn read_suite(&mut self, context: &'static str) -> Result<[u8; 4], SecurityError> {
        self.read_array(context)
    }

    fn read_array<const N: usize>(
        &mut self,
        context: &'static str,
    ) -> Result<[u8; N], SecurityError> {
        // The cursor advances only across a checked exact-width slice
        let end = self
            .offset
            .checked_add(N)
            .ok_or(SecurityError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SecurityError::Truncated {
                context,
                needed: end,
                available: self.bytes.len(),
            })?;
        self.offset = end;
        value.try_into().map_err(|_| SecurityError::LengthOverflow)
    }

    fn skip(&mut self, count: usize, context: &'static str) -> Result<(), SecurityError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(SecurityError::LengthOverflow)?;
        if self.bytes.get(self.offset..end).is_none() {
            return Err(SecurityError::Truncated {
                context,
                needed: end,
                available: self.bytes.len(),
            });
        }
        self.offset = end;
        Ok(())
    }
}
