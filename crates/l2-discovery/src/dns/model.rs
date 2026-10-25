use crate::NetworkAddress;
use serde::Serialize;
use std::{error::Error, fmt};

/// Expanded length-prefixed labels, including the final root byte
/// Original label bytes and case are retained; compression is resolved separately
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DnsName {
    pub(super) wire: Vec<u8>,
}

impl DnsName {
    #[must_use]
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// ASCII case folding preserves every non-ASCII label byte and label boundary
    #[must_use]
    pub fn canonical(&self) -> Vec<u8> {
        self.wire.iter().map(u8::to_ascii_lowercase).collect()
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rest = self.wire();
        if rest == [0] {
            return output.write_str(".");
        }
        while let Some((&length, body)) = rest.split_first() {
            if length == 0 {
                break;
            }
            // Only the parser can construct a name, so each label already fits
            let Some(label) = body.get(..usize::from(length)) else {
                return Err(fmt::Error);
            };
            for &byte in label {
                match byte {
                    b'.' => output.write_str("\\.")?,
                    b'\\' => output.write_str("\\\\")?,
                    0x21..=0x7e => write!(output, "{}", char::from(byte))?,
                    _ => write!(output, "\\{byte:03}")?,
                }
            }
            output.write_str(".")?;
            rest = body.get(usize::from(length)..).ok_or(fmt::Error)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DnsQuestion {
    pub name: DnsName,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsSection {
    Answer,
    Authority,
    Additional,
}

/// Zero-based range relative to the beginning of the DNS message
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DnsRange {
    pub offset: usize,
    pub length: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum DnsValue {
    Address(NetworkAddress),
    Name(DnsName),
    Opaque,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DnsRecord {
    pub section: DnsSection,
    pub name: DnsName,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    /// Raw RDATA is referenced in the source message rather than copied
    pub rdata: DnsRange,
    pub value: DnsValue,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DnsMessage {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<DnsQuestion>,
    /// Records follow answer, authority, then additional wire order
    pub records: Vec<DnsRecord>,
}

impl DnsMessage {
    #[must_use]
    pub const fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    #[must_use]
    pub const fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0xf) as u8
    }

    /// EDNS extends the low four header bits through the OPT TTL high byte
    #[must_use]
    pub fn response_code(&self) -> u16 {
        let extension = self
            .records
            .iter()
            .find(|record| record.section == DnsSection::Additional && record.rr_type == 41);
        let high = extension.map_or(0, |record| (record.ttl >> 24) as u16);
        high * 16 + (self.flags & 0xf)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsErrorKind {
    Incomplete,
    /// The target is outside verified name fields; opaque bytes are not proof of an invalid name
    UnsupportedNameTarget,
    UnsupportedLabel,
    NameLimit,
    EntryLimit,
    MessageLimit,
    InvalidRecord,
    TrailingData,
}

/// An unresolved layout with a message-relative location, without an intent verdict
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DnsError {
    pub kind: DnsErrorKind,
    pub offset: usize,
}

impl fmt::Display for DnsError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "DNS {:?} at message byte {}",
            self.kind, self.offset
        )
    }
}

impl Error for DnsError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DnsDecoding {
    Decoded { message: DnsMessage },
    Unresolved { error: DnsError },
}
