//! Bounded DNS wire layouts with literal names, record sections, and source ranges
//!
//! Decoding does not establish server authenticity, DNSSEC validity, or host acceptance

mod model;
mod name;
mod records;

use crate::{IpPacket, TransportHeader, bytes::read_u16};
pub use model::{
    DnsDecoding, DnsError, DnsErrorKind, DnsMessage, DnsName, DnsQuestion, DnsRange, DnsRecord,
    DnsSection, DnsValue,
};

pub const MAX_MESSAGE_BYTES: usize = 16_384;
pub const MAX_ENTRIES: usize = 64;

/// Decode one complete message, retaining unknown record types as raw source ranges
///
/// # Errors
/// Returns a located error for unsupported, incomplete, over-budget, or inconsistent layouts
pub fn decode(bytes: &[u8]) -> Result<DnsMessage, DnsError> {
    let incomplete = DnsError {
        kind: DnsErrorKind::Incomplete,
        offset: bytes.len(),
    };
    let id = read_u16(bytes, 0).ok_or(incomplete)?;
    let flags = read_u16(bytes, 2).ok_or(incomplete)?;
    let [
        Some(question_count),
        Some(answer),
        Some(authority),
        Some(additional),
    ] = [4, 6, 8, 10].map(|offset| read_u16(bytes, offset))
    else {
        return Err(incomplete);
    };
    let section_counts = [answer, authority, additional];
    // One-byte root names plus fixed fields need five bytes per question and eleven per record
    // This lower bound rejects impossible counts but does not prove the bytes form a DNS message
    let record_count = section_counts
        .iter()
        .map(|value| usize::from(*value))
        .sum::<usize>();
    let entries = usize::from(question_count) + record_count;
    let minimum_size = 12 + usize::from(question_count) * 5 + record_count * 11;
    if minimum_size > bytes.len() {
        return Err(incomplete);
    }
    // Reject size only after the header proves that this candidate can fit its declared sections
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(DnsError {
            kind: DnsErrorKind::MessageLimit,
            offset: MAX_MESSAGE_BYTES,
        });
    }
    // Validate aggregate counts before any count-dependent allocation or iteration
    if entries > MAX_ENTRIES {
        return Err(DnsError {
            kind: DnsErrorKind::EntryLimit,
            offset: 4,
        });
    }
    let mut cursor = 12;
    let mut names = name::NameContext::new(bytes.len());
    let mut questions = Vec::with_capacity(usize::from(question_count));
    for _ in 0..question_count {
        let (name, end) = name::decode(bytes, cursor, bytes.len(), &mut names)?;
        let qtype = read_u16(bytes, end).ok_or(incomplete)?;
        let qclass = read_u16(bytes, end + 2).ok_or(incomplete)?;
        questions.push(DnsQuestion {
            name,
            qtype,
            qclass,
        });
        cursor = end + 4;
    }
    let records = decode_records(bytes, &mut cursor, section_counts, &mut names)?;
    if cursor != bytes.len() {
        return Err(DnsError {
            kind: DnsErrorKind::TrailingData,
            offset: cursor,
        });
    }
    Ok(DnsMessage {
        id,
        flags,
        questions,
        records,
    })
}

fn decode_records(
    bytes: &[u8],
    cursor: &mut usize,
    counts: [u16; 3],
    names: &mut name::NameContext,
) -> Result<Vec<DnsRecord>, DnsError> {
    let mut records = Vec::with_capacity(counts.iter().map(|value| usize::from(*value)).sum());
    let mut opt_seen = false;
    for (count, section) in counts.into_iter().zip([
        DnsSection::Answer,
        DnsSection::Authority,
        DnsSection::Additional,
    ]) {
        for _ in 0..count {
            let record = records::decode(bytes, cursor, section, names)?;
            // A single root-owned OPT in Additional provides one unambiguous extended RCODE
            if record.rr_type == 41 {
                if opt_seen || section != DnsSection::Additional || record.name.wire() != [0] {
                    return Err(DnsError {
                        kind: DnsErrorKind::InvalidRecord,
                        offset: record.rdata.offset,
                    });
                }
                opt_seen = true;
            }
            records.push(record);
        }
    }
    Ok(records)
}

/// Select conventional unicast UDP DNS candidates without interpreting TCP segments as messages
#[must_use]
pub fn udp_message(ip: IpPacket<'_>) -> Option<DnsDecoding> {
    let transport = ip.transport?;
    if transport.header != TransportHeader::Udp
        || (transport.ports.0 != 53 && transport.ports.1 != 53)
    {
        return None;
    }
    Some(match decode(transport.payload) {
        Ok(message) => DnsDecoding::Decoded { message },
        Err(error) => DnsDecoding::Unresolved { error },
    })
}
