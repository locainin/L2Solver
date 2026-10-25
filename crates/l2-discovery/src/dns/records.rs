use super::{DnsError, DnsErrorKind, DnsRange, DnsRecord, DnsSection, DnsValue, name};
use crate::{
    NetworkAddress,
    bytes::{read_u16, read_u32},
};

pub fn decode(
    bytes: &[u8],
    cursor: &mut usize,
    section: DnsSection,
    names: &mut name::NameContext,
) -> Result<DnsRecord, DnsError> {
    let (owner, end) = name::decode(bytes, *cursor, bytes.len(), names)?;
    let invalid = DnsError {
        kind: DnsErrorKind::Incomplete,
        offset: end,
    };
    let rr_type = read_u16(bytes, end).ok_or(invalid)?;
    let class = read_u16(bytes, end + 2).ok_or(invalid)?;
    let ttl = read_u32(bytes, end + 4).ok_or(invalid)?;
    let length = usize::from(read_u16(bytes, end + 8).ok_or(invalid)?);
    let offset = end + 10;
    let data = bytes.get(offset..offset + length).ok_or(invalid)?;
    let invalid_record = DnsError {
        kind: DnsErrorKind::InvalidRecord,
        offset,
    };
    let value = match (class, rr_type) {
        (1, 1) => DnsValue::Address(NetworkAddress::Ipv4(
            data.try_into().map_err(|_| invalid_record)?,
        )),
        (1, 28) => DnsValue::Address(NetworkAddress::Ipv6(
            data.try_into().map_err(|_| invalid_record)?,
        )),
        (1, 2 | 5 | 12) => {
            let (target, consumed) = name::decode(bytes, offset, offset + length, names)?;
            if consumed != offset + length {
                return Err(invalid_record);
            }
            DnsValue::Name(target)
        }
        _ => DnsValue::Opaque,
    };
    *cursor = offset + length;
    Ok(DnsRecord {
        section,
        name: owner,
        rr_type,
        class,
        ttl,
        rdata: DnsRange { offset, length },
        value,
    })
}
