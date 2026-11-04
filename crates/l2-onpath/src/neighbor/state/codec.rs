//! Canonical fixed-width state-source encoding and checked decoding

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::model::validate_neighbor_address;
use crate::{
    AgentId, ClockDomainId, ClockStamp, InterfaceBindingRequest, MAX_STIMULI, MacAddress, RunId,
};

use super::{StateRecordClaim, StateSourceError, StateSourceQuality};

const MARKER: &[u8; 8] = b"L2STATE\0";
const VERSION: u8 = 1;
pub(super) const HEADER_LEN: usize = 20;
pub(super) const RECORD_LEN: usize = 120;

pub(super) fn encode(
    quality: StateSourceQuality,
    records: &[StateRecordClaim],
) -> Result<Vec<u8>, StateSourceError> {
    if records.len() > MAX_STIMULI {
        return Err(StateSourceError::RecordLimit);
    }
    // Reject invalid addresses before allocating the encoded source
    for record in records {
        validate_neighbor_address(record.address).map_err(|_| StateSourceError::InvalidAddress)?;
    }
    let count = u16::try_from(records.len()).map_err(|_| StateSourceError::RecordLimit)?;
    let size = HEADER_LEN + records.len() * RECORD_LEN;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| StateSourceError::Allocation)?;
    bytes.extend_from_slice(MARKER);
    bytes.push(VERSION);
    bytes.push(u8::from(quality.complete));
    bytes.extend_from_slice(&quality.dropped_records.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    for record in records {
        encode_record(&mut bytes, *record)?;
    }
    Ok(bytes)
}

fn encode_record(bytes: &mut Vec<u8>, record: StateRecordClaim) -> Result<(), StateSourceError> {
    bytes.extend_from_slice(&record.run_id.into_bytes());
    bytes.extend_from_slice(record.observer.as_bytes());
    // The existing interface codec defines the canonical attachment bytes
    let mut interface = [0; InterfaceBindingRequest::ENCODED_LENGTH];
    record
        .interface
        .encode(&mut interface)
        .map_err(|_| StateSourceError::InvalidEncoding)?;
    bytes.extend_from_slice(&interface);
    bytes.extend_from_slice(record.subject.as_bytes());
    match record.address {
        IpAddr::V4(address) => {
            bytes.push(4);
            bytes.extend_from_slice(&address.octets());
            bytes.extend_from_slice(&[0; 12]);
        }
        IpAddr::V6(address) => {
            bytes.push(6);
            bytes.extend_from_slice(&address.octets());
        }
    }
    if let Some(binding) = record.binding {
        bytes.push(1);
        bytes.extend_from_slice(binding.as_bytes());
    } else {
        bytes.push(0);
        bytes.extend_from_slice(&[0; 6]);
    }
    bytes.extend_from_slice(&record.observed_at.domain().get());
    bytes.extend_from_slice(&record.observed_at.ticks().to_be_bytes());
    Ok(())
}

pub(super) fn validate(bytes: &[u8]) -> Result<(), StateSourceError> {
    let (_, count) = header(bytes)?;
    let records = bytes
        .get(HEADER_LEN..)
        .ok_or(StateSourceError::InvalidEncoding)?;
    // A source is retained only after every record has passed the same decoder
    for chunk in records.as_chunks::<RECORD_LEN>().0.iter().take(count) {
        parse_record(chunk)?;
    }
    Ok(())
}

pub(super) fn decode_record(
    bytes: &[u8],
    index: usize,
) -> Result<(StateRecordClaim, StateSourceQuality), StateSourceError> {
    let (quality, count) = header(bytes)?;
    if index >= count {
        return Err(StateSourceError::RecordOutOfBounds);
    }
    // The validated count bounds both arithmetic and the record slice
    let start = HEADER_LEN + index * RECORD_LEN;
    let record = bytes
        .get(start..start + RECORD_LEN)
        .ok_or(StateSourceError::InvalidEncoding)?;
    Ok((parse_record(record)?, quality))
}

fn header(bytes: &[u8]) -> Result<(StateSourceQuality, usize), StateSourceError> {
    let mut reader = Reader::new(bytes);
    let complete = parse_preamble(&mut reader)?;
    let dropped_records = u64::from_be_bytes(reader.read()?);
    let count = usize::from(u16::from_be_bytes(reader.read()?));
    if count > MAX_STIMULI {
        return Err(StateSourceError::RecordLimit);
    }
    if bytes.len() != HEADER_LEN + count * RECORD_LEN {
        return Err(StateSourceError::InvalidEncoding);
    }
    Ok((
        StateSourceQuality {
            complete,
            dropped_records,
        },
        count,
    ))
}

fn parse_preamble(reader: &mut Reader<'_>) -> Result<bool, StateSourceError> {
    // The marker, version, and completion flag identify a supported source
    if reader.read::<8>()? != *MARKER || reader.byte()? != VERSION {
        return Err(StateSourceError::InvalidEncoding);
    }
    match reader.byte()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StateSourceError::InvalidEncoding),
    }
}

fn parse_record(bytes: &[u8]) -> Result<StateRecordClaim, StateSourceError> {
    let mut reader = Reader::new(bytes);
    let (run_id, observer, interface) = parse_observer_scope(&mut reader)?;
    let (subject, address) = parse_subject(&mut reader)?;
    let binding = parse_binding(&mut reader)?;
    let observed_at = parse_stamp(&mut reader)?;
    // Both callers supply one exact record, and these fields consume it fully
    Ok(StateRecordClaim {
        run_id,
        observer,
        interface,
        subject,
        address,
        binding,
        observed_at,
    })
}

fn parse_observer_scope(
    reader: &mut Reader<'_>,
) -> Result<(RunId, AgentId, InterfaceBindingRequest), StateSourceError> {
    let run_id =
        RunId::from_recorded(reader.read()?).map_err(|_| StateSourceError::InvalidEncoding)?;
    let observer = AgentId::new(reader.read()?).map_err(|_| StateSourceError::InvalidEncoding)?;
    let interface = InterfaceBindingRequest::decode(&reader.read::<24>()?)
        .map_err(|_| StateSourceError::InvalidEncoding)?;
    Ok((run_id, observer, interface))
}

fn parse_subject(reader: &mut Reader<'_>) -> Result<(AgentId, IpAddr), StateSourceError> {
    let subject = AgentId::new(reader.read()?).map_err(|_| StateSourceError::InvalidEncoding)?;
    let family = reader.byte()?;
    let address = reader.read::<16>()?;
    // IPv4 padding must be zero so each address has one byte representation
    let address = match (family, address) {
        (4, [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) => {
            IpAddr::V4(Ipv4Addr::new(a, b, c, d))
        }
        (6, address) => IpAddr::V6(Ipv6Addr::from(address)),
        _ => return Err(StateSourceError::InvalidEncoding),
    };
    validate_neighbor_address(address).map_err(|_| StateSourceError::InvalidEncoding)?;
    Ok((subject, address))
}

fn parse_binding(reader: &mut Reader<'_>) -> Result<Option<MacAddress>, StateSourceError> {
    let present = reader.byte()?;
    let mac = reader.read::<6>()?;
    // Absence cannot hide MAC bytes in the source
    match (present, mac) {
        (0, [0, 0, 0, 0, 0, 0]) => Ok(None),
        (1, value) => MacAddress::new(value)
            .map(Some)
            .map_err(|_| StateSourceError::InvalidEncoding),
        _ => Err(StateSourceError::InvalidEncoding),
    }
}

fn parse_stamp(reader: &mut Reader<'_>) -> Result<ClockStamp, StateSourceError> {
    let domain =
        ClockDomainId::new(reader.read()?).map_err(|_| StateSourceError::InvalidEncoding)?;
    ClockStamp::new(domain, u64::from_be_bytes(reader.read()?))
        .map_err(|_| StateSourceError::InvalidEncoding)
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn read<const N: usize>(&mut self) -> Result<[u8; N], StateSourceError> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(N)
            .ok_or(StateSourceError::InvalidEncoding)?;
        self.remaining = remaining;
        value
            .try_into()
            .map_err(|_| StateSourceError::InvalidEncoding)
    }

    fn byte(&mut self) -> Result<u8, StateSourceError> {
        let [value] = self.read()?;
        Ok(value)
    }
}
