//! Decode bounded verbose ethtool bitsets without assuming feature indices

use std::{io, str};

use netlink_packet_core::NlasIterator;

use super::{Capability, FeatureFlags, TimestampCapabilities, UnknownReason, VlanOffloads};

const MAX_ATTRIBUTES: usize = 512;
const MAX_BITS: u32 = 512;
const MAX_NAME: usize = 128;

#[derive(Clone, Copy)]
struct Attribute<'a> {
    kind: u16,
    value: &'a [u8],
}

#[derive(Clone, Copy)]
struct Bit<'a> {
    index: u32,
    name: &'a str,
    value: bool,
}

struct Bitset<'a> {
    size: u32,
    bits: Vec<Bit<'a>>,
}

pub fn features(bytes: &[u8], index: u32) -> io::Result<VlanOffloads> {
    let attributes = attributes(bytes)?;
    check_header(required(&attributes, 1)?, index)?;
    let hw = bitset(required(&attributes, 2)?, false)?;
    let wanted = bitset(required(&attributes, 3)?, true)?;
    let active = bitset(required(&attributes, 4)?, true)?;
    Ok(VlanOffloads {
        ctag_rx: feature(&hw, &wanted, &active, "rx-vlan-hw-parse")?,
        ctag_tx: feature(&hw, &wanted, &active, "tx-vlan-hw-insert")?,
        ctag_filter: feature(&hw, &wanted, &active, "rx-vlan-filter")?,
        stag_rx: feature(&hw, &wanted, &active, "rx-vlan-stag-hw-parse")?,
        stag_tx: feature(&hw, &wanted, &active, "tx-vlan-stag-hw-insert")?,
        stag_filter: feature(&hw, &wanted, &active, "rx-vlan-stag-filter")?,
    })
}

pub fn timestamps(bytes: &[u8], index: u32) -> io::Result<TimestampCapabilities> {
    let attributes = attributes(bytes)?;
    check_header(required(&attributes, 1)?, index)?;
    // An omitted timestamping bitset means that no flag is set
    let flags = optional(&attributes, 2)?
        .map(|bytes| bitset(bytes, true))
        .transpose()?;
    let phc = optional(&attributes, 5)?.map(integer).transpose()?;
    Ok(TimestampCapabilities {
        tx_software: timestamp_flag(flags.as_ref(), "software-transmit"),
        rx_software: timestamp_flag(flags.as_ref(), "software-receive"),
        tx_hardware: timestamp_flag(flags.as_ref(), "hardware-transmit"),
        rx_hardware: timestamp_flag(flags.as_ref(), "hardware-receive"),
        phc_index: Capability::Reported(phc),
    })
}

fn timestamp_flag(flags: Option<&Bitset<'_>>, name: &str) -> Capability<bool> {
    let Some(flags) = flags else {
        return Capability::Reported(false);
    };
    if flags.bits.iter().any(|bit| bit.name == name) {
        Capability::Reported(true)
    } else if flags.bits.iter().any(|bit| bit.name.is_empty()) {
        // An unnamed set bit may be the requested flag, so absence is unknown
        Capability::Unknown(UnknownReason::NotReported)
    } else {
        Capability::Reported(false)
    }
}

fn feature(
    hw: &Bitset<'_>,
    wanted: &Bitset<'_>,
    active: &Bitset<'_>,
    name: &str,
) -> io::Result<Capability<FeatureFlags>> {
    let mut matching = hw.bits.iter().filter(|bit| bit.name == name);
    let Some(bit) = matching.next() else {
        return Ok(Capability::Unknown(UnknownReason::NotReported));
    };
    if matching.next().is_some() {
        return Err(invalid("duplicate feature name"));
    }
    Ok(Capability::Reported(FeatureFlags {
        hw: bit.value,
        wanted: present(wanted, bit.index, name)?,
        active: present(active, bit.index, name)?,
    }))
}

fn present(bitset: &Bitset<'_>, index: u32, name: &str) -> io::Result<bool> {
    if index >= bitset.size {
        return Err(invalid("feature index exceeds bitmap size"));
    }
    match bitset.bits.iter().find(|bit| bit.index == index) {
        Some(bit) if bit.name == name => Ok(true),
        Some(_) => Err(invalid("feature index and name disagree")),
        None => Ok(false),
    }
}

fn check_header(bytes: &[u8], expected: u32) -> io::Result<()> {
    let header = attributes(bytes)?;
    if integer(required(&header, 1)?)? != expected {
        return Err(invalid("ethtool reply identifies another interface"));
    }
    Ok(())
}

fn bitset(bytes: &[u8], no_mask: bool) -> io::Result<Bitset<'_>> {
    let attrs = attributes(bytes)?;
    let flag = optional(&attrs, 1)?;
    if flag.is_some() != no_mask || flag.is_some_and(|value| !value.is_empty()) {
        return Err(invalid("unexpected bitmap mask"));
    }
    let size = integer(required(&attrs, 2)?)?;
    if size > MAX_BITS {
        return Err(invalid("bitmap exceeds limit"));
    }
    let entries = attributes(required(&attrs, 3)?)?;
    let mut bits = Vec::new();
    bits.try_reserve_exact(entries.len())
        .map_err(io::Error::other)?;
    for entry in entries {
        if entry.kind != 1 {
            return Err(invalid("unexpected bitmap entry"));
        }
        let fields = attributes(entry.value)?;
        let index = integer(required(&fields, 1)?)?;
        if index >= size || bits.iter().any(|bit: &Bit<'_>| bit.index == index) {
            return Err(invalid("duplicate or out-of-range bitmap index"));
        }
        let name = optional(&fields, 2)?.map(name).transpose()?.unwrap_or("");
        let flag = optional(&fields, 3)?;
        if flag.is_some_and(|value| !value.is_empty()) || (no_mask && flag.is_some()) {
            return Err(invalid("invalid bitmap value"));
        }
        bits.push(Bit {
            index,
            name,
            value: no_mask || flag.is_some(),
        });
    }
    Ok(Bitset { size, bits })
}

fn name(bytes: &[u8]) -> io::Result<&str> {
    if bytes.len() > MAX_NAME || bytes.last() != Some(&0) {
        return Err(invalid("invalid bitmap name"));
    }
    let value = bytes
        .get(..bytes.len() - 1)
        .ok_or_else(|| invalid("empty bitmap name"))?;
    if value.contains(&0) {
        return Err(invalid("bitmap name has embedded zero"));
    }
    str::from_utf8(value).map_err(invalid)
}

fn integer(bytes: &[u8]) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(bytes.try_into().map_err(invalid)?))
}

fn attributes(bytes: &[u8]) -> io::Result<Vec<Attribute<'_>>> {
    if !bytes.len().is_multiple_of(4) {
        return Err(invalid("unaligned netlink attributes"));
    }
    let mut result = Vec::new();
    for entry in NlasIterator::new(bytes) {
        if result.len() == MAX_ATTRIBUTES {
            return Err(invalid("too many netlink attributes"));
        }
        let entry = entry.map_err(invalid)?;
        let kind = entry.kind();
        let length = usize::from(entry.length());
        let value = entry
            .into_inner()
            .get(4..length)
            .ok_or_else(|| invalid("invalid attribute length"))?;
        result.try_reserve(1).map_err(io::Error::other)?;
        result.push(Attribute { kind, value });
    }
    Ok(result)
}

fn optional<'a>(attributes: &[Attribute<'a>], kind: u16) -> io::Result<Option<&'a [u8]>> {
    let mut matches = attributes.iter().filter(|attribute| attribute.kind == kind);
    let value = matches.next().map(|attribute| attribute.value);
    if matches.next().is_some() {
        return Err(invalid("duplicate netlink attribute"));
    }
    Ok(value)
}

fn required<'a>(attributes: &[Attribute<'a>], kind: u16) -> io::Result<&'a [u8]> {
    optional(attributes, kind)?.ok_or_else(|| invalid("missing netlink attribute"))
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
