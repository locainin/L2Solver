//! Bounded network envelopes for Ethernet and Linux cooked capture formats

use crate::bytes::{read_u8, read_u16, read_u32, take};
use l2_capture::LinkType;
use l2_core::{ETHERTYPE_MIN, EthernetFrame, FrameField, TPID_8021AD, TPID_8021Q};
use serde::Serialize;

const SLL_HEADER_LEN: usize = 16;
const SLL2_HEADER_LEN: usize = 20;
const ADDRESS_STORAGE_LEN: usize = 8;

/// Linux cooked header layout
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CookedVersion {
    V1,
    V2,
}

/// Direction and destination class reported by a Linux cooked capture
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CookedPacketType {
    Host,
    Broadcast,
    Multicast,
    OtherHost,
    Outgoing,
}

impl CookedPacketType {
    /// Return the packet type value carried in the capture header
    #[must_use]
    pub const fn raw(self) -> u16 {
        match self {
            Self::Host => 0,
            Self::Broadcast => 1,
            Self::Multicast => 2,
            Self::OtherHost => 3,
            Self::Outgoing => 4,
        }
    }

    const fn from_raw(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Host),
            1 => Some(Self::Broadcast),
            2 => Some(Self::Multicast),
            3 => Some(Self::OtherHost),
            4 => Some(Self::Outgoing),
            _ => None,
        }
    }
}

/// Linux cooked metadata and its borrowed payload
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CookedFrame<'a> {
    version: CookedVersion,
    packet_type: CookedPacketType,
    hardware_type: u16,
    address_length: u16,
    address: &'a [u8],
    interface_index: Option<u32>,
    protocol: u16,
    payload: &'a [u8],
}

impl<'a> CookedFrame<'a> {
    /// Return which Linux cooked header layout was captured
    #[must_use]
    pub const fn version(&self) -> CookedVersion {
        self.version
    }

    /// Return the validated packet type
    #[must_use]
    pub const fn packet_type(&self) -> CookedPacketType {
        self.packet_type
    }

    /// Return the Linux ARPHRD hardware type
    #[must_use]
    pub const fn hardware_type(&self) -> u16 {
        self.hardware_type
    }

    /// Return the declared sender address length, which can exceed stored bytes
    #[must_use]
    pub const fn address_length(&self) -> u16 {
        self.address_length
    }

    /// Return the sender address bytes available in the eight-byte header field
    #[must_use]
    pub const fn address(&self) -> &'a [u8] {
        self.address
    }

    /// Return the Linux interface index when the SLL2 header carries one
    ///
    /// This index belongs to the capture host, not the capture file interface ID
    #[must_use]
    pub const fn interface_index(&self) -> Option<u32> {
        self.interface_index
    }
}

/// A decoded frame without inventing Ethernet addresses for cooked captures
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkEnvelope<'a> {
    Ethernet(EthernetFrame<'a>),
    LinuxCooked(CookedFrame<'a>),
}

impl<'a> NetworkEnvelope<'a> {
    /// Return the Ethernet type/length field or the raw cooked protocol field
    #[must_use]
    pub const fn protocol(&self) -> u16 {
        match self {
            Self::Ethernet(frame) => match frame.field {
                FrameField::EtherType(value) | FrameField::Length(value) => value,
            },
            Self::LinuxCooked(frame) => frame.protocol,
        }
    }

    /// Return a field only when its Ethernet interpretation is supported
    ///
    /// Cooked VLAN payloads and hardware types with special protocol meanings
    /// remain opaque. Low cooked protocol values are not Ethernet lengths
    #[must_use]
    pub const fn field(&self) -> Option<FrameField> {
        match self {
            Self::Ethernet(frame) => Some(frame.field),
            Self::LinuxCooked(frame)
                if !matches!(frame.hardware_type, 770 | 803 | 824)
                    && frame.protocol >= ETHERTYPE_MIN
                    && !matches!(frame.protocol, TPID_8021Q | TPID_8021AD) =>
            {
                Some(FrameField::EtherType(frame.protocol))
            }
            Self::LinuxCooked(_) => None,
        }
    }

    /// Return the bytes after the decoded link header
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        match self {
            Self::Ethernet(frame) => frame.payload,
            Self::LinuxCooked(frame) => frame.payload,
        }
    }

    /// Return the payload offset from the start of the captured frame
    #[must_use]
    pub const fn payload_offset(&self) -> usize {
        match self {
            Self::Ethernet(frame) => 14 + frame.vlan_tags.len() * 4,
            Self::LinuxCooked(frame) => match frame.version {
                CookedVersion::V1 => SLL_HEADER_LEN,
                CookedVersion::V2 => SLL2_HEADER_LEN,
            },
        }
    }

    /// Return Ethernet addresses and VLAN tags only for Ethernet captures
    #[must_use]
    pub const fn ethernet(&self) -> Option<&EthernetFrame<'a>> {
        match self {
            Self::Ethernet(frame) => Some(frame),
            Self::LinuxCooked(_) => None,
        }
    }

    /// Return cooked metadata only for Linux cooked captures
    #[must_use]
    pub const fn cooked(&self) -> Option<&CookedFrame<'a>> {
        match self {
            Self::Ethernet(_) => None,
            Self::LinuxCooked(frame) => Some(frame),
        }
    }
}

/// Decode a supported link header without copying its payload
///
/// Unsupported link types, truncated headers, invalid packet types, and nonzero
/// SLL2 reserved fields produce no envelope
#[must_use]
pub fn decode_network_frame(link_type: LinkType, bytes: &[u8]) -> Option<NetworkEnvelope<'_>> {
    match link_type {
        LinkType::Ethernet => l2_core::decode(bytes).ok().map(NetworkEnvelope::Ethernet),
        LinkType::LinuxSll => decode_sll(bytes).map(NetworkEnvelope::LinuxCooked),
        LinkType::LinuxSll2 => decode_sll2(bytes).map(NetworkEnvelope::LinuxCooked),
        _ => None,
    }
}

fn address(bytes: &[u8], offset: usize, length: u16) -> Option<&[u8]> {
    // A long hardware address is legal, but only its first eight bytes are stored
    let stored = take(bytes, offset, ADDRESS_STORAGE_LEN)?;
    stored.get(..usize::from(length).min(ADDRESS_STORAGE_LEN))
}

fn decode_sll(bytes: &[u8]) -> Option<CookedFrame<'_>> {
    // Require the entire fixed header even when the address has zero length
    let (header, payload) = bytes.split_at_checked(SLL_HEADER_LEN)?;
    let address_length = read_u16(header, 4)?;
    Some(CookedFrame {
        version: CookedVersion::V1,
        packet_type: CookedPacketType::from_raw(read_u16(header, 0)?)?,
        hardware_type: read_u16(header, 2)?,
        address_length,
        address: address(header, 6, address_length)?,
        interface_index: None,
        protocol: read_u16(header, 14)?,
        payload,
    })
}

fn decode_sll2(bytes: &[u8]) -> Option<CookedFrame<'_>> {
    let (header, payload) = bytes.split_at_checked(SLL2_HEADER_LEN)?;
    // The SLL2 reserved field is required to be zero
    if read_u16(header, 2)? != 0 {
        return None;
    }
    let address_length = u16::from(read_u8(header, 11)?);
    Some(CookedFrame {
        version: CookedVersion::V2,
        packet_type: CookedPacketType::from_raw(u16::from(read_u8(header, 10)?))?,
        hardware_type: read_u16(header, 8)?,
        address_length,
        address: address(header, 12, address_length)?,
        interface_index: Some(read_u32(header, 4)?),
        protocol: read_u16(header, 0)?,
        payload,
    })
}
