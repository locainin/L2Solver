//! Interpret only the VLAN attributes needed to identify the selected scope

use std::io;

use netlink_packet_core::{Emitable, NetlinkBuffer, NetlinkMessage, NetlinkPayload, NlasIterator};
use netlink_packet_route::{
    RouteNetlinkMessage,
    link::{
        InfoData, InfoKind, InfoVlan, LinkAttribute, LinkHeader, LinkInfo, LinkMessage, VlanFlags,
    },
};

use super::{VlanData, VlanProtocol, unsupported};

// These are the Linux UAPI attribute numbers for the nested VLAN protocol
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_DATA: u16 = 2;
const IFLA_VLAN_PROTOCOL: u16 = 5;
const NLA_HEADER_BYTES: usize = 4;

pub(super) fn decode_link(bytes: &[u8], ifindex: u32) -> io::Result<Option<VlanData>> {
    let packet = NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes).map_err(invalid)?;
    if usize::try_from(packet.header.length).ok() != Some(bytes.len()) {
        return Err(invalid("link reply has an unexpected length"));
    }
    let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) = packet.payload else {
        return Err(invalid("link reply has an unexpected type"));
    };
    if ifindex == 0 || link.header.index != ifindex {
        return Err(invalid("link reply has a different interface index"));
    }
    let Some(info) = link_info(&link)? else {
        return Ok(None);
    };
    if !is_vlan(info)? {
        return Ok(None);
    }
    let parent_ifindex = parent(&link, ifindex)?;
    let (id, reorders_headers) = vlan_properties(info)?;
    let protocol = original_protocol(bytes)?;
    Ok(Some(VlanData {
        id,
        protocol,
        parent_ifindex,
        reorders_headers,
    }))
}

fn link_info(link: &LinkMessage) -> io::Result<Option<&[LinkInfo]>> {
    let mut found = None;
    for attribute in &link.attributes {
        if let LinkAttribute::LinkInfo(value) = attribute
            && found.replace(value.as_slice()).is_some()
        {
            return Err(invalid("link reply has duplicate link information"));
        }
    }
    Ok(found)
}

fn is_vlan(info: &[LinkInfo]) -> io::Result<bool> {
    let mut kind = None;
    for item in info {
        if let LinkInfo::Kind(value) = item
            && kind.replace(value).is_some()
        {
            return Err(invalid("link reply has duplicate link kinds"));
        }
    }
    Ok(matches!(kind, Some(InfoKind::Vlan)))
}

fn parent(link: &LinkMessage, selected: u32) -> io::Result<u32> {
    let mut found = None;
    for attribute in &link.attributes {
        match attribute {
            LinkAttribute::Link(index) => {
                if found.replace(*index).is_some() {
                    return Err(invalid("VLAN has duplicate parent indices"));
                }
            }
            LinkAttribute::LinkNetNsId(_) => {
                return Err(unsupported("VLAN parent is in another network namespace"));
            }
            _ => {}
        }
    }
    found
        .filter(|index| *index != 0 && *index != selected)
        .ok_or_else(|| invalid("VLAN parent index is missing or invalid"))
}

fn vlan_properties(info: &[LinkInfo]) -> io::Result<(u16, bool)> {
    let mut data = None;
    for item in info {
        if let LinkInfo::Data(value) = item
            && data.replace(value).is_some()
        {
            return Err(invalid("VLAN has duplicate link data"));
        }
    }
    let Some(InfoData::Vlan(attributes)) = data else {
        return Err(invalid("VLAN link data is missing"));
    };
    let mut id = None;
    let mut flags = None;
    for attribute in attributes {
        match attribute {
            InfoVlan::Id(value) => {
                if id.replace(*value).is_some() {
                    return Err(invalid("VLAN has duplicate identifiers"));
                }
            }
            InfoVlan::Flags(_) if flags.is_some() => {
                return Err(invalid("VLAN has duplicate flags"));
            }
            InfoVlan::Flags((active, _)) => flags = Some(*active),
            _ => {}
        }
    }
    let id = id
        .filter(|value| *value <= 4094)
        .ok_or_else(|| invalid("VLAN identifier is missing or reserved"))?;
    // Linux omits the flags attribute when no flags are enabled
    Ok((
        id,
        flags.is_some_and(|value| value.contains(VlanFlags::ReorderHdr)),
    ))
}

fn original_protocol(bytes: &[u8]) -> io::Result<VlanProtocol> {
    let packet = NetlinkBuffer::new_checked(bytes).map_err(invalid)?;
    let attrs = packet
        .payload()
        .get(LinkHeader::default().buffer_len()..)
        .ok_or_else(|| invalid("short link message"))?;
    let info = one_attribute(attrs, IFLA_LINKINFO)?
        .ok_or_else(|| invalid("VLAN link information is missing"))?;
    let data =
        one_attribute(info, IFLA_INFO_DATA)?.ok_or_else(|| invalid("VLAN link data is missing"))?;
    // The typed dependency turns unknown protocol values into 802.1Q
    let protocol = one_attribute(data, IFLA_VLAN_PROTOCOL)?
        .ok_or_else(|| invalid("VLAN protocol is missing"))?;
    let value = <[u8; 2]>::try_from(protocol).map_err(invalid)?;
    match u16::from_be_bytes(value) {
        0x8100 => Ok(VlanProtocol::Ieee8021Q),
        0x88a8 => Ok(VlanProtocol::Ieee8021Ad),
        _ => Err(unsupported("unsupported VLAN protocol")),
    }
}

fn one_attribute(bytes: &[u8], wanted: u16) -> io::Result<Option<&[u8]>> {
    let mut found = None;
    for item in NlasIterator::new(bytes) {
        let item = item.map_err(invalid)?;
        if item.kind() == wanted {
            let end = usize::from(item.length());
            let value = item
                .into_inner()
                .get(NLA_HEADER_BYTES..end)
                .ok_or_else(|| invalid("invalid attribute bounds"))?;
            if found.replace(value).is_some() {
                return Err(invalid("duplicate VLAN protocol attribute"));
            }
        }
    }
    Ok(found)
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
