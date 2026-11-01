use std::{error::Error, io};

use netlink_packet_core::NetlinkMessage;
use netlink_packet_route::{
    RouteNetlinkMessage,
    link::{
        InfoData, InfoKind, InfoVlan, LinkAttribute, LinkInfo, LinkMessage, VlanFlags,
        VlanProtocol as WireProtocol,
    },
};

use super::{VlanProtocol, decode::decode_link};

const INDEX: u32 = 7;
const PARENT: u32 = 4;

fn vlan_attributes(id: u16, protocol: WireProtocol) -> Vec<LinkAttribute> {
    vec![
        LinkAttribute::Link(PARENT),
        LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Vlan),
            LinkInfo::Data(InfoData::Vlan(vec![
                InfoVlan::Id(id),
                InfoVlan::Protocol(protocol),
                InfoVlan::Flags((VlanFlags::ReorderHdr, VlanFlags::all())),
            ])),
        ]),
    ]
}

fn encode(index: u32, attributes: Vec<LinkAttribute>) -> Vec<u8> {
    let mut link = LinkMessage::default();
    link.header.index = index;
    link.attributes = attributes;
    let mut packet = NetlinkMessage::from(RouteNetlinkMessage::NewLink(link));
    packet.finalize();
    let mut bytes = vec![0; packet.buffer_len()];
    packet.serialize(&mut bytes);
    bytes
}

#[test]
fn extracts_single_vlan_identifier_protocol_and_parent() -> Result<(), Box<dyn Error>> {
    for (id, wire, expected) in [
        (0, WireProtocol::Ieee8021Q, VlanProtocol::Ieee8021Q),
        (37, WireProtocol::Ieee8021Ad, VlanProtocol::Ieee8021Ad),
        (4094, WireProtocol::Ieee8021Q, VlanProtocol::Ieee8021Q),
    ] {
        let info = decode_link(&encode(INDEX, vlan_attributes(id, wire)), INDEX)?
            .ok_or("VLAN metadata missing")?;
        assert_eq!(info.id, id);
        assert_eq!(info.protocol, expected);
        assert_eq!(info.parent_ifindex, PARENT);
        assert!(info.reorders_headers);
    }
    Ok(())
}

#[test]
fn reports_mutable_reorder_header_state_and_rejects_duplicates() -> Result<(), Box<dyn Error>> {
    let make = |flags: Vec<InfoVlan>| {
        let mut attrs = vec![
            InfoVlan::Id(37),
            InfoVlan::Protocol(WireProtocol::Ieee8021Q),
        ];
        attrs.extend(flags);
        vec![
            LinkAttribute::Link(PARENT),
            LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::Vlan),
                LinkInfo::Data(InfoData::Vlan(attrs)),
            ]),
        ]
    };
    let none = decode_link(&encode(INDEX, make(vec![])), INDEX)?.ok_or("missing VLAN")?;
    assert!(!none.reorders_headers);
    let other = InfoVlan::Flags((VlanFlags::Gvrp, VlanFlags::all()));
    let non_reorder =
        decode_link(&encode(INDEX, make(vec![other.clone()])), INDEX)?.ok_or("missing VLAN")?;
    assert!(!non_reorder.reorders_headers);
    assert!(decode_link(&encode(INDEX, make(vec![other.clone(), other])), INDEX).is_err());
    Ok(())
}

#[test]
fn ordinary_links_are_not_reported_as_vlan() -> Result<(), Box<dyn Error>> {
    let plain = encode(INDEX, vec![]);
    let veth = encode(
        INDEX,
        vec![LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
            InfoKind::Veth,
        )])],
    );
    assert_eq!(decode_link(&plain, INDEX)?, None);
    assert_eq!(decode_link(&veth, INDEX)?, None);
    Ok(())
}

#[test]
fn rejects_incomplete_duplicate_and_invalid_vlan_metadata() {
    let info = |items| {
        LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Vlan),
            LinkInfo::Data(InfoData::Vlan(items)),
        ])
    };
    let id = || InfoVlan::Id(37);
    let protocol = || InfoVlan::Protocol(WireProtocol::Ieee8021Q);
    let cases = [
        vec![info(vec![id(), protocol()])],
        vec![LinkAttribute::Link(0), info(vec![id(), protocol()])],
        vec![LinkAttribute::Link(INDEX), info(vec![id(), protocol()])],
        vec![
            LinkAttribute::Link(PARENT),
            LinkAttribute::Link(PARENT),
            info(vec![id(), protocol()]),
        ],
        vec![LinkAttribute::Link(PARENT), info(vec![protocol()])],
        vec![LinkAttribute::Link(PARENT), info(vec![id()])],
        vec![
            LinkAttribute::Link(PARENT),
            info(vec![InfoVlan::Id(4095), protocol()]),
        ],
        vec![
            LinkAttribute::Link(PARENT),
            info(vec![id(), id(), protocol()]),
        ],
        vec![
            LinkAttribute::Link(PARENT),
            info(vec![id(), protocol(), protocol()]),
        ],
        vec![
            LinkAttribute::Link(PARENT),
            LinkAttribute::LinkNetNsId(0),
            info(vec![id(), protocol()]),
        ],
        vec![
            LinkAttribute::Link(PARENT),
            info(vec![id(), protocol()]),
            info(vec![id(), protocol()]),
        ],
    ];
    for attributes in cases {
        assert!(decode_link(&encode(INDEX, attributes), INDEX).is_err());
    }
}

#[test]
fn rejects_unknown_protocol_even_when_dependency_would_treat_it_as_8021q()
-> Result<(), Box<dyn Error>> {
    let mut bytes = encode(INDEX, vlan_attributes(37, WireProtocol::Ieee8021Q));
    let marker = [6_u16.to_ne_bytes(), 5_u16.to_ne_bytes(), [0x81, 0], [0, 0]].concat();
    let offset = bytes
        .windows(marker.len())
        .position(|part| part == marker)
        .ok_or("protocol attribute not found")?;
    bytes
        .get_mut(offset + 4..offset + 6)
        .ok_or("protocol value missing")?
        .copy_from_slice(&[0x91, 0]);
    let error = decode_link(&bytes, INDEX)
        .err()
        .ok_or("unknown VLAN protocol was accepted")?;
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert!(matches!(error.get_ref(), Some(source) if source.is::<super::UnsupportedVlan>()));
    Ok(())
}

#[test]
fn rejects_wrong_index_truncated_message_and_trailing_bytes() -> Result<(), Box<dyn Error>> {
    let bytes = encode(INDEX, vlan_attributes(37, WireProtocol::Ieee8021Q));
    assert!(decode_link(&bytes, INDEX + 1).is_err());
    for length in 0..bytes.len() {
        assert!(
            decode_link(bytes.get(..length).ok_or("missing prefix")?, INDEX).is_err(),
            "truncated at {length}"
        );
    }
    let mut extra = bytes;
    extra.push(0);
    assert!(decode_link(&extra, INDEX).is_err());
    Ok(())
}

#[test]
#[ignore = "queries only VLAN interfaces in a proved private network namespace"]
fn decodes_real_kernel_vlan_metadata_for_both_protocols_and_reorder_states()
-> Result<(), Box<dyn Error>> {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vlan/kernel.py");
    let output = std::process::Command::new("python3").arg(script).output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::str::from_utf8(&output.stdout)?;
    let q_index: u32 = field(text, "q_index")?.parse()?;
    let ad_index: u32 = field(text, "ad_index")?.parse()?;
    let parent: u32 = field(text, "parent")?.parse()?;
    for (key, index, protocol, reorder) in [
        ("q_on", q_index, VlanProtocol::Ieee8021Q, true),
        ("q_off", q_index, VlanProtocol::Ieee8021Q, false),
        ("ad_on", ad_index, VlanProtocol::Ieee8021Ad, true),
    ] {
        let raw = field(text, key)?
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        let info = decode_link(&raw, index)?.ok_or("missing kernel VLAN metadata")?;
        assert_eq!(info.id, 37);
        assert_eq!(info.parent_ifindex, parent);
        assert_eq!(info.protocol, protocol);
        assert_eq!(info.reorders_headers, reorder);
    }
    assert!(text.contains("cleanup_confirmed=true"));
    Ok(())
}

fn field<'a>(text: &'a str, key: &str) -> Result<&'a str, Box<dyn Error>> {
    let prefix = format!("{key}=");
    text.split_whitespace()
        .find_map(|item| item.strip_prefix(&prefix))
        .ok_or_else(|| format!("missing fixture field {key}").into())
}
