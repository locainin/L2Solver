use l2_capture::LinkType;
use l2_core::FrameField;
use l2_discovery::link::{CookedPacketType, CookedVersion, decode_network_frame};

fn cooked(link_type: LinkType, protocol: u16, address_length: u16, payload: &[u8]) -> Vec<u8> {
    let address = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    let mut bytes = Vec::new();
    match link_type {
        LinkType::LinuxSll => {
            bytes.extend_from_slice(&4_u16.to_be_bytes());
            bytes.extend_from_slice(&1_u16.to_be_bytes());
            bytes.extend_from_slice(&address_length.to_be_bytes());
            bytes.extend_from_slice(&address);
            bytes.extend_from_slice(&protocol.to_be_bytes());
        }
        LinkType::LinuxSll2 => {
            bytes.extend_from_slice(&protocol.to_be_bytes());
            bytes.extend_from_slice(&0_u16.to_be_bytes());
            bytes.extend_from_slice(&0x0102_0304_u32.to_be_bytes());
            bytes.extend_from_slice(&1_u16.to_be_bytes());
            bytes.push(4);
            bytes.push(u8::try_from(address_length).unwrap_or_default());
            bytes.extend_from_slice(&address);
        }
        _ => return bytes,
    }
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn cooked_headers_expose_checked_fields_and_exact_payload_offsets() -> Result<(), &'static str> {
    for (link_type, version, offset, interface) in [
        (LinkType::LinuxSll, CookedVersion::V1, 16, None),
        (
            LinkType::LinuxSll2,
            CookedVersion::V2,
            20,
            Some(0x0102_0304),
        ),
    ] {
        let bytes = cooked(link_type, 0x0800, 6, &[0xaa, 0xbb]);
        let frame = decode_network_frame(link_type, &bytes).ok_or("missing cooked frame")?;
        let header = frame.cooked().ok_or("missing cooked header")?;
        assert_eq!(header.version(), version);
        assert_eq!(header.packet_type(), CookedPacketType::Outgoing);
        assert_eq!(header.hardware_type(), 1);
        assert_eq!(header.address_length(), 6);
        assert_eq!(header.address(), [0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);
        assert_eq!(header.interface_index(), interface);
        assert!(frame.ethernet().is_none());
        assert_eq!(frame.protocol(), 0x0800);
        assert_eq!(frame.field(), Some(FrameField::EtherType(0x0800)));
        assert_eq!(frame.payload_offset(), offset);
        assert_eq!(frame.payload(), [0xaa, 0xbb]);
    }
    Ok(())
}

#[test]
fn cooked_address_is_bounded_to_bytes_present_in_header() -> Result<(), &'static str> {
    for link_type in [LinkType::LinuxSll, LinkType::LinuxSll2] {
        for length in [0_u16, 1, 8, 9, 255] {
            let bytes = cooked(link_type, 0x0800, length, &[0xaa]);
            let frame = decode_network_frame(link_type, &bytes).ok_or("missing cooked frame")?;
            let header = frame.cooked().ok_or("missing cooked header")?;
            assert_eq!(header.address_length(), length);
            assert_eq!(header.address().len(), usize::from(length).min(8));
            assert_eq!(frame.payload(), [0xaa]);
        }
    }
    Ok(())
}

#[test]
fn cooked_fixed_headers_require_every_byte() -> Result<(), &'static str> {
    for (link_type, header_len) in [(LinkType::LinuxSll, 16), (LinkType::LinuxSll2, 20)] {
        let bytes = cooked(link_type, 0x0800, 0, &[]);
        for length in 0..header_len {
            let prefix = bytes.get(..length).ok_or("bad fixture prefix")?;
            assert!(
                decode_network_frame(link_type, prefix).is_none(),
                "accepted {length} bytes"
            );
        }
        let frame = decode_network_frame(link_type, &bytes).ok_or("missing empty cooked frame")?;
        assert_eq!(frame.payload_offset(), header_len);
        assert_eq!(frame.payload(), []);
    }
    Ok(())
}

#[test]
fn cooked_rejects_invalid_packet_types_and_nonzero_sll2_reserved() -> Result<(), &'static str> {
    let mut v1 = cooked(LinkType::LinuxSll, 0x0800, 0, &[]);
    let mut v2 = cooked(LinkType::LinuxSll2, 0x0800, 0, &[]);
    for value in [5_u16, 256, u16::MAX] {
        v1.get_mut(..2)
            .ok_or("short fixture")?
            .copy_from_slice(&value.to_be_bytes());
        assert!(decode_network_frame(LinkType::LinuxSll, &v1).is_none());
    }
    *v2.get_mut(10).ok_or("short fixture")? = 5;
    assert!(decode_network_frame(LinkType::LinuxSll2, &v2).is_none());
    *v2.get_mut(10).ok_or("short fixture")? = 4;
    *v2.get_mut(3).ok_or("short fixture")? = 1;
    assert!(decode_network_frame(LinkType::LinuxSll2, &v2).is_none());
    Ok(())
}

#[test]
fn cooked_packet_types_preserve_each_assigned_value() -> Result<(), &'static str> {
    for link_type in [LinkType::LinuxSll, LinkType::LinuxSll2] {
        for (raw, expected) in [
            (0_u8, CookedPacketType::Host),
            (1, CookedPacketType::Broadcast),
            (2, CookedPacketType::Multicast),
            (3, CookedPacketType::OtherHost),
            (4, CookedPacketType::Outgoing),
        ] {
            let mut bytes = cooked(link_type, 0x0800, 0, &[]);
            let position = if link_type == LinkType::LinuxSll {
                1
            } else {
                10
            };
            *bytes.get_mut(position).ok_or("short fixture")? = raw;
            let frame = decode_network_frame(link_type, &bytes).ok_or("missing cooked frame")?;
            let header = frame.cooked().ok_or("missing cooked header")?;
            assert_eq!(header.packet_type(), expected);
            assert_eq!(header.packet_type().raw(), u16::from(raw));
        }
    }
    Ok(())
}

#[test]
fn cooked_unsupported_protocol_meanings_are_not_ethernet_fields() -> Result<(), &'static str> {
    for link_type in [LinkType::LinuxSll, LinkType::LinuxSll2] {
        for protocol in [0x0001, 0x0004, 0x8100, 0x88a8, 0x9100, 0x9200, 0x9300] {
            let bytes = cooked(link_type, protocol, 0, &[]);
            let frame = decode_network_frame(link_type, &bytes).ok_or("missing cooked frame")?;
            assert_eq!(frame.protocol(), protocol);
            assert!(frame.field().is_none());
        }
        for hardware in [770_u16, 803, 824] {
            let mut bytes = cooked(link_type, 0x0800, 0, &[]);
            let position = if link_type == LinkType::LinuxSll {
                2
            } else {
                8
            };
            bytes
                .get_mut(position..position + 2)
                .ok_or("short fixture")?
                .copy_from_slice(&hardware.to_be_bytes());
            let frame = decode_network_frame(link_type, &bytes).ok_or("missing cooked frame")?;
            assert!(frame.field().is_none());
        }
    }
    Ok(())
}

#[test]
fn ethernet_vlan_offsets_and_unsupported_link_types_remain_distinct() -> Result<(), &'static str> {
    let bytes = [
        2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x81, 0, 0, 7, 0x88, 0xa8, 0, 9, 0x08, 0x00, 0x45, 0,
    ];
    let frame = decode_network_frame(LinkType::Ethernet, &bytes).ok_or("missing Ethernet frame")?;
    assert_eq!(frame.field(), Some(FrameField::EtherType(0x0800)));
    assert_eq!(frame.protocol(), 0x0800);
    assert_eq!(frame.payload_offset(), 22);
    assert_eq!(frame.payload(), [0x45, 0]);
    assert_eq!(
        frame
            .ethernet()
            .ok_or("missing Ethernet facts")?
            .vlan_tags
            .len(),
        2
    );
    assert!(frame.cooked().is_none());
    assert!(decode_network_frame(LinkType::Ieee80211, &bytes).is_none());
    assert!(decode_network_frame(LinkType::Unknown(999), &bytes).is_none());
    Ok(())
}
