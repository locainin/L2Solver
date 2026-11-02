use super::{capture, cooked_fixture, dns, fragments, frames, udp};
use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus, InterfaceId, LinkType,
    TimestampResolution, TimestampSource,
};
use l2_pcap::{InterfaceConfig, PcapNgWriter};
use l2_workbench::store::{Options, SharedFactKind, Store};
use rusqlite::Connection;
use std::{error::Error, io::Cursor};

type TestResult = Result<(), Box<dyn Error>>;

fn classic(
    version: u16,
    seconds: u32,
    frames: &[CapturedFrame],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&65_535_u32.to_le_bytes());
    bytes.extend_from_slice(&u32::from(version).to_le_bytes());
    for frame in frames {
        bytes.extend_from_slice(&seconds.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        let length = u32::try_from(frame.bytes().len())?;
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(frame.bytes());
    }
    Ok(bytes)
}

fn ipv6_from_ipv4(frame: &CapturedFrame, protocol: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    let body = frame.bytes().get(34..).ok_or("missing IPv4 body")?;
    let mut bytes = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x86, 0xdd];
    bytes.extend_from_slice(&[0x60, 0, 0, 0]);
    bytes.extend_from_slice(&u16::try_from(body.len())?.to_be_bytes());
    bytes.extend_from_slice(&[protocol, 64]);
    bytes.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    bytes.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    bytes.extend_from_slice(body);
    Ok(bytes)
}

fn frame(bytes: &[u8], version: u16, ifindex: u32) -> Result<CapturedFrame, Box<dyn Error>> {
    cooked_fixture::cooked(
        bytes,
        version,
        InterfaceId {
            section: 0,
            index: 0,
        },
        ifindex,
    )
}

#[test]
fn classic_cooked_indexes_ipv4_ipv6_tcp_udp_and_shared_nontransport_facts() -> TestResult {
    for version in [113_u16, 276] {
        let tcp4 = frames::tcp(false, 101, 0x18, b"data")?;
        let udp4 = udp(false, &dns(false))?;
        let tcp6 = ipv6_from_ipv4(&tcp4, 6)?;
        let udp6 = ipv6_from_ipv4(&udp4, 17)?;
        let fragment = fragments::fragment(0x2000, b"fragment")?;
        let frames = [
            frame(tcp4.bytes(), version, 37)?,
            frame(udp4.bytes(), version, 37)?,
            frame(&tcp6, version, 37)?,
            frame(&udp6, version, 37)?,
            frame(fragment.bytes(), version, 37)?,
        ];
        let temporary = tempfile::tempdir()?;
        let mut store = Store::create(temporary.path(), Options::default())?;
        let first = store.ingest("first", Cursor::new(classic(version, 1, &frames)?))?;
        let second = store.ingest("second", Cursor::new(classic(version, 2, &frames)?))?;
        assert_eq!(
            (first.transport_packets, first.unsupported_transport_packets),
            (4, 1)
        );
        assert_eq!(store.inventory()?.flows, 8);
        let first_packet = store.packet(&first.source_id, 1)?;
        assert!(first_packet.flow.is_some());
        assert!(store.packet(&first.source_id, 5)?.flow.is_none());
        let mut found_fragment = false;
        store.visit_shared_occurrences(
            SharedFactKind::IpAddress,
            &[192, 0, 2, 1],
            None,
            None,
            |occurrence| {
                if occurrence.source_id == first.source_id && occurrence.packet == 5 {
                    found_fragment = occurrence.scope.is_some();
                }
                Ok(())
            },
        )?;
        assert!(
            found_fragment,
            "fragment IP address and scope must be indexed"
        );
        let mut question_offset = None;
        store.visit_shared_groups(None, None, |group| {
            if group.kind == SharedFactKind::DnsQuestion {
                store.visit_shared_occurrences(
                    group.kind,
                    &group.key,
                    None,
                    None,
                    |occurrence| {
                        if occurrence.source_id == first.source_id && occurrence.packet == 2 {
                            question_offset = Some(occurrence.range.offset);
                        }
                        Ok(())
                    },
                )?;
            }
            Ok(())
        })?;
        let dns_packet = store.packet(&first.source_id, 2)?;
        let link_header = if version == 113 { 16 } else { 20 };
        assert_eq!(
            question_offset,
            Some(dns_packet.range.offset + link_header + 20 + 8)
        );
        assert_eq!(
            store.frame(&second.source_id, 1)?.bytes(),
            frames.first().ok_or("missing cooked frame")?.bytes()
        );
        store.verify_sources()?;
        drop(store);
        Store::open(temporary.path(), Options::default())?.verify_sources()?;
    }
    Ok(())
}

#[test]
fn pcapng_sll2_ifindex_is_separate_from_capture_interface_and_flow_scope() -> TestResult {
    let input = frames::tcp(false, 101, 0x18, b"data")?;
    let mut writer = PcapNgWriter::new(Vec::new(), 1_048_576)?;
    let interface = InterfaceId {
        section: 0,
        index: 0,
    };
    writer.add_interface(
        interface,
        InterfaceConfig::new_with_link_type(
            LinkType::LinuxSll2,
            65_535,
            TimestampResolution::MICROSECOND,
            0,
            FcsStatus::Unknown,
        )?,
    )?;
    for ifindex in [37_u32, 38, 37] {
        let bytes = frame(input.bytes(), 276, ifindex)?.bytes().to_vec();
        let metadata = CaptureMetadata::new(
            interface,
            u32::try_from(bytes.len())?,
            None,
            Some(CaptureTimestamp::new(
                1,
                TimestampResolution::MICROSECOND,
                0,
                TimestampSource::CaptureFile,
            )),
            Direction::Unknown,
            None,
            FcsStatus::Unknown,
        )
        .with_link_type(LinkType::LinuxSll2);
        writer.write_frame(&CapturedFrame::new(bytes, metadata)?)?;
    }
    writer.finish()?;
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let receipt = store.ingest("sll2", Cursor::new(writer.into_inner()))?;
    assert_eq!(receipt.transport_packets, 3);
    let first = store.packet(&receipt.source_id, 1)?.flow;
    assert_eq!(first, store.packet(&receipt.source_id, 3)?.flow);
    assert_ne!(first, store.packet(&receipt.source_id, 2)?.flow);
    let mut scopes = Vec::new();
    store.visit_flows(0, None, |flow| {
        scopes.push(flow.scope);
        Ok(())
    })?;
    assert_eq!(scopes.len(), 2);
    for (scope, ifindex) in scopes.iter().zip([37, 38]) {
        assert_eq!(scope.get("interface"), Some(&serde_json::json!(0)));
        assert_eq!(
            scope.get("cooked_ifindex"),
            Some(&serde_json::json!(ifindex))
        );
        assert_eq!(scope.get("vlan_ids"), Some(&serde_json::json!([])));
    }
    store.verify_sources()?;
    Ok(())
}

#[test]
fn legacy_index_accepts_ethernet_but_rejects_cooked_requiring_reindex() -> TestResult {
    for version in [1_u16, 113, 276] {
        let packet = frames::tcp(false, 101, 0x18, b"data")?;
        let bytes = if version == 1 {
            capture(&[packet])?
        } else {
            classic(version, 1, &[frame(packet.bytes(), version, 37)?])?
        };
        let temporary = tempfile::tempdir()?;
        let mut store = Store::create(temporary.path(), Options::default())?;
        store.ingest("old", Cursor::new(bytes))?;
        drop(store);
        let connection = Connection::open(temporary.path().join("index.sqlite"))?;
        connection.pragma_update(None, "user_version", 5)?;
        drop(connection);
        if version == 1 {
            Store::open(temporary.path(), Options::default())?.verify_sources()?;
        } else {
            let Err(error) = Store::open(temporary.path(), Options::default()) else {
                return Err("legacy cooked index was accepted".into());
            };
            assert!(error.to_string().contains("rebuild"));
        }
    }
    Ok(())
}

#[test]
fn unsupported_cooked_payloads_remain_opaque_without_ip_or_flow_facts() -> TestResult {
    let tcp = frames::tcp(false, 101, 0x18, b"data")?;
    let valid = frame(tcp.bytes(), 276, 37)?;
    let mut bad_reserved = valid.bytes().to_vec();
    *bad_reserved.get_mut(3).ok_or("missing reserved field")? = 1;
    let mut vlan = valid.bytes().to_vec();
    vlan.get_mut(..2)
        .ok_or("missing protocol field")?
        .copy_from_slice(&0x8100_u16.to_be_bytes());
    let frames = [
        CapturedFrame::new(bad_reserved, valid.metadata().clone())?,
        CapturedFrame::new(vlan, valid.metadata().clone())?,
    ];
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    for second in [1, 2] {
        let receipt = store.ingest("opaque", Cursor::new(classic(276, second, &frames)?))?;
        assert_eq!(
            (
                receipt.transport_packets,
                receipt.unsupported_transport_packets
            ),
            (0, 2)
        );
    }
    assert_eq!(store.inventory()?.flows, 0);
    store.visit_shared_groups(None, None, |group| {
        assert_ne!(group.kind, SharedFactKind::IpAddress);
        Ok(())
    })?;
    store.verify_sources()?;
    Ok(())
}
