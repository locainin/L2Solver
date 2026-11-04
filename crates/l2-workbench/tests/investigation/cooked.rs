use super::{
    case_support::located_records,
    support::{cooked, fragment, tcp},
};
use l2_capture::{
    CaptureLocator, CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus,
    InterfaceId, LinkType, TimestampResolution, TimestampSource,
};
use l2_pcap::{InterfaceConfig, MAX_EVIDENCE_OUTPUT_BYTES, PcapNgReader, PcapNgWriter};
use l2_workbench::{
    investigation::{BuildInput, Record, build},
    sha256,
};
use serde_json::json;
use std::error::Error;
use std::io::Cursor;

#[test]
fn cooked_packet_nodes_preserve_header_metadata_ip_and_tcp_provenance() -> Result<(), Box<dyn Error>>
{
    for (version, header, ifindex) in [(113, 16, None), (276, 20, Some(91))] {
        let frame = cooked(
            tcp(false, 101, 0x18, b"payload")?.bytes(),
            version,
            InterfaceId {
                section: 3,
                index: 5,
            },
            91,
        )?;
        let (records, length) = located_records(vec![frame])?;
        let result = build(BuildInput {
            label: "cooked capture",
            length,
            sha256_hex: &sha256(b"cooked packet source"),
            records: &records,
            frames_seen: 1,
        })?;
        result.case.validate()?;
        let packet = result
            .case
            .nodes()
            .iter()
            .find(|node| node.kind == "packet")
            .ok_or("missing cooked packet")?;
        let bytes = result
            .case
            .blobs()
            .iter()
            .find(|blob| Some(&blob.id) == packet.blob.as_ref())
            .ok_or("missing raw packet bytes")?;
        let record = records.first().ok_or("missing source record")?;
        assert_eq!(bytes.bytes, record.frame.bytes());
        assert_packet_metadata(&packet.details, version, ifindex);
        let run = result
            .case
            .nodes()
            .iter()
            .find(|node| node.kind == "tcp_byte_run")
            .ok_or("missing TCP byte run")?;
        let Some(CaptureLocator::ClassicPcap { data_offset, .. }) =
            record.frame.metadata().locator()
        else {
            return Err("missing locator".into());
        };
        assert!(
            run.ranges
                .iter()
                .any(|range| range.offset == data_offset + header + 40 && range.length == 7)
        );
        assert!(
            !result
                .case
                .nodes()
                .iter()
                .any(|node| node.kind == "ip_communication")
        );
        assert!(
            result
                .case
                .limitations()
                .iter()
                .any(|text| text.contains("SLL1") && text.contains("VLAN"))
        );
    }
    Ok(())
}

fn assert_packet_metadata(details: &serde_json::Value, version: u16, ifindex: Option<u64>) {
    assert_eq!(details.get("source_ip"), Some(&json!("192.0.2.1")));
    assert_eq!(details.get("destination_ip"), Some(&json!("192.0.2.2")));
    assert!(details.get("source_mac").is_none());
    assert!(details.get("destination_mac").is_none());
    assert_eq!(details.pointer("/scope/section"), Some(&json!(3)));
    assert_eq!(details.pointer("/scope/interface"), Some(&json!(5)));
    assert_eq!(
        details
            .pointer("/scope/cooked_ifindex")
            .and_then(serde_json::Value::as_u64),
        ifindex
    );
    assert_eq!(
        details.pointer("/cooked/version"),
        Some(&json!(if version == 113 { "sll1" } else { "sll2" }))
    );
    assert_eq!(details.pointer("/cooked/hardware_type"), Some(&json!(1)));
    assert_eq!(details.pointer("/cooked/packet_type"), Some(&json!(0)));
    assert_eq!(
        details.pointer("/cooked/address"),
        Some(&json!([2, 0, 0, 0, 0, 1]))
    );
    assert_eq!(details.pointer("/cooked/address_length"), Some(&json!(6)));
}

#[test]
fn opaque_cooked_protocols_never_interpret_ip_or_claim_complete_analysis()
-> Result<(), Box<dyn Error>> {
    for version in [113, 276] {
        let frame = cooked(
            tcp(false, 101, 0x18, b"hidden")?.bytes(),
            version,
            InterfaceId {
                section: 0,
                index: 0,
            },
            5,
        )?;
        // A VLAN protocol needs its own decoder and cannot be treated as direct IP
        let mut bytes = frame.bytes().to_vec();
        let offset = if version == 113 { 14 } else { 0 };
        bytes
            .get_mut(offset..offset + 2)
            .ok_or("missing protocol")?
            .copy_from_slice(&0x8100_u16.to_be_bytes());
        let frame = l2_capture::CapturedFrame::new(bytes, frame.metadata().clone())?;
        let (records, length) = located_records(vec![frame])?;
        let result = build(BuildInput {
            label: "opaque cooked capture",
            length,
            sha256_hex: &sha256(b"opaque cooked source"),
            records: &records,
            frames_seen: 1,
        })?;
        let packet = result
            .case
            .nodes()
            .iter()
            .find(|node| node.kind == "packet")
            .ok_or("missing packet")?;
        assert!(packet.details.get("source_ip").is_none());
        assert!(
            !result
                .case
                .nodes()
                .iter()
                .any(|node| node.kind == "tcp_episode")
        );
        assert!(!result.complete);
        assert!(
            result
                .case
                .limitations()
                .iter()
                .any(|text| text.contains("protocol layouts"))
        );
    }
    Ok(())
}

#[test]
fn truncated_cooked_headers_keep_bytes_and_mark_case_incomplete() -> Result<(), Box<dyn Error>> {
    for (version, header) in [(113, 16), (276, 20)] {
        let frame = cooked(
            tcp(false, 101, 0x18, b"hidden")?.bytes(),
            version,
            InterfaceId {
                section: 0,
                index: 0,
            },
            5,
        )?;
        let bytes = frame
            .bytes()
            .get(..header - 1)
            .ok_or("short fixture")?
            .to_vec();
        let truncated = CapturedFrame::new(bytes.clone(), frame.metadata().clone())?;
        let (records, length) = located_records(vec![truncated])?;
        let result = build(BuildInput {
            label: "truncated cooked capture",
            length,
            sha256_hex: &sha256(b"truncated cooked source"),
            records: &records,
            frames_seen: 1,
        })?;
        let packet = result
            .case
            .nodes()
            .iter()
            .find(|node| node.kind == "packet")
            .ok_or("missing packet")?;
        let blob = result
            .case
            .blobs()
            .iter()
            .find(|blob| Some(&blob.id) == packet.blob.as_ref())
            .ok_or("missing raw bytes")?;
        assert_eq!(blob.bytes, bytes);
        assert_eq!(packet.details.get("truncated"), Some(&json!(true)));
        assert!(packet.details.get("source_ip").is_none());
        assert!(packet.details.get("cooked").is_none());
        assert!(!result.complete);
    }
    Ok(())
}

#[test]
fn mixed_pcapng_interfaces_keep_scopes_and_literal_byte_ranges() -> Result<(), Box<dyn Error>> {
    let capture = mixed_pcapng()?;
    let mut reader = PcapNgReader::new(Cursor::new(&capture))?;
    let mut records = Vec::new();
    while let Some(frame) = reader.next_packet()? {
        records.push(Record {
            number: u32::try_from(records.len() + 1)?,
            frame,
        });
    }
    assert_eq!(records.len(), 4);
    let result = build(BuildInput {
        label: "mixed.pcapng",
        length: u64::try_from(capture.len())?,
        sha256_hex: &sha256(&capture),
        records: &records,
        frames_seen: 4,
    })?;
    result.case.validate()?;
    let runs: Vec<_> = result
        .case
        .nodes()
        .iter()
        .filter(|node| node.kind == "tcp_byte_run")
        .collect();
    assert_eq!(runs.len(), 4);
    for run in runs {
        let blob = result
            .case
            .blobs()
            .iter()
            .find(|blob| Some(&blob.id) == run.blob.as_ref())
            .ok_or("missing TCP bytes")?;
        let range = run.ranges.first().ok_or("missing TCP source range")?;
        let start = usize::try_from(range.offset)?;
        let end = start
            .checked_add(usize::try_from(range.length)?)
            .ok_or("source range overflow")?;
        assert_eq!(capture.get(start..end), Some(blob.bytes.as_slice()));
    }
    let mut cooked_scopes = result
        .case
        .nodes()
        .iter()
        .filter(|node| node.kind == "packet")
        .filter(|node| node.details.pointer("/scope/cooked_ifindex") == Some(&json!(37)))
        .filter_map(|node| {
            node.details
                .pointer("/scope/interface")
                .and_then(serde_json::Value::as_u64)
        })
        .collect::<Vec<_>>();
    cooked_scopes.sort_unstable();
    assert_eq!(cooked_scopes, [2, 3]);
    Ok(())
}

fn mixed_pcapng() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    for (index, link_type) in [
        (0, LinkType::Ethernet),
        (1, LinkType::LinuxSll),
        (2, LinkType::LinuxSll2),
        (3, LinkType::LinuxSll2),
    ] {
        writer.add_interface(
            InterfaceId { section: 0, index },
            InterfaceConfig::new_with_link_type(
                link_type,
                65_535,
                TimestampResolution::MICROSECOND,
                0,
                FcsStatus::Unknown,
            )?,
        )?;
    }
    for (index, version, payload) in [
        (0, 1, b"ether".as_slice()),
        (1, 113, b"sll1".as_slice()),
        (2, 276, b"first-sll2".as_slice()),
        (3, 276, b"second-sll2".as_slice()),
    ] {
        let source = tcp(false, 101, 0x18, payload)?;
        let interface = InterfaceId { section: 0, index };
        let frame = if version == 1 {
            source
        } else {
            cooked(source.bytes(), version, interface, 37)?
        };
        let metadata = CaptureMetadata::new(
            interface,
            u32::try_from(frame.bytes().len())?,
            None,
            Some(CaptureTimestamp::new(
                0,
                TimestampResolution::MICROSECOND,
                0,
                TimestampSource::Unknown,
            )),
            Direction::Unknown,
            None,
            FcsStatus::Unknown,
        )
        .with_link_type(frame.metadata().link_type());
        writer.write_frame(&CapturedFrame::new(frame.bytes().to_vec(), metadata)?)?;
    }
    writer.finish()?;
    Ok(writer.into_inner())
}

#[test]
fn cooked_dns_observation_uses_exact_payload_offset() -> Result<(), Box<dyn Error>> {
    let dns = [
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
    ];
    let mut udp = vec![0x9c, 0x40, 0, 53, 0, u8::try_from(8 + dns.len())?, 0, 0];
    udp.extend_from_slice(&dns);
    for (version, header) in [(113, 16), (276, 20)] {
        let frame = cooked(
            fragment(0, &udp)?.bytes(),
            version,
            InterfaceId {
                section: 1,
                index: 2,
            },
            7,
        )?;
        let (records, length) = located_records(vec![frame])?;
        let result = build(BuildInput {
            label: "dns capture",
            length,
            sha256_hex: &sha256(b"cooked DNS source"),
            records: &records,
            frames_seen: 1,
        })?;
        let node = result
            .case
            .nodes()
            .iter()
            .find(|node| node.kind == "dns_wire")
            .ok_or("missing DNS wire observation")?;
        assert_eq!(
            node.details.get("payload_offset"),
            Some(&json!(header + 28))
        );
        assert_eq!(node.details.get("payload_length"), Some(&json!(dns.len())));
        let udp_node = result
            .case
            .nodes()
            .iter()
            .find(|node| node.kind == "udp_payload")
            .ok_or("missing UDP payload")?;
        let blob = result
            .case
            .blobs()
            .iter()
            .find(|blob| Some(&blob.id) == udp_node.blob.as_ref())
            .ok_or("missing UDP bytes")?;
        assert_eq!(blob.bytes, dns);
    }
    Ok(())
}
