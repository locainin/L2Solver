#[path = "reconstruction/ipv4.rs"]
mod ipv4;

#[path = "reconstruction/fragment.rs"]
mod fragments;

#[path = "reconstruction/tcp.rs"]
mod frames;

#[path = "store/collection.rs"]
mod collection;

#[path = "../../../tests/fixtures/cooked.rs"]
mod cooked_fixture;

#[path = "store/cooked.rs"]
mod cooked;

#[path = "store/cache.rs"]
mod cache;

#[path = "store/integrity.rs"]
mod integrity;

#[path = "store/link_types.rs"]
mod link_types;

#[path = "store/dns_relationships.rs"]
mod dns_relationships;

#[path = "store/flow_frames.rs"]
mod flow_frames;

#[path = "store/multi_flow.rs"]
mod multi_flow;

#[path = "store/memory.rs"]
mod memory;

#[path = "store/scopes.rs"]
mod scopes;

#[path = "store/support.rs"]
mod support;

use l2_capture::CapturedFrame;
use l2_workbench::{
    sha256,
    store::{Options, Store},
};
use std::{error::Error, io::Cursor};
use support::capture;

#[test]
fn index_exact_original_ranges_reopen() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let frames = [
        frames::tcp(false, 100, 2, b"")?,
        frames::tcp(false, 101, 0x10, b"hello")?,
    ];
    let bytes = capture(&frames)?;
    let mut store = Store::create(temp.path(), Options::default())?;
    let source = store.ingest("capture.pcap", Cursor::new(&bytes))?;
    assert_eq!(source.source_id, format!("sha256:{}", sha256(&bytes)));
    assert_eq!(source.packets, 2);
    assert_eq!(source.bytes, u64::try_from(bytes.len())?);
    assert_eq!(store.inventory()?.flows, 1);
    drop(store);
    let store = Store::open(temp.path(), Options::default())?;
    let packet = store.packet(&source.source_id, 2)?;
    assert_eq!(
        packet.range.offset,
        24 + 16 + u64::try_from(frames.first().ok_or("missing frame")?.bytes().len())? + 16
    );
    assert_eq!(packet.range.packet, Some(2));
    assert_eq!(
        store.frame(&source.source_id, 2)?.bytes(),
        frames.last().ok_or("missing frame")?.bytes()
    );
    store.verify_sources()?;
    Ok(())
}

#[test]
fn index_source_linux_identity_reopen() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let packet = frames::tcp(false, 100, 2, b"")?;
    let identity = l2_capture::LinuxInterfaceIdentity::new(1, 2, 3, 4, 7)?;
    let time = l2_capture::CaptureTimestamp::new(
        12,
        l2_capture::TimestampResolution::MICROSECOND,
        0,
        l2_capture::TimestampSource::Unknown,
    );
    let metadata = packet.metadata();
    let packet = CapturedFrame::new(
        packet.bytes().to_vec(),
        l2_capture::CaptureMetadata::new(
            metadata.interface(),
            metadata.original_len(),
            None,
            Some(time),
            metadata.direction(),
            metadata.vlan(),
            metadata.fcs(),
        )
        .with_link_type(metadata.link_type())
        .with_linux_interface(identity),
    )?;
    let metadata = packet.metadata();
    let time = metadata.timestamp().ok_or("missing timestamp")?;
    let config = l2_pcap::InterfaceConfig::new_with_link_type(
        metadata.link_type(),
        65_535,
        time.resolution(),
        time.offset_seconds(),
        metadata.fcs(),
    )?
    .with_linux_interface(identity);
    let mut writer = l2_pcap::PcapNgWriter::new(Vec::new(), 1_048_576)?;
    writer.add_interface_and_write_frame(metadata.interface(), config, &packet)?;
    writer.finish()?;
    let mut store = Store::create(temp.path(), Options::default())?;
    let source = store.ingest("live.pcapng", Cursor::new(writer.into_inner()))?;
    drop(store);
    let store = Store::open(temp.path(), Options::default())?;
    assert_eq!(
        store
            .frame(&source.source_id, 1)?
            .metadata()
            .linux_interface(),
        Some(identity)
    );
    store.verify_sources()?;
    Ok(())
}

#[test]
fn bidirectional_flow_crosses_arbitrarily_distant() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let mut packets = vec![frames::tcp(false, 100, 2, b"")?];
    for number in 0..1400_u32 {
        packets.push(frames::tcp_ports(
            false,
            (41000, 8000),
            number,
            0x10,
            b"noise",
        )?);
    }
    packets.push(frames::tcp(true, 900, 0x12, b"reply")?);
    let mut store = Store::create(temp.path(), Options::default())?;
    let source = store.ingest("distant.pcap", Cursor::new(capture(&packets)?))?;
    let first = store.packet(&source.source_id, 1)?;
    let last = store.packet(&source.source_id, 1402)?;
    assert!(first.flow.is_some());
    assert_eq!(first.flow, last.flow);
    assert_eq!(store.inventory()?.flows, 2);
    let mut selected = Vec::new();
    store.visit_flow_packets(first.flow.ok_or("missing flow")?, |packet| {
        selected.push(packet.number);
        Ok(())
    })?;
    assert_eq!(selected, [1, 1402]);
    Ok(())
}

#[test]
fn different_sources_never_transport_identity() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let mut store = Store::create(temp.path(), Options::default())?;
    let first = store.ingest(
        "first",
        Cursor::new(capture(&[frames::tcp(false, 1, 2, b"a")?])?),
    )?;
    let second = store.ingest(
        "second",
        Cursor::new(capture(&[frames::tcp(false, 2, 2, b"b")?])?),
    )?;
    assert_ne!(
        store.packet(&first.source_id, 1)?.flow,
        store.packet(&second.source_id, 1)?.flow
    );
    assert_eq!(store.inventory()?.sources, 2);
    Ok(())
}

#[test]
fn failed_import_without_later_imports() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let mut store = Store::create(temp.path(), Options::default())?;
    let mut bytes = capture(&[frames::tcp(false, 1, 2, b"abc")?])?;
    bytes.pop();
    assert!(store.ingest("truncated", Cursor::new(bytes)).is_err());
    assert_eq!(store.inventory()?.sources, 0);
    assert_eq!(store.inventory()?.packets, 0);
    assert_eq!(std::fs::read_dir(temp.path().join("sources"))?.count(), 0);
    store.ingest(
        "good",
        Cursor::new(capture(&[frames::tcp(false, 1, 2, b"abc")?])?),
    )?;
    assert_eq!(store.inventory()?.packets, 1);
    Ok(())
}

#[test]
fn duplicate_source_not_extra_files() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let bytes = capture(&[frames::tcp(false, 1, 2, b"abc")?])?;
    let mut store = Store::create(temp.path(), Options::default())?;
    store.ingest("first", Cursor::new(&bytes))?;
    let Err(error) = store.ingest("same", Cursor::new(&bytes)) else {
        return Err("duplicate source content was accepted".into());
    };
    assert!(
        error
            .to_string()
            .contains("duplicate capture source content")
    );
    assert!(!error.to_string().contains("UNIQUE constraint"));
    assert_eq!(store.inventory()?.sources, 1);
    assert_eq!(store.inventory()?.packets, 1);
    assert_eq!(std::fs::read_dir(temp.path().join("sources"))?.count(), 1);
    Ok(())
}

#[test]
fn altered_retained_rejected_integrity_verification() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let mut store = Store::create(temp.path(), Options::default())?;
    let source = store.ingest(
        "source",
        Cursor::new(capture(&[frames::tcp(false, 1, 2, b"abc")?])?),
    )?;
    let path = temp.path().join("sources").join(format!(
        "{}.pcap",
        source
            .source_id
            .strip_prefix("sha256:")
            .ok_or("invalid source")?
    ));
    std::fs::write(path, b"changed")?;
    assert!(store.verify_sources().is_err());
    Ok(())
}

#[test]
fn creation_never_overwrites_existing_index() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let store = Store::create(temp.path(), Options::default())?;
    assert!(Store::create(temp.path(), Options::default()).is_err());
    assert_eq!(store.inventory()?.packets, 0);
    Ok(())
}

fn udp(reverse: bool, payload: &[u8]) -> Result<CapturedFrame, Box<dyn Error>> {
    let (source, destination) = if reverse {
        (53_u16, 44000_u16)
    } else {
        (44000, 53)
    };
    let mut body = source.to_be_bytes().to_vec();
    body.extend_from_slice(&destination.to_be_bytes());
    body.extend_from_slice(&u16::try_from(8 + payload.len())?.to_be_bytes());
    body.extend_from_slice(&[0; 2]);
    body.extend_from_slice(payload);
    let frame = fragments::fragment(0, &body)?;
    let mut bytes = frame.bytes().to_vec();
    if reverse {
        bytes
            .get_mut(26..30)
            .ok_or("missing source")?
            .copy_from_slice(&[192, 0, 2, 2]);
        bytes
            .get_mut(30..34)
            .ok_or("missing destination")?
            .copy_from_slice(&[192, 0, 2, 1]);
    }
    Ok(CapturedFrame::new(bytes, frame.metadata().clone())?)
}

fn dns(response: bool) -> Vec<u8> {
    let mut bytes = vec![0, 7];
    bytes.extend_from_slice(&if response { 0x8180_u16 } else { 0x0100 }.to_be_bytes());
    bytes.extend_from_slice(&[0, 1, 0, u8::from(response), 0, 0, 0, 0]);
    bytes.extend_from_slice(b"\x01x\x07invalid\x00\x00\x01\x00\x01");
    if response {
        bytes.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 2]);
    }
    bytes
}

#[test]
fn persistent_dns_packet_rdata_witnesses() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let mut packets = vec![udp(false, &dns(false))?];
    for number in 0..1400_u32 {
        packets.push(frames::tcp_ports(
            false,
            (42000, 8000),
            number,
            0x10,
            b"noise",
        )?);
    }
    packets.push(udp(true, &dns(true))?);
    packets.push(frames::tcp(false, 100, 2, b"")?);
    let mut store = Store::create(temp.path(), Options::default())?;
    store.ingest("distant-dns", Cursor::new(capture(&packets)?))?;
    let mut relationships = Vec::new();
    store.visit_relationships(None, |relationship| {
        relationships.push(relationship);
        Ok(())
    })?;
    let relation = relationships.first().ok_or("missing relationship")?;
    assert_eq!(relation.request_packet, Some(1));
    assert_eq!(relation.response_packet, 1402);
    assert_eq!(relation.destination_packet, 1403);
    assert_eq!(relation.association, "unique");
    assert_eq!(relation.answer_range.packet, Some(1402));
    assert_eq!(relation.answer_range.length, 4);
    Ok(())
}

#[test]
fn retransmitted_dns_requests_ambiguous_association() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let packets = [
        udp(false, &dns(false))?,
        udp(false, &dns(false))?,
        udp(true, &dns(true))?,
        frames::tcp(false, 100, 2, b"")?,
    ];
    let mut store = Store::create(temp.path(), Options::default())?;
    store.ingest("ambiguous-dns", Cursor::new(capture(&packets)?))?;
    let mut relationships = Vec::new();
    store.visit_relationships(None, |relationship| {
        relationships.push(relationship);
        Ok(())
    })?;
    let relation = relationships.first().ok_or("missing relationship")?;
    assert_eq!(relation.request_packet, None);
    assert_eq!(relation.association, "ambiguous");
    Ok(())
}

fn vlan(frame: &CapturedFrame, vid: u16) -> Result<CapturedFrame, Box<dyn Error>> {
    let mut bytes = frame
        .bytes()
        .get(..12)
        .ok_or("missing Ethernet prefix")?
        .to_vec();
    bytes.extend_from_slice(&0x8100_u16.to_be_bytes());
    bytes.extend_from_slice(&vid.to_be_bytes());
    bytes.extend_from_slice(frame.bytes().get(12..).ok_or("missing EtherType")?);
    let metadata = l2_capture::CaptureMetadata::unknown(
        l2_capture::InterfaceId {
            section: 0,
            index: 0,
        },
        u32::try_from(bytes.len())?,
    );
    Ok(CapturedFrame::new(bytes, metadata)?)
}

#[test]
fn dns_destination_never_vlan_scopes() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let packets = [
        vlan(&udp(false, &dns(false))?, 7)?,
        vlan(&udp(true, &dns(true))?, 7)?,
        vlan(&frames::tcp(false, 100, 2, b"")?, 8)?,
    ];
    let mut store = Store::create(temp.path(), Options::default())?;
    store.ingest("different-vlans", Cursor::new(capture(&packets)?))?;
    let mut count = 0;
    store.visit_relationships(None, |_| {
        count += 1;
        Ok(())
    })?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn integrity_verification_indexed_range_disagrees() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let mut store = Store::create(temp.path(), Options::default())?;
    store.ingest(
        "source",
        Cursor::new(capture(&[frames::tcp(false, 1, 2, b"abc")?])?),
    )?;
    let connection = rusqlite::Connection::open(temp.path().join("index.sqlite"))?;
    connection.execute("UPDATE packets SET offset=offset+1", [])?;
    assert!(store.verify_sources().is_err());
    Ok(())
}

#[test]
fn integrity_verification_disagree_source_bytes() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let packets = [udp(false, &dns(false))?, udp(true, &dns(true))?];
    let mut store = Store::create(temp.path(), Options::default())?;
    store.ingest("dns-source", Cursor::new(capture(&packets)?))?;
    let connection = rusqlite::Connection::open(temp.path().join("index.sqlite"))?;
    connection.execute("UPDATE dns_addresses SET address=X'c0000263'", [])?;
    assert!(store.verify_sources().is_err());
    Ok(())
}

#[test]
fn indexed_flow_source_packet_ranges() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let payload = b"POST /data HTTP/1.1\r\nContent-Length: 4\r\n\r\nABCD";
    let packets = [
        frames::tcp(false, 100, 2, b"")?,
        frames::tcp_ports(false, (41000, 8000), 500, 0x10, b"noise")?,
        frames::tcp(false, 101, 0x18, payload)?,
        frames::tcp(false, 101 + u32::try_from(payload.len())?, 0x11, b"")?,
    ];
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest("http.pcap", Cursor::new(capture(&packets)?))?;
    let flow = store
        .packet(&source.source_id, 1)?
        .flow
        .ok_or("missing tuple")?;
    let result = store.investigate_flow(flow)?;
    let body = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "http_body")
        .ok_or("missing body")?;
    assert_eq!(body.ranges.first().and_then(|range| range.packet), Some(3));
    assert_eq!(
        body.ranges.first().map(|range| range.source.as_str()),
        Some(source.source_id.as_str())
    );
    let bytes = result
        .case
        .blobs()
        .iter()
        .find(|blob| Some(&blob.id) == body.blob.as_ref())
        .ok_or("missing carved bytes")?;
    assert_eq!(bytes.bytes, b"ABCD");
    assert!(result.complete);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn renamed_index_directory_redirected() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let original = temp.path().join("original");
    let moved = temp.path().join("moved");
    std::fs::create_dir(&original)?;
    let mut store = Store::create(&original, Options::default())?;
    let source = store.ingest(
        "held-source",
        Cursor::new(capture(&[frames::tcp(false, 1, 2, b"abc")?])?),
    )?;
    std::fs::rename(&original, &moved)?;
    std::fs::create_dir(&original)?;
    assert!(
        store
            .ingest(
                "later-source",
                Cursor::new(capture(&[frames::tcp(false, 2, 2, b"def")?])?)
            )
            .is_err()
    );
    assert!(store.frame(&source.source_id, 1).is_ok());
    store.verify_sources()?;
    assert_eq!(std::fs::read_dir(&original)?.count(), 0);
    assert_eq!(std::fs::read_dir(moved.join("sources"))?.count(), 1);
    Ok(())
}

#[test]
fn packet_analysis_changes_retained_bytes() -> Result<(), Box<dyn Error>> {
    use std::io::{Seek, SeekFrom, Write};
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest(
        "source.pcap",
        Cursor::new(capture(&[frames::tcp(false, 100, 2, b"abc")?])?),
    )?;
    let packet = store.packet(&source.source_id, 1)?;
    let path = temporary.path().join("sources").join(format!(
        "{}.pcap",
        source
            .source_id
            .strip_prefix("sha256:")
            .ok_or("invalid digest")?
    ));
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(
        packet.range.offset + packet.range.length - 1,
    ))?;
    file.write_all(b"X")?;
    file.sync_all()?;
    assert!(store.frame(&source.source_id, 1).is_err());
    assert!(
        store
            .investigate_flow(packet.flow.ok_or("missing flow")?)
            .is_err()
    );
    Ok(())
}
