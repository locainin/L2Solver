use super::{capture, frames, sha256};
use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus, InterfaceId, LinkType,
    LinuxInterfaceIdentity, TimestampResolution, TimestampSource,
};
use l2_pcap::{InterfaceConfig, PcapNgWriter};
use l2_workbench::store::{Options, Store};
use rusqlite::Connection;
use std::{
    error::Error,
    io::{self, Cursor, Read},
    net::IpAddr,
    path::PathBuf,
};

struct MoveSourcesReader<R> {
    inner: R,
    source_directory: PathBuf,
    moved_directory: PathBuf,
    moved: bool,
}

impl<R: Read> Read for MoveSourcesReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.moved {
            std::fs::rename(&self.source_directory, &self.moved_directory)?;
            std::fs::create_dir(&self.source_directory)?;
            self.moved = true;
        }
        self.inner.read(buffer)
    }
}

fn pcapng_with_metadata(frame: &CapturedFrame) -> Result<Vec<u8>, Box<dyn Error>> {
    let metadata = frame.metadata();
    let timestamp = metadata.timestamp().ok_or("timestamp missing")?;
    let identity = metadata
        .linux_interface()
        .ok_or("Linux interface identity missing")?;
    let config = InterfaceConfig::new_with_link_type(
        metadata.link_type(),
        65_535,
        timestamp.resolution(),
        timestamp.offset_seconds(),
        metadata.fcs(),
    )?
    .with_linux_interface(identity);
    let mut writer = PcapNgWriter::new(Vec::new(), 1_048_576)?;
    writer.add_interface_and_write_frame(metadata.interface(), config, frame)?;
    writer.finish()?;
    Ok(writer.into_inner())
}

#[test]
fn flow_aggregation_sums_transport_payloads() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest(
        "flow-aggregate.pcap",
        Cursor::new(capture(&[
            frames::tcp(false, 10, 0x18, b"abc")?,
            frames::tcp(true, 20, 0x18, b"defg")?,
            frames::tcp(false, 13, 0x11, b"")?,
        ])?),
    )?;

    let mut flows = Vec::new();
    store.visit_flows(0, None, |flow| {
        flows.push(flow);
        Ok(())
    })?;

    assert_eq!(flows.len(), 1);
    let flow = flows.first().ok_or("flow missing")?;
    assert_eq!(flow.source_id, source.source_id);
    assert_eq!((flow.first_packet, flow.last_packet), (1, 3));
    assert_eq!(flow.packets, 3);
    assert_eq!(flow.payload_bytes, 7);
    Ok(())
}

#[test]
fn indexed_pcapng_ranges_decoded_source() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let base = frames::tcp(false, 1, 0x18, b"metadata")?;
    let bytes = base.bytes().to_vec();
    let interface = InterfaceId {
        section: 0,
        index: 0,
    };
    let timestamp = CaptureTimestamp::new(
        123_456,
        TimestampResolution::binary(3)?,
        -2,
        TimestampSource::CaptureFile,
    );
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 7)?;
    let fcs = FcsStatus::present(4)?;
    let original_length = u32::try_from(bytes.len())?
        .checked_add(5)
        .ok_or("length overflow")?;
    let frame = CapturedFrame::new(
        bytes,
        CaptureMetadata::new(
            interface,
            original_length,
            None,
            Some(timestamp),
            Direction::Outbound,
            None,
            fcs,
        )
        .with_link_type(LinkType::Ethernet)
        .with_linux_interface(identity),
    )?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest(
        "metadata.pcapng",
        Cursor::new(pcapng_with_metadata(&frame)?),
    )?;

    let packet = store.packet(&source.source_id, 1)?;
    let indexed = store.frame(&source.source_id, 1)?;
    let metadata = indexed.metadata();
    let data_offset = match metadata.locator().ok_or("locator missing")? {
        l2_capture::CaptureLocator::ClassicPcap { data_offset, .. }
        | l2_capture::CaptureLocator::PcapNg { data_offset, .. } => data_offset,
    };
    assert_eq!(indexed.bytes(), frame.bytes());
    assert_eq!(packet.range.offset, data_offset);
    assert_eq!(packet.range.length, u64::try_from(indexed.bytes().len())?);
    assert_eq!(metadata.interface(), interface);
    assert_eq!(metadata.link_type(), LinkType::Ethernet);
    assert_eq!(metadata.direction(), Direction::Outbound);
    assert_eq!(metadata.fcs(), fcs);
    assert_eq!(metadata.linux_interface(), Some(identity));
    assert_eq!(metadata.timestamp(), Some(timestamp));
    assert_eq!(metadata.original_len(), original_length);
    store.verify_sources()?;
    Ok(())
}

#[test]
fn dns_answer_inside_response_packet() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let packets = [
        super::udp(false, &super::dns(false))?,
        super::udp(true, &super::dns(true))?,
        frames::tcp(false, 1, 0x18, b"")?,
    ];
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest("dns-range.pcap", Cursor::new(capture(&packets)?))?;
    let mut relationships = Vec::new();
    store.visit_relationships(None, |relationship| {
        relationships.push(relationship);
        Ok(())
    })?;

    let relationship = relationships.first().ok_or("relationship missing")?;
    let packet = store.packet(&source.source_id, relationship.response_packet)?;
    let frame = store.frame(&source.source_id, relationship.response_packet)?;
    let relative = usize::try_from(
        relationship
            .answer_range
            .offset
            .checked_sub(packet.range.offset)
            .ok_or("answer precedes response frame")?,
    )?;
    let end = relative
        .checked_add(usize::try_from(relationship.answer_range.length)?)
        .ok_or("answer range overflow")?;
    let expected = match relationship.answer_address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    };
    assert_eq!(
        relationship.answer_range.packet,
        Some(u64::from(packet.number))
    );
    assert_eq!(frame.bytes().get(relative..end), Some(expected.as_slice()));
    Ok(())
}

#[test]
fn deep_verification_changes_inventory_counts() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    store.ingest(
        "one-flow.pcap",
        Cursor::new(capture(&[frames::tcp(false, 1, 0x18, b"payload")?])?),
    )?;
    let connection = Connection::open(temporary.path().join("index.sqlite"))?;
    connection.execute(
        "INSERT INTO flows(source,scope,protocol,a,ap,b,bp) SELECT source,scope,6,X'C0000201',40001,X'C0000202',9001 FROM flows LIMIT 1",
        [],
    )?;

    assert_eq!(store.inventory()?.flows, 2);
    let mut listed = 0;
    store.visit_flows(0, None, |_| {
        listed += 1;
        Ok(())
    })?;
    assert_eq!(listed, 1);
    assert!(store.verify_sources().is_err());
    Ok(())
}

#[test]
fn deep_verification_unsupported_packet_counter() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    store.ingest(
        "supported-flow.pcap",
        Cursor::new(capture(&[frames::tcp(false, 1, 0x18, b"payload")?])?),
    )?;
    let connection = Connection::open(temporary.path().join("index.sqlite"))?;
    connection.execute("UPDATE sources SET unsupported=7", [])?;

    assert_eq!(store.inventory()?.unsupported_transport_packets, 7);
    assert!(store.verify_sources().is_err());
    Ok(())
}

#[test]
fn verification_source_header_bytes_change() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let original = capture(&[frames::tcp(false, 1, 0x18, b"payload")?])?;
    let mut changed = original.clone();
    *changed
        .get_mut(8)
        .ok_or("missing classic PCAP header field")? ^= 1;
    assert_eq!(original.len(), changed.len());
    assert_ne!(sha256(&original), sha256(&changed));

    let mut original_reader = l2_pcap::CaptureSource::new(Cursor::new(&original))?;
    let mut changed_reader = l2_pcap::CaptureSource::new(Cursor::new(&changed))?;
    let mut original_frames = Vec::new();
    let mut changed_frames = Vec::new();
    while let Some(frame) = original_reader.next_packet()? {
        original_frames.push(frame);
    }
    while let Some(frame) = changed_reader.next_packet()? {
        changed_frames.push(frame);
    }
    assert_eq!(original_frames, changed_frames);

    let mut store = Store::create(temporary.path(), Options::default())?;
    let receipt = store.ingest("reserved-header.pcap", Cursor::new(original))?;
    let digest = receipt
        .source_id
        .strip_prefix("sha256:")
        .ok_or("source identity lacks SHA-256 prefix")?;
    std::fs::write(
        temporary
            .path()
            .join("sources")
            .join(format!("{digest}.pcap")),
        changed,
    )?;

    assert!(store.verify_sources().is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn ingest_moved_committing_source_row() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source_directory = temporary.path().join("sources");
    let moved_directory = temporary.path().join("detached-sources");
    std::fs::rename(&source_directory, &moved_directory)?;
    std::fs::create_dir(&source_directory)?;

    let import = store.ingest(
        "moved-directory.pcap",
        Cursor::new(capture(&[frames::tcp(false, 1, 0x18, b"payload")?])?),
    );

    assert!(import.is_err());
    assert_eq!(store.inventory()?.sources, 0);
    assert_eq!(std::fs::read_dir(&source_directory)?.count(), 0);
    assert_eq!(std::fs::read_dir(&moved_directory)?.count(), 0);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn ingest_source_directory_moved_reading() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source_directory = temporary.path().join("sources");
    let moved_directory = temporary.path().join("detached-sources");
    let reader = MoveSourcesReader {
        inner: Cursor::new(capture(&[frames::tcp(false, 1, 0x18, b"payload")?])?),
        source_directory: source_directory.clone(),
        moved_directory: moved_directory.clone(),
        moved: false,
    };

    let import = store.ingest("moving-source.pcap", reader);

    assert!(import.is_err());
    assert_eq!(store.inventory()?.sources, 0);
    assert_eq!(std::fs::read_dir(&source_directory)?.count(), 0);
    assert_eq!(std::fs::read_dir(&moved_directory)?.count(), 0);
    Ok(())
}
