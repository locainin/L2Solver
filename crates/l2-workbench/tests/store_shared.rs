#[path = "reconstruction/ipv4.rs"]
mod ipv4;

#[path = "reconstruction/fragment.rs"]
mod fragments;

#[path = "reconstruction/tcp.rs"]
mod frames;

use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, InterfaceId, LinkType, TimestampResolution,
    TimestampSource,
};
use l2_pcap::{InterfaceConfig, PcapNgWriter};
use l2_workbench::store::{
    Options, SharedFactKind, SharedGroup, SharedGroupCursor, SharedOccurrence,
    SharedOccurrenceCursor, SharedWarning, Store,
};
use sha2::{Digest, Sha256};
use std::{error::Error, io::Cursor};

fn capture(frames: &[CapturedFrame]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes());
    bytes.extend_from_slice(&[2, 0, 4, 0]);
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&65_535_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    for (index, frame) in frames.iter().enumerate() {
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(index)?.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(frame.bytes().len())?.to_le_bytes());
        bytes.extend_from_slice(&frame.metadata().original_len().to_le_bytes());
        bytes.extend_from_slice(frame.bytes());
    }
    Ok(bytes)
}

fn private_ip_frame(payload: &[u8]) -> Result<CapturedFrame, Box<dyn Error>> {
    let frame = frames::tcp(false, 1, 0x18, payload)?;
    let mut bytes = frame.bytes().to_vec();
    bytes
        .get_mut(26..30)
        .ok_or("missing IPv4 source")?
        .copy_from_slice(&[10, 0, 0, 7]);
    bytes
        .get_mut(30..34)
        .ok_or("missing IPv4 destination")?
        .copy_from_slice(&[10, 0, 0, 8]);
    Ok(CapturedFrame::new(bytes, frame.metadata().clone())?)
}

fn vlan(frame: &CapturedFrame, vid: u16) -> Result<CapturedFrame, Box<dyn Error>> {
    let mut bytes = frame
        .bytes()
        .get(..12)
        .ok_or("missing Ethernet header")?
        .to_vec();
    bytes.extend_from_slice(&0x8100_u16.to_be_bytes());
    bytes.extend_from_slice(&vid.to_be_bytes());
    bytes.extend_from_slice(frame.bytes().get(12..).ok_or("missing EtherType")?);
    let length = u32::try_from(bytes.len())?;
    let metadata = CaptureMetadata::unknown(
        InterfaceId {
            section: 0,
            index: 0,
        },
        length,
    );
    Ok(CapturedFrame::new(bytes, metadata)?)
}

fn packet_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn dns_query(name: &[u8]) -> Result<CapturedFrame, Box<dyn Error>> {
    let message = dns_message(name);
    let mut udp = vec![0xab, 0xc0, 0, 53];
    udp.extend_from_slice(&u16::try_from(8 + message.len())?.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(&message);
    fragments::fragment(0, &udp)
}

fn dns_message(name: &[u8]) -> Vec<u8> {
    let mut message = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    message.extend_from_slice(name);
    message.extend_from_slice(&[0, 1, 0, 1]);
    message
}

fn unknown_link_capture(frame: &CapturedFrame) -> Result<Vec<u8>, Box<dyn Error>> {
    let source = frame.metadata();
    let link_type = LinkType::Unknown(999);
    let timestamp = CaptureTimestamp::new(
        1,
        TimestampResolution::MICROSECOND,
        0,
        TimestampSource::CaptureFile,
    );
    let metadata = CaptureMetadata::new(
        source.interface(),
        source.original_len(),
        None,
        Some(timestamp),
        source.direction(),
        source.vlan(),
        source.fcs(),
    )
    .with_link_type(link_type);
    let unknown_frame = CapturedFrame::new(frame.bytes().to_vec(), metadata)?;
    let configuration = InterfaceConfig::new_with_link_type(
        link_type,
        65_535,
        TimestampResolution::MICROSECOND,
        0,
        source.fcs(),
    )?;
    let mut writer = PcapNgWriter::new(Vec::new(), 1_048_576)?;
    writer.add_interface_and_write_frame(source.interface(), configuration, &unknown_frame)?;
    writer.finish()?;
    Ok(writer.into_inner())
}

fn assert_dns_range(
    store: &Store,
    occurrence: &SharedOccurrence,
    expected_payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    let packet = store.packet(&occurrence.source_id, occurrence.packet)?;
    let frame = store.frame(&occurrence.source_id, occurrence.packet)?;
    let offset = frame
        .bytes()
        .windows(expected_payload.len())
        .position(|window| window == expected_payload)
        .ok_or("DNS payload not found in original packet bytes")?;
    let absolute = packet
        .range
        .offset
        .checked_add(u64::try_from(offset)?)
        .ok_or("DNS payload source offset overflow")?;
    assert_eq!(occurrence.range.offset, absolute);
    assert_eq!(
        occurrence.range.length,
        u64::try_from(expected_payload.len())?
    );
    let end = offset
        .checked_add(expected_payload.len())
        .ok_or("DNS payload frame range overflow")?;
    assert_eq!(frame.bytes().get(offset..end), Some(expected_payload));
    Ok(())
}

fn groups(store: &Store) -> Result<Vec<SharedGroup>, Box<dyn Error>> {
    let mut values = Vec::new();
    store.visit_shared_groups(None, None, |group| {
        values.push(group);
        Ok(())
    })?;
    Ok(values)
}

fn group_for<'a>(
    groups: &'a [SharedGroup],
    kind: SharedFactKind,
    key: &[u8],
) -> Option<&'a SharedGroup> {
    groups
        .iter()
        .find(|group| group.kind == kind && group.key == key)
}

#[test]
fn shared_literal_without_claiming_identity() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    store.ingest(
        "first",
        Cursor::new(capture(&[vlan(&private_ip_frame(b"first")?, 7)?])?),
    )?;
    store.ingest(
        "second",
        Cursor::new(capture(&[vlan(&private_ip_frame(b"second")?, 8)?])?),
    )?;

    let indexed = groups(&store)?;
    let group = group_for(&indexed, SharedFactKind::IpAddress, &[10, 0, 0, 7])
        .ok_or("missing literal source-address group")?;
    assert_eq!(group.source_count, 2);
    assert_eq!(group.occurrence_count, 2);
    assert!(
        group
            .warnings
            .contains(&SharedWarning::PrivateAddressAcrossSources)
    );
    assert!(
        group
            .warnings
            .contains(&SharedWarning::MultipleCaptureLocalScopes)
    );
    let serialized = serde_json::to_value(group)?;
    assert_eq!(serialized.get("key"), Some(&serde_json::json!("0a000007")));

    let mut occurrences = Vec::<SharedOccurrence>::new();
    store.visit_shared_occurrences(group.kind, &group.key, None, None, |occurrence| {
        occurrences.push(occurrence);
        Ok(())
    })?;
    assert_eq!(occurrences.len(), 2);
    assert!(
        occurrences
            .iter()
            .all(|occurrence| occurrence.scope.is_some())
    );
    assert!(
        occurrences
            .iter()
            .all(|occurrence| occurrence.range.length > 0)
    );
    let first = occurrences.first().ok_or("missing first IP occurrence")?;
    let second = occurrences.get(1).ok_or("missing second IP occurrence")?;
    assert_eq!(first.range.packet, Some(1));
    assert_ne!(first.source_id, second.source_id);
    let first_vlan = first
        .scope
        .as_ref()
        .and_then(|scope| scope.pointer("/vlan_ids/0/1"))
        .and_then(serde_json::Value::as_u64)
        .ok_or("first scope lacks its VLAN ID")?;
    let second_vlan = second
        .scope
        .as_ref()
        .and_then(|scope| scope.pointer("/vlan_ids/0/1"))
        .and_then(serde_json::Value::as_u64)
        .ok_or("second scope lacks its VLAN ID")?;
    assert_eq!((first_vlan, second_vlan), (7, 8));
    Ok(())
}

#[test]
fn canonical_dns_variants_unmatched_queries() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let first_name = b"\x07ExAmPlE\x07invalid\x00";
    let second_name = b"\x07example\x07INVALID\x00";
    let first_payload = dns_message(first_name);
    let second_payload = dns_message(second_name);
    let first = store.ingest(
        "first-query",
        Cursor::new(capture(&[dns_query(first_name)?])?),
    )?;
    let second = store.ingest(
        "second-query",
        Cursor::new(capture(&[dns_query(second_name)?])?),
    )?;

    let canonical = b"\x07example\x07invalid\x00";
    let indexed = groups(&store)?;
    let group = group_for(&indexed, SharedFactKind::DnsQuestion, canonical)
        .ok_or("missing canonical DNS question group")?;
    assert_eq!(group.source_count, 2);
    assert_eq!(group.occurrence_count, 2);
    assert!(group.warnings.is_empty());
    let mut occurrences = Vec::new();
    store.visit_shared_occurrences(group.kind, &group.key, None, None, |occurrence| {
        occurrences.push(occurrence);
        Ok(())
    })?;
    for (source_id, payload) in [
        (first.source_id.as_str(), first_payload.as_slice()),
        (second.source_id.as_str(), second_payload.as_slice()),
    ] {
        let occurrence = occurrences
            .iter()
            .find(|value| value.source_id == source_id)
            .ok_or("missing DNS question occurrence")?;
        assert_dns_range(&store, occurrence, payload)?;
    }
    Ok(())
}

#[test]
fn shared_unavailable_known_unknown_observations() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let common = private_ip_frame(b"same packet bytes")?;
    store.ingest(
        "ethernet",
        Cursor::new(capture(std::slice::from_ref(&common))?),
    )?;
    store.ingest("unknown-link", Cursor::new(unknown_link_capture(&common)?))?;

    let digest = packet_digest(common.bytes());
    let indexed = groups(&store)?;
    let group = group_for(&indexed, SharedFactKind::PacketBytes, &digest)
        .ok_or("missing shared packet-byte group")?;
    assert!(
        group
            .warnings
            .contains(&SharedWarning::CaptureScopeUnavailable)
    );
    assert!(
        !group
            .warnings
            .contains(&SharedWarning::MultipleCaptureLocalScopes)
    );
    Ok(())
}

#[test]
fn shared_cursor_key_cannot_kind() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let store = Store::create(temporary.path(), Options::default())?;
    let cursor = SharedGroupCursor {
        kind: SharedFactKind::DnsQuestion,
        key: Vec::new(),
    };
    assert!(
        store
            .visit_shared_groups(Some(&cursor), Some(1), |_| Ok(()))
            .is_err()
    );
    Ok(())
}

#[test]
fn canonical_dns_label_bytes_distinct() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    store.ingest(
        "first-byte",
        Cursor::new(capture(&[dns_query(b"\x01\xc0\x00")?])?),
    )?;
    store.ingest(
        "second-byte",
        Cursor::new(capture(&[dns_query(b"\x01\xe0\x00")?])?),
    )?;

    let indexed = groups(&store)?;
    assert!(group_for(&indexed, SharedFactKind::DnsQuestion, b"\x01\xc0\x00").is_none());
    assert!(group_for(&indexed, SharedFactKind::DnsQuestion, b"\x01\xe0\x00").is_none());
    Ok(())
}

#[test]
fn identical_packet_equality_ranges() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let common = private_ip_frame(b"same bytes")?;
    let different_a = private_ip_frame(b"different a")?;
    let different_b = private_ip_frame(b"different b")?;
    let different_a_digest = packet_digest(different_a.bytes());
    store.ingest(
        "first",
        Cursor::new(capture(&[common.clone(), different_a])?),
    )?;
    store.ingest(
        "second",
        Cursor::new(capture(&[common.clone(), different_b])?),
    )?;

    let digest = packet_digest(common.bytes());
    let indexed = groups(&store)?;
    let group = group_for(&indexed, SharedFactKind::PacketBytes, &digest)
        .ok_or("missing identical packet-byte group")?;
    assert_eq!(group.source_count, 2);
    assert_eq!(group.occurrence_count, 2);
    assert!(
        group
            .warnings
            .contains(&SharedWarning::CaptureBytesMayBeCorrelated)
    );
    assert!(group_for(&indexed, SharedFactKind::PacketBytes, &different_a_digest).is_none());

    let mut occurrences = Vec::new();
    store.visit_shared_occurrences(group.kind, &group.key, None, None, |occurrence| {
        occurrences.push(occurrence);
        Ok(())
    })?;
    assert_eq!(occurrences.len(), 2);
    let common_length = u64::try_from(common.bytes().len())?;
    assert!(
        occurrences
            .iter()
            .all(|occurrence| occurrence.range.length == common_length)
    );
    assert!(
        occurrences
            .iter()
            .all(|occurrence| occurrence.range.offset == 40)
    );
    Ok(())
}

#[test]
fn shared_occurrence_cover_packet_once() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let common = private_ip_frame(b"repeat")?;
    for (label, unique) in [
        ("first", private_ip_frame(b"unique first")?),
        ("second", private_ip_frame(b"unique second")?),
    ] {
        store.ingest(
            label,
            Cursor::new(capture(&[common.clone(), common.clone(), unique])?),
        )?;
    }
    let digest = packet_digest(common.bytes());
    let all_groups = groups(&store)?;
    let group = group_for(&all_groups, SharedFactKind::PacketBytes, &digest)
        .ok_or("missing repeated packet group")?
        .clone();
    assert_eq!(group.occurrence_count, 4);
    let first_group = all_groups.first().ok_or("missing first shared group")?;
    let second_group = all_groups.get(1).ok_or("missing next shared group")?;
    let group_cursor = SharedGroupCursor {
        kind: first_group.kind,
        key: first_group.key.clone(),
    };
    let mut next_groups = Vec::new();
    store.visit_shared_groups(Some(&group_cursor), Some(1), |next| {
        next_groups.push(next);
        Ok(())
    })?;
    assert_eq!(next_groups.first(), Some(second_group));

    let mut page = Vec::new();
    store.visit_shared_occurrences(group.kind, &group.key, None, Some(2), |occurrence| {
        page.push(occurrence);
        Ok(())
    })?;
    assert_eq!(page.len(), 2);
    let last = page.last().ok_or("missing first page row")?;
    let after = SharedOccurrenceCursor {
        source_id: last.source_id.clone(),
        packet: last.packet,
    };
    let mut second_page = Vec::new();
    store.visit_shared_occurrences(
        group.kind,
        &group.key,
        Some(&after),
        Some(2),
        |occurrence| {
            second_page.push(occurrence);
            Ok(())
        },
    )?;
    assert_eq!(second_page.len(), 2);
    assert!(
        page.iter()
            .chain(&second_page)
            .all(|occurrence| occurrence.packet > 0)
    );
    let references = page.iter().chain(&second_page).fold(
        std::collections::BTreeSet::new(),
        |mut references, occurrence| {
            references.insert((occurrence.source_id.clone(), occurrence.packet));
            references
        },
    );
    assert_eq!(references.len(), 4);
    Ok(())
}

#[test]
fn integrity_verification_facts_retained_packets() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    store.ingest(
        "source",
        Cursor::new(capture(&[private_ip_frame(b"verify")?])?),
    )?;
    store.verify_sources()?;
    let connection = rusqlite::Connection::open(temporary.path().join("index.sqlite"))?;
    connection.execute(
        "UPDATE shared_facts SET fact_key=X'00000000' WHERE kind='ip_address' AND fact_key=X'0a000007'",
        [],
    )?;
    assert!(store.verify_sources().is_err());
    Ok(())
}
