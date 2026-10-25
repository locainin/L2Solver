use super::frames;
use l2_capture::{CaptureLocator, LinkType};
use l2_workbench::store::{Options, SharedFactKind, SharedOccurrenceCursor, Store};
use sha2::{Digest, Sha256};
use std::{error::Error, io::Cursor};

fn classic_capture(link_type: u16, seconds: u32, frame: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes());
    bytes.extend_from_slice(&[2, 0, 4, 0]);
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&65_535_u32.to_le_bytes());
    bytes.extend_from_slice(&u32::from(link_type).to_le_bytes());
    bytes.extend_from_slice(&seconds.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    let frame_length = u32::try_from(frame.len())?;
    bytes.extend_from_slice(&frame_length.to_le_bytes());
    bytes.extend_from_slice(&frame_length.to_le_bytes());
    bytes.extend_from_slice(frame);
    Ok(bytes)
}

#[test]
fn opaque_classic_evidence_without_transport() -> Result<(), Box<dyn Error>> {
    for link_type in [12_u16, 228, 0x1234] {
        verify_opaque_classic_link_type(link_type)?;
    }
    Ok(())
}

fn verify_opaque_classic_link_type(link_type: u16) -> Result<(), Box<dyn Error>> {
    let raw = frames::tcp(false, 41, 0x18, b"opaque")?;
    let raw_length = u64::try_from(raw.bytes().len())?;
    let raw_digest: [u8; 32] = Sha256::digest(raw.bytes()).into();
    let temporary = tempfile::tempdir()?;
    let mut writer = Store::create(temporary.path(), Options::default())?;
    let first = writer.ingest(
        "opaque-first",
        Cursor::new(classic_capture(link_type, 1, raw.bytes())?),
    )?;
    let second = writer.ingest(
        "opaque-second",
        Cursor::new(classic_capture(link_type, 2, raw.bytes())?),
    )?;

    assert_ne!(first.source_id, second.source_id);
    for receipt in [&first, &second] {
        assert_eq!(receipt.packets, 1);
        assert_eq!(receipt.transport_packets, 0);
        assert_eq!(receipt.unsupported_transport_packets, 1);
    }
    assert_eq!(writer.inventory()?.flows, 0);
    assert_eq!(writer.inventory()?.unsupported_transport_packets, 2);
    drop(writer);

    let store = Store::open(temporary.path(), Options::default())?;
    store.verify_sources()?;
    assert_retained_packets(
        &store,
        [&first, &second],
        link_type,
        raw.bytes(),
        raw_length,
    )?;
    assert_shared_packet_evidence(&store, raw_digest, raw_length)?;
    Ok(())
}

fn assert_retained_packets(
    store: &Store,
    receipts: [&l2_workbench::store::IngestReceipt; 2],
    link_type: u16,
    expected_bytes: &[u8],
    expected_length: u64,
) -> Result<(), Box<dyn Error>> {
    for receipt in receipts {
        let packet = store.packet(&receipt.source_id, 1)?;
        assert_eq!(packet.flow, None);
        assert_eq!(packet.range.offset, 40);
        assert_eq!(packet.range.length, expected_length);

        let extracted = store.frame(&receipt.source_id, 1)?;
        assert_eq!(extracted.bytes(), expected_bytes);
        assert_eq!(
            extracted.metadata().link_type(),
            LinkType::Unknown(link_type)
        );
        assert!(!extracted.metadata().link_type().is_supported());
        assert_eq!(
            extracted.metadata().locator(),
            Some(CaptureLocator::ClassicPcap {
                record_offset: 24,
                data_offset: 40,
            })
        );
    }
    Ok(())
}

fn assert_shared_packet_evidence(
    store: &Store,
    digest: [u8; 32],
    raw_length: u64,
) -> Result<(), Box<dyn Error>> {
    let mut groups = Vec::new();
    store.visit_shared_groups(None, None, |group| {
        groups.push(group);
        Ok(())
    })?;
    assert_eq!(groups.len(), 1);
    let group = groups.first().ok_or("packet-byte group missing")?;
    assert_eq!(group.kind, SharedFactKind::PacketBytes);
    assert_eq!(group.key.as_slice(), digest.as_slice());
    assert_eq!(group.source_count, 2);
    assert_eq!(group.occurrence_count, 2);

    let mut occurrences = Vec::new();
    store.visit_shared_occurrences(group.kind, &group.key, None, None, |occurrence| {
        occurrences.push(occurrence);
        Ok(())
    })?;
    assert_eq!(occurrences.len(), 2);
    assert!(occurrences.iter().all(|occurrence| {
        occurrence.packet == 1
            && occurrence.range.length == raw_length
            && occurrence.scope.is_none()
    }));
    assert_ne!(
        occurrences
            .first()
            .map(|occurrence| occurrence.source_id.as_str()),
        occurrences
            .get(1)
            .map(|occurrence| occurrence.source_id.as_str())
    );

    // A cursor on the first witness leaves the second source occurrence available
    let first_occurrence = occurrences.first().ok_or("first packet witness missing")?;
    let cursor = SharedOccurrenceCursor {
        source_id: first_occurrence.source_id.clone(),
        packet: first_occurrence.packet,
    };
    let mut remaining = Vec::new();
    store.visit_shared_occurrences(group.kind, &group.key, Some(&cursor), None, |occurrence| {
        remaining.push(occurrence);
        Ok(())
    })?;
    assert_eq!(remaining.len(), 1);
    assert_ne!(
        remaining
            .first()
            .map(|occurrence| occurrence.source_id.as_str()),
        Some(first_occurrence.source_id.as_str())
    );
    Ok(())
}
