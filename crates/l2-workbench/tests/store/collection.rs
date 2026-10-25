use super::frames;
use l2_capture::{CaptureMetadata, CaptureTimestamp, CapturedFrame, TimestampSource};
use l2_pcap::{
    CollectionGoal, CollectionReport, CollectionStopReason, CollectionSummary, InterfaceConfig,
    PcapNgWriter,
};
use l2_workbench::{
    investigation::BuildResult,
    store::{Options, Source, Store},
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{error::Error, io::Cursor};

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SummaryField {
    #[serde(
        default,
        serialize_with = "l2_workbench::capture_collection::serialize",
        deserialize_with = "l2_workbench::capture_collection::deserialize"
    )]
    collection_summary: CollectionSummary,
}

fn pcapng(
    frame: &CapturedFrame,
    report: Option<CollectionReport>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = match report {
        Some(report) => PcapNgWriter::new_with_collection_report(Vec::new(), 1_048_576, report)?,
        None => PcapNgWriter::new(Vec::new(), 1_048_576)?,
    };
    let metadata = frame.metadata();
    let configuration = InterfaceConfig::new_with_link_type(
        metadata.link_type(),
        65_535,
        l2_capture::TimestampResolution::MICROSECOND,
        0,
        metadata.fcs(),
    )?;
    writer.add_interface_and_write_frame(metadata.interface(), configuration, frame)?;
    writer.finish()?;
    Ok(writer.into_inner())
}

fn pcapng_with_packet_block_drops(
    frame: &CapturedFrame,
    drops_count: u16,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = pcapng(frame, None)?;
    let mut cursor = 0_usize;
    let mut found_packet_block = false;
    while cursor < bytes.len() {
        let header_end = cursor.checked_add(8).ok_or("block header overflow")?;
        let header = bytes
            .get(cursor..header_end)
            .ok_or("truncated generated block header")?;
        let block_type_bytes: [u8; 4] = header
            .get(..4)
            .ok_or("generated block type is missing")?
            .try_into()?;
        let block_length_bytes: [u8; 4] = header
            .get(4..8)
            .ok_or("generated block length is missing")?
            .try_into()?;
        let block_type = u32::from_le_bytes(block_type_bytes);
        let block_length = usize::try_from(u32::from_le_bytes(block_length_bytes))?;
        let block_end = cursor
            .checked_add(block_length)
            .ok_or("generated block length overflow")?;
        if block_length < 12 || block_end > bytes.len() {
            return Err("invalid generated block length".into());
        }
        if block_type == 6 {
            bytes
                .get_mut(cursor..cursor + 4)
                .ok_or("packet block type field is missing")?
                .copy_from_slice(&2_u32.to_le_bytes());
            bytes
                .get_mut(cursor + 10..cursor + 12)
                .ok_or("packet block drops field is missing")?
                .copy_from_slice(&drops_count.to_le_bytes());
            found_packet_block = true;
        }
        cursor = block_end;
    }
    if !found_packet_block {
        return Err("generated capture contains no enhanced packet block".into());
    }
    Ok(bytes)
}

fn frame() -> Result<CapturedFrame, Box<dyn Error>> {
    let frame = frames::tcp(false, 1, 0x18, b"collection")?;
    let metadata = frame.metadata();
    let timestamp = CaptureTimestamp::new(
        1,
        l2_capture::TimestampResolution::MICROSECOND,
        0,
        TimestampSource::CaptureFile,
    );
    let metadata = CaptureMetadata::new(
        metadata.interface(),
        metadata.original_len(),
        None,
        Some(timestamp),
        metadata.direction(),
        metadata.vlan(),
        metadata.fcs(),
    )
    .with_link_type(metadata.link_type());
    Ok(CapturedFrame::new(frame.bytes().to_vec(), metadata)?)
}

fn assert_selected_case_quality(
    analysis: &BuildResult,
    source_id: &str,
    summary: CollectionSummary,
) -> Result<(), Box<dyn Error>> {
    assert!(!analysis.complete);
    assert!(!analysis.case.collection_complete());
    let quality = analysis
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "capture_collection_summary")
        .ok_or("collection summary node missing")?;
    let expected_source = json!(source_id);
    let expected_summary = l2_workbench::capture_collection::to_value(summary)?;
    assert_eq!(quality.details.get("source_id"), Some(&expected_source));
    assert_eq!(quality.details.get("summary"), Some(&expected_summary));
    assert!(analysis.case.limitations().iter().any(|limitation| {
        limitation.contains("source-reported collection") && limitation.contains("incomplete")
    }));
    Ok(())
}

#[test]
fn incomplete_source_reopen_selected_analysis() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let report = CollectionReport::new(
        CollectionStopReason::Unavailable,
        CollectionGoal::Packets,
        1,
        2,
        3,
        true,
    );
    let receipt = store.ingest(
        "reported.pcapng",
        Cursor::new(pcapng(&frame()?, Some(report))?),
    )?;
    let expected = CollectionSummary {
        sections: 1,
        reported_sections: 1,
        incomplete_sections: 1,
        capture_dropped: 2,
        interface_dropped: 3,
        ..CollectionSummary::default()
    };
    assert_eq!(receipt.collection_summary, expected);
    let receipt_json = serde_json::to_value(&receipt)?;
    let expected_json = l2_workbench::capture_collection::to_value(expected)?;
    assert_eq!(receipt_json.get("collection_summary"), Some(&expected_json));

    let mut sources = Vec::<Source>::new();
    store.visit_sources(|source| {
        sources.push(source);
        Ok(())
    })?;
    assert_eq!(
        sources.first().ok_or("source missing")?.collection_summary,
        expected
    );
    let expected_json = l2_workbench::capture_collection::to_value(expected)?;
    let source_json = serde_json::to_value(sources.first().ok_or("source missing")?)?;
    assert_eq!(source_json.get("collection_summary"), Some(&expected_json));

    let inventory = store.inventory()?;
    assert_eq!(inventory.collection_summary, expected);
    assert_eq!(inventory.sources_with_unknown_collection_quality, 0);
    let inventory_json = serde_json::to_value(inventory)?;
    assert_eq!(
        inventory_json.get("collection_summary"),
        Some(&expected_json)
    );

    let flow = store
        .packet(&receipt.source_id, 1)?
        .flow
        .ok_or("flow missing")?;
    let analysis = store.investigate_flow(flow)?;
    assert_selected_case_quality(&analysis, &receipt.source_id, expected)?;

    drop(store);
    let store = Store::open(temporary.path(), Options::default())?;
    store.verify_sources()?;
    Ok(())
}

#[test]
fn collection_summary_trips_inconsistent_counters() -> Result<(), Box<dyn Error>> {
    let summary = CollectionSummary {
        sections: 2,
        reported_sections: 1,
        incomplete_sections: 1,
        capture_dropped: 8,
        interface_dropped: 9,
        ..CollectionSummary::default()
    };
    let encoded = l2_workbench::capture_collection::to_json(summary)?;
    assert_eq!(
        l2_workbench::capture_collection::from_json(&encoded)?,
        summary
    );
    let field = SummaryField {
        collection_summary: summary,
    };
    let serialized = serde_json::to_string(&field)?;
    assert_eq!(serde_json::from_str::<SummaryField>(&serialized)?, field);
    assert_eq!(
        serde_json::from_str::<SummaryField>("{}")?.collection_summary,
        CollectionSummary::default()
    );
    assert_eq!(
        l2_workbench::capture_collection::from_json(
            r#"{"sections":1,"reported_sections":1,"incomplete_sections":0,"capture_dropped":0,"interface_dropped":0}"#
        )?,
        CollectionSummary {
            sections: 1,
            reported_sections: 1,
            ..CollectionSummary::default()
        }
    );
    assert!(l2_workbench::capture_collection::from_json(
        r#"{"sections":1,"reported_sections":2,"incomplete_sections":0,"capture_dropped":0,"interface_dropped":0}"#
    )
    .is_err());
    Ok(())
}

#[test]
fn missing_collection_not_counted_clean() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let receipt = store.ingest("unreported.pcapng", Cursor::new(pcapng(&frame()?, None)?))?;
    assert_eq!(
        receipt.collection_summary,
        CollectionSummary {
            sections: 1,
            ..CollectionSummary::default()
        }
    );
    let inventory = store.inventory()?;
    assert_eq!(inventory.collection_summary.incomplete_sections, 0);
    assert_eq!(inventory.sources_with_unknown_collection_quality, 1);

    let flow = store
        .packet(&receipt.source_id, 1)?
        .flow
        .ok_or("flow missing")?;
    let analysis = store.investigate_flow(flow)?;
    assert!(analysis.complete);
    assert!(analysis.case.limitations().iter().any(|limitation| {
        limitation.contains("collection quality") && limitation.contains("unknown")
    }));
    Ok(())
}

#[test]
fn deep_verification_persisted_collection_summary() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let receipt = store.ingest(
        "reported.pcapng",
        Cursor::new(pcapng(
            &frame()?,
            Some(CollectionReport::new(
                CollectionStopReason::PacketLimit,
                CollectionGoal::Packets,
                1,
                0,
                0,
                true,
            )),
        )?),
    )?;
    drop(store);

    let connection = Connection::open(temporary.path().join("index.sqlite"))?;
    connection.execute(
        "UPDATE sources SET collection_summary=?1 WHERE sha256=?2",
        [
            "{\"sections\":1,\"reported_sections\":1,\"incomplete_sections\":0,\"capture_dropped\":0,\"interface_dropped\":9}",
            receipt.source_id.as_str(),
        ],
    )?;
    drop(connection);

    let store = Store::open(temporary.path(), Options::default())?;
    assert!(store.verify_sources().is_err());
    Ok(())
}

#[test]
fn packet_block_drop_summary_roundtrips_store_and_verification() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let receipt = store.ingest(
        "packet-block-drops.pcapng",
        Cursor::new(pcapng_with_packet_block_drops(&frame()?, 11)?),
    )?;
    store.ingest(
        "packet-block-unavailable.pcapng",
        Cursor::new(pcapng_with_packet_block_drops(&frame()?, u16::MAX)?),
    )?;
    let expected = CollectionSummary {
        sections: 2,
        packet_block_packets_dropped: 11,
        packet_blocks_with_unavailable_drop_count: 1,
        ..CollectionSummary::default()
    };
    assert_eq!(receipt.collection_summary.sections, 1);
    assert_eq!(receipt.collection_summary.packet_block_packets_dropped, 11);
    drop(store);

    let store = Store::open(temporary.path(), Options::default())?;
    assert_eq!(store.inventory()?.collection_summary, expected);
    let retained = store.frame(&receipt.source_id, 1)?;
    assert_eq!(
        retained.metadata().original_len(),
        frame()?.metadata().original_len()
    );
    assert_eq!(
        retained.metadata().link_type(),
        l2_capture::LinkType::Ethernet
    );
    assert!(matches!(
        retained.metadata().locator(),
        Some(l2_capture::CaptureLocator::PcapNg { block_type: 2, .. })
    ));
    store.verify_sources()?;
    Ok(())
}
