use super::{PacketFacts, frame_facts};
use crate::evidence::SourceRange;
use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus, InterfaceId, LinkType,
    TimestampResolution, TimestampSource, VlanAuxData,
};
use std::error::Error;

#[test]
fn captured_frame_auxiliary_vlan_clock() -> Result<(), Box<dyn Error>> {
    let bytes = ethernet_frame()?;
    let frame = captured_frame(&bytes, LinkType::Ethernet)?;
    let range = source_range(&bytes)?;

    let facts = frame_facts(&frame, range.clone());

    assert_source_identity(&facts, &range);
    assert_eq!(facts.node_id, 0);
    assert_eq!(
        facts.scope,
        serde_json::json!({
            "section": 3,
            "interface": 2,
            "vlan_ids": [],
            "vlan_aux": [0x8100, 5],
        })
    );
    assert_eq!(facts.eth_type, Some(0x88b5));
    assert_eq!(facts.auxiliary_vlan_id, Some(5));
    assert_eq!(facts.epoch_second(), Some(9));
    assert_eq!(
        facts.timestamp.as_ref().map(|time| time.source.as_str()),
        Some("CaptureFile")
    );
    Ok(())
}

#[test]
fn unknown_layout_not_ethernet_bytes() -> Result<(), Box<dyn Error>> {
    let bytes = ethernet_frame()?;
    let frame = captured_frame(&bytes, LinkType::Unknown(147))?;
    let range = source_range(&bytes)?;

    let facts = frame_facts(&frame, range.clone());

    assert_source_identity(&facts, &range);
    assert_eq!(facts.section, Some(3));
    assert_eq!(facts.interface, Some(2));
    assert_eq!(
        facts
            .scope
            .get("section")
            .and_then(serde_json::Value::as_u64),
        Some(3)
    );
    assert_eq!(facts.eth_type, None);
    assert_eq!(facts.protocol, None);
    assert_eq!(facts.source_ip, None);
    Ok(())
}

fn assert_source_identity(facts: &PacketFacts, range: &SourceRange) {
    assert_eq!(facts.packet_number, 9);
    assert_eq!(facts.source_id.as_deref(), Some("capture-a"));
    assert_eq!(facts.ranges.as_slice(), std::slice::from_ref(range));
}

fn source_range(bytes: &[u8]) -> Result<SourceRange, Box<dyn Error>> {
    Ok(SourceRange {
        source: "capture-a".to_owned(),
        packet: Some(9),
        offset: 42,
        length: u64::try_from(bytes.len())?,
    })
}

fn ethernet_frame() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = vec![0; 14];
    bytes
        .get_mut(12..14)
        .ok_or("missing Ethernet type field")?
        .copy_from_slice(&0x88b5_u16.to_be_bytes());
    Ok(bytes)
}

fn captured_frame(bytes: &[u8], link_type: LinkType) -> Result<CapturedFrame, Box<dyn Error>> {
    let length = u32::try_from(bytes.len())?;
    let timestamp = CaptureTimestamp::new(
        123_456_789,
        TimestampResolution::decimal(7)?,
        -3,
        TimestampSource::CaptureFile,
    );
    let metadata = CaptureMetadata::new(
        InterfaceId {
            section: 3,
            index: 2,
        },
        length,
        None,
        Some(timestamp),
        Direction::Unknown,
        Some(VlanAuxData {
            tpid: 0x8100,
            tci: 0x1005,
        }),
        FcsStatus::Unknown,
    )
    .with_link_type(link_type);
    Ok(CapturedFrame::new(bytes.to_vec(), metadata)?)
}
