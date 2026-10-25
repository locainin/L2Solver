#[path = "../src/inspect.rs"]
mod inspect;
#[path = "../src/render.rs"]
mod render;
#[path = "../src/report.rs"]
mod report;
#[path = "../src/source_collection.rs"]
pub mod source_collection;

use l2_io::{FakeLink, Packet};

#[test]
fn counts_loss_continues_malformed() -> Result<(), Box<dyn std::error::Error>> {
    let mut source = FakeLink::default();
    source.push_rx(packet(vec![0], 60)?)?;
    let mut capture =
        l2_pcap::CaptureReader::new(include_bytes!("../../../tests/pcaps/lldp.pcap").as_slice())?;
    source.push_rx(capture.next_packet()?.ok_or("missing fixture frame")?)?;
    let mut output = Vec::new();
    let summary = inspect::inspect(&mut source, &mut output)?;
    assert_eq!(summary.malformed, 1);
    assert_eq!(summary.truncated, 1);
    let output = String::from_utf8(output)?;
    assert!(output.contains("LLDP Valid"));
    assert!(output.ends_with("frames=2 malformed=1 invalid=0 unsupported=0 truncated=1\n"));
    Ok(())
}

#[test]
fn receive_loop_propagates_write_failure() -> Result<(), Box<dyn std::error::Error>> {
    let mut source = FakeLink::default();
    let mut empty = [].as_mut_slice();
    assert!(inspect::inspect(&mut source, &mut empty).is_err());
    source.push_rx(packet(vec![0], 1)?)?;
    assert!(inspect::inspect(&mut source, &mut empty).is_err());
    Ok(())
}

#[test]
fn reports_malformed_and_invalid_lldp() -> Result<(), Box<dyn std::error::Error>> {
    let mut source = FakeLink::default();
    // End-only LLDP is structurally complete but lacks the mandatory TLVs
    for payload in [vec![0, 0], vec![2]] {
        let mut bytes = vec![0; 12];
        bytes.extend_from_slice(&0x88cc_u16.to_be_bytes());
        bytes.extend_from_slice(&payload);
        source.push_rx(packet(bytes.clone(), u32::try_from(bytes.len())?)?)?;
    }
    let mut output = Vec::new();
    let summary = inspect::inspect(&mut source, &mut output)?;
    assert_eq!(summary.malformed, 1);
    assert_eq!(summary.invalid, 1);
    assert_eq!(summary.truncated, 0);
    let output = String::from_utf8(output)?;
    assert!(output.contains("LLDP Invalid"));
    assert!(output.contains("malformed LLDP:"));
    Ok(())
}

#[test]
fn observes_unknown_ethertype() -> Result<(), Box<dyn std::error::Error>> {
    let mut source = FakeLink::default();
    let mut bytes = vec![0; 12];
    bytes.extend_from_slice(&0x9999_u16.to_be_bytes());
    source.push_rx(packet(bytes, 14)?)?;
    let mut output = Vec::new();
    let summary = inspect::inspect(&mut source, &mut output)?;
    assert_eq!(summary.malformed, 0);
    let output = String::from_utf8(output)?;
    assert!(output.contains("EtherType(39321)"));
    assert!(!output.contains("LLDP"));
    Ok(())
}

#[test]
fn reports_packet_block_loss_in_text_and_json() -> Result<(), Box<dyn std::error::Error>> {
    let summary = l2_pcap::CollectionSummary {
        packet_block_packets_dropped: 4,
        packet_blocks_with_unavailable_drop_count: 2,
        ..l2_pcap::CollectionSummary::default()
    };
    let mut text = Vec::new();
    assert!(!source_collection::text(summary, &mut text)?);
    let text = String::from_utf8(text)?;
    assert!(text.contains("packet_block_packets_dropped=4"));
    assert!(text.contains("packet_blocks_with_unavailable_drop_count=2"));

    let mut json = Vec::new();
    source_collection::json(summary, &mut json)?;
    let json: serde_json::Value = serde_json::from_slice(&json)?;
    assert_eq!(
        json.pointer("/source_collection/packet_block_packets_dropped"),
        Some(&serde_json::json!(4))
    );
    assert_eq!(
        json.pointer("/source_collection/packet_blocks_with_unavailable_drop_count"),
        Some(&serde_json::json!(2))
    );
    Ok(())
}

fn packet(bytes: Vec<u8>, original_len: u32) -> Result<Packet, l2_capture::FrameError> {
    Packet::new(
        bytes,
        l2_capture::CaptureMetadata::unknown(
            l2_capture::InterfaceId {
                section: 0,
                index: 0,
            },
            original_len,
        ),
    )
}
