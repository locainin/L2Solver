use super::{case_support::located_records, support::tcp};
use l2_capture::{CapturedFrame, LinkType};
use l2_workbench::{
    investigation::{BuildInput, build},
    sha256,
};
use std::error::Error;

#[test]
fn radiotap_frames_skip_ip_parsing() -> Result<(), Box<dyn Error>> {
    let ethernet = tcp(false, 100, 0x10, b"opaque")?;
    let opaque = CapturedFrame::new(
        ethernet.bytes().to_vec(),
        ethernet
            .metadata()
            .clone()
            .with_link_type(LinkType::Ieee80211Radiotap),
    )?;
    let (records, length) = located_records(vec![opaque])?;
    let result = build(BuildInput {
        label: "wireless.pcap",
        length,
        sha256_hex: &sha256(b"wireless source"),
        records: &records,
        frames_seen: 1,
    })?;
    let packet = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "packet")
        .ok_or("missing raw packet")?;
    assert_eq!(
        packet.details.get("link_type"),
        Some(&serde_json::json!(127))
    );
    assert!(packet.details.get("source_ip").is_none());
    assert!(!result.case.nodes().iter().any(|node| matches!(
        node.kind.as_str(),
        "ip_communication" | "tcp_episode" | "carrier_series"
    )));
    assert!(!result.case.collection_complete());
    Ok(())
}
