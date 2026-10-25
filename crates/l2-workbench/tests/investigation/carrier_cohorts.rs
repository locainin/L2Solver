use super::{
    case_support::located_records,
    support::{frame, tcp_ports},
};
use l2_capture::{CaptureMetadata, CapturedFrame};
use l2_workbench::{
    evidence::Case,
    investigation::{BuildInput, Record, build},
    sha256,
};
use serde_json::Value;
use std::error::Error;

#[test]
fn repeated_endpoints_without_peer_addresses() -> Result<(), Box<dyn Error>> {
    let case = scoped_cohort_case()?;
    let cohorts: Vec<_> = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "carrier_endpoint_cohort")
        .collect();
    assert_eq!(cohorts.len(), 1);
    let cohort = cohorts.first().ok_or("missing endpoint cohort")?;
    assert_eq!(
        cohort.details.get("local_address").and_then(Value::as_str),
        Some("192.0.2.1"),
        "{:#}",
        cohort.details
    );
    assert_eq!(
        cohort.details.get("direction").and_then(Value::as_str),
        Some("to_endpoint")
    );
    assert_eq!(
        cohort
            .details
            .get("peer_tuple_count")
            .and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        cohort
            .details
            .get("scope")
            .and_then(|scope| scope.get("interface"))
            .and_then(Value::as_u64),
        Some(0)
    );
    assert!(
        cohort
            .details
            .get("interpretation")
            .and_then(Value::as_str)
            .is_some_and(|text| text.contains("candidate"))
    );

    let included_series: Vec<_> = case
        .edges()
        .iter()
        .filter(|edge| edge.from == cohort.id && edge.relation == "includes_connection")
        .collect();
    assert_eq!(included_series.len(), 2);
    assert!(
        included_series
            .iter()
            .all(|edge| edge.status == l2_workbench::evidence::EvidenceStatus::Hypothesis)
    );
    let included_episodes = case
        .edges()
        .iter()
        .filter(|edge| edge.from == cohort.id && edge.relation == "contains_candidate_episode")
        .count();
    assert_eq!(
        cohort
            .details
            .get("tcp_episode_count")
            .and_then(Value::as_u64),
        Some(u64::try_from(included_episodes)?)
    );
    case.validate()?;
    Ok(())
}

fn scoped_cohort_case() -> Result<Case, Box<dyn Error>> {
    let alternate_peer = with_source_address(
        &tcp_ports(false, (40002, 9000), 301, 0x18, b"third")?,
        [192, 0, 2, 3],
    )?;

    let records = [
        Record {
            number: 1,
            frame: frame(0, &tcp_ports(false, (40000, 9000), 101, 0x18, b"one")?)?,
        },
        Record {
            number: 2,
            frame: frame(0, &tcp_ports(false, (40001, 9000), 201, 0x18, b"two")?)?,
        },
        Record {
            number: 3,
            frame: frame(0, &alternate_peer)?,
        },
        Record {
            number: 4,
            frame: frame(
                1,
                &tcp_ports(false, (40003, 9000), 401, 0x18, b"other scope")?,
            )?,
        },
        Record {
            number: 5,
            frame: frame(0, &tcp_ports(true, (40000, 9000), 501, 0x18, b"reply")?)?,
        },
    ];
    let (records, length) =
        located_records(records.into_iter().map(|record| record.frame).collect())?;
    let result = build(BuildInput {
        label: "carrier-cohorts.pcap",
        length,
        sha256_hex: &sha256(b"carrier cohort source"),
        records: &records,
        frames_seen: 5,
    })?;
    Ok(result.case)
}

fn with_source_address(
    frame: &CapturedFrame,
    address: [u8; 4],
) -> Result<CapturedFrame, Box<dyn Error>> {
    let mut bytes = frame.bytes().to_vec();
    // The IPv4 source address begins after the Ethernet header and the first twelve IP bytes
    bytes
        .get_mut(26..30)
        .ok_or("frame does not contain IPv4 source address")?
        .copy_from_slice(&address);
    let metadata = CaptureMetadata::unknown(
        frame.metadata().interface(),
        frame.metadata().original_len(),
    );
    Ok(CapturedFrame::new(bytes, metadata)?)
}
