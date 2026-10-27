#[path = "investigation/application_limits.rs"]
mod application_limits;
#[path = "investigation/artifacts.rs"]
mod artifacts;
#[path = "investigation/carrier_cohorts.rs"]
mod carrier_cohorts;
#[path = "investigation/support.rs"]
mod case_support;
#[path = "investigation/fragments.rs"]
mod fragments;
#[path = "investigation/ftp.rs"]
mod ftp;
#[path = "investigation/large_runs.rs"]
mod large_runs;
#[path = "investigation/link_type.rs"]
mod link_type;
#[path = "investigation/memory.rs"]
mod memory;
#[path = "investigation/parser_validity.rs"]
mod parser_validity;
#[path = "investigation/provenance.rs"]
mod provenance;
#[path = "investigation/selected.rs"]
mod selected;
#[path = "reconstruction/support.rs"]
mod support;
#[path = "investigation/timestamps.rs"]
mod timestamps;
#[path = "investigation/window.rs"]
mod window;

use case_support::located_records;
use l2_workbench::{
    investigation::{BuildInput, Record, build},
    sha256,
};
use std::error::Error;
use support::{fragment, frame, tcp};

#[test]
fn investigation_recovers_body_packet_locations() -> Result<(), Box<dyn Error>> {
    let payload = b"POST /data HTTP/1.1\r\nContent-Length: 4\r\n\r\n4142";
    let frames = vec![
        tcp(false, 100, 2, b"")?,
        tcp(false, 101, 0x18, payload)?,
        tcp(false, 101 + u32::try_from(payload.len())?, 0x11, b"")?,
    ];
    let (records, offset) = located_records(frames)?;
    let result = build(BuildInput {
        label: "sample.pcap",
        length: offset,
        sha256_hex: &sha256(b"source identity supplied by caller"),
        records: &records,
        frames_seen: 3,
    })?;
    result.case.validate()?;
    let body = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "http_body")
        .ok_or("missing HTTP body")?;
    let blob = result
        .case
        .blobs()
        .iter()
        .find(|blob| Some(&blob.id) == body.blob.as_ref())
        .ok_or("missing body blob")?;
    assert_eq!(blob.bytes, b"4142");
    assert_eq!(body.ranges.first().and_then(|range| range.packet), Some(2));
    assert!(
        result
            .case
            .edges()
            .iter()
            .any(|edge| edge.to == body.id && edge.relation == "derived_from")
    );
    Ok(())
}

#[test]
fn chunked_body_source_mapping_receipts() -> Result<(), Box<dyn Error>> {
    let payload =
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nAB\r\n2\r\nCD\r\n0\r\n\r\n";
    let (records, length) = located_records(vec![
        tcp(false, 100, 2, b"")?,
        tcp(false, 101, 0x18, payload)?,
    ])?;
    let result = build(BuildInput {
        label: "chunks.pcap",
        length,
        sha256_hex: &sha256(b"chunk source"),
        records: &records,
        frames_seen: 2,
    })?;
    let body = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "http_body")
        .ok_or("missing body")?;
    let mapping_edge = result
        .case
        .edges()
        .iter()
        .find(|edge| edge.from == body.id && edge.relation == "mapped_by")
        .ok_or("missing byte mapping receipt")?;
    let mapping = result
        .case
        .nodes()
        .iter()
        .find(|node| node.id == mapping_edge.to)
        .ok_or("missing mapping node")?;
    let blob = result
        .case
        .blobs()
        .iter()
        .find(|blob| Some(&blob.id) == mapping.blob.as_ref())
        .ok_or("missing mapping bytes")?;
    let value: serde_json::Value = serde_json::from_slice(&blob.bytes)?;
    assert_eq!(value.pointer("/0/offset"), Some(&serde_json::json!(0)));
    assert_eq!(value.pointer("/1/offset"), Some(&serde_json::json!(2)));
    assert_eq!(
        value.pointer("/0/range/length"),
        Some(&serde_json::json!(2))
    );
    Ok(())
}

#[test]
fn layout_hypotheses_held_out_counterexamples() -> Result<(), Box<dyn Error>> {
    let payloads = [
        vec![4, b'A', 0, 0],
        vec![5, b'A', 0, 0, 0],
        vec![6, b'A', 0, 0, 0, 0],
        vec![9, b'B', 0, 0, 0, 0, 0],
    ];
    let mut frames = vec![tcp(false, 100, 2, b"")?];
    let mut sequence = 101;
    for payload in payloads {
        frames.push(tcp(false, sequence, 0x18, &payload)?);
        sequence += u32::try_from(payload.len())?;
    }
    let (records, length) = located_records(frames)?;
    let result = build(BuildInput {
        label: "layouts.pcap",
        length,
        sha256_hex: &sha256(b"layout source"),
        records: &records,
        frames_seen: 5,
    })?;
    let node = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "length_field_hypotheses")
        .ok_or("missing length tests")?;
    let value = if let Some(blob) = &node.blob {
        serde_json::from_slice(
            &result
                .case
                .blobs()
                .iter()
                .find(|entry| &entry.id == blob)
                .ok_or("missing layout blob")?
                .bytes,
        )?
    } else {
        node.details.clone()
    };
    let candidates = value
        .pointer("/results/candidates")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing candidates")?;
    let candidate = candidates
        .iter()
        .find(|item| {
            item.pointer("/candidate/offset") == Some(&serde_json::json!(0))
                && item.pointer("/candidate/width") == Some(&serde_json::json!(1))
        })
        .ok_or("missing selected length candidate")?;
    assert_eq!(
        candidate.pointer("/holdout/status"),
        Some(&serde_json::json!("constraint_failed"))
    );
    assert!(
        result
            .case
            .nodes()
            .iter()
            .any(|node| node.kind == "prefix_hypotheses")
    );
    Ok(())
}

#[test]
fn missing_frames_mark_case_incomplete() -> Result<(), Box<dyn Error>> {
    let records = [Record {
        number: 1,
        frame: tcp(false, 100, 2, b"")?,
    }];
    let result = build(BuildInput {
        label: "bounded.pcap",
        length: 1024,
        sha256_hex: &sha256(b"bounded source"),
        records: &records,
        frames_seen: 5,
    })?;
    assert!(!result.complete);
    assert!(
        result
            .case
            .limitations()
            .iter()
            .any(|text| text.contains("omitted"))
    );
    Ok(())
}

#[test]
fn conflicts_prevent_complete_http_body() -> Result<(), Box<dyn Error>> {
    let records = [
        Record {
            number: 1,
            frame: tcp(false, 100, 2, b"")?,
        },
        Record {
            number: 2,
            frame: tcp(
                false,
                101,
                0x18,
                b"POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\nA",
            )?,
        },
        Record {
            number: 3,
            frame: tcp(false, 101, 0x18, b"X")?,
        },
    ];
    let result = build(BuildInput {
        label: "overlap.pcap",
        length: 2048,
        sha256_hex: &sha256(b"overlap source"),
        records: &records,
        frames_seen: 3,
    })?;
    assert!(!result.case.nodes().iter().any(|node| {
        node.kind == "http_body"
            && node
                .details
                .get("status")
                .and_then(serde_json::Value::as_str)
                == Some("complete")
    }));
    Ok(())
}

#[test]
fn separate_interfaces_create_series() -> Result<(), Box<dyn Error>> {
    let records = [
        Record {
            number: 1,
            frame: frame(0, &tcp(false, 101, 0x10, b"abc")?)?,
        },
        Record {
            number: 2,
            frame: frame(1, &tcp(false, 104, 0x10, b"def")?)?,
        },
    ];
    let result = build(BuildInput {
        label: "scoped.pcap",
        length: 2048,
        sha256_hex: &sha256(b"scoped source"),
        records: &records,
        frames_seen: 2,
    })?;
    assert_eq!(
        result
            .case
            .nodes()
            .iter()
            .filter(|node| node.kind == "carrier_series")
            .count(),
        2
    );
    Ok(())
}

#[test]
fn fragmented_payload_keeps_ambiguous_identity() -> Result<(), Box<dyn Error>> {
    let records = [
        Record {
            number: 1,
            frame: fragment(0x2000, &[0x9c, 0x40, 0x23, 0x45, 0, 14, 0, 0])?,
        },
        Record {
            number: 2,
            frame: fragment(1, b"abcdef")?,
        },
    ];
    let result = build(BuildInput {
        label: "fragments.pcap",
        length: 2048,
        sha256_hex: &sha256(b"fragments source"),
        records: &records,
        frames_seen: 2,
    })?;
    let payload = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "udp_payload")
        .ok_or("missing recovered payload")?;
    assert_eq!(
        payload.details.get("identity_ambiguous"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(
        payload.details.get("from_fragments"),
        Some(&serde_json::json!(true))
    );
    Ok(())
}

#[test]
fn packet_budget_limits_large_inputs() -> Result<(), Box<dyn Error>> {
    let payload = vec![0; 65_481];
    let captured = tcp(false, 101, 0x10, &payload)?;
    let records: Vec<_> = (1..=257)
        .map(|number| Record {
            number,
            frame: captured.clone(),
        })
        .collect();
    let result = build(BuildInput {
        label: "budget.pcap",
        length: 20 * 1024 * 1024,
        sha256_hex: &sha256(b"budget source"),
        records: &records,
        frames_seen: 257,
    })?;
    assert!(!result.complete);
    assert_eq!(
        result
            .case
            .nodes()
            .iter()
            .filter(|node| node.kind == "packet")
            .count(),
        256
    );
    result.case.validate()?;
    Ok(())
}
