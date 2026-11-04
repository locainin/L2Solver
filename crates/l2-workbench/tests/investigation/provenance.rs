use super::{case_support::located_records, support::tcp};
use l2_capture::CaptureLocator;
use l2_workbench::{
    carrier::discovery::{DiscoveryError, mapped_node, mapped_node_with_supporting_mappings},
    investigation::{BuildInput, build},
    sha256,
};
use serde_json::Value;
use std::error::Error;

#[test]
fn reconstructed_tcp_run_keeps_all_identical_retransmission_sources() -> Result<(), Box<dyn Error>>
{
    let (records, length) = located_records(vec![
        tcp(false, 100, 0x02, b"")?,
        tcp(false, 101, 0x18, b"abcd")?,
        tcp(false, 101, 0x18, b"abcd")?,
        tcp(false, 105, 0x18, b"ef")?,
    ])?;
    let result = build(BuildInput {
        label: "retransmission.pcap",
        length,
        sha256_hex: &sha256(b"retransmission source"),
        records: &records,
        frames_seen: u64::try_from(records.len())?,
    })?;
    let node = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "tcp_byte_run")
        .ok_or("reconstructed TCP run is missing")?;

    // Discovery still requires exactly one mapping for each input byte
    assert!(
        matches!(mapped_node(&result.case, node.id), Err(DiscoveryError::InvalidMapping { sample_id }) if sample_id == node.id)
    );
    let supporting = mapped_node_with_supporting_mappings(&result.case, node.id)?;
    assert_eq!(supporting.bytes, b"abcdef");
    assert_eq!(
        supporting
            .mappings
            .iter()
            .filter_map(|mapping| mapping.range.packet)
            .collect::<Vec<_>>(),
        [2, 3, 4]
    );
    assert_eq!(supporting.node.ranges.len(), 3);
    let encoded = serde_json::to_value(&supporting.mappings)?;
    compare_mappings(
        encoded.as_array().ok_or("mappings are not an array")?,
        supporting.bytes,
        &records,
        node.id,
    )?;
    Ok(())
}

#[test]
fn conflicting_retransmissions_never_gain_exact_coverage_from_supporting_witnesses()
-> Result<(), Box<dyn Error>> {
    for reverse_order in [false, true] {
        let first = tcp(false, 101, 0x18, b"abcdef")?;
        let conflicting = tcp(false, 103, 0x18, b"XY")?;
        let packets = if reverse_order {
            vec![conflicting, first]
        } else {
            vec![first, conflicting]
        };
        let (records, length) = located_records(
            std::iter::once(tcp(false, 100, 0x02, b"")?)
                .chain(packets)
                .chain(std::iter::once(tcp(false, 101, 0x18, b"abcdef")?))
                .collect(),
        )?;
        let result = build(BuildInput {
            label: "generated conflicting retransmissions",
            length,
            sha256_hex: &sha256(b"generated conflicting retransmissions"),
            records: &records,
            frames_seen: u64::try_from(records.len())?,
        })?;
        let mut runs = Vec::new();
        for node in result
            .case
            .nodes()
            .iter()
            .filter(|node| node.kind == "tcp_byte_run")
        {
            let mapped = mapped_node_with_supporting_mappings(&result.case, node.id)?;
            // Each retained witness must match the actual source bytes even after overlap
            let encoded = serde_json::to_value(&mapped.mappings)?;
            compare_mappings(
                encoded.as_array().ok_or("mappings are not an array")?,
                mapped.bytes,
                &records,
                node.id,
            )?;
            runs.push(mapped.bytes.to_vec());
        }
        runs.sort();
        assert_eq!(runs, [b"ab".to_vec(), b"ef".to_vec()]);
    }
    Ok(())
}

#[test]
fn byte_mapping_literal_recovered_bytes() -> Result<(), Box<dyn Error>> {
    let mut payload = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n".to_vec();
    for _ in 0..80 {
        payload.extend_from_slice(b"X-Note: value\r\n");
    }
    payload.extend_from_slice(b"\r\n1\r\nA\r\n1\r\nB\r\n0\r\n\r\n");
    let (records, length) = located_records(vec![
        tcp(false, 100, 2, b"")?,
        tcp(false, 101, 0x18, &payload)?,
    ])?;
    let result = build(BuildInput {
        label: "provenance.pcap",
        length,
        sha256_hex: &sha256(b"provenance source"),
        records: &records,
        frames_seen: 2,
    })?;
    let edges: Vec<_> = result
        .case
        .edges()
        .iter()
        .filter(|edge| edge.relation == "mapped_by")
        .collect();
    assert_ne!(edges.len(), 0);
    for edge in edges {
        let output_node = result
            .case
            .nodes()
            .iter()
            .find(|node| node.id == edge.from)
            .ok_or("missing mapped node")?;
        let output = result
            .case
            .blobs()
            .iter()
            .find(|blob| Some(&blob.id) == output_node.blob.as_ref())
            .ok_or("missing mapped bytes")?;
        let receipt = result
            .case
            .nodes()
            .iter()
            .find(|node| node.id == edge.to)
            .ok_or("missing receipt")?;
        let mapping_blob = result
            .case
            .blobs()
            .iter()
            .find(|blob| Some(&blob.id) == receipt.blob.as_ref())
            .ok_or("missing receipt bytes")?;
        let mappings: Vec<Value> = serde_json::from_slice(&mapping_blob.bytes)?;
        compare_mappings(&mappings, &output.bytes, &records, output_node.id)?;
    }
    Ok(())
}

fn compare_mappings(
    mappings: &[Value],
    output: &[u8],
    records: &[l2_workbench::investigation::Record],
    node: u64,
) -> Result<(), Box<dyn Error>> {
    for mapping in mappings {
        let offset = number(mapping, "/offset")?;
        let length = number(mapping, "/range/length")?;
        let packet = number(mapping, "/range/packet")?;
        let file_offset = number(mapping, "/range/offset")?;
        let record = records
            .get(packet.checked_sub(1).ok_or("zero record")?)
            .ok_or("missing record")?;
        let Some(CaptureLocator::ClassicPcap { data_offset, .. }) =
            record.frame.metadata().locator()
        else {
            return Err("missing locator".into());
        };
        let source_offset = file_offset
            .checked_sub(usize::try_from(data_offset)?)
            .ok_or("range precedes frame")?;
        let actual = output
            .get(offset..offset + length)
            .ok_or("mapped output interval is out of bounds")?;
        let original = record
            .frame
            .bytes()
            .get(source_offset..source_offset + length)
            .ok_or("mapped source interval is out of bounds")?;
        assert!(
            actual == original,
            "node {node} has a nonliteral byte mapping"
        );
    }
    Ok(())
}

fn number(value: &Value, path: &str) -> Result<usize, Box<dyn Error>> {
    Ok(usize::try_from(
        value
            .pointer(path)
            .and_then(Value::as_u64)
            .ok_or("missing integer")?,
    )?)
}
