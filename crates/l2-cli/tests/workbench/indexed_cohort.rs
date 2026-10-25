use super::support::{empty_capture, path_arg, run};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{error::Error, fs, path::Path};

fn packet(
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut frame = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0];
    frame.extend_from_slice(&[0x45, 0]);
    frame.extend_from_slice(&u16::try_from(40 + payload.len())?.to_be_bytes());
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(&[64, 6, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2]);
    frame.extend_from_slice(&source_port.to_be_bytes());
    frame.extend_from_slice(&destination_port.to_be_bytes());
    frame.extend_from_slice(&sequence.to_be_bytes());
    frame.extend_from_slice(&0_u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, 0x18, 0, 0, 0, 0, 0, 0]);
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn capture() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = empty_capture();
    for (index, frame) in [
        packet(40_000, 9_000, 100, b"first")?,
        packet(41_000, 8_000, 200, b"middle")?,
        packet(40_000, 9_000, 105, b"last")?,
    ]
    .into_iter()
    .enumerate()
    {
        bytes.extend_from_slice(&u32::try_from(index)?.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        let length = u32::try_from(frame.len())?;
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&frame);
    }
    Ok(bytes)
}

fn indexed_fixture(directory: &Path) -> Result<Vec<Value>, Box<dyn Error>> {
    let capture_path = directory.join("cohort.pcap");
    let index_path = directory.join("index");
    fs::write(&capture_path, capture()?)?;
    let indexed = run(
        &[
            "index",
            path_arg(&capture_path)?,
            "--directory",
            path_arg(&index_path)?,
        ],
        b"",
    )?;
    assert!(
        indexed.status.success(),
        "{}",
        String::from_utf8_lossy(&indexed.stderr)
    );
    let flows = run(&["indexed", path_arg(&index_path)?, "flows"], b"")?;
    assert!(flows.status.success());
    Ok(String::from_utf8(flows.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?)
}

fn flow_id_for_packet(flows: &[Value], packet: u64) -> Result<i64, Box<dyn Error>> {
    flows
        .iter()
        .find(|flow| flow.get("first_packet").and_then(Value::as_u64) == Some(packet))
        .and_then(|flow| flow.get("id"))
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("flow for packet {packet} is missing").into())
}

fn case_node<'a>(case: &'a Value, kind: &str) -> Result<&'a Value, Box<dyn Error>> {
    case.pointer("/nodes")
        .and_then(Value::as_array)
        .and_then(|nodes| {
            nodes
                .iter()
                .find(|node| node.get("kind").and_then(Value::as_str) == Some(kind))
        })
        .ok_or_else(|| format!("{kind} evidence is missing").into())
}

fn node_blob_json(case: &Value, node: &Value) -> Result<Value, Box<dyn Error>> {
    let blob_id = node
        .get("blob")
        .and_then(Value::as_str)
        .ok_or("node receipt blob is missing")?;
    let encoded = case
        .get("blobs")
        .and_then(Value::as_array)
        .and_then(|blobs| {
            blobs
                .iter()
                .find(|blob| blob.get("id").and_then(Value::as_str) == Some(blob_id))
        })
        .and_then(|blob| blob.get("bytes_base64"))
        .and_then(Value::as_str)
        .ok_or("node receipt bytes are missing")?;
    Ok(serde_json::from_slice(&STANDARD.decode(encoded)?)?)
}

#[test]
fn indexed_flow_accepts_ordered_cohorts() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let flows = indexed_fixture(temporary.path())?;
    let index_path = temporary.path().join("index");
    let first = flow_id_for_packet(&flows, 1)?.to_string();
    let second = flow_id_for_packet(&flows, 2)?.to_string();
    let first_number = first.parse::<i64>()?;
    let second_number = second.parse::<i64>()?;

    let single = run(&["indexed", path_arg(&index_path)?, "flow", &first], b"")?;
    assert!(
        single.status.success(),
        "{}",
        String::from_utf8_lossy(&single.stderr)
    );
    let single_case: Value = serde_json::from_slice(&single.stdout)?;
    let single_selection = case_node(&single_case, "index_flow_selection")?;
    assert_eq!(
        single_selection.pointer("/details/flow_id"),
        Some(&json!(first_number))
    );
    assert_eq!(
        node_blob_json(&single_case, single_selection)?.get("requested_flow_ids"),
        Some(&json!([first_number]))
    );

    let cohort = run(
        &["indexed", path_arg(&index_path)?, "flow", &second, &first],
        b"",
    )?;
    assert!(
        cohort.status.success(),
        "{}",
        String::from_utf8_lossy(&cohort.stderr)
    );
    let case: Value = serde_json::from_slice(&cohort.stdout)?;
    let selection_node = case_node(&case, "index_flow_selection")?;
    assert_eq!(
        node_blob_json(&case, selection_node)?.get("requested_flow_ids"),
        Some(&json!([second_number, first_number]))
    );
    assert_eq!(
        selection_node.pointer("/details/retained_input_records"),
        Some(&json!(3))
    );
    assert_eq!(
        selection_node.pointer("/details/selected_records"),
        Some(&json!(3))
    );
    let packet_numbers: Vec<_> = case
        .pointer("/nodes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|node| node.get("kind") == Some(&json!("packet")))
        .filter_map(|node| node.pointer("/details/record").and_then(Value::as_u64))
        .collect();
    assert_eq!(packet_numbers, [1, 2, 3]);
    Ok(())
}

#[test]
fn indexed_flow_reconstruction_retention_overrides() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let flows = indexed_fixture(temporary.path())?;
    let index_path = temporary.path().join("index");
    let first = flow_id_for_packet(&flows, 1)?.to_string();
    let second = flow_id_for_packet(&flows, 2)?.to_string();
    let limited = run(
        &[
            "indexed",
            path_arg(&index_path)?,
            "flow",
            &second,
            &first,
            "--max-frames",
            "1",
        ],
        b"",
    )?;
    assert_eq!(
        limited.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&limited.stderr)
    );
    let case: Value = serde_json::from_slice(&limited.stdout)?;
    let selection = case
        .pointer("/nodes")
        .and_then(Value::as_array)
        .and_then(|nodes| {
            nodes
                .iter()
                .find(|node| node.get("kind") == Some(&json!("index_flow_selection")))
        })
        .ok_or("flow selection evidence is missing")?;
    assert_eq!(
        selection.pointer("/details/retained_input_records"),
        Some(&json!(1))
    );
    assert_eq!(
        selection.pointer("/details/omitted_records"),
        Some(&json!(2))
    );
    Ok(())
}
