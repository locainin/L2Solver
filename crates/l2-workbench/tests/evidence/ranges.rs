use l2_workbench::evidence::{Case, MAX_NODE_RANGES, MAX_TOTAL_SOURCE_RANGES, SourceRange};
use serde_json::{Value, json};
use std::error::Error;

#[test]
fn aggregate_source_quota_next_node() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = case.add_source("sample.bin", "file", 1_024, &"0".repeat(64), None)?;
    let ranges = make_ranges(&source)?;
    let node_count = MAX_TOTAL_SOURCE_RANGES / MAX_NODE_RANGES;

    for _ in 0..node_count {
        case.add_node("observation", None, ranges.clone(), json!({}))?;
    }
    let previous_count = case.nodes().len();
    let first_range = ranges.first().ok_or("missing range fixture")?.clone();
    assert!(
        case.add_node("observation", None, vec![first_range], json!({}))
            .is_err()
    );
    assert_eq!(case.nodes().len(), previous_count);
    Ok(())
}

#[test]
fn loader_oversized_range_sequence_decoding() -> Result<(), Box<dyn Error>> {
    let source = format!("sha256:{}", "0".repeat(64));
    let ranges: Vec<_> = (0..=MAX_NODE_RANGES)
        .map(|offset| {
            json!({
                "source": source.clone(),
                "packet": null,
                "offset": offset,
                "length": 1,
            })
        })
        .collect();
    let document = json!({
        "schema_version": 1,
        "collection_complete": true,
        "sources": [],
        "blobs": [],
        "nodes": [{
            "id": 1,
            "kind": "observation",
            "blob": null,
            "ranges": ranges,
            "details": {},
        }],
        "edges": [],
        "limitations": [],
    });
    let encoded = serde_json::to_vec(&document)?;

    assert!(Case::from_json(&encoded).is_err());
    Ok(())
}

#[test]
fn loader_zero_length_source_range() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = case.add_source("range.bin", "file", 1, &"0".repeat(64), None)?;
    case.add_node(
        "observation",
        None,
        vec![SourceRange {
            source,
            packet: None,
            offset: 0,
            length: 1,
        }],
        json!({}),
    )?;
    let mut document: Value = serde_json::from_slice(&case.to_json()?)?;
    let range = document
        .get_mut("nodes")
        .and_then(Value::as_array_mut)
        .and_then(|nodes| nodes.first_mut())
        .and_then(|node| node.get_mut("ranges"))
        .and_then(Value::as_array_mut)
        .and_then(|ranges| ranges.first_mut())
        .and_then(Value::as_object_mut)
        .ok_or("serialized source range is missing")?;
    range.insert("length".to_owned(), json!(0));

    assert!(Case::from_json(&serde_json::to_vec(&document)?).is_err());
    Ok(())
}

fn make_ranges(source: &str) -> Result<Vec<SourceRange>, Box<dyn Error>> {
    (0..MAX_NODE_RANGES)
        .map(|offset| {
            Ok(SourceRange {
                source: source.to_owned(),
                packet: None,
                offset: u64::try_from(offset)?,
                length: 1,
            })
        })
        .collect()
}
