use super::support::run;
use l2_workbench::evidence::{ByteMapping, Case, SourceRange};
use serde_json::Value;
use std::error::Error;

#[test]
fn concatenate_reads_retained_bytes_from_selected_node() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let node = case.add_bytes_node("candidate", b"selected bytes", Vec::new(), Value::Null)?;

    let output = run(
        &["concatenate", "-", "--node", &node.to_string()],
        &case.to_json()?,
    )?;

    assert!(output.status.success());
    let result = Case::from_json(&output.stdout)?;
    let object = result
        .nodes()
        .iter()
        .find(|candidate| candidate.kind == "concatenated_object")
        .ok_or("missing concatenated output node")?;
    let blob = result
        .blob(object.blob.as_deref().ok_or("output node has no blob id")?)
        .ok_or("concatenated output blob is missing")?;
    assert_eq!(blob.bytes, b"selected bytes");
    Ok(())
}

#[test]
fn concatenate_reports_a_missing_selected_node() -> Result<(), Box<dyn Error>> {
    let output = run(
        &["concatenate", "-", "--node", "1"],
        &Case::new().to_json()?,
    )?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("selected node does not exist"));
    Ok(())
}

#[test]
fn concatenate_reports_a_selected_node_without_retained_bytes() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let node = case.add_node("metadata_only", None, Vec::new(), Value::Null)?;

    let output = run(
        &["concatenate", "-", "--node", &node.to_string()],
        &case.to_json()?,
    )?;

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("selected node has no retained bytes")
    );
    Ok(())
}

#[test]
fn concatenate_keeps_case_validation_for_a_missing_blob_reference() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    case.add_bytes_node("candidate", b"retained", Vec::new(), Value::Null)?;
    let mut document: Value = serde_json::from_slice(&case.to_json()?)?;
    let node = document
        .get_mut("nodes")
        .and_then(Value::as_array_mut)
        .and_then(|nodes| nodes.first_mut())
        .ok_or("case has no first node")?;
    let blob = node
        .as_object_mut()
        .and_then(|node| node.get_mut("blob"))
        .ok_or("first node has no blob field")?;
    *blob = Value::String(format!("sha256:{}", "0".repeat(64)));

    let output = run(
        &["concatenate", "-", "--node", "1"],
        &serde_json::to_vec(&document)?,
    )?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing evidence blob reference"));
    Ok(())
}

#[test]
fn concatenate_reads_mapped_node_bytes_without_changing_them() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = case.add_source(
        "source.bin",
        "file",
        4,
        &l2_workbench::sha256(b"ABCD"),
        None,
    )?;
    let mappings = [
        ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source.clone(),
                packet: None,
                offset: 0,
                length: 1,
            },
        },
        ByteMapping {
            offset: 1,
            range: SourceRange {
                source,
                packet: None,
                offset: 3,
                length: 1,
            },
        },
    ];
    let node = case.add_mapped_bytes_node("mapped_candidate", b"AC", &mappings, Value::Null)?;

    let output = run(
        &["concatenate", "-", "--node", &node.to_string()],
        &case.to_json()?,
    )?;

    assert!(output.status.success());
    let result = Case::from_json(&output.stdout)?;
    let selected = result
        .nodes()
        .iter()
        .find(|candidate| candidate.id == node)
        .ok_or("mapped input node is missing")?;
    assert_eq!(selected.ranges.len(), 2);
    let object = result
        .nodes()
        .iter()
        .find(|candidate| candidate.kind == "concatenated_object")
        .ok_or("missing concatenated output node")?;
    let blob = result
        .blob(object.blob.as_deref().ok_or("output node has no blob id")?)
        .ok_or("concatenated output blob is missing")?;
    assert_eq!(blob.bytes, b"AC");
    Ok(())
}
