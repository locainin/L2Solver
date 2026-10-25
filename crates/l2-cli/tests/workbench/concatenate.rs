use super::support::run;
use l2_workbench::evidence::Case;
use std::error::Error;

#[test]
fn concatenate_explicit_repeats_output_ranges() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = case.add_bytes_node("decoded_part", b"ab", Vec::new(), serde_json::json!({}))?;
    let second = case.add_bytes_node("decoded_part", b"cde", Vec::new(), serde_json::json!({}))?;

    let output = run(
        &[
            "concatenate",
            "-",
            "--node",
            &first.to_string(),
            "--node",
            &second.to_string(),
            "--node",
            &first.to_string(),
        ],
        &case.to_json()?,
    )?;

    assert!(output.status.success());
    let result = Case::from_json(&output.stdout)?;
    let object = result
        .nodes()
        .iter()
        .find(|node| node.kind == "concatenated_object")
        .ok_or("missing concatenated object")?;
    let blob = result
        .blobs()
        .iter()
        .find(|blob| Some(blob.id.as_str()) == object.blob.as_deref())
        .ok_or("missing concatenated bytes")?;
    assert_eq!(blob.bytes, b"abcdeab");
    assert_eq!(
        object.details.pointer("/parts/0/output_offset"),
        Some(&serde_json::json!(0))
    );
    assert_eq!(
        object.details.pointer("/parts/1/output_offset"),
        Some(&serde_json::json!(2))
    );
    assert_eq!(
        object.details.pointer("/parts/2/output_offset"),
        Some(&serde_json::json!(5))
    );
    assert_eq!(
        result
            .edges()
            .iter()
            .filter(|edge| edge.to == object.id && edge.relation == "concatenated_into")
            .count(),
        3
    );
    Ok(())
}

#[test]
fn concatenate_output_above_explicit_budget() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = case.add_bytes_node("decoded_part", b"abc", Vec::new(), serde_json::json!({}))?;
    let second = case.add_bytes_node("decoded_part", b"def", Vec::new(), serde_json::json!({}))?;

    let output = run(
        &[
            "concatenate",
            "-",
            "--node",
            &first.to_string(),
            "--node",
            &second.to_string(),
            "--max-output-bytes",
            "5",
        ],
        &case.to_json()?,
    )?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("maximum is 5"));
    Ok(())
}
