use super::support::{path_arg, run, save_case};
use l2_workbench::evidence::Case;
use serde_json::json;
use std::{error::Error, fs};

#[test]
fn malformed_forged_cases_rejected_output() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let malformed = directory.path().join("malformed.json");
    let forged = directory.path().join("forged.json");
    let destination = directory.path().join("report.json");
    fs::write(&malformed, b"{")?;
    let mut case = Case::new();
    case.add_bytes_node("candidate", b"original", Vec::new(), json!({}))?;
    let mut forged_json: serde_json::Value = serde_json::from_slice(&case.to_json()?)?;
    let bytes = forged_json
        .pointer_mut("/blobs/0/bytes_base64")
        .ok_or("serialized case has no first blob")?;
    *bytes = json!("Zm9yZ2Vk");
    fs::write(&forged, serde_json::to_vec(&forged_json)?)?;

    for path in [&malformed, &forged] {
        let output = run(
            &[
                "inspect",
                path_arg(path)?,
                "--format",
                "json",
                "--output",
                path_arg(&destination)?,
            ],
            &[],
        )?;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(!destination.exists());
    }
    Ok(())
}

#[test]
fn inspect_incomplete_persisted_partial_case() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    case.mark_incomplete("Some observations were omitted")?;
    let case_path = save_case(directory.path(), "case.json", &case)?;

    let output = run(&["inspect", path_arg(&case_path)?, "--format", "json"], &[])?;

    assert_eq!(output.status.code(), Some(3));
    assert!(!Case::from_json(&output.stdout)?.collection_complete());

    let text = run(&["inspect", path_arg(&case_path)?], &[])?;
    assert_eq!(text.status.code(), Some(3));
    let text = String::from_utf8(text.stdout)?;
    assert!(text.contains(&case_path.display().to_string()));
    assert!(text.contains("collection=incomplete"));
    assert!(text.contains("Some observations were omitted"));
    Ok(())
}

#[test]
fn inspect_text_without_kind_allowlist() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let node_id = case.add_bytes_node(
        "future_artifact",
        b"retained evidence",
        Vec::new(),
        json!({}),
    )?;
    let blob_id = case
        .nodes()
        .iter()
        .find(|node| node.id == node_id)
        .and_then(|node| node.blob.as_deref())
        .ok_or("byte node has no retained blob")?
        .to_owned();
    let case_path = save_case(directory.path(), "case.json", &case)?;

    let output = run(&["inspect", path_arg(&case_path)?], &[])?;

    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.starts_with("Saved analysis: file="));
    assert!(text.contains(&format!(
        "retained bytes item={node_id} type=future_artifact"
    )));
    assert!(!text.contains("digest="));
    assert!(!text.contains(&blob_id));
    assert!(!text.contains("schema="));
    assert!(!text.contains("nodes="));
    assert!(!text.contains("blob="));

    let json = run(&["inspect", path_arg(&case_path)?, "--format", "json"], &[])?;
    assert!(json.status.success());
    let parsed = Case::from_json(&json.stdout)?;
    assert!(parsed.blobs().iter().any(|blob| blob.id == blob_id));
    Ok(())
}
