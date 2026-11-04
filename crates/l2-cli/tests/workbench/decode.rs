use super::support::{path_arg, run, save_case};
use l2_workbench::evidence::Case;
use serde_json::{Value, json};
use std::{error::Error, fs};

#[test]
fn imported_bytes_decoded_reproducible_receipt() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let imported = directory.path().join("candidate.bin");
    let recipe = directory.path().join("recipe.json");
    fs::write(&imported, b"4142")?;
    fs::write(&recipe,br#"{"steps":[{"kind":"hex_decode"}],"constraints":[{"kind":"length","bytes":2},{"kind":"prefix","bytes":[65,66]}]}"#)?;
    let output = run(
        &["import", "-", path_arg(&imported)?, "--kind", "binary"],
        &Case::new().to_json()?,
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stored = Case::from_json(&output.stdout)?;
    let source_node = stored
        .nodes()
        .iter()
        .find(|node| node.kind == "imported_source")
        .ok_or("missing imported source node")?;
    let id = source_node.id.to_string();
    let output = run(
        &["decode", "-", "--node", &id, "--recipe", path_arg(&recipe)?],
        &output.stdout,
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decoded = Case::from_json(&output.stdout)?;
    let node = decoded
        .nodes()
        .iter()
        .find(|node| node.kind == "decoding_output")
        .ok_or("missing output node")?;
    let blob = decoded
        .blobs()
        .iter()
        .find(|blob| Some(&blob.id) == node.blob.as_ref())
        .ok_or("missing output blob")?;
    assert_eq!(blob.bytes, b"AB");
    assert!(
        decoded
            .nodes()
            .iter()
            .any(|node| node.kind == "decoding_receipt")
    );
    assert!(decoded.limitations().iter().any(|limitation| {
        limitation.contains("No authenticated-decryption operation or constraint was supplied")
    }));
    Ok(())
}

#[test]
fn failed_recipe_receipt_incomplete() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let imported = directory.path().join("candidate.bin");
    let recipe = directory.path().join("recipe.json");
    fs::write(&imported, b"4g")?;
    fs::write(
        &recipe,
        br#"{"steps":[{"kind":"hex_decode"}],"constraints":[]}"#,
    )?;
    let imported_case = run(
        &["import", "-", path_arg(&imported)?, "--kind", "binary"],
        &Case::new().to_json()?,
    )?;
    assert!(imported_case.status.success());
    let case = Case::from_json(&imported_case.stdout)?;
    let input_node = case
        .nodes()
        .iter()
        .find(|node| node.kind == "imported_source")
        .ok_or("missing imported source node")?;
    let id = input_node.id.to_string();

    let output = run(
        &["decode", "-", "--node", &id, "--recipe", path_arg(&recipe)?],
        &imported_case.stdout,
    )?;

    assert_eq!(output.status.code(), Some(3));
    let case = Case::from_json(&output.stdout)?;
    let receipt = receipt(&case)?;
    assert_eq!(
        receipt.pointer("/status/status").and_then(Value::as_str),
        Some("failed")
    );
    assert_eq!(
        receipt
            .pointer("/steps/0/status/status")
            .and_then(Value::as_str),
        Some("failed")
    );
    assert!(
        case.nodes()
            .iter()
            .any(|node| node.kind == "decoding_output")
    );
    Ok(())
}

#[test]
fn violated_constraint_completed_recipe_receipt() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let imported = directory.path().join("candidate.bin");
    let recipe = directory.path().join("recipe.json");
    fs::write(&imported, b"bytes")?;
    fs::write(
        &recipe,
        br#"{"steps":[{"kind":"reverse"}],"constraints":[{"kind":"length","bytes":99}]}"#,
    )?;
    let imported_case = run(
        &["import", "-", path_arg(&imported)?, "--kind", "binary"],
        &Case::new().to_json()?,
    )?;
    let case = Case::from_json(&imported_case.stdout)?;
    let input_node = case
        .nodes()
        .iter()
        .find(|node| node.kind == "imported_source")
        .ok_or("missing imported source node")?;
    let id = input_node.id.to_string();

    let output = run(
        &["decode", "-", "--node", &id, "--recipe", path_arg(&recipe)?],
        &imported_case.stdout,
    )?;

    assert_eq!(output.status.code(), Some(3));
    let case = Case::from_json(&output.stdout)?;
    let receipt = receipt(&case)?;
    assert_eq!(
        receipt.pointer("/status/status").and_then(Value::as_str),
        Some("completed")
    );
    assert_eq!(
        receipt
            .pointer("/constraints/0/status/status")
            .and_then(Value::as_str),
        Some("violated")
    );
    assert!(
        case.nodes()
            .iter()
            .any(|node| node.kind == "decoding_output")
    );
    Ok(())
}

#[test]
fn successful_prior_incomplete_collection_status() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let recipe = directory.path().join("recipe.json");
    fs::write(
        &recipe,
        br#"{"steps":[{"kind":"reverse"}],"constraints":[]}"#,
    )?;
    let mut case = Case::new();
    case.mark_incomplete("A bounded source was omitted")?;
    let input_node = case.add_bytes_node("candidate", b"abc", Vec::new(), serde_json::json!({}))?;
    let case_path = save_case(directory.path(), "case.json", &case)?;

    let output = run(
        &[
            "decode",
            path_arg(&case_path)?,
            "--node",
            &input_node.to_string(),
            "--recipe",
            path_arg(&recipe)?,
        ],
        &[],
    )?;

    assert_eq!(output.status.code(), Some(3));
    let decoded = Case::from_json(&output.stdout)?;
    assert!(!decoded.collection_complete());
    assert!(
        decoded
            .nodes()
            .iter()
            .any(|node| node.kind == "decoding_output")
    );
    Ok(())
}

#[test]
fn decoded_file_exact_output_blob() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let recipe = directory.path().join("recipe.json");
    fs::write(
        &recipe,
        br#"{"steps":[{"kind":"reverse"}],"constraints":[]}"#,
    )?;
    let mut case = Case::new();
    let mut encoded = b"RIFF\x11\x22\x33\x44WAVEbody".to_vec();
    encoded.reverse();
    let input_node = case.add_bytes_node("candidate", &encoded, Vec::new(), json!({}))?;

    let output = run(
        &[
            "decode",
            "-",
            "--node",
            &input_node.to_string(),
            "--recipe",
            path_arg(&recipe)?,
        ],
        &case.to_json()?,
    )?;

    assert!(output.status.success());
    let decoded = Case::from_json(&output.stdout)?;
    let bytes = decoded
        .nodes()
        .iter()
        .find(|node| node.kind == "decoding_output")
        .ok_or("decoding output is missing")?;
    let signature = decoded
        .nodes()
        .iter()
        .find(|node| node.kind == "file_signature_match")
        .ok_or("decoded file signature is missing")?;
    assert_eq!(signature.details.get("rule_id"), Some(&json!("riff-wave")));
    assert_eq!(
        signature.details.pointer("/catalogue/version"),
        Some(&json!(2))
    );
    assert_eq!(signature.details.get("input_node"), Some(&json!(bytes.id)));
    assert_eq!(signature.blob, bytes.blob);
    let edge = decoded
        .edges()
        .iter()
        .find(|edge| {
            edge.from == bytes.id
                && edge.to == signature.id
                && edge.relation == "contains_signature"
        })
        .ok_or("decoded signature relationship is missing")?;
    assert!(edge.reason.contains("exact or explicitly masked"));
    Ok(())
}

#[test]
fn multi_node_success() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let recipe = directory.path().join("recipe.json");
    fs::write(
        &recipe,
        br#"{"steps":[{"kind":"reverse"}],"constraints":[]}"#,
    )?;
    let mut case = Case::new();
    let first = case.add_bytes_node("candidate", b"first", Vec::new(), json!({}))?;
    let second = case.add_bytes_node("candidate", b"second", Vec::new(), json!({}))?;

    let output = run(
        &[
            "decode",
            "-",
            "--node",
            &first.to_string(),
            "--node",
            &second.to_string(),
            "--recipe",
            path_arg(&recipe)?,
        ],
        &case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decoded = Case::from_json(&output.stdout)?;
    let results = decoded
        .nodes()
        .iter()
        .filter(|node| node.kind == "decoding_output")
        .map(|node| {
            let blob_id = node.blob.as_deref().ok_or("decoding output has no blob")?;
            let blob = decoded
                .blobs()
                .iter()
                .find(|blob| blob.id == blob_id)
                .ok_or("decoding output blob is missing")?;
            Ok::<_, Box<dyn Error>>((
                node.details.get("item_index").and_then(Value::as_u64),
                blob.bytes.as_slice(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        results,
        [(Some(0), b"tsrif".as_slice()), (Some(1), b"dnoces")]
    );
    assert_eq!(
        decoded
            .nodes()
            .iter()
            .filter(|node| node.kind == "decoding_receipt")
            .count(),
        2
    );
    Ok(())
}

#[test]
fn failed_aes_supplied_key_scope() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let recipe_path = directory.path().join("recipe.json");
    fs::write(
        &recipe_path,
        // Input recipes supply the key; serialized reports retain only its identity
        serde_json::to_vec(&json!({
            "steps": [],
            "constraints": [{
                "kind": "aes_gcm",
                "key": vec![0; 16],
                "nonce": vec![0; 12],
                "associated_data": [],
            }],
        }))?,
    )?;
    let mut input = Case::new();
    // Zero ciphertext and tag do not authenticate under these supplied parameters
    let node = input.add_bytes_node("candidate", &[0; 32], Vec::new(), serde_json::json!({}))?;
    let output = run(
        &[
            "decode",
            "-",
            "--node",
            &node.to_string(),
            "--recipe",
            path_arg(&recipe_path)?,
        ],
        &input.to_json()?,
    )?;

    assert_eq!(output.status.code(), Some(3));
    let decoded = Case::from_json(&output.stdout)?;
    let report = receipt(&decoded)?;
    assert_eq!(
        report
            .pointer("/constraints/0/status/status")
            .and_then(Value::as_str),
        Some("violated")
    );
    assert!(
        decoded
            .limitations()
            .iter()
            .any(|limitation| { limitation.contains("supplied key, nonce, and associated data") })
    );
    Ok(())
}

#[test]
fn authenticated_aes_not_reported_unauthenticated() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let recipe_path = directory.path().join("recipe.json");
    fs::write(
        &recipe_path,
        serde_json::to_vec(&json!({
            "steps": [{
                "kind": "aes_gcm_decrypt",
                "key": vec![0; 16],
                "nonce": vec![0; 12],
                "associated_data": [],
                "tag_layout": {"layout": "appended"},
            }],
            "constraints": [{"kind": "length", "bytes": 16}],
        }))?,
    )?;
    let ciphertext_and_tag = [
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe,
        0x78, 0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
        0xbd, 0xdf,
    ];
    let mut input = Case::new();
    let node = input.add_bytes_node(
        "candidate",
        &ciphertext_and_tag,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let output = run(
        &[
            "decode",
            "-",
            "--node",
            &node.to_string(),
            "--recipe",
            path_arg(&recipe_path)?,
        ],
        &input.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decoded = Case::from_json(&output.stdout)?;
    assert!(decoded.limitations().iter().any(|limitation| {
        limitation.contains("AES-GCM decryption operation")
            && limitation.contains("supplied key, nonce, and associated data")
    }));
    assert!(!decoded.limitations().iter().any(|limitation| {
        limitation.contains("No authenticated-decryption operation or constraint was supplied")
    }));
    Ok(())
}

#[test]
fn unknown_node_recipe_no_case() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let case_path = save_case(directory.path(), "case.json", &Case::new())?;
    let recipe = directory.path().join("recipe.json");
    let destination = directory.path().join("output.json");
    fs::write(&recipe, b"not a recipe")?;

    let unknown_node = run(
        &[
            "decode",
            path_arg(&case_path)?,
            "--node",
            "1",
            "--recipe",
            path_arg(&recipe)?,
            "--output",
            path_arg(&destination)?,
        ],
        &[],
    )?;
    assert_eq!(unknown_node.status.code(), Some(1));
    assert_eq!(unknown_node.stdout.len(), 0);
    assert!(!destination.exists());

    let valid_input = directory.path().join("input.json");
    let mut case = Case::new();
    let input_node = case.add_bytes_node("candidate", b"abc", Vec::new(), serde_json::json!({}))?;
    fs::write(&valid_input, case.to_json()?)?;
    let invalid_recipe = run(
        &[
            "decode",
            path_arg(&valid_input)?,
            "--node",
            &input_node.to_string(),
            "--recipe",
            path_arg(&recipe)?,
            "--output",
            path_arg(&destination)?,
        ],
        &[],
    )?;
    assert_eq!(invalid_recipe.status.code(), Some(1));
    assert_eq!(invalid_recipe.stdout.len(), 0);
    assert!(!destination.exists());
    Ok(())
}

#[test]
fn fatal_record_atomicity() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let recipe = directory.path().join("recipe.json");
    let destination = directory.path().join("output.json");
    fs::write(
        &recipe,
        br#"{"steps":[{"kind":"reverse"}],"constraints":[]}"#,
    )?;
    let mut case = Case::with_blob_limit(3)?;
    let input = case.add_bytes_node("candidate", b"abc", Vec::new(), json!({}))?;

    let output = run(
        &[
            "decode",
            "-",
            "--node",
            &input.to_string(),
            "--recipe",
            path_arg(&recipe)?,
            "--output",
            path_arg(&destination)?,
        ],
        &case.to_json()?,
    )?;

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout.len(), 0);
    assert!(!destination.exists());
    Ok(())
}

#[test]
fn runtime_budgets_expensive_explicit_derivations() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let recipe = directory.path().join("scrypt.json");
    fs::write(
        &recipe,
        br#"{"steps":[{"kind":"scrypt_derive","salt":[],"log_n":4,"r":1,"p":1,"output_length":64}],"constraints":[{"kind":"length","bytes":64}]}"#,
    )?;
    let mut case = Case::new();
    let input = case.add_bytes_node("password_candidate", b"", Vec::new(), json!({}))?;

    let limited = run(
        &[
            "decode",
            "-",
            "--node",
            &input.to_string(),
            "--recipe",
            path_arg(&recipe)?,
            "--max-work-bytes",
            "1",
        ],
        &case.to_json()?,
    )?;
    assert_eq!(limited.status.code(), Some(3));

    let allowed = run(
        &[
            "decode",
            "-",
            "--node",
            &input.to_string(),
            "--recipe",
            path_arg(&recipe)?,
            "--max-work-bytes",
            "4096",
        ],
        &case.to_json()?,
    )?;
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let decoded = Case::from_json(&allowed.stdout)?;
    let report = receipt(&decoded)?;
    assert_eq!(report.get("work_bytes"), Some(&json!(2368)));
    Ok(())
}

fn receipt(case: &Case) -> Result<Value, Box<dyn Error>> {
    let node = case
        .nodes()
        .iter()
        .find(|node| node.kind == "decoding_receipt")
        .ok_or("missing derivation receipt node")?;
    let blob_id = node.blob.as_deref().ok_or("receipt node has no blob")?;
    let blob = case
        .blobs()
        .iter()
        .find(|blob| blob.id == blob_id)
        .ok_or("receipt blob is missing")?;
    Ok(serde_json::from_slice(&blob.bytes)?)
}
