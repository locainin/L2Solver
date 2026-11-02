use super::support::{path_arg, run};
use l2_workbench::evidence::Case;
use serde_json::{Value, json};
use std::{error::Error, fs, path::Path};

#[test]
fn retained_node_operand_ranges_provenance() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let reference_recipe = directory.path().join("reference.json");
    let literal_recipe = directory.path().join("literal.json");
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate", b"input bytes", Vec::new(), json!({}))?;
    let provider = case.add_bytes_node("seed_source", b"xxseedyy", Vec::new(), json!({}))?;
    let provider_blob = case
        .nodes()
        .iter()
        .find(|node| node.id == provider)
        .and_then(|node| node.blob.as_deref())
        .ok_or("seed provider has no retained blob")?
        .to_owned();
    let reference_json = json!({
        "steps": [{
            "kind": "sha256_counter_xor",
            "seed": {"source": "node_range", "node_id": provider, "offset": 2, "length": 4},
            "initial_counter": 0,
            "counter_width": "one_byte",
            "counter_byte_order": "big_endian",
            "seed_order": "seed_then_counter"
        }],
        "constraints": []
    });
    fs::write(&reference_recipe, serde_json::to_vec(&reference_json)?)?;
    fs::write(
        &literal_recipe,
        br#"{"steps":[{"kind":"sha256_counter_xor","seed":[115,101,101,100],"initial_counter":0,"counter_width":"one_byte","counter_byte_order":"big_endian","seed_order":"seed_then_counter"}],"constraints":[]}"#,
    )?;

    let referenced = run_decode(&reference_recipe, input, &case)?;
    assert!(
        referenced.status.success(),
        "{}",
        String::from_utf8_lossy(&referenced.stderr)
    );
    let referenced_case = Case::from_json(&referenced.stdout)?;
    let receipt = receipt(&referenced_case)?;
    let operand = receipt
        .pointer("/steps/0/operand_provenance/0")
        .ok_or("resolved operand provenance is missing")?;
    assert_eq!(operand.get("slot"), Some(&json!("seed")));
    assert_eq!(operand.get("provider_node"), Some(&json!(provider)));
    assert_eq!(operand.get("provider_blob"), Some(&json!(provider_blob)));
    assert_eq!(operand.get("offset"), Some(&json!(2)));
    assert_eq!(operand.get("length"), Some(&json!(4)));
    assert_eq!(
        operand.get("sha256"),
        Some(&json!(l2_workbench::sha256(b"seed")))
    );
    assert_eq!(
        receipt.pointer("/steps/0/operation/seed/source"),
        Some(&json!("node_range"))
    );
    let receipt_node = referenced_case
        .nodes()
        .iter()
        .find(|node| node.kind == "decoding_receipt")
        .ok_or("derivation receipt node is missing")?;
    assert!(referenced_case.edges().iter().any(|edge| {
        edge.from == provider && edge.to == receipt_node.id && edge.relation == "supplied_operand"
    }));

    let literal = run_decode(&literal_recipe, input, &case)?;
    assert!(literal.status.success());
    assert_eq!(
        output_bytes(&referenced_case)?,
        output_bytes(&Case::from_json(&literal.stdout)?)?
    );
    Ok(())
}

#[test]
fn operand_ranges_exceed_retained_blob() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate", b"input", Vec::new(), json!({}))?;
    let provider = case.add_bytes_node("seed_source", b"seed", Vec::new(), json!({}))?;

    for (offset, length) in [(3_u64, 2_u64), (u64::MAX, 1_u64)] {
        let recipe = write_recipe(
            directory.path(),
            &json!({
                "steps": [{
                    "kind": "sha256_counter_xor",
                    "seed": {"source": "node_range", "node_id": provider, "offset": offset, "length": length},
                    "initial_counter": 0,
                    "counter_width": "one_byte",
                    "counter_byte_order": "big_endian",
                    "seed_order": "seed_then_counter"
                }],
                "constraints": []
            }),
        )?;
        let output = run_decode(&recipe, input, &case)?;
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(output.stdout.len(), 0);
        assert_ne!(output.stderr.len(), 0);
    }
    Ok(())
}

#[test]
fn operand_references_nodes_unretained_blobs() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate", b"input", Vec::new(), json!({}))?;
    let missing_bytes = case.add_node("metadata_only", None, Vec::new(), json!({}))?;

    for provider in [missing_bytes, u64::MAX] {
        let recipe = write_recipe(
            directory.path(),
            &json!({
                "steps": [{
                    "kind": "scrypt_derive",
                    "salt": {"source": "node_range", "node_id": provider, "offset": 0, "length": 1},
                    "log_n": 4,
                    "r": 1,
                    "p": 1,
                    "output_length": 32
                }],
                "constraints": []
            }),
        )?;
        let output = run_decode(&recipe, input, &case)?;
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(output.stdout.len(), 0);
    }
    Ok(())
}

#[test]
fn constraint_operand_provenance_provider_edges() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let recipe_path = directory.path().join("recipe.json");
    let mut case = Case::new();
    let ciphertext_and_tag = [
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe,
        0x78, 0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
        0xbd, 0xdf,
    ];
    let input = case.add_bytes_node("candidate", &ciphertext_and_tag, Vec::new(), json!({}))?;
    let key = case.add_bytes_node("key_source", &[0; 16], Vec::new(), json!({}))?;
    let nonce = case.add_bytes_node("nonce_source", &[0; 12], Vec::new(), json!({}))?;
    let aad = case.add_bytes_node("aad_source", b"unused AAD", Vec::new(), json!({}))?;
    fs::write(
        &recipe_path,
        serde_json::to_vec(&json!({
            "steps": [],
            "constraints": [{
                "kind": "aes_gcm",
                "key": {"source": "node_range", "node_id": key, "offset": 0, "length": 16},
                "nonce": {"source": "node_range", "node_id": nonce, "offset": 0, "length": 12},
                "associated_data": {"source": "node_range", "node_id": aad, "offset": 0, "length": 0}
            }]
        }))?,
    )?;

    let output = run_decode(&recipe_path, input, &case)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result_case = Case::from_json(&output.stdout)?;
    let report = receipt(&result_case)?;
    assert_eq!(
        report.pointer("/constraints/0/constraint/key/source"),
        Some(&json!("node_range"))
    );
    assert_eq!(
        report.pointer("/constraints/0/operand_provenance/0/provider_node"),
        Some(&json!(key))
    );
    let receipt_node = result_case
        .nodes()
        .iter()
        .find(|node| node.kind == "decoding_receipt")
        .ok_or("derivation receipt node is missing")?;
    for provider in [key, nonce, aad] {
        assert!(result_case.edges().iter().any(|edge| {
            edge.from == provider
                && edge.to == receipt_node.id
                && edge.relation == "supplied_operand"
        }));
    }
    Ok(())
}

#[test]
fn recipe_per_node_reset_state() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let recipe = write_recipe(
        directory.path(),
        &json!({ "steps": [{ "kind": "hex_decode" }], "constraints": [] }),
    )?;
    let mut case = Case::new();
    let first = case.add_bytes_node("candidate", b"4142", Vec::new(), json!({}))?;
    let second = case.add_bytes_node("candidate", b"4344", Vec::new(), json!({}))?;

    let output = run_decode_many(&recipe, &[first, second], &case, &[])?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = Case::from_json(&output.stdout)?;
    let receipts = values_for_kind(&result, "decoding_receipt")?;
    let outputs = bytes_for_kind(&result, "decoding_output")?;
    assert_eq!(receipts.len(), 2);
    assert_eq!(outputs, [b"AB".to_vec(), b"CD".to_vec()]);
    let first_receipt = receipts.first().ok_or("first receipt is missing")?;
    let second_receipt = receipts.get(1).ok_or("second receipt is missing")?;
    assert_eq!(first_receipt.get("input_node"), Some(&json!(first)));
    assert_eq!(second_receipt.get("input_node"), Some(&json!(second)));
    assert_eq!(
        first_receipt.get("work_bytes"),
        second_receipt.get("work_bytes")
    );
    assert_eq!(
        first_receipt.get("input_sha256"),
        Some(&json!(l2_workbench::sha256(b"4142")))
    );
    assert_eq!(
        second_receipt.get("input_sha256"),
        Some(&json!(l2_workbench::sha256(b"4344")))
    );
    Ok(())
}

fn write_selected_input_recipe(directory: &Path) -> Result<std::path::PathBuf, Box<dyn Error>> {
    write_recipe(
        directory,
        &json!({
            "steps": [
                { "kind": "slice", "start": 19 },
                {
                    "kind": "sha256_counter_xor",
                    "seed": { "source": "selected_input_range", "offset": 3, "length": 7 },
                    "initial_counter": 0,
                    "counter_width": "one_byte",
                    "counter_byte_order": "big_endian",
                    "seed_order": "seed_then_counter"
                }
            ],
            "constraints": []
        }),
    )
}

fn selected_input_bytes(seed: &[u8], tail: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = vec![b'H'; 19];
    bytes
        .get_mut(3..10)
        .ok_or("selected-input seed fixture range is missing")?
        .copy_from_slice(seed);
    bytes.extend_from_slice(tail);
    Ok(bytes)
}

#[test]
fn selected_range_survives_slice() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let recipe = write_selected_input_recipe(directory.path())?;
    let mut case = Case::new();
    let first_bytes = selected_input_bytes(b"sample1", b"first body")?;
    let second_bytes = selected_input_bytes(b"sample2", b"second body")?;
    let first = case.add_bytes_node("candidate", &first_bytes, Vec::new(), json!({}))?;
    let second = case.add_bytes_node("candidate", &second_bytes, Vec::new(), json!({}))?;

    let output = run_decode_many(&recipe, &[first, second], &case, &[])?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = Case::from_json(&output.stdout)?;
    let receipts = values_for_kind(&result, "decoding_receipt")?;
    assert_eq!(receipts.len(), 2);
    let first_receipt = receipts.first().ok_or("first receipt is missing")?;
    let second_receipt = receipts.get(1).ok_or("second receipt is missing")?;
    for (receipt, provider, provider_blob, range_hash, tail_length) in [
        (
            first_receipt,
            first,
            blob_id(&case, first)?,
            l2_workbench::sha256(b"sample1"),
            10,
        ),
        (
            second_receipt,
            second,
            blob_id(&case, second)?,
            l2_workbench::sha256(b"sample2"),
            11,
        ),
    ] {
        assert_eq!(
            receipt.pointer("/steps/0/operation/start"),
            Some(&json!(19))
        );
        assert_eq!(receipt.pointer("/steps/0/operation/length"), None);
        assert_eq!(
            receipt.pointer("/steps/0/output_length"),
            Some(&json!(tail_length))
        );
        let operand = receipt
            .pointer("/steps/1/operand_provenance/0")
            .ok_or("selected input provenance is missing")?;
        assert_eq!(operand.get("provider_node"), Some(&json!(provider)));
        assert_eq!(operand.get("provider_blob"), Some(&json!(provider_blob)));
        assert_eq!(operand.get("offset"), Some(&json!(3)));
        assert_eq!(operand.get("length"), Some(&json!(7)));
        assert_eq!(operand.get("sha256"), Some(&json!(range_hash)));
        assert_eq!(
            receipt.pointer("/steps/1/operation/seed/source"),
            Some(&json!("selected_input_range"))
        );
        assert_eq!(receipt.pointer("/batch_limits/max_items"), Some(&json!(64)));
    }
    let receipt_nodes: Vec<_> = result
        .nodes()
        .iter()
        .filter(|node| node.kind == "decoding_receipt")
        .collect();
    assert_eq!(receipt_nodes.len(), 2);
    for (provider, receipt_node) in [first, second].into_iter().zip(receipt_nodes) {
        assert!(result.edges().iter().any(|edge| {
            edge.from == provider
                && edge.to == receipt_node.id
                && edge.relation == "supplied_operand"
        }));
    }
    let outputs = bytes_for_kind(&result, "decoding_output")?;
    assert_eq!(outputs.first().map(Vec::len), Some(10));
    assert_eq!(outputs.get(1).map(Vec::len), Some(11));
    Ok(())
}

#[test]
fn item_failure_incomplete() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let recipe = write_recipe(
        directory.path(),
        &json!({ "steps": [{ "kind": "hex_decode" }], "constraints": [] }),
    )?;
    let mut case = Case::new();
    let invalid = case.add_bytes_node("candidate", b"4g", Vec::new(), json!({}))?;
    let valid = case.add_bytes_node("candidate", b"4142", Vec::new(), json!({}))?;

    let output = run_decode_many(&recipe, &[invalid, valid], &case, &[])?;
    assert_eq!(output.status.code(), Some(3));
    let result = Case::from_json(&output.stdout)?;
    let receipts = values_for_kind(&result, "decoding_receipt")?;
    assert_eq!(receipts.len(), 2);
    let first_receipt = receipts.first().ok_or("first receipt is missing")?;
    let second_receipt = receipts.get(1).ok_or("second receipt is missing")?;
    assert_eq!(
        first_receipt.pointer("/status/status"),
        Some(&json!("failed"))
    );
    assert_eq!(
        second_receipt.pointer("/status/status"),
        Some(&json!("completed"))
    );
    assert_eq!(
        bytes_for_kind(&result, "decoding_output")?.get(1),
        Some(&b"AB".to_vec())
    );
    Ok(())
}

#[test]
fn input_range_item_failure() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let recipe = write_recipe(
        directory.path(),
        &json!({
            "steps": [{
                "kind": "sha256_counter_xor",
                "seed": { "source": "selected_input_range", "offset": 1, "length": 2 },
                "initial_counter": 0,
                "counter_width": "one_byte",
                "counter_byte_order": "big_endian",
                "seed_order": "seed_then_counter"
            }],
            "constraints": []
        }),
    )?;
    let mut case = Case::new();
    let short = case.add_bytes_node("candidate", b"a", Vec::new(), json!({}))?;
    let valid = case.add_bytes_node("candidate", b"abc", Vec::new(), json!({}))?;

    let output = run_decode_many(&recipe, &[short, valid], &case, &[])?;
    assert_eq!(output.status.code(), Some(3));
    let result = Case::from_json(&output.stdout)?;
    let receipts = values_for_kind(&result, "decoding_receipt")?;
    assert_eq!(receipts.len(), 2);
    let first_receipt = receipts.first().ok_or("first receipt is missing")?;
    let second_receipt = receipts.get(1).ok_or("second receipt is missing")?;
    assert!(
        first_receipt
            .get("execution_error")
            .and_then(Value::as_str)
            .is_some_and(|error| error.contains("operand range 1+2"))
    );
    assert_eq!(
        second_receipt.pointer("/status/status"),
        Some(&json!("completed"))
    );
    let outputs = bytes_for_kind(&result, "decoding_output")?;
    assert_eq!(outputs.first(), Some(&b"a".to_vec()));
    assert_eq!(outputs.get(1).map(Vec::len), Some(3));
    Ok(())
}

#[test]
fn aggregate_limits_case() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let recipe = write_recipe(
        directory.path(),
        &json!({ "steps": [{ "kind": "reverse" }], "constraints": [] }),
    )?;
    let mut case = Case::new();
    let first = case.add_bytes_node("candidate", b"abc", Vec::new(), json!({}))?;
    let second = case.add_bytes_node("candidate", b"def", Vec::new(), json!({}))?;

    for (name, value) in [
        ("--max-items", "1"),
        ("--max-total-input-bytes", "5"),
        ("--max-total-output-bytes", "5"),
        ("--max-total-report-bytes", "1"),
    ] {
        let arguments = [(name, value)];
        let extra: Vec<String> = arguments
            .iter()
            .flat_map(|(key, value)| [(*key).to_owned(), (*value).to_owned()])
            .collect();
        let output = run_decode_many(&recipe, &[first, second], &case, &extra)?;
        assert_eq!(
            output.status.code(),
            Some(1),
            "{name} should reject the batch"
        );
        assert!(
            output.stdout.is_empty(),
            "{name} must reject before writing the case"
        );
    }

    let work_limited = run_decode_many(
        &recipe,
        &[first, second],
        &case,
        &["--max-total-work-bytes".to_owned(), "1".to_owned()],
    )?;
    assert_eq!(work_limited.status.code(), Some(3));
    let result = Case::from_json(&work_limited.stdout)?;
    let receipts = values_for_kind(&result, "decoding_receipt")?;
    assert_eq!(receipts.len(), 2);
    assert!(receipts.iter().all(|receipt| {
        receipt.pointer("/status/status") == Some(&json!("failed"))
            && receipt.get("work_bytes") == Some(&json!(0))
    }));
    Ok(())
}

fn run_decode(
    recipe: &Path,
    input: u64,
    case: &Case,
) -> Result<std::process::Output, Box<dyn Error>> {
    run(
        &[
            "decode",
            "-",
            "--node",
            &input.to_string(),
            "--recipe",
            path_arg(recipe)?,
        ],
        &case.to_json()?,
    )
}

fn run_decode_many(
    recipe: &Path,
    inputs: &[u64],
    case: &Case,
    extra: &[String],
) -> Result<std::process::Output, Box<dyn Error>> {
    let mut arguments = vec!["decode".to_owned(), "-".to_owned()];
    for input in inputs {
        arguments.push("--node".to_owned());
        arguments.push(input.to_string());
    }
    arguments.push("--recipe".to_owned());
    arguments.push(path_arg(recipe)?.to_owned());
    arguments.extend_from_slice(extra);
    let arguments: Vec<_> = arguments.iter().map(String::as_str).collect();
    run(&arguments, &case.to_json()?)
}

fn values_for_kind(case: &Case, kind: &str) -> Result<Vec<Value>, Box<dyn Error>> {
    case.nodes()
        .iter()
        .filter(|node| node.kind == kind)
        .map(|node| {
            let blob = case
                .blobs()
                .iter()
                .find(|blob| Some(&blob.id) == node.blob.as_ref())
                .ok_or("node blob is missing")?;
            Ok(serde_json::from_slice(&blob.bytes)?)
        })
        .collect()
}

fn bytes_for_kind(case: &Case, kind: &str) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    case.nodes()
        .iter()
        .filter(|node| node.kind == kind)
        .map(|node| {
            let blob = case
                .blobs()
                .iter()
                .find(|blob| Some(&blob.id) == node.blob.as_ref())
                .ok_or("node blob is missing")?;
            Ok(blob.bytes.clone())
        })
        .collect()
}

fn write_recipe(directory: &Path, value: &Value) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let path = directory.join("recipe.json");
    fs::write(&path, serde_json::to_vec(value)?)?;
    Ok(path)
}

fn receipt(case: &Case) -> Result<Value, Box<dyn Error>> {
    let node = case
        .nodes()
        .iter()
        .find(|node| node.kind == "decoding_receipt")
        .ok_or("derivation receipt node is missing")?;
    let blob = case
        .blobs()
        .iter()
        .find(|blob| Some(&blob.id) == node.blob.as_ref())
        .ok_or("derivation receipt blob is missing")?;
    Ok(serde_json::from_slice(&blob.bytes)?)
}

fn output_bytes(case: &Case) -> Result<Vec<u8>, Box<dyn Error>> {
    let node = case
        .nodes()
        .iter()
        .find(|node| node.kind == "decoding_output")
        .ok_or("derivation output node is missing")?;
    Ok(case
        .blobs()
        .iter()
        .find(|blob| Some(&blob.id) == node.blob.as_ref())
        .ok_or("derivation output blob is missing")?
        .bytes
        .clone())
}

fn blob_id(case: &Case, node_id: u64) -> Result<String, Box<dyn Error>> {
    case.nodes()
        .iter()
        .find(|node| node.id == node_id)
        .and_then(|node| node.blob.clone())
        .ok_or_else(|| "node blob reference is missing".into())
}
