use super::support::{path_arg, run};
use l2_workbench::{evidence::Case, sha256};
use serde_json::{Value, json};
use std::{
    error::Error,
    fs,
    io::{Seek, SeekFrom, Write},
};

#[test]
fn query_behavior_emit_bounded_evidence() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let node = case.add_bytes_node("candidate", b"bytes", Vec::new(), json!({}))?;
    let query = run(
        &[
            "query",
            "-",
            "--filter",
            "kind=candidate",
            "--format",
            "json",
        ],
        &case.to_json()?,
    )?;
    assert!(
        query.status.success(),
        "{}",
        String::from_utf8_lossy(&query.stderr)
    );
    let report: Value = serde_json::from_slice(&query.stdout)?;
    assert_eq!(report.pointer("/matches/0/node_id"), Some(&json!(node)));
    assert_eq!(report.get("matched_nodes"), Some(&json!(1)));
    let behavior = run(
        &["behavior", "-", "--internal", "192.0.2.0/24"],
        &case.to_json()?,
    )?;
    assert!(behavior.status.success());
    let report: Value = serde_json::from_slice(&behavior.stdout)?;
    assert_eq!(report.get("findings"), Some(&json!([])));
    assert!(
        report
            .get("limitations")
            .and_then(Value::as_array)
            .is_some_and(|limits| !limits.is_empty())
    );

    Ok(())
}

#[test]
fn search_experiment_selected_input_bytes() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let node = case.add_bytes_node("candidate", b"4142", Vec::new(), json!({}))?;
    let search = directory.path().join("search.json");
    fs::write(&search, br#"{"families":[{"kind":"hex"}],"constraints":[{"kind":"prefix","bytes":[65,66]}],"max_depth":1,"max_candidates":8}"#)?;
    let output = run(
        &[
            "search",
            "-",
            "--node",
            &node.to_string(),
            "--plan",
            path_arg(&search)?,
        ],
        &case.to_json()?,
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        report.pointer("/search/input_sha256"),
        Some(&json!(sha256(b"4142")))
    );
    assert_eq!(
        report.pointer("/search/candidates/1/status"),
        Some(&json!("constraints_satisfied"))
    );
    let mutation = directory.path().join("mutation.json");
    fs::write(
        &mutation,
        br#"{"mutations":[{"operation":"flip_bit","offset":0,"bit":0}]}"#,
    )?;
    let output = run(
        &[
            "experiment",
            "-",
            "--node",
            &node.to_string(),
            "--plan",
            path_arg(&mutation)?,
            "--mode",
            "loopback",
        ],
        &case.to_json()?,
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.pointer("/input/node_id"), Some(&json!(node)));
    assert_eq!(
        report.pointer("/experiment/input_sha256"),
        Some(&json!(sha256(b"4142")))
    );
    Ok(())
}

#[test]
fn unavailable_known_without_collection_status() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let node = case.add_bytes_node("candidate", b"short", Vec::new(), json!({}))?;
    let plan = directory.path().join("search.json");
    fs::write(
        &plan,
        serde_json::to_vec(&json!({
            "families": [{"kind": "known_plaintext_xor", "offset": 10, "bytes": [0,0,0,0,0,0], "key_lengths": [3]}],
            "constraints": [{"kind": "utf8"}], "max_depth": 1, "max_candidates": 8,
        }))?,
    )?;
    let output = run(
        &[
            "search",
            "-",
            "--node",
            &node.to_string(),
            "--plan",
            path_arg(&plan)?,
        ],
        &case.to_json()?,
    )?;
    assert_eq!(output.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.get("case_collection_complete"), Some(&json!(true)));
    assert_eq!(
        report.pointer("/search/search_exhaustive_within_plan"),
        Some(&json!(false))
    );
    assert_eq!(
        report.pointer("/search/key_tests/0/status"),
        Some(&json!("untestable"))
    );
    assert_eq!(
        report.pointer("/search/limits"),
        Some(&json!(["known_plaintext_unavailable"]))
    );
    Ok(())
}

#[test]
fn protocol_command_sample_holdout_counterexamples() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let mut samples = Vec::new();
    for bytes in [
        &b"\x03ab"[..],
        &b"\x04abc"[..],
        &b"\x05abcd"[..],
        &b"\x09abcde"[..],
    ] {
        let id = case.add_bytes_node("candidate", bytes, Vec::new(), json!({}))?;
        samples.push(format!("{id}:unclassified"));
    }
    let mut args = vec!["protocol", "-"];
    for sample in &samples {
        args.extend(["--sample", sample.as_str()]);
    }
    let output = run(&args, &case.to_json()?)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        report.pointer("/framing/holdout_samples"),
        Some(&json!([3, 4]))
    );
    assert!(
        report
            .pointer("/framing/candidates")
            .and_then(Value::as_array)
            .is_some_and(|candidates| candidates.iter().any(|candidate| candidate
                .pointer("/holdout/counterexample_count")
                .and_then(Value::as_u64)
                .is_some_and(|count| count > 0)))
    );
    Ok(())
}

#[test]
fn invalid_filters_binary_inputs_no() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("new-report.json");
    let filtered = run(
        &[
            "query",
            "-",
            "--filter",
            "ip=invalid",
            "--output",
            path_arg(&output)?,
        ],
        &Case::new().to_json()?,
    )?;
    assert_eq!(filtered.status.code(), Some(1));
    assert!(!output.exists());
    let binary = directory.path().join("invalid.bin");
    fs::write(&binary, b"not an executable")?;
    let analyzed = run(
        &["binary", path_arg(&binary)?, "--output", path_arg(&output)?],
        b"",
    )?;
    assert_eq!(analyzed.status.code(), Some(1));
    assert!(!output.exists());
    Ok(())
}

#[test]
fn binary_signature_without_file_subtype() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let binary = directory.path().join("container.bin");
    fs::write(&binary, b"PK\x03\x04generic bytes")?;

    let output = run(
        &["binary", path_arg(&binary)?, "--engine", "signatures"],
        b"",
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        report.pointer("/matches/0/rule_id"),
        Some(&json!("zip-local-file"))
    );
    assert_eq!(
        report.pointer("/matches/0/possible_formats"),
        Some(&json!(["zip_container"]))
    );
    assert!(
        report
            .pointer("/limitations/0")
            .and_then(Value::as_str)
            .is_some_and(|text| text.contains("does not establish"))
    );
    Ok(())
}

#[test]
fn signature_engine_large_input_budget() -> Result<(), Box<dyn Error>> {
    const DEFAULT_SIGNATURE_INPUT_BYTES: usize = 16 * 1024 * 1024;

    let directory = tempfile::tempdir()?;
    let binary = directory.path().join("large-hdf5.bin");
    let offset = DEFAULT_SIGNATURE_INPUT_BYTES;
    let length = offset.checked_add(8).ok_or("test input length overflow")?;
    let mut file = fs::File::create(&binary)?;
    file.set_len(u64::try_from(length)?)?;
    file.seek(SeekFrom::Start(u64::try_from(offset)?))?;
    file.write_all(b"\x89HDF\r\n\x1a\n")?;
    file.sync_all()?;

    let default_budget = run(
        &["binary", path_arg(&binary)?, "--engine", "signatures"],
        b"",
    )?;
    assert_eq!(default_budget.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&default_budget.stderr).contains("input exceeds 16777216 bytes")
    );

    let configured_length = length.to_string();
    let output = run(
        &[
            "binary",
            path_arg(&binary)?,
            "--engine",
            "signatures",
            "--max-input-bytes",
            &configured_length,
        ],
        b"",
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert!(
        report
            .get("matches")
            .and_then(Value::as_array)
            .is_some_and(|matches| matches.iter().any(|candidate| {
                candidate.get("rule_id") == Some(&json!("hdf5"))
                    && candidate.pointer("/range/offset") == Some(&json!(offset))
            }))
    );

    let largest_budget = usize::MAX.to_string();
    let boundary = run(
        &[
            "binary",
            path_arg(&binary)?,
            "--engine",
            "signatures",
            "--max-input-bytes",
            &largest_budget,
        ],
        b"",
    )?;
    let boundary_error = String::from_utf8_lossy(&boundary.stderr);
    assert!(
        !boundary_error.contains("panicked"),
        "an input budget must never reach arithmetic that can panic: {boundary_error}"
    );
    if usize::BITS == u64::BITS {
        assert_eq!(boundary.status.code(), Some(1));
        assert!(boundary_error.contains("input byte budget exceeds the supported range"));
    }
    Ok(())
}
