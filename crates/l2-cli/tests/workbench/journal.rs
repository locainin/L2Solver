use super::support::{path_arg, run, save_case};
use l2_workbench::evidence::Case;
use l2_workbench::sha256;
use serde_json::{Value, json};
use std::{error::Error, fs, path::Path};

#[test]
fn journal_cli_derived_delta_bytes() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let mut case = Case::new();
    let node = case.add_bytes_node("sample", b"dog", Vec::new(), json!({}))?;
    let base = save_case(temp.path(), "case.json", &case)?;
    let dir = temp.path().join("investigation");
    let created = run(
        &["journal", path_arg(&dir)?, "create", path_arg(&base)?],
        b"",
    )?;
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let recipe = temp.path().join("recipe.json");
    fs::write(
        &recipe,
        br#"{"steps":[{"kind":"reverse"}],"constraints":[]}"#,
    )?;
    let derived = run(
        &[
            "journal",
            path_arg(&dir)?,
            "derive",
            "--node",
            &node.to_string(),
            "--recipe",
            path_arg(&recipe)?,
        ],
        b"",
    )?;
    assert!(
        derived.status.success(),
        "{}",
        String::from_utf8_lossy(&derived.stderr)
    );
    let receipt: Value = serde_json::from_slice(&derived.stdout)?;
    let id = receipt
        .get("id")
        .and_then(Value::as_str)
        .ok_or("missing hypothesis id")?;
    let exported = run(&["journal", path_arg(&dir)?, "export", id], b"")?;
    assert!(exported.status.success());
    assert_eq!(exported.stdout, b"god");
    let reviewed = run(
        &["journal", path_arg(&dir)?, "review", "--format", "html"],
        b"",
    )?;
    assert!(
        reviewed.status.success(),
        "{}",
        String::from_utf8_lossy(&reviewed.stderr)
    );
    assert!(String::from_utf8(reviewed.stdout)?.contains("unresolved"));
    Ok(())
}

#[test]
fn journal_cli_identity_survives_verification() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let base = save_case(temp.path(), "case.json", &Case::new())?;
    let dir = temp.path().join("investigation");
    let created = run(
        &["journal", path_arg(&dir)?, "create", path_arg(&base)?],
        b"",
    )?;
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let model = temp.path().join("model.json");
    fs::write(
        &model,
        br#"{"title":"Candidate","input":{"source":"sample"},"operation":{"kind":"inspect"},"assumptions":[]}"#,
    )?;
    let added = run(&["journal", path_arg(&dir)?, "add", path_arg(&model)?], b"")?;
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    let entry: Value = serde_json::from_slice(&added.stdout)?;
    let id = entry
        .get("id")
        .and_then(Value::as_str)
        .ok_or("missing hypothesis id")?;

    let check = temp.path().join("check.json");
    fs::write(
        &check,
        br#"{"kind":"independent","outcome":"pass","explanation":"verified retained output"}"#,
    )?;
    let evidence = temp.path().join("check-evidence.txt");
    fs::write(&evidence, b"independent evidence")?;
    let recorded = run(
        &[
            "journal",
            path_arg(&dir)?,
            "check",
            id,
            path_arg(&check)?,
            path_arg(&evidence)?,
        ],
        b"",
    )?;
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    let recorded_entry: Value = serde_json::from_slice(&recorded.stdout)?;
    let identity = recorded_entry
        .pointer("/checks/0/identity")
        .and_then(Value::as_str)
        .ok_or("check identity missing from CLI entry")?;
    assert_eq!(identity.len(), 64);

    let verification = run(&["journal", path_arg(&dir)?, "verify"], b"")?;
    assert!(
        verification.status.success(),
        "{}",
        String::from_utf8_lossy(&verification.stderr)
    );
    assert_cli_review_preserves_check_identity_and_binding(&dir, identity)?;
    Ok(())
}

fn assert_cli_review_preserves_check_identity_and_binding(
    directory: &Path,
    identity: &str,
) -> Result<(), Box<dyn Error>> {
    let reviewed = run(
        &[
            "journal",
            path_arg(directory)?,
            "review",
            "--format",
            "json",
        ],
        b"",
    )?;
    assert!(
        reviewed.status.success(),
        "{}",
        String::from_utf8_lossy(&reviewed.stderr)
    );
    let output = String::from_utf8(reviewed.stdout)?;
    let entry_line = output.lines().nth(1).ok_or("missing CLI review entry")?;
    let reviewed_entry: Value = serde_json::from_str(entry_line)?;
    assert_eq!(
        reviewed_entry.pointer("/checks/0/identity"),
        Some(&json!(identity))
    );

    let text_review = run(
        &[
            "journal",
            path_arg(directory)?,
            "review",
            "--format",
            "text",
        ],
        b"",
    )?;
    assert!(text_review.status.success());
    assert!(String::from_utf8(text_review.stdout)?.contains("binding=Recorded"));
    Ok(())
}

#[test]
fn journal_derivation_retained_partial_status() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let mut case = Case::new();
    let node = case.add_bytes_node("sample", b"abc", Vec::new(), json!({}))?;
    let base = save_case(temp.path(), "case.json", &case)?;
    let dir = temp.path().join("investigation");
    assert!(
        run(
            &["journal", path_arg(&dir)?, "create", path_arg(&base)?],
            b""
        )?
        .status
        .success()
    );
    let recipe = temp.path().join("bad-recipe.json");
    fs::write(
        &recipe,
        br#"{"steps":[{"kind":"slice","start":10,"length":2}],"constraints":[]}"#,
    )?;
    let failed = run(
        &[
            "journal",
            path_arg(&dir)?,
            "derive",
            "--node",
            &node.to_string(),
            "--recipe",
            path_arg(&recipe)?,
        ],
        b"",
    )?;
    assert_eq!(failed.status.code(), Some(3));
    let entry: Value = serde_json::from_slice(&failed.stdout)?;
    assert_eq!(
        entry.pointer("/derivation/operation_completed"),
        Some(&json!(false))
    );
    let reviewed = run(
        &["journal", path_arg(&dir)?, "review", "--format", "json"],
        b"",
    )?;
    assert!(
        reviewed.status.success(),
        "{}",
        String::from_utf8_lossy(&reviewed.stderr)
    );
    assert!(String::from_utf8(reviewed.stdout)?.contains("operation_completed"));
    Ok(())
}

#[test]
fn journal_review_text_default() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let directory = create_journal(temp.path())?;
    let reviewed = run(&["journal", path_arg(&directory)?, "review"], b"")?;
    assert!(
        reviewed.status.success(),
        "{}",
        String::from_utf8_lossy(&reviewed.stderr)
    );
    let text = String::from_utf8(reviewed.stdout)?;
    assert!(text.starts_with("Investigation: hypotheses=0"));
    assert!(!text.starts_with('{'));
    Ok(())
}

#[test]
fn journal_cli_id_identity_hash() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let directory = create_journal(temp.path())?;
    let (evidence, references) = record_binary_check(temp.path(), &directory)?;

    for reference in references {
        let exported = run(
            &[
                "journal",
                path_arg(&directory)?,
                "export-evidence",
                &reference,
            ],
            b"",
        )?;
        assert!(
            exported.status.success(),
            "{}",
            String::from_utf8_lossy(&exported.stderr)
        );
        assert_eq!(exported.stdout, fs::read(&evidence)?);
    }
    let unpublished = temp.path().join("unpublished.bin");
    let failed = run(
        &[
            "journal",
            path_arg(&directory)?,
            "export-evidence",
            &"0".repeat(64),
            "--output",
            path_arg(&unpublished)?,
        ],
        b"",
    )?;
    assert!(!failed.status.success());
    assert!(!unpublished.exists());
    Ok(())
}

fn create_journal(root: &Path) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let base = save_case(root, "case.json", &Case::new())?;
    let directory = root.join("investigation");
    let created = run(
        &["journal", path_arg(&directory)?, "create", path_arg(&base)?],
        b"",
    )?;
    if !created.status.success() {
        return Err(String::from_utf8_lossy(&created.stderr).into_owned().into());
    }
    Ok(directory)
}

fn record_binary_check(
    root: &Path,
    directory: &Path,
) -> Result<(std::path::PathBuf, Vec<String>), Box<dyn Error>> {
    let model = root.join("model.json");
    fs::write(
        &model,
        br#"{"title":"Candidate","input":{"source":"sample"},"operation":{"kind":"inspect"},"assumptions":[]}"#,
    )?;
    let added = run(
        &["journal", path_arg(directory)?, "add", path_arg(&model)?],
        b"",
    )?;
    if !added.status.success() {
        return Err(String::from_utf8_lossy(&added.stderr).into_owned().into());
    }
    let entry: Value = serde_json::from_slice(&added.stdout)?;
    let hypothesis = entry
        .get("id")
        .and_then(Value::as_str)
        .ok_or("missing hypothesis identity")?;

    let check = root.join("check.json");
    fs::write(
        &check,
        br#"{"kind":"independent","outcome":"pass","explanation":"supporting evidence"}"#,
    )?;
    let evidence = root.join("evidence.bin");
    fs::write(&evidence, b"retained bytes\0with binary content")?;
    let recorded = run(
        &[
            "journal",
            path_arg(directory)?,
            "check",
            hypothesis,
            path_arg(&check)?,
            path_arg(&evidence)?,
        ],
        b"",
    )?;
    if !recorded.status.success() {
        return Err(String::from_utf8_lossy(&recorded.stderr)
            .into_owned()
            .into());
    }
    let entry: Value = serde_json::from_slice(&recorded.stdout)?;
    let check_id = entry
        .pointer("/checks/0/id")
        .and_then(Value::as_u64)
        .ok_or("missing check ID")?;
    let evidence_hash = entry
        .pointer("/checks/0/evidence_sha256")
        .and_then(Value::as_str)
        .ok_or("missing evidence hash")?;
    let check_identity = entry
        .pointer("/checks/0/identity")
        .and_then(Value::as_str)
        .ok_or("missing check identity")?;
    Ok((
        evidence,
        vec![
            check_id.to_string(),
            check_identity.to_owned(),
            evidence_hash.to_owned(),
        ],
    ))
}

#[test]
fn journal_cli_tshark_bound_supplied() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let base = save_case(temp.path(), "case.json", &Case::new())?;
    let directory = temp.path().join("investigation");
    assert!(
        run(
            &["journal", path_arg(&directory)?, "create", path_arg(&base)?],
            b""
        )?
        .status
        .success()
    );

    let capture = temp.path().join("capture.pcap");
    fs::write(&capture, b"capture")?;
    let report = temp.path().join("tshark.json");
    fs::write(&report, tshark_report(&sha256(b"capture"))?)?;
    let imported = run(
        &[
            "journal",
            path_arg(&directory)?,
            "import-tshark",
            path_arg(&report)?,
            "--source",
            path_arg(&capture)?,
            "--max-report-mib",
            "257",
            "--max-tool-report-bytes",
            "269484032",
        ],
        b"",
    )?;
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );

    let review = run(
        &[
            "journal",
            path_arg(&directory)?,
            "review",
            "--format",
            "json",
        ],
        b"",
    )?;
    assert!(review.status.success());
    let lines: Vec<Value> = String::from_utf8(review.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let receipt = lines
        .iter()
        .find(|line| line.get("tool").and_then(Value::as_str) == Some("tshark"))
        .ok_or("review omitted the TShark receipt")?;
    assert_eq!(receipt.get("linked_events"), Some(&json!(1)));
    let receipt_hash = receipt
        .get("evidence_sha256")
        .and_then(Value::as_str)
        .ok_or("review omitted the receipt evidence link")?;
    let verified = run(&["journal", path_arg(&directory)?, "verify"], b"")?;
    assert!(
        verified.status.success(),
        "receipt {receipt_hash}: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
    Ok(())
}

#[test]
fn journal_cli_budget_without_importing() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let base = save_case(temp.path(), "case.json", &Case::new())?;
    let directory = temp.path().join("investigation");
    assert!(
        run(
            &["journal", path_arg(&directory)?, "create", path_arg(&base)?],
            b""
        )?
        .status
        .success()
    );

    let capture = temp.path().join("capture.pcap");
    fs::write(&capture, b"capture")?;
    let mut report_bytes = tshark_report(&sha256(b"capture"))?;
    report_bytes.resize(1024 * 1024 + 1, b' ');
    let report = temp.path().join("large-tshark.json");
    fs::write(&report, report_bytes)?;
    let rejected = run(
        &[
            "journal",
            path_arg(&directory)?,
            "import-tshark",
            path_arg(&report)?,
            "--source",
            path_arg(&capture)?,
            "--max-report-mib",
            "1",
        ],
        b"",
    )?;
    assert!(!rejected.status.success());

    let verified = run(&["journal", path_arg(&directory)?, "verify"], b"")?;
    assert!(verified.status.success());
    let verification: Value = serde_json::from_slice(&verified.stdout)?;
    assert_eq!(verification.pointer("/summary/events"), Some(&json!(0)));
    assert_eq!(
        verification.pointer("/summary/tool_receipts"),
        Some(&json!(0))
    );
    Ok(())
}

#[test]
fn journal_cli_tool_budget_receipts() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let base = save_case(temp.path(), "case.json", &Case::new())?;
    let directory = temp.path().join("investigation");
    assert!(
        run(
            &["journal", path_arg(&directory)?, "create", path_arg(&base)?],
            b""
        )?
        .status
        .success()
    );

    let capture = temp.path().join("capture.pcap");
    fs::write(&capture, b"capture")?;
    let mut report_bytes = tshark_report(&sha256(b"capture"))?;
    report_bytes.resize(1024 * 1024, b' ');
    let report = temp.path().join("tshark.json");
    fs::write(&report, report_bytes)?;
    let imported = run(
        &[
            "journal",
            path_arg(&directory)?,
            "import-tshark",
            path_arg(&report)?,
            "--source",
            path_arg(&capture)?,
        ],
        b"",
    )?;
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );

    let limited = run(
        &[
            "journal",
            path_arg(&directory)?,
            "review",
            "--format",
            "json",
            "--max-tool-report-bytes",
            "1024",
        ],
        b"",
    )?;
    assert!(!limited.status.success());
    Ok(())
}

fn tshark_report(source_hash: &str) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&json!({
        "schema_version":2,
        "source":{"label":"capture.pcap","length":7,"sha256":source_hash},
        "source_packet_count":{"count":1,"output_sha256":sha256(b"1\n")},
        "provenance":{
            "source_change_verified":true,
            "tool_derived":true,
            "tls_decryption":"disabled",
            "physical_byte_ranges":"not_reported"
        },
        "tool":{
            "executable_requested":"tshark",
            "executable":"test-bin/tshark",
            "executable_bytes":1,
            "executable_sha256":sha256(b"tool"),
            "version":"TShark (Wireshark) 4.4.0",
            "budgets":{
                "timeout_seconds":1,
                "combined_input_bytes":7,
                "metadata_stdout_bytes_per_phase":1,
                "json_output_bytes":1,
                "diagnostic_bytes_per_phase":1
            },
            "profile":{
                "name":"l2solver-offline",
                "preferences_sha256":sha256(b"preferences"),
                "name_resolution":"disabled_by_-n",
                "reassembly_preferences":["tcp.desegment_tcp_streams=TRUE"],
                "process_environment":"isolated",
                "tls_keylog":null
            },
            "plugins":[],
            "plugin_inventory_sha256":sha256(b"plugins"),
            "version_output_sha256":sha256(b"version"),
            "effective_preferences_sha256":sha256(b"effective preferences"),
            "effective_preferences_count":1,
            "verified_profile_preferences":{"tcp.desegment_tcp_streams":"TRUE"},
            "invocations":[
                {"phase":"packet_count","argv":[
                    "-n","-C","l2solver-offline","--disable-all-protocols",
                    "-r","<source-snapshot>","-T","fields","-e","frame.number"
                ]},
                {"phase":"decode","argv":[
                    "-n","-2","-q","-C","l2solver-offline",
                    "-r","<source-snapshot>","-T","json","--no-duplicate-keys"
                ]}
            ],
            "diagnostics":[]
        },
        "output_sha256":sha256(b"decoded output"),
        "packets":[{
            "packet_number":1,
            "tool_derived":true,
            "fields":{"frame":{"frame.number":1},"tcp":{"tcp.payload":"aabb"}},
            "reassembled_fields":["tcp.payload"]
        }]
    }))
}
