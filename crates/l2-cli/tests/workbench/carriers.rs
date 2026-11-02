use super::support::{path_arg, run};
use serde_json::{Value, json};
use std::{error::Error, fs};

fn save_plan(
    directory: &std::path::Path,
    bytes: &[u8],
    source_id: &str,
    sequence: Option<u64>,
) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let source = directory.join("sample.bin");
    fs::write(&source, bytes)?;
    let sequence_value = sequence.map_or(Value::Null, Value::from);
    let plan = json!({
        "sources": [
            {"id": source_id, "length": bytes.len(), "path": "sample.bin"},
            {"id": format!("sha256:{}", "0".repeat(64)), "length": 1, "path": "unused.bin"}
        ],
        "samples": [{
            "id": 1,
            "event_id": "event-a",
            "sequence": sequence_value,
            "length": bytes.len(),
            "mappings": [{
                "offset": 0,
                "range": {
                    "source": source_id,
                    "packet": 17,
                    "offset": 0,
                    "length": bytes.len()
                }
            }]
        }],
        "rules": [{"kind": "bytes"}, {"kind": "sequence"}],
        "composition": {
            "parts": [{
                "sample_ids": [1],
                "rule": {"kind": "bytes"},
                "component_index": null,
                "field": "bytes",
                "encoding": {"kind": "bytes"}
            }]
        },
        "action": {
            "kind": "derive",
            "recipe": {
                "steps": [{"kind": "hex_decode"}],
                "constraints": [
                    {"kind": "length", "bytes": 2},
                    {"kind": "prefix", "bytes": [104, 105]}
                ]
            }
        }
    });
    let plan_path = directory.join("carrier-plan.json");
    fs::write(plan_path.as_path(), serde_json::to_vec(&plan)?)?;
    Ok(plan_path)
}

#[test]
fn carrier_cli_projection_source_ranges() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let source_bytes = b"6869";
    let source_id = format!("sha256:{}", l2_workbench::sha256(source_bytes));
    let plan = save_plan(directory.path(), source_bytes, &source_id, Some(3))?;

    let result = run(&["carrier", path_arg(&plan)?], b"")?;

    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(report.pointer("/status"), Some(&json!("complete")));
    assert_eq!(
        report.pointer("/composition/output_sha256"),
        Some(&json!(l2_workbench::sha256(source_bytes)))
    );
    assert_eq!(
        report.pointer("/composition/parts/0/ranges/0/packet"),
        Some(&json!(17))
    );
    assert_eq!(report.pointer("/analysis/kind"), Some(&json!("derive")));
    assert_eq!(
        report.pointer("/analysis/result/derivation/output"),
        Some(&json!([104, 105]))
    );
    Ok(())
}

#[test]
fn carrier_cli_part_partial_analysis() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let source_bytes = b"6869";
    let source_id = format!("sha256:{}", l2_workbench::sha256(source_bytes));
    let plan_path = save_plan(directory.path(), source_bytes, &source_id, None)?;
    let mut plan: Value = serde_json::from_slice(&fs::read(&plan_path)?)?;
    let parts = plan
        .pointer_mut("/composition/parts")
        .and_then(Value::as_array_mut)
        .ok_or("missing composition parts")?;
    parts.push(json!({
        "sample_ids": [1],
        "rule": {"kind": "sequence"},
        "component_index": null,
        "field": "unsigned",
        "encoding": {
            "kind": "unsigned",
            "width": "one",
            "byte_order": "big_endian"
        }
    }));
    fs::write(&plan_path, serde_json::to_vec(&plan)?)?;

    let result = run(&["carrier", path_arg(&plan_path)?], b"")?;

    assert_eq!(result.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(report.pointer("/status"), Some(&json!("partial")));
    assert_eq!(report.pointer("/composition/complete"), Some(&json!(false)));
    assert_eq!(report.pointer("/analysis"), Some(&Value::Null));
    assert_eq!(
        report.pointer("/composition/parts/1/status/status"),
        Some(&json!("missing"))
    );
    Ok(())
}

#[test]
fn carrier_cli_source_hash_publishing() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let source_bytes = b"6869";
    let wrong_source_id = format!("sha256:{}", l2_workbench::sha256(b"other"));
    let plan = save_plan(directory.path(), source_bytes, &wrong_source_id, Some(3))?;

    let result = run(&["carrier", path_arg(&plan)?], b"")?;

    assert_eq!(result.status.code(), Some(1));
    assert_eq!(result.stdout.len(), 0);
    Ok(())
}

#[test]
fn carrier_cli_nonexhaustive_search_partial() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let source_bytes = b"6869";
    let source_id = format!("sha256:{}", l2_workbench::sha256(source_bytes));
    let plan_path = save_plan(directory.path(), source_bytes, &source_id, Some(3))?;
    let mut plan: Value = serde_json::from_slice(&fs::read(&plan_path)?)?;
    plan.as_object_mut()
        .ok_or("plan root was not an object")?
        .insert(
            "action".to_owned(),
            json!({
                "kind": "search",
                "plan": {
                    "families": [{"kind": "hex"}],
                    "constraints": [{"kind": "length", "bytes": 2}],
                    "max_depth": 1,
                    "max_candidates": 1
                }
            }),
        );
    fs::write(&plan_path, serde_json::to_vec(&plan)?)?;

    let result = run(&["carrier", path_arg(&plan_path)?], b"")?;

    assert_eq!(result.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(report.pointer("/status"), Some(&json!("partial")));
    assert_eq!(report.pointer("/analysis/kind"), Some(&json!("search")));
    assert_eq!(
        report.pointer("/analysis/result/search_exhaustive_within_plan"),
        Some(&json!(false))
    );
    Ok(())
}
