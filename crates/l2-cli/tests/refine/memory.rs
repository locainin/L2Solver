use std::{error::Error, fs};

use crate::arguments::{RecoveryOptions, RefineOptions};
use l2_workbench::job::{Job, MemoryBudget, MemoryClass};

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "shared admission and the result manifest form one scenario"
)]
fn shared_memory_pressure_skips_one_input_and_preserves_a_later_small_input()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("inputs");
    let output = directory.path().join("result");
    fs::create_dir(&input)?;
    let png = super::structural_png()?;
    fs::write(input.join("large.bin"), vec![7_u8; 200 * 1024])?;
    fs::write(input.join("small.png"), &png)?;
    fs::write(
        input.join("manifest.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "artifacts": [
                {"file": "large.bin", "byte_length": 200 * 1024},
                {"file": "small.png", "byte_length": png.len()}
            ]
        }))?,
    )?;
    let options = RefineOptions {
        input,
        output: Some(output.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    let memory = MemoryBudget::new(options.recovery.memory_limit);
    let held = memory.try_reserve(MemoryClass::Executor, 900 * 1024)?;
    let job = Job::new("refinement shared memory pressure");
    assert!(!crate::refine::run_with_memory_budget(
        &options,
        &mut Vec::new(),
        &job,
        &memory
    )?);
    let snapshot = memory.snapshot()?;
    assert!(snapshot.rejected > 0);
    assert!(snapshot.peak_bytes <= snapshot.limit_bytes);
    assert_eq!(snapshot.used_bytes, held.bytes());
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    assert!(
        manifest
            .pointer("/sources/0/sha256")
            .is_none_or(serde_json::Value::is_null)
    );
    assert!(
        manifest
            .pointer("/l2solver_result/source_identity_sha256")
            .is_none_or(serde_json::Value::is_null)
    );
    assert!(
        manifest
            .pointer("/sources/0/omissions")
            .and_then(serde_json::Value::as_array)
            .ok_or("source omissions missing")?
            .iter()
            .any(|item| item.get("kind").and_then(serde_json::Value::as_str)
                == Some("source_memory_limit"))
    );
    assert_eq!(
        manifest
            .pointer("/sources/1/sha256")
            .and_then(serde_json::Value::as_str),
        Some(l2_workbench::sha256(&png).as_str())
    );
    assert!(
        manifest
            .get("artifacts")
            .and_then(serde_json::Value::as_array)
            .ok_or("artifacts missing")?
            .iter()
            .any(
                |artifact| artifact.get("sha256").and_then(serde_json::Value::as_str)
                    == Some(l2_workbench::sha256(&png).as_str())
            )
    );
    drop(held);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}
