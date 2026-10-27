use std::{error::Error, fs};

use crate::arguments::{RecoveryOptions, RefineOptions};
use l2_workbench::job::{Job, MemoryBudget, MemoryClass, MemoryError};

#[test]
fn publication_buffer_uses_the_fixed_policy_size_and_releases_its_lease()
-> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(32 * 1024);
    let held = budget.try_reserve(MemoryClass::Executor, 16 * 1024)?;
    let mut buffer = crate::refine::publication_memory::PublicationBuffer::try_new(&budget)?;
    assert_eq!(buffer.bytes_mut().len(), 16 * 1024);
    assert_eq!(budget.snapshot()?.used(MemoryClass::Publication), 16 * 1024);
    drop(buffer);
    assert_eq!(budget.snapshot()?.used_bytes, held.bytes());
    drop(held);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn publication_buffer_reports_typed_pressure_instead_of_changing_size() -> Result<(), Box<dyn Error>>
{
    let budget = MemoryBudget::new(32 * 1024);
    let _held = budget.try_reserve(MemoryClass::Executor, 16 * 1024 + 1)?;
    let error = crate::refine::publication_memory::PublicationBuffer::try_new(&budget)
        .err()
        .ok_or("publication pressure was ignored")?;
    assert!(matches!(
        error.downcast_ref::<MemoryError>(),
        Some(MemoryError::Limit { .. })
    ));
    Ok(())
}

#[test]
fn temporary_cache_pressure_fails_without_publication_and_retry_keeps_the_same_artifacts()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("inputs");
    let baseline = directory.path().join("baseline");
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
    let mut options = RefineOptions {
        input,
        output: Some(baseline.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    let baseline_job = Job::new("baseline refinement");
    let baseline_result = crate::refine::run_with_job(&options, &mut Vec::new(), &baseline_job)?;
    options.output = Some(output.clone());
    let memory = MemoryBudget::new(options.recovery.memory_limit);
    let held = memory.try_reserve(MemoryClass::Cache, 900 * 1024)?;
    let job = Job::new("temporary cache pressure");
    let error = crate::refine::run_with_memory_budget(&options, &mut Vec::new(), &job, &memory)
        .err()
        .ok_or("temporary pressure was ignored")?;
    assert!(matches!(
        error.downcast_ref::<MemoryError>(),
        Some(MemoryError::Limit { .. })
    ));
    assert!(!output.exists(), "failed admission published a result");
    assert_eq!(memory.snapshot()?.used_bytes, held.bytes());
    drop(held);
    let retry = crate::refine::run_with_memory_budget(
        &options,
        &mut Vec::new(),
        &Job::new("retry"),
        &memory,
    )?;
    assert_eq!(retry, baseline_result);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    let first: serde_json::Value =
        serde_json::from_slice(&fs::read(baseline.join("manifest.json"))?)?;
    let second: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    assert_eq!(first.get("artifacts"), second.get("artifacts"));
    assert_eq!(first.get("sources"), second.get("sources"));
    Ok(())
}
