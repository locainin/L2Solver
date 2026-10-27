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

#[test]
fn range_scanner_scratch_shares_the_job_budget_and_fails_before_publication()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("large.bin");
    let output = directory.path().join("result");
    fs::File::create(&input)?.set_len(5 * 1024 * 1024)?;
    let options = RefineOptions {
        input,
        output: Some(output.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 8 * 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    let budget = MemoryBudget::new(options.recovery.memory_limit);
    let held = budget.try_reserve(MemoryClass::Cache, 4 * 1024 * 1024)?;
    let error = crate::refine::run_with_memory_budget(
        &options,
        &mut Vec::new(),
        &Job::new("blocked range scan"),
        &budget,
    )
    .err()
    .ok_or("range scan ignored shared pressure")?;
    assert!(matches!(
        error.downcast_ref::<MemoryError>(),
        Some(MemoryError::Limit { .. })
    ));
    assert!(!output.exists());
    drop(held);
    assert!(!crate::refine::run_with_memory_budget(
        &options,
        &mut Vec::new(),
        &Job::new("range scan retry"),
        &budget
    )?);
    let snapshot = budget.snapshot()?;
    assert!(snapshot.peak_bytes > 4 * 1024 * 1024 && snapshot.peak_bytes <= snapshot.limit_bytes);
    assert_eq!(snapshot.used_bytes, 0);
    Ok(())
}

#[test]
fn manifest_memory_is_admitted_before_reading_manifest_contents() -> Result<(), Box<dyn Error>> {
    use l2_workbench::job::Counter;
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("inputs");
    fs::create_dir(&input)?;
    fs::write(input.join("manifest.json"), vec![b' '; 32 * 1024])?;
    let budget = MemoryBudget::new(1024);
    let job = Job::new("manifest admission");
    let error = crate::refine::input::prepare_input_set_with_limit(&input, u64::MAX, &job, &budget)
        .err()
        .ok_or("manifest was read without admission")?;
    assert!(matches!(
        error.downcast_ref::<MemoryError>(),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(
        job.snapshot()?
            .counters
            .get(&Counter::SourceReadBytes)
            .copied()
            .unwrap_or(0),
        0
    );
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn oversized_manifest_entry_list_is_rejected_with_its_lease_released() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let entries = vec![serde_json::json!({"file": "item.bin", "byte_length": 0}); 4097];
    fs::write(
        directory.path().join("manifest.json"),
        serde_json::to_vec(&serde_json::json!({"schema_version": 1, "artifacts": entries}))?,
    )?;
    let budget = MemoryBudget::new(16 * 1024 * 1024);
    let error = crate::refine::input::prepare_input_set_with_limit(
        directory.path(),
        u64::MAX,
        &Job::new("oversized manifest"),
        &budget,
    )
    .err()
    .ok_or("oversized manifest was accepted")?;
    assert!(error.to_string().contains("entry count"), "{error}");
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
