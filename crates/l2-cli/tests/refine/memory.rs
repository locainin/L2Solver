use std::{error::Error, fs};

use crate::arguments::{RecoveryOptions, RefineOptions};
use l2_workbench::job::{Job, MemoryBudget, MemoryClass, MemoryError};

#[test]
fn cached_refinement_preserves_memory_pressure_in_optional_and_strict_modes()
-> Result<(), Box<dyn Error>> {
    use l2_workbench::job::cache::Cache;

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("cache");
    let state = temporary.path().join("state");
    let cache = Cache::open_at(&root, &state, 1024 * 1024)?;
    let source = super::loaded_source("source.bin", &super::structural_png()?);
    let options = l2_workbench::artifact::ArtifactAnalysisOptions::default();
    super::analyze_source_cached(
        &source,
        options,
        &RecoveryOptions::default(),
        Some(&cache),
        &Job::new("populate"),
    )?;
    drop(cache);
    let cache = Cache::open_at(root, state, 1024 * 1024)?;
    let budget = MemoryBudget::new(1);
    cache.attach_memory_budget(budget.clone())?;
    for strict_cache in [false, true] {
        let recovery = RecoveryOptions {
            strict_cache,
            ..RecoveryOptions::default()
        };
        let job = Job::new("cache pressure");
        let error = super::analyze_source_cached(&source, options, &recovery, Some(&cache), &job)
            .err()
            .ok_or("memory pressure was swallowed as an optional cache failure")?;
        assert!(matches!(
            crate::memory_error::find(error.as_ref()),
            Some(MemoryError::Limit { .. })
        ));
        assert!(job.snapshot()?.cache_fallbacks.records().is_empty());
        assert_eq!(budget.snapshot()?.used_bytes, 0);
    }
    Ok(())
}

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
    let held = budget.try_reserve(MemoryClass::Cache, 6 * 1024 * 1024)?;
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
    assert!(snapshot.peak_bytes > 6 * 1024 * 1024 && snapshot.peak_bytes <= snapshot.limit_bytes);
    assert_eq!(snapshot.used_bytes, 0);
    Ok(())
}

#[test]
fn range_scan_does_not_reserve_unused_maximum_output() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("large.bin");
    let output = directory.path().join("result");
    fs::File::create(&input)?.set_len(5 * 1024 * 1024)?;
    let mut options = RefineOptions {
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
    assert!(!crate::refine::run_with_memory_budget(
        &options,
        &mut Vec::new(),
        &Job::new("bounded range scan"),
        &budget
    )?);
    assert!(output.join("manifest.json").is_file());
    assert_eq!(budget.snapshot()?.used_bytes, held.bytes());
    let first: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    drop(held);
    let retry = directory.path().join("retry");
    options.output = Some(retry.clone());
    assert!(!crate::refine::run_with_memory_budget(
        &options,
        &mut Vec::new(),
        &Job::new("uncontended range scan"),
        &budget
    )?);
    let second: serde_json::Value =
        serde_json::from_slice(&fs::read(retry.join("manifest.json"))?)?;
    assert_eq!(first.get("sources"), second.get("sources"));
    assert_eq!(first.get("artifacts"), second.get("artifacts"));
    Ok(())
}

#[test]
fn range_zip_expansion_is_admitted_before_member_reads_and_retries_without_omissions()
-> Result<(), Box<dyn Error>> {
    use l2_workbench::artifact::{ArtifactAnalysisOptions, analyze_artifacts};
    use l2_workbench::job::Counter;

    let directory = tempfile::tempdir()?;
    let input_path = directory.path().join("large.zip");
    let png = super::structural_png()?;
    super::large_formats::write_large_archive(&input_path, 7, &png)?;
    let source_length = usize::try_from(fs::metadata(&input_path)?.len())?;
    let digest = l2_workbench::sha256(&fs::read(&input_path)?);
    let options = ArtifactAnalysisOptions::default();
    let mut report = analyze_artifacts(b"", options)?;
    report.source_sha256.clone_from(&digest);
    report.source_length = source_length;

    // Keep parser work eligible so that a work omission cannot hide missing memory admission
    let memory = MemoryBudget::new(16 * 1024 * 1024);
    let job = Job::new("ZIP member pressure");
    let input =
        crate::refine::input::prepare_input_set_with_limit(&input_path, u64::MAX, &job, &memory)?;
    let mut file = fs::File::open(&input_path)?;
    let mut retained = memory.try_reserve(MemoryClass::Executor, 0)?;
    let mut omissions = memory.try_reserve(MemoryClass::Executor, 0)?;
    let held = memory.try_reserve(MemoryClass::Cache, 11 * 1024 * 1024)?;
    let before = memory.snapshot()?.used_bytes;
    let error = crate::refine::range_zip::inspect(
        &mut file,
        source_length,
        &digest,
        &mut report,
        options,
        &input,
        &job,
        &mut retained,
        &mut omissions,
    )
    .err()
    .ok_or("ZIP expansion ignored shared pressure")?;
    assert!(matches!(
        error.downcast_ref::<MemoryError>(),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(report.zip_expanded_work_bytes, 0);
    assert!(report.omissions.is_empty());
    let reads = job
        .snapshot()?
        .counters
        .get(&Counter::SourceReadBytes)
        .copied()
        .unwrap_or(0);
    assert!(
        reads < 2 * 1024 * 1024,
        "member was read before admission: {reads}"
    );
    assert_eq!(memory.snapshot()?.used_bytes, before);

    drop(held);
    let archive = crate::refine::range_zip::inspect(
        &mut file,
        source_length,
        &digest,
        &mut report,
        options,
        &input,
        &job,
        &mut retained,
        &mut omissions,
    )?
    .ok_or("retry did not inspect the ZIP")?;
    assert_eq!(archive.extracted_entry_count, 2);
    assert_eq!(archive.omitted_entry_count, 0);
    let [large, small] = archive.entries.as_slice() else {
        return Err("expected both ZIP members".into());
    };
    let large = large.content.as_deref().ok_or("large member is missing")?;
    assert_eq!(large.len(), 320 * 16 * 1024);
    assert!(large.iter().all(|byte| *byte == 7));
    assert_eq!(small.content.as_deref(), Some(png.as_slice()));
    assert!(retained.bytes() >= u64::try_from(large.len())?);
    drop(archive);
    drop(retained);
    drop(omissions);
    drop(input);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn failed_zip_read_retains_expansion_work_already_charged() -> Result<(), Box<dyn Error>> {
    use l2_workbench::{
        artifact::{ArtifactAnalysisOptions, analyze_artifacts},
        job::{Counter, cache::SourceFingerprint},
    };
    use std::io::Write;

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("archive.zip");
    let mut writer = zip::ZipWriter::new(fs::File::create(&path)?);
    let stored =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer.start_file("small.bin", stored)?;
    writer.write_all(b"small member")?;
    writer.start_file("large.bin", stored)?;
    for _ in 0..128 {
        writer.write_all(&[7_u8; 16 * 1024])?;
    }
    writer.finish()?.sync_all()?;
    let bytes = fs::read(&path)?;
    let length = u64::try_from(bytes.len())?;
    let read_limit = length
        .checked_add(1)
        .and_then(|value| value.checked_add(SourceFingerprint::sample_read_bytes(length) * 3))
        .and_then(|value| value.checked_add(512 * 1024))
        .ok_or("read limit overflows")?;
    let memory = MemoryBudget::new(16 * 1024 * 1024);
    let job = Job::new("limited ZIP reader");
    let input =
        crate::refine::input::prepare_input_set_with_limit(&path, read_limit, &job, &memory)?;
    let options = ArtifactAnalysisOptions::default();
    let mut report = analyze_artifacts(b"", options)?;
    let digest = l2_workbench::sha256(&bytes);
    report.source_sha256.clone_from(&digest);
    report.source_length = bytes.len();
    let mut retained = memory.try_reserve(MemoryClass::Executor, 0)?;
    let mut omissions = memory.try_reserve(MemoryClass::Executor, 0)?;
    let result = crate::refine::range_zip::inspect(
        &mut fs::File::open(&path)?,
        bytes.len(),
        &digest,
        &mut report,
        options,
        &input,
        &job,
        &mut retained,
        &mut omissions,
    )?;
    assert!(
        result.is_none(),
        "the bounded ZIP read unexpectedly completed"
    );
    assert!(report.zip_expanded_work_bytes >= b"small member".len());
    assert!(report.omissions.iter().any(|omission| matches!(
        omission,
        l2_workbench::artifact::AnalysisOmission::SourceRangeValidationLimit { reason, .. }
            if reason.contains("ZIP read")
    )));
    let reads = job
        .snapshot()?
        .counters
        .get(&Counter::SourceReadBytes)
        .copied()
        .unwrap_or(0);
    assert!(reads <= 512 * 1024);
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
