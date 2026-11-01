use std::{error::Error, fs};

use crate::arguments::{RecoveryOptions, RecoveryProfile, RefineOptions};
use l2_workbench::job::{Counter, Job};

#[test]
fn zip_tail_hint_requires_shared_work_before_reading() -> Result<(), Box<dyn Error>> {
    use crate::refine::range_zip::{TailProbe, probe_tail};
    use l2_workbench::job::MemoryBudget;

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.bin");
    let file = fs::File::create(&path)?;
    file.set_len(128 * 1024)?;
    let memory = MemoryBudget::new(1024 * 1024);
    let job = Job::new("ZIP hint work quota");
    let input = crate::refine::input::prepare_input_set_with_limit(&path, u64::MAX, &job, &memory)?;
    let mut file = fs::File::open(&path)?;
    let work = 2 * (65_535 + 22);
    let before = job
        .snapshot()?
        .counters
        .get(&Counter::SourceReadBytes)
        .copied()
        .unwrap_or(0);
    let limited = probe_tail(
        &mut file,
        128 * 1024,
        128 * 1024,
        &input,
        &job,
        &memory,
        work - 1,
    )?;
    assert!(matches!(limited, TailProbe::WorkLimit));
    assert_eq!(
        job.snapshot()?
            .counters
            .get(&Counter::SourceReadBytes)
            .copied()
            .unwrap_or(0),
        before
    );
    let admitted = probe_tail(
        &mut file,
        128 * 1024,
        128 * 1024,
        &input,
        &job,
        &memory,
        work,
    )?;
    assert!(matches!(admitted, TailProbe::Scanned { work_bytes, .. } if work_bytes == work));
    let after = job
        .snapshot()?
        .counters
        .get(&Counter::SourceReadBytes)
        .copied()
        .unwrap_or(0);
    assert_eq!(after - before, u64::try_from(work / 2)?);
    Ok(())
}

#[test]
fn aggregate_source_read_limit_skips_large_source_and_retains_later_small_input()
-> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "linux")]
    const CHILD_MARKER: &str = "L2_TEST_SOURCE_QUOTA_CHILD";
    #[cfg(target_os = "linux")]
    if std::env::var_os(CHILD_MARKER).is_none() {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["refine::tests::read_budget::aggregate_source_read_limit_skips_large_source_and_retains_later_small_input", "--exact"])
            .env(CHILD_MARKER, "1")
            .output()?;
        assert!(
            output.status.success(),
            "child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("inputs");
    let output = directory.path().join("result");
    fs::create_dir(&input)?;
    for name in ["first.bin", "second.bin"] {
        let file = fs::File::create(input.join(name))?;
        file.set_len(2 * 1024 * 1024)?;
    }
    let png = super::structural_png()?;
    fs::write(input.join("small.png"), &png)?;
    fs::write(
        input.join("manifest.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1, "artifacts": [
                {"file": "first.bin", "byte_length": 2 * 1024 * 1024},
                {"file": "second.bin", "byte_length": 2 * 1024 * 1024},
                {"file": "small.png", "byte_length": png.len()},
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
            profile: RecoveryProfile::Fast,
            memory_limit: 4 * 1024 * 1024,
            source_read_limit: 5 * 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    let job = Job::new("aggregate source read quota");
    #[cfg(target_os = "linux")]
    let before = super::range_analysis::process_read_bytes()?;
    assert!(!super::run_with_job(&options, &mut Vec::new(), &job)?);
    #[cfg(target_os = "linux")]
    let observed = super::range_analysis::process_read_bytes()? - before;
    check_partial_manifest(&output, &png)?;
    let reads = job
        .snapshot()?
        .counters
        .get(&Counter::SourceReadBytes)
        .copied()
        .ok_or("read counter missing")?;
    assert!(
        reads <= options.recovery.source_read_limit,
        "source read accounting exceeded its limit"
    );
    #[cfg(target_os = "linux")]
    {
        assert!(
            observed >= reads.saturating_sub(16),
            "accounted {reads} bytes but process read {observed}"
        );
        assert!(
            observed <= reads + 128 * 1024,
            "process read {observed} bytes but accounted only {reads}"
        );
    }
    Ok(())
}

fn check_partial_manifest(output: &std::path::Path, png: &[u8]) -> Result<(), Box<dyn Error>> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let sources = manifest
        .get("sources")
        .and_then(serde_json::Value::as_array)
        .ok_or("sources missing")?;
    assert_eq!(
        manifest
            .get("schema_version")
            .and_then(serde_json::Value::as_u64),
        Some(2)
    );
    assert_eq!(sources.len(), 3);
    assert!(
        sources
            .first()
            .and_then(|source| source.get("sha256"))
            .and_then(serde_json::Value::as_str)
            .is_some()
    );
    let skipped = sources.get(1).ok_or("skipped source missing")?;
    assert!(skipped.get("sha256").is_none_or(serde_json::Value::is_null));
    assert_eq!(
        skipped.get("status").and_then(serde_json::Value::as_str),
        Some("partial")
    );
    assert!(
        skipped
            .get("omissions")
            .and_then(serde_json::Value::as_array)
            .ok_or("omissions missing")?
            .iter()
            .any(|item| item.get("kind").and_then(serde_json::Value::as_str)
                == Some("source_read_limit"))
    );
    let last = sources.get(2).ok_or("small source missing")?;
    assert_eq!(
        last.get("sha256").and_then(serde_json::Value::as_str),
        Some(l2_workbench::sha256(png).as_str())
    );
    assert!(
        manifest
            .get("artifacts")
            .and_then(serde_json::Value::as_array)
            .ok_or("artifacts missing")?
            .iter()
            .any(
                |item| item.get("sha256").and_then(serde_json::Value::as_str)
                    == Some(l2_workbench::sha256(png).as_str())
            )
    );
    let input_set = super::prepare_input_set(output)?;
    let loaded = super::read_sources(
        &input_set,
        1024 * 1024,
        1024 * 1024,
        &Job::new("reinspect partial result"),
    )?;
    assert!(loaded.iter().any(|source| source.bytes() == Some(png)));
    Ok(())
}

#[test]
fn skipped_source_has_no_digest_and_cannot_be_reused_as_verified() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("source.bin");
    let output = directory.path().join("result");
    fs::File::create(&input)?.set_len(2 * 1024 * 1024)?;
    let mut options = RefineOptions {
        input,
        output: Some(output.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 4 * 1024 * 1024,
            source_read_limit: 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    assert!(!super::run(&options, &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    assert!(
        manifest
            .pointer("/sources/0/sha256")
            .is_none_or(serde_json::Value::is_null)
    );
    assert!(manifest.pointer("/sources/0/work_bytes_charged").is_none());
    assert!(
        manifest
            .pointer("/sources/0/zip_expanded_work_bytes_charged")
            .is_none()
    );
    assert!(
        manifest
            .pointer("/l2solver_result/source_identity_sha256")
            .is_none_or(serde_json::Value::is_null)
    );
    assert_eq!(
        manifest
            .pointer("/l2solver_result/schema_version")
            .and_then(serde_json::Value::as_u64),
        Some(2)
    );
    options.recovery.strict_cache = true;
    let job = Job::new("skipped source retry");
    let mut status = Vec::new();
    let original_manifest = fs::read(output.join("manifest.json"))?;
    let error = super::run_with_job(&options, &mut status, &job)
        .err()
        .ok_or("unverified source was reused or replaced")?;
    assert!(
        error.to_string().contains("source identity is unavailable"),
        "{error}"
    );
    assert_eq!(fs::read(output.join("manifest.json"))?, original_manifest);
    assert!(!String::from_utf8(status)?.contains("Reused existing"));
    assert_eq!(job.snapshot()?.counters.get(&Counter::CacheHits), Some(&0));
    options.recovery.refresh = true;
    assert!(!super::run(&options, &mut Vec::new())?);
    Ok(())
}

#[test]
fn strict_reuse_charges_the_complete_source_verification() -> Result<(), Box<dyn Error>> {
    const LENGTH: u64 = 2 * 1024 * 1024;
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("source.bin");
    let output = directory.path().join("result");
    fs::File::create(&input)?.set_len(LENGTH)?;
    let mut options = RefineOptions {
        input,
        output: Some(output),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            profile: RecoveryProfile::Fast,
            memory_limit: 4 * 1024 * 1024,
            source_read_limit: 3 * 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    assert!(!super::run(&options, &mut Vec::new())?);
    options.recovery.strict_cache = true;
    let job = Job::new("strict source quota");
    let mut status = Vec::new();
    assert!(!super::run_with_job(&options, &mut status, &job)?);
    assert!(String::from_utf8(status)?.contains("Reused existing"));
    let reads = job
        .snapshot()?
        .counters
        .get(&Counter::SourceReadBytes)
        .copied()
        .ok_or("source read counter missing")?;
    assert!(reads >= LENGTH && reads <= options.recovery.source_read_limit);
    Ok(())
}
