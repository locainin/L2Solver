use super::*;
use l2_workbench::job::{CacheFallbackKind, CacheStage};

#[test]
fn recovery_operation_uses_the_budget_observed_by_its_job() -> Result<(), Box<dyn Error>> {
    let options = RecoveryOptions {
        progress: ProgressMode::Never,
        quiet: true,
        memory_limit: 123_456,
        ..RecoveryOptions::default()
    };
    let result = run(&options, "observed recovery", |job| {
        let memory = job.memory_budget().ok_or("recovery budget missing")?;
        let _lease = memory.try_reserve(l2_workbench::job::MemoryClass::Executor, 32)?;
        let snapshot = job.snapshot()?;
        let observed = snapshot
            .memory_admission
            .ok_or("memory observation missing")?;
        assert_eq!(observed.limit_bytes, options.memory_limit);
        assert_eq!(observed.used_bytes, 32);
        assert_eq!(observed.used(l2_workbench::job::MemoryClass::Executor), 32);
        Ok(true)
    })?;
    assert_eq!(result, RunOutcome::Completed);
    Ok(())
}

#[test]
fn human_cache_fallback_summary_is_one_bounded_grouped_line() -> Result<(), Box<dyn Error>> {
    let job = Job::new("cache fallback output");
    for detail in ["cached analysis was rejected", "cache entry was invalid"] {
        job.record_cache_fallback(
            CacheStage::ArtifactAnalysis,
            CacheFallbackKind::InvalidEntry,
            format_args!("{detail}"),
        )?;
    }
    let snapshot = job.snapshot()?;
    let mut output = Vec::new();

    write_cache_fallback_summary(&mut output, &snapshot, &RecoveryOptions::default())?;

    let output = String::from_utf8(output)?;
    assert_eq!(output.lines().count(), 1);
    assert!(output.contains("Cache fallback summary:"));
    assert!(output.contains("artifact analysis invalid entry x2"));
    assert!(output.contains("cache entry was invalid"));
    assert_eq!(output.matches('\n').count(), 1);
    Ok(())
}

#[test]
fn cache_fallback_summary_is_silent_for_empty_quiet_and_json_states() -> Result<(), Box<dyn Error>>
{
    let job = Job::new("cache fallback suppression");
    job.record_cache_fallback(
        CacheStage::CaseRecovery,
        CacheFallbackKind::LookupFailed,
        format_args!("cache lookup failed"),
    )?;
    let snapshot = job.snapshot()?;
    let cases = [
        RecoveryOptions {
            quiet: true,
            ..RecoveryOptions::default()
        },
        RecoveryOptions {
            progress: ProgressMode::Json,
            ..RecoveryOptions::default()
        },
    ];

    for options in cases {
        let mut output = Vec::new();
        write_cache_fallback_summary(&mut output, &snapshot, &options)?;
        assert!(output.is_empty());
    }

    let mut empty_output = Vec::new();
    write_cache_fallback_summary(
        &mut empty_output,
        &Job::new("no cache fallbacks").snapshot()?,
        &RecoveryOptions::default(),
    )?;
    assert!(empty_output.is_empty());
    Ok(())
}
