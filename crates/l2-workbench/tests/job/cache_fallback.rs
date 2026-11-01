use super::TestResult;
use l2_workbench::job::{CacheFallbackKind, CacheStage, Job, JobSnapshot};
use std::{cell::Cell, fmt, io};

#[test]
fn cache_fallbacks_group_by_stage_and_kind_and_choose_a_stable_sample() -> TestResult {
    let job = Job::new("cache fallback summary");
    job.record_cache_fallback(
        CacheStage::CaseRecovery,
        CacheFallbackKind::InvalidEntry,
        format_args!("cache entry was rejected\n"),
    )?;
    job.record_cache_fallback(
        CacheStage::CaseRecovery,
        CacheFallbackKind::InvalidEntry,
        format_args!("cached Case could not be restored"),
    )?;
    job.record_cache_fallback(
        CacheStage::ArtifactAnalysis,
        CacheFallbackKind::CacheUnavailable,
        format_args!("persistent cache could not be opened"),
    )?;

    let snapshot = job.snapshot()?;
    assert_eq!(snapshot.cache_fallbacks.records().len(), 2);

    let recovery = snapshot
        .cache_fallbacks
        .records()
        .iter()
        .find(|record| {
            record.stage() == CacheStage::CaseRecovery
                && record.kind() == CacheFallbackKind::InvalidEntry
        })
        .ok_or_else(|| io::Error::other("Case recovery fallback summary is missing"))?;
    assert_eq!(recovery.count(), 2);
    assert_eq!(
        recovery.sample_detail(),
        Some("cache entry was rejected\\n")
    );
    Ok(())
}

#[test]
fn cache_commit_failure_causes_keep_separate_counts_and_safe_samples() -> TestResult {
    let job = Job::new("typed cache commit failures");
    let categories = [
        (
            CacheFallbackKind::CommitCaseTooLarge,
            "Case JSON exceeds the recovery-cache limit",
        ),
        (
            CacheFallbackKind::CommitMetadataTooLarge,
            "cache metadata exceeds its limit",
        ),
        (
            CacheFallbackKind::CommitQuotaExceeded,
            "cache quota exceeded",
        ),
        (
            CacheFallbackKind::CommitStorageIo,
            "cache storage I/O failed",
        ),
        (CacheFallbackKind::CommitFailed, "cache commit failed"),
    ];

    for (kind, detail) in categories {
        job.record_cache_fallback(CacheStage::CaseRecovery, kind, format_args!("{detail}"))?;
    }

    let snapshot = job.snapshot()?;
    assert_eq!(snapshot.cache_fallbacks.records().len(), categories.len());
    for (kind, detail) in categories {
        let record = snapshot
            .cache_fallbacks
            .records()
            .iter()
            .find(|record| record.stage() == CacheStage::CaseRecovery && record.kind() == kind)
            .ok_or_else(|| io::Error::other("typed cache commit category is missing"))?;
        assert_eq!(record.count(), 1);
        assert_eq!(record.sample_detail(), Some(detail));
    }

    let serialized = serde_json::to_string(&snapshot)?;
    let restored: JobSnapshot = serde_json::from_str(&serialized)?;
    assert_eq!(restored, snapshot);
    Ok(())
}

#[test]
fn cache_fallback_samples_are_escaped_and_bounded_while_formatting() -> TestResult {
    let job = Job::new("bounded cache fallback detail");
    let detail = "long cache diagnostic ".repeat(32);
    job.record_cache_fallback(
        CacheStage::CaptureIndex,
        CacheFallbackKind::ContentionFallback,
        format_args!("{detail}"),
    )?;
    job.record_cache_fallback(
        CacheStage::CaptureIndex,
        CacheFallbackKind::ContentionFallback,
        format_args!("line one\nline two\t"),
    )?;

    let snapshot = job.snapshot()?;
    let fallback = snapshot
        .cache_fallbacks
        .records()
        .first()
        .ok_or_else(|| io::Error::other("capture fallback summary is missing"))?;
    let sample = fallback
        .sample_detail()
        .ok_or_else(|| io::Error::other("cache fallback sample is missing"))?;

    assert!(
        sample.len() <= 160,
        "sample length was {} bytes",
        sample.len()
    );
    assert!(!sample.chars().any(char::is_control));
    assert_eq!(sample, "line one\\nline two\\t");
    assert_eq!(fallback.count(), 2);
    Ok(())
}

#[test]
fn older_job_snapshots_restore_without_cache_fallbacks() -> TestResult {
    let job = Job::new("old checkpoint shape");
    let mut saved = serde_json::to_value(job.snapshot()?)?;
    saved
        .as_object_mut()
        .ok_or_else(|| io::Error::other("serialized job snapshot is not an object"))?
        .remove("cache_fallbacks");

    let snapshot: JobSnapshot = serde_json::from_value(saved)?;
    let resumed = Job::new("resumed old checkpoint");
    resumed.restore(snapshot)?;
    assert!(resumed.snapshot()?.cache_fallbacks.records().is_empty());
    Ok(())
}

#[test]
fn cache_fallback_snapshot_rejects_duplicate_oversized_and_unescaped_records() -> TestResult {
    let job = Job::new("invalid cache fallback snapshot");
    job.record_cache_fallback(
        CacheStage::CaseRecovery,
        CacheFallbackKind::LookupFailed,
        format_args!("cache lookup failed"),
    )?;
    let snapshot = serde_json::to_value(job.snapshot()?)?;
    let records = snapshot
        .pointer("/cache_fallbacks/records")
        .and_then(serde_json::Value::as_array)
        .and_then(|records| records.first())
        .cloned()
        .ok_or_else(|| io::Error::other("cache fallback record is missing"))?;

    assert_rejects_cache_fallback_records(
        &snapshot,
        serde_json::json!([records.clone(), records]),
        "duplicate categories",
    )?;

    let mut all_categories = cache_fallback_categories();
    let first_category = all_categories
        .first()
        .cloned()
        .ok_or_else(|| io::Error::other("cache fallback categories are empty"))?;
    all_categories.push(first_category);
    assert_rejects_cache_fallback_records(
        &snapshot,
        serde_json::Value::Array(all_categories),
        "too many categories",
    )?;

    assert_rejects_cache_fallback_records(
        &snapshot,
        serde_json::json!([{
            "stage": "case_recovery",
            "kind": "lookup_failed",
            "count": 1,
            "sample_detail": "x".repeat(1_024),
        }]),
        "oversized sample",
    )?;

    assert_rejects_cache_fallback_records(
        &snapshot,
        serde_json::json!([{
            "stage": "unknown_stage",
            "kind": "lookup_failed",
            "count": 1,
            "sample_detail": "cache lookup failed",
        }]),
        "unknown stage",
    )?;

    assert_rejects_cache_fallback_records(
        &snapshot,
        serde_json::json!([{
            "stage": "case_recovery",
            "kind": "lookup_failed",
            "count": 1,
            "sample_detail": "line one\nline two",
        }]),
        "unescaped sample",
    )?;
    Ok(())
}

#[test]
fn restore_merges_cache_fallback_counts_and_keeps_the_stable_sample() -> TestResult {
    let saved_job = Job::new("saved cache fallback");
    saved_job.record_cache_fallback(
        CacheStage::CaseRecovery,
        CacheFallbackKind::InvalidEntry,
        format_args!("zeta diagnostic"),
    )?;
    let checkpoint = saved_job.snapshot()?;

    let resumed = Job::new("resumed cache fallback");
    resumed.record_cache_fallback(
        CacheStage::CaseRecovery,
        CacheFallbackKind::InvalidEntry,
        format_args!("alpha diagnostic"),
    )?;
    resumed.restore(checkpoint)?;

    let snapshot = resumed.snapshot()?;
    let fallback = snapshot
        .cache_fallbacks
        .records()
        .first()
        .ok_or_else(|| io::Error::other("restored cache fallback summary is missing"))?;
    assert_eq!(fallback.count(), 2);
    assert_eq!(fallback.sample_detail(), Some("alpha diagnostic"));
    Ok(())
}

#[test]
fn cache_fallback_formatting_stops_cooperative_display_at_the_sample_bound() -> TestResult {
    struct ChunkedDisplay<'a> {
        calls: &'a Cell<usize>,
    }

    impl fmt::Display for ChunkedDisplay<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            for _ in 0..1_000 {
                self.calls.set(self.calls.get() + 1);
                formatter.write_str("1234567")?;
            }
            Ok(())
        }
    }

    let calls = Cell::new(0);
    let detail = ChunkedDisplay { calls: &calls };
    let job = Job::new("bounded formatter");
    job.record_cache_fallback(
        CacheStage::CaseRecovery,
        CacheFallbackKind::LookupFailed,
        format_args!("{detail}"),
    )?;

    let snapshot = job.snapshot()?;
    let sample = snapshot
        .cache_fallbacks
        .records()
        .first()
        .and_then(|record| record.sample_detail())
        .ok_or_else(|| io::Error::other("bounded cache sample is missing"))?;
    assert!(calls.get() < 1_000, "formatter calls: {}", calls.get());
    assert_eq!(calls.get(), 23);
    assert!(sample.len() <= 160, "sample length: {} bytes", sample.len());
    assert!(
        sample.ends_with("..."),
        "sample was not visibly truncated: {sample}"
    );
    Ok(())
}

fn assert_rejects_cache_fallback_records(
    snapshot: &serde_json::Value,
    records: serde_json::Value,
    label: &str,
) -> TestResult {
    let mut changed = snapshot.clone();
    let field = changed
        .pointer_mut("/cache_fallbacks/records")
        .ok_or_else(|| io::Error::other("serialized cache fallback records are missing"))?;
    *field = records;
    assert!(
        serde_json::from_value::<JobSnapshot>(changed).is_err(),
        "accepted {label} in a job snapshot"
    );
    Ok(())
}

fn cache_fallback_categories() -> Vec<serde_json::Value> {
    let stages = [
        CacheStage::CaptureIndex,
        CacheStage::CaseRecovery,
        CacheStage::ArtifactAnalysis,
        CacheStage::Checkpoint,
    ];
    let kinds = [
        CacheFallbackKind::InvalidEntry,
        CacheFallbackKind::LookupFailed,
        CacheFallbackKind::LeaseUnavailable,
        CacheFallbackKind::CommitFailed,
        CacheFallbackKind::CommitCaseTooLarge,
        CacheFallbackKind::CommitMetadataTooLarge,
        CacheFallbackKind::CommitQuotaExceeded,
        CacheFallbackKind::CommitStorageIo,
        CacheFallbackKind::CheckpointUnsupported,
        CacheFallbackKind::CacheUnavailable,
        CacheFallbackKind::ContentionFallback,
    ];
    stages
        .into_iter()
        .flat_map(|stage| kinds.into_iter().map(move |kind| (stage, kind)))
        .map(|(stage, kind)| {
            serde_json::json!({
                "stage": stage,
                "kind": kind,
                "count": 1,
                "sample_detail": "bounded detail",
            })
        })
        .collect()
}
