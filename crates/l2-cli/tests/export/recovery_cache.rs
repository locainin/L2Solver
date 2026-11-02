use super::{RecoveryCaseKind, RecoveryContext, recover, recovery_key};
use crate::arguments::{ProgressMode, RecoveryOptions, RecoveryProfile};
use l2_workbench::{
    evidence::{Case, Edge, EvidenceStatus, MAX_EDGES, MAX_REASON_BYTES},
    job::{
        CacheFallbackKind, CacheStage, Counter, Job,
        cache::{Cache, CacheReadPolicy, StageStatus},
    },
    sha256,
};
use serde_json::{Value, json};
use std::{error::Error, fs};

#[path = "recovery_cache/failures.rs"]
mod failures;

#[path = "recovery_cache/integrity.rs"]
mod integrity;

#[path = "recovery_cache/memory.rs"]
mod memory;

#[path = "recovery_cache/compatibility.rs"]
mod compatibility;

#[path = "recovery_cache/lifecycle.rs"]
mod lifecycle;

#[test]
fn warm_cache_restores_the_case_and_local_coverage() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let (mut first_case, scope) = case_and_scope(b"4142", 7)?;
    let first = recover(
        &mut first_case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: None,
            options: &options,
        },
    )?;
    let expected_case = first_case.to_json()?;
    let entry_key = recovery_key(RecoveryCaseKind::Flow, &scope, &options)?;
    let entry = cache
        .lookup(&entry_key, CacheReadPolicy::AllowPartial)?
        .ok_or("the first recovery did not publish its cache entry")?;
    let graph_path = entry.directory().join("case.graph.gz");
    let blob_pack_path = entry.directory().join("case.blobs");
    assert!(
        graph_path.is_file(),
        "the exact graph stream should be stored"
    );
    assert!(
        blob_pack_path.is_file(),
        "the exact blob pack should be stored"
    );
    assert!(
        !entry.directory().join("case.json").exists(),
        "new entries should use the normalized snapshot pair"
    );
    assert_snapshot_metadata(entry.metadata())?;

    let job = Job::new("cached flow recovery");
    job.increment(Counter::CandidatesExamined, 7)?;
    let (mut second_case, second_scope) = case_and_scope(b"4142", 7)?;
    let second = recover(
        &mut second_case,
        RecoveryCaseKind::Flow,
        &second_scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;
    let snapshot = job.snapshot()?;

    assert_eq!(second_case.to_json()?, expected_case);
    assert_eq!(
        serde_json::to_value(second.coverage)?,
        serde_json::to_value(first.coverage)?
    );
    assert_eq!(second.omissions, first.omissions);
    assert_eq!(snapshot.counters.get(&Counter::CacheHits), Some(&1));
    assert_eq!(
        snapshot
            .counters
            .get(&Counter::CacheMisses)
            .copied()
            .unwrap_or(0),
        0
    );
    assert!(first.coverage.candidates > 0);
    assert_eq!(
        snapshot.counters.get(&Counter::CandidatesExamined),
        Some(&7),
        "a cache hit must not count cached candidates as newly examined"
    );
    Ok(())
}

#[test]
fn large_case_snapshot_commits_and_replays_above_the_legacy_json_limit()
-> Result<(), Box<dyn Error>> {
    const EDGE_COUNT: usize = MAX_EDGES - 10_000;
    const CACHE_LIMIT_BYTES: u64 = 96 * 1024 * 1024;

    let temporary = tempfile::tempdir()?;
    let cache = open_cache_with_limit(temporary.path(), CACHE_LIMIT_BYTES)?;
    let options = RecoveryOptions {
        cache_max_bytes: CACHE_LIMIT_BYTES,
        ..RecoveryOptions::default()
    };
    let (mut first_case, scope) = large_case_and_scope(EDGE_COUNT)?;
    assert!(
        count_case_json_bytes(&first_case)?
            > u64::try_from(l2_workbench::evidence::MAX_CASE_JSON_BYTES)?,
        "the test Case should exceed the legacy JSON cache ceiling"
    );

    let first_job = Job::new("large recovery snapshot commit");
    let first_result = recover(
        &mut first_case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&first_job),
            options: &options,
        },
    )?;
    assert_eq!(
        first_job.snapshot()?.counters.get(&Counter::CacheMisses),
        Some(&1)
    );
    let key = recovery_key(RecoveryCaseKind::Flow, &scope, &options)?;
    let entry = cache
        .lookup(&key, CacheReadPolicy::AllowPartial)?
        .ok_or("the large Case recovery did not publish a cache entry")?;
    assert!(
        snapshot_graph_decoded_bytes(entry.metadata())?
            > u64::try_from(l2_workbench::evidence::MAX_CASE_JSON_BYTES)?
    );

    let (mut second_case, second_scope) = case_and_scope(b"4142", 101)?;
    let job = Job::new("large recovery snapshot replay");
    let second_result = recover(
        &mut second_case,
        RecoveryCaseKind::Flow,
        &second_scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;

    assert_cases_equal(&second_case, &first_case);
    assert_eq!(
        serde_json::to_value(second_result.coverage)?,
        serde_json::to_value(first_result.coverage)?
    );
    assert_eq!(second_result.omissions, first_result.omissions);
    assert_eq!(job.snapshot()?.counters.get(&Counter::CacheHits), Some(&1));
    assert_eq!(
        job.snapshot()?.counters.get(&Counter::CacheMisses),
        Some(&0)
    );
    Ok(())
}

#[test]
fn refresh_recomputes_and_atomically_replaces_the_cached_recovery() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let (mut initial_case, scope) = case_and_scope(b"4142", 9)?;
    recover(
        &mut initial_case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: None,
            options: &options,
        },
    )?;

    let mut refresh = options.clone();
    refresh.refresh = true;
    let job = Job::new("refresh cached flow recovery");
    let (mut refreshed_case, refreshed_scope) = case_and_scope(b"4142", 9)?;
    let result = recover(
        &mut refreshed_case,
        RecoveryCaseKind::Flow,
        &refreshed_scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &refresh,
        },
    )?;

    assert_eq!(result.coverage.flow_cases, 1);
    let snapshot = job.snapshot()?;
    assert_eq!(
        snapshot
            .counters
            .get(&Counter::CacheHits)
            .copied()
            .unwrap_or(0),
        0
    );
    assert_eq!(snapshot.counters.get(&Counter::CacheMisses), Some(&1));
    assert_eq!(snapshot.cache_fallbacks.records().len(), 0);
    assert_eq!(cache.stats()?.entries, 1);
    Ok(())
}

#[test]
fn valid_cache_miss_and_no_cache_do_not_record_fallback_diagnostics() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let job = Job::new("cold cache recovery");
    let (mut case, scope) = case_and_scope(b"4142", 41)?;
    recover(
        &mut case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;

    let cold_snapshot = job.snapshot()?;
    assert_eq!(cold_snapshot.cache_fallbacks.records().len(), 0);
    assert_eq!(cold_snapshot.counters.get(&Counter::CacheMisses), Some(&1));

    let mut no_cache = options.clone();
    no_cache.no_cache = true;
    let no_cache_job = Job::new("cache disabled recovery");
    let (mut uncached_case, uncached_scope) = case_and_scope(b"4142", 41)?;
    recover(
        &mut uncached_case,
        RecoveryCaseKind::Flow,
        &uncached_scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&no_cache_job),
            options: &no_cache,
        },
    )?;

    let no_cache_snapshot = no_cache_job.snapshot()?;
    assert_eq!(no_cache_snapshot.cache_fallbacks.records().len(), 0);
    assert_eq!(
        no_cache_snapshot.counters.get(&Counter::CacheHits),
        Some(&0)
    );
    assert_eq!(
        no_cache_snapshot.counters.get(&Counter::CacheMisses),
        Some(&0)
    );
    Ok(())
}

#[test]
fn partial_recovery_is_reused_as_partial_for_the_same_policy() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let (mut first_case, scope) = case_and_scope(b"4142", 11)?;
    first_case.mark_incomplete("fixture collection stopped early")?;

    let first = recover(
        &mut first_case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: None,
            options: &options,
        },
    )?;

    assert!(!first.coverage.is_complete());
    assert_eq!(
        first
            .coverage
            .flow_cases_with_incomplete_case_evidence_collection,
        1
    );

    let job = Job::new("partial cache reuse");
    let (mut second_case, second_scope) = case_and_scope(b"4142", 11)?;
    second_case.mark_incomplete("fixture collection stopped early")?;
    let second = recover(
        &mut second_case,
        RecoveryCaseKind::Flow,
        &second_scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;

    assert!(!second.coverage.is_complete());
    assert_eq!(
        second
            .coverage
            .flow_cases_with_incomplete_case_evidence_collection,
        1
    );
    assert_eq!(job.snapshot()?.counters.get(&Counter::CacheHits), Some(&1));
    Ok(())
}

#[test]
fn legacy_json_cache_entries_remain_readable_without_snapshot_metadata()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let (mut expected_case, scope) = case_and_scope(b"4142", 13)?;
    let expected_result = recover(
        &mut expected_case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: None,
            job: None,
            options: &options,
        },
    )?;
    let key = recovery_key(RecoveryCaseKind::Flow, &scope, &options)?;
    let lease = cache.lease(&key)?;
    fs::write(
        lease.directory().join("case.json"),
        expected_case.to_json()?,
    )?;
    let metadata = json!({
        "coverage": &expected_result.coverage,
        "omissions": &expected_result.omissions,
    });
    drop(lease.commit(StageStatus::Complete, metadata)?);

    let (mut restored_case, restored_scope) = case_and_scope(b"4142", 13)?;
    let job = Job::new("legacy recovery cache replay");
    let restored_result = recover(
        &mut restored_case,
        RecoveryCaseKind::Flow,
        &restored_scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;

    assert_eq!(restored_case.sources(), expected_case.sources());
    assert_eq!(restored_case.nodes(), expected_case.nodes());
    assert_eq!(restored_result.omissions, expected_result.omissions);
    assert_eq!(
        serde_json::to_value(restored_result.coverage)?,
        serde_json::to_value(expected_result.coverage)?
    );
    assert_eq!(job.snapshot()?.counters.get(&Counter::CacheHits), Some(&1));
    Ok(())
}

#[test]
fn legacy_json_replay_obeys_the_current_physical_storage_limit() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let mut options = RecoveryOptions::default();
    let (mut expected_case, scope) = case_and_scope(b"4142", 14)?;
    let expected_result = recover(
        &mut expected_case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: None,
            job: None,
            options: &options,
        },
    )?;
    let key = recovery_key(RecoveryCaseKind::Flow, &scope, &options)?;
    let lease = cache.lease(&key)?;
    fs::write(
        lease.directory().join("case.json"),
        expected_case.to_json()?,
    )?;
    let metadata = json!({
        "coverage": &expected_result.coverage,
        "omissions": &expected_result.omissions,
    });
    let status = if expected_result.coverage.is_complete() {
        StageStatus::Complete
    } else {
        StageStatus::Partial
    };
    drop(lease.commit(status, metadata)?);

    options.cache_max_bytes = 1;
    let (mut fresh_case, fresh_scope) = case_and_scope(b"4142", 14)?;
    let job = Job::new("legacy cache physical limit");
    let fresh = recover(
        &mut fresh_case,
        RecoveryCaseKind::Flow,
        &fresh_scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;

    assert!(fresh.coverage.is_complete());
    let snapshot = job.snapshot()?;
    assert_eq!(snapshot.counters.get(&Counter::CacheHits), Some(&0));
    assert_eq!(snapshot.counters.get(&Counter::CacheMisses), Some(&1));
    assert!(snapshot.cache_fallbacks.records().iter().any(|fallback| {
        fallback.stage() == CacheStage::CaseRecovery
            && fallback.kind() == CacheFallbackKind::InvalidEntry
    }));
    Ok(())
}

#[test]
fn null_snapshot_metadata_is_not_treated_as_a_legacy_entry() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let (mut previous_case, scope) = case_and_scope(b"4142", 15)?;
    let previous_result = recover(
        &mut previous_case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: None,
            job: None,
            options: &options,
        },
    )?;
    let key = recovery_key(RecoveryCaseKind::Flow, &scope, &options)?;
    let lease = cache.lease(&key)?;
    fs::write(
        lease.directory().join("case.json"),
        previous_case.to_json()?,
    )?;
    let metadata = json!({
        "coverage": &previous_result.coverage,
        "omissions": &previous_result.omissions,
        "case_storage_format": null,
        "case_snapshot_usage": null,
    });
    drop(lease.commit(StageStatus::Complete, metadata)?);

    let (mut fresh_case, fresh_scope) = case_and_scope(b"4142", 15)?;
    let job = Job::new("null snapshot format metadata");
    let _fresh = recover(
        &mut fresh_case,
        RecoveryCaseKind::Flow,
        &fresh_scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;
    let snapshot = job.snapshot()?;
    assert_eq!(snapshot.counters.get(&Counter::CacheHits), Some(&0));
    assert_eq!(snapshot.counters.get(&Counter::CacheMisses), Some(&1));
    assert!(snapshot.cache_fallbacks.records().iter().any(|fallback| {
        fallback.stage() == CacheStage::CaseRecovery
            && fallback.kind() == CacheFallbackKind::InvalidEntry
    }));
    Ok(())
}

#[test]
fn cache_key_tracks_scope_profile_and_memory_policy_only() -> Result<(), Box<dyn Error>> {
    let (_, scope) = case_and_scope(b"4142", 17)?;
    let normal = RecoveryOptions::default();
    let normal_key = recovery_key(RecoveryCaseKind::Flow, &scope, &normal)?;

    let mut fast = normal.clone();
    fast.profile = RecoveryProfile::Fast;
    let fast_key = recovery_key(RecoveryCaseKind::Flow, &scope, &fast)?;
    assert_ne!(normal_key, fast_key);

    let mut larger_memory = normal.clone();
    larger_memory.memory_limit = normal.memory_limit + 1;
    let larger_memory_key = recovery_key(RecoveryCaseKind::Flow, &scope, &larger_memory)?;
    assert_ne!(normal_key, larger_memory_key);

    let (_, other_scope) = case_and_scope(b"4142", 18)?;
    let other_scope_key = recovery_key(RecoveryCaseKind::Flow, &other_scope, &normal)?;
    assert_ne!(normal_key, other_scope_key);

    let cohort_key = recovery_key(RecoveryCaseKind::Cohort, &scope, &normal)?;
    assert_ne!(normal_key, cohort_key);

    let (_, other_source_scope) = case_and_scope(b"4143", 17)?;
    let other_source_key = recovery_key(RecoveryCaseKind::Flow, &other_source_scope, &normal)?;
    assert_ne!(normal_key, other_source_key);

    let mut presentation_change = normal;
    presentation_change.refresh = true;
    presentation_change.no_cache = true;
    presentation_change.strict_cache = true;
    presentation_change.progress = ProgressMode::Always;
    presentation_change.jobs = Some(3);
    presentation_change.quiet = true;
    presentation_change.verbosity = 2;
    presentation_change.cache_max_bytes *= 2;
    assert_eq!(
        normal_key,
        recovery_key(RecoveryCaseKind::Flow, &scope, &presentation_change)?
    );
    Ok(())
}

#[test]
fn cache_key_does_not_reuse_the_previous_transform_proposal_policy() -> Result<(), Box<dyn Error>> {
    use l2_workbench::job::cache::{SourceIdentity, StageKey};

    let (_, scope) = case_and_scope(b"4142", 19)?;
    let options = RecoveryOptions::default();
    let source = SourceIdentity::from_sha256(sha256(b"4142"))?;
    let previous_policy = json!({
        "native_case_version": crate::workbench::full_source::NATIVE_CASE_VERSION,
        "kind": "flow",
        "profile": "normal",
        "memory_limit_bytes": options.memory_limit,
        "scope": scope,
    });
    let previous_key = StageKey::new(
        super::RECOVERY_STAGE,
        super::RECOVERY_STAGE_VERSION,
        super::RECOVERY_ALGORITHM,
        &previous_policy,
        &source,
        &[],
    )?;
    assert_ne!(
        recovery_key(RecoveryCaseKind::Flow, &scope, &options)?,
        previous_key
    );
    Ok(())
}

#[test]
fn cache_key_does_not_reuse_results_without_xor_discovery() -> Result<(), Box<dyn Error>> {
    let (_, scope) = case_and_scope(b"4142", 19)?;
    let options = RecoveryOptions::default();
    let old = previous_recovery_key(&scope, &options, super::RECOVERY_STAGE_VERSION)?;
    assert_ne!(recovery_key(RecoveryCaseKind::Flow, &scope, &options)?, old);
    Ok(())
}

#[test]
fn changed_recovery_algorithm_rejects_a_stale_partial_result() -> Result<(), Box<dyn Error>> {
    // Earlier stages lack current search, schema handoff, or deferred assembly semantics
    for version in [
        4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
        28, 29, 30,
    ] {
        assert_previous_recovery_recomputed(version)?;
    }
    Ok(())
}

fn assert_previous_recovery_recomputed(version: u32) -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let (mut old_case, scope) = case_and_scope(b"4142", 37)?;
    let mut previous = recover(
        &mut old_case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: None,
            job: None,
            options: &options,
        },
    )?;
    assert!(previous.coverage.is_complete());
    previous.coverage.flow_cases_with_non_exhaustive_search = 1;
    previous
        .omissions
        .push("previous algorithm omitted 720 length checks".into());
    previous.coverage.omissions = u64::try_from(previous.omissions.len())?;
    old_case.add_node("previous_algorithm_marker", None, Vec::new(), json!({}))?;
    let previous_key = previous_recovery_key(&scope, &options, version)?;
    super::store_result(
        cache.lease(&previous_key)?,
        &old_case,
        &previous,
        &options,
        None,
    )?;

    let job = Job::new("recovery algorithm invalidation");
    let (mut current_case, _) = case_and_scope(b"4142", 37)?;
    let current = recover(
        &mut current_case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;
    assert!(
        current.coverage.is_complete(),
        "stale partial recovery was replayed"
    );
    assert_eq!(current.omissions.len(), 0);
    assert!(
        !current_case
            .nodes()
            .iter()
            .any(|node| node.kind == "previous_algorithm_marker")
    );
    assert_eq!(
        job.snapshot()?.counters.get(&Counter::CacheMisses),
        Some(&1)
    );
    // Invalidation changes the affected stage key instead of deleting other cached work
    assert!(
        cache
            .lookup(&previous_key, CacheReadPolicy::AllowPartial)?
            .is_some()
    );
    assert_eq!(
        cache.stats()?.entries,
        2,
        "recovery version {version}; cache fallback: {:?}",
        job.snapshot()?.cache_fallbacks
    );
    Ok(())
}

fn previous_recovery_key(
    scope: &Value,
    options: &RecoveryOptions,
    version: u32,
) -> Result<l2_workbench::job::cache::StageKey, Box<dyn Error>> {
    use l2_workbench::job::cache::{SourceIdentity, StageKey};

    // Preserve the exact old key format that replayed obsolete search omissions
    let policy = json!({
        "native_case_version": crate::workbench::full_source::NATIVE_CASE_VERSION,
        "transform_proposal_version": l2_workbench::recovery::proposals::TRANSFORM_PROPOSAL_FORMAT_VERSION,
        "kind": "flow",
        "profile": "normal",
        "memory_limit_bytes": options.memory_limit,
        "scope": scope,
    });
    Ok(StageKey::new(
        super::RECOVERY_STAGE,
        version,
        super::RECOVERY_ALGORITHM,
        &policy,
        &SourceIdentity::from_sha256(sha256(b"4142"))?,
        &[],
    )?)
}

#[test]
fn cached_case_with_inaccurate_snapshot_usage_is_rejected_and_recomputed()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let (mut first_case, scope) = case_and_scope(b"4142", 19)?;
    let first = recover(
        &mut first_case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: None,
            options: &options,
        },
    )?;

    let key = recovery_key(RecoveryCaseKind::Flow, &scope, &options)?;
    store_case_with_inaccurate_snapshot_usage(&cache, &key, &first_case, &first, &options)?;

    let mut strict = options.clone();
    strict.strict_cache = true;
    let (mut strict_case, strict_scope) = case_and_scope(b"4142", 19)?;
    let strict_job = Job::new("strict corrupt cache check");
    assert!(
        recover(
            &mut strict_case,
            RecoveryCaseKind::Flow,
            &strict_scope,
            &RecoveryContext {
                memory: None,
                cache: Some(&cache),
                job: Some(&strict_job),
                options: &strict,
            },
        )
        .is_err()
    );
    assert_eq!(strict_job.snapshot()?.cache_fallbacks.records().len(), 0);

    let job = Job::new("repair corrupt cache entry");
    let (mut fresh_case, fresh_scope) = case_and_scope(b"4142", 19)?;
    let recomputed = recover(
        &mut fresh_case,
        RecoveryCaseKind::Flow,
        &fresh_scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;

    assert_eq!(recomputed.coverage.flow_cases, 1);
    assert_eq!(
        job.snapshot()?.counters.get(&Counter::CacheMisses),
        Some(&1)
    );
    let snapshot = job.snapshot()?;
    let fallback = snapshot
        .cache_fallbacks
        .records()
        .iter()
        .find(|record| {
            record.stage() == CacheStage::CaseRecovery
                && record.kind() == CacheFallbackKind::InvalidEntry
        })
        .ok_or("normal mode did not record the rejected cached Case")?;
    assert_eq!(fallback.count(), 1);
    assert_eq!(
        fallback.sample_detail(),
        Some("cached Case could not be restored")
    );
    assert_eq!(cache.stats()?.entries, 1);
    assert!(cache.lookup(&key, CacheReadPolicy::AllowPartial)?.is_some());
    Ok(())
}

#[test]
fn unknown_snapshot_format_is_rejected_instead_of_counted_as_a_hit() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let (mut source_case, scope) = case_and_scope(b"4142", 21)?;
    let result = recover(
        &mut source_case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: None,
            job: None,
            options: &options,
        },
    )?;
    let key = recovery_key(RecoveryCaseKind::Flow, &scope, &options)?;
    let metadata = json!({
        "coverage": result.coverage,
        "omissions": result.omissions,
        "case_storage_format": 77,
        "case_snapshot_usage": {
            "graph_bytes": 0,
            "graph_decoded_bytes": 0,
            "blob_pack_bytes": 0,
        },
    });
    drop(cache.lease(&key)?.commit(StageStatus::Complete, metadata)?);

    let (mut fresh_case, fresh_scope) = case_and_scope(b"4142", 21)?;
    let job = Job::new("unsupported recovery snapshot format");
    let fresh = recover(
        &mut fresh_case,
        RecoveryCaseKind::Flow,
        &fresh_scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;

    assert!(fresh.coverage.is_complete());
    assert_eq!(job.snapshot()?.counters.get(&Counter::CacheHits), Some(&0));
    assert_eq!(
        job.snapshot()?.counters.get(&Counter::CacheMisses),
        Some(&1)
    );
    assert!(
        job.snapshot()?
            .cache_fallbacks
            .records()
            .iter()
            .any(|fallback| {
                fallback.stage() == CacheStage::CaseRecovery
                    && fallback.kind() == CacheFallbackKind::InvalidEntry
            })
    );
    Ok(())
}

fn store_case_with_inaccurate_snapshot_usage(
    cache: &Cache,
    key: &l2_workbench::job::cache::StageKey,
    case: &Case,
    result: &super::CachedRecovery,
    options: &RecoveryOptions,
) -> Result<(), Box<dyn Error>> {
    let lease = cache.lease(key)?;
    let mut graph = Vec::new();
    let mut blob_pack = Vec::new();
    let mut usage = case.write_snapshot(
        &mut graph,
        &mut blob_pack,
        l2_workbench::evidence::CaseSnapshotLimits::new(
            options.cache_max_bytes,
            options.memory_limit,
        ),
    )?;
    fs::write(
        lease.directory().join(crate::case_snapshot::GRAPH_FILE),
        graph,
    )?;
    fs::write(
        lease.directory().join(crate::case_snapshot::BLOB_PACK_FILE),
        blob_pack,
    )?;
    usage.graph_decoded_bytes = usage
        .graph_decoded_bytes
        .checked_add(1)
        .ok_or("snapshot usage fixture overflow")?;
    // Keep the exact files valid while corrupting only their diagnostic usage receipt
    let metadata = serde_json::to_value(super::RecoveryMetadataRef {
        coverage: &result.coverage,
        omissions: &result.omissions,
        case_storage_format: super::CASE_SNAPSHOT_FORMAT,
        case_snapshot_usage: &usage,
    })?;
    let status = if result.coverage.is_complete() {
        StageStatus::Complete
    } else {
        StageStatus::Partial
    };
    drop(lease.commit(status, metadata)?);
    Ok(())
}

#[test]
fn cache_keys_require_a_strong_source_identity() -> Result<(), Box<dyn Error>> {
    let (_, mut scope) = case_and_scope(b"4142", 23)?;
    *scope
        .get_mut("source_id")
        .ok_or("fixture source is missing")? = Value::String(String::from("not-a-sha256-id"));

    assert!(recovery_key(RecoveryCaseKind::Flow, &scope, &RecoveryOptions::default()).is_err());
    Ok(())
}

#[test]
fn recovery_rejects_a_valid_digest_outside_the_case_sources() -> Result<(), Box<dyn Error>> {
    let (mut case, mut scope) = case_and_scope(b"4142", 29)?;
    *scope
        .get_mut("source_id")
        .ok_or("fixture source is missing")? =
        json!(format!("sha256:{}", sha256(b"different source")));
    let options = RecoveryOptions::default();

    assert!(
        recover(
            &mut case,
            RecoveryCaseKind::Flow,
            &scope,
            &RecoveryContext {
                memory: None,
                cache: None,
                job: None,
                options: &options,
            },
        )
        .is_err()
    );
    Ok(())
}

fn open_cache(root: &std::path::Path) -> Result<Cache, Box<dyn Error>> {
    open_cache_with_limit(root, 16 * 1024 * 1024)
}

fn open_cache_with_limit(
    root: &std::path::Path,
    maximum_bytes: u64,
) -> Result<Cache, Box<dyn Error>> {
    Ok(Cache::open_at(
        root.join("cache"),
        root.join("state"),
        maximum_bytes,
    )?)
}

fn count_case_json_bytes(case: &Case) -> Result<u64, Box<dyn Error>> {
    struct ByteCounter(u64);

    impl std::io::Write for ByteCounter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(u64::try_from(bytes.len()).map_err(std::io::Error::other)?)
                .ok_or_else(|| std::io::Error::other("encoded Case byte count overflow"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut counter = ByteCounter(0);
    case.write_json(&mut counter)?;
    Ok(counter.0)
}

fn snapshot_graph_decoded_bytes(metadata: &Value) -> Result<u64, Box<dyn Error>> {
    metadata
        .get("case_snapshot_usage")
        .and_then(Value::as_object)
        .and_then(|usage| usage.get("graph_decoded_bytes"))
        .and_then(Value::as_u64)
        .ok_or_else(|| "snapshot graph usage was not recorded".into())
}

fn assert_snapshot_metadata(metadata: &Value) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        metadata.get("case_storage_format").and_then(Value::as_u64),
        Some(u64::from(super::CASE_SNAPSHOT_FORMAT))
    );
    let usage = metadata
        .get("case_snapshot_usage")
        .and_then(Value::as_object)
        .ok_or("snapshot usage details are missing")?;
    for field in ["graph_bytes", "graph_decoded_bytes", "blob_pack_bytes"] {
        assert!(usage.get(field).and_then(Value::as_u64).is_some());
    }
    Ok(())
}

fn assert_cases_equal(left: &Case, right: &Case) {
    assert_eq!(left.sources(), right.sources());
    assert_eq!(left.blobs(), right.blobs());
    assert_eq!(left.nodes(), right.nodes());
    assert_eq!(left.edges(), right.edges());
    assert_eq!(left.limitations(), right.limitations());
}

fn large_case_and_scope(edge_count: usize) -> Result<(Case, Value), Box<dyn Error>> {
    let (mut case, scope) = case_and_scope(b"4142", 101)?;
    let first = case.add_node("large_fixture_first", None, Vec::new(), json!({}))?;
    let second = case.add_node("large_fixture_second", None, Vec::new(), json!({}))?;
    let reason = "r".repeat(MAX_REASON_BYTES);
    for _ in 0..edge_count {
        case.add_edge(Edge {
            from: first,
            to: second,
            relation: String::from("fixture_relation"),
            status: EvidenceStatus::Observed,
            reason: reason.clone(),
        })?;
    }
    Ok((case, scope))
}

fn case_and_scope(bytes: &[u8], flow_id: u64) -> Result<(Case, Value), Box<dyn Error>> {
    let digest = sha256(bytes);
    let mut case = Case::new();
    let source_id = case.add_source(
        "capture.pcap",
        "capture",
        u64::try_from(bytes.len())?,
        &digest,
        None,
    )?;
    case.add_bytes_node(
        "imported_source",
        bytes,
        Vec::new(),
        json!({"source_id": source_id}),
    )?;
    let scope = json!({
        "kind": "flow",
        "source_id": source_id,
        "flow_id": flow_id,
    });
    Ok((case, scope))
}
