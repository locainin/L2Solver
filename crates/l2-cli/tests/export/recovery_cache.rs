use super::{RecoveryCaseKind, RecoveryContext, recover, recovery_key};
use crate::arguments::{ProgressMode, RecoveryOptions, RecoveryProfile};
use l2_workbench::{
    evidence::Case,
    job::{
        Counter, Job,
        cache::{Cache, CacheReadPolicy, StageStatus},
    },
    sha256,
};
use serde_json::{Value, json};
use std::{error::Error, fs};

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
            cache: Some(&cache),
            job: None,
            options: &options,
        },
    )?;
    let expected_case = first_case.to_json()?;

    let job = Job::new("cached flow recovery");
    job.increment(Counter::CandidatesExamined, 7)?;
    let (mut second_case, second_scope) = case_and_scope(b"4142", 7)?;
    let second = recover(
        &mut second_case,
        RecoveryCaseKind::Flow,
        &second_scope,
        &RecoveryContext {
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
    assert_eq!(cache.stats()?.entries, 1);
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

    let mut presentation_change = normal.clone();
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
fn corrupt_cached_case_is_rejected_in_strict_mode_and_recomputed_otherwise()
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
            cache: Some(&cache),
            job: None,
            options: &options,
        },
    )?;

    let key = recovery_key(RecoveryCaseKind::Flow, &scope, &options)?;
    let lease = cache.lease(&key)?;
    fs::write(
        lease.directory().join("case.json"),
        b"not a valid cached Case",
    )?;
    let metadata = serde_json::to_value(super::RecoveryMetadataRef {
        coverage: &first.coverage,
        omissions: &first.omissions,
    })?;
    let status = if first.coverage.is_complete() {
        StageStatus::Complete
    } else {
        StageStatus::Partial
    };
    drop(lease.commit(status, metadata)?);

    let mut strict = options.clone();
    strict.strict_cache = true;
    let (mut strict_case, strict_scope) = case_and_scope(b"4142", 19)?;
    assert!(
        recover(
            &mut strict_case,
            RecoveryCaseKind::Flow,
            &strict_scope,
            &RecoveryContext {
                cache: Some(&cache),
                job: None,
                options: &strict,
            },
        )
        .is_err()
    );

    let job = Job::new("repair corrupt cache entry");
    let (mut fresh_case, fresh_scope) = case_and_scope(b"4142", 19)?;
    let recomputed = recover(
        &mut fresh_case,
        RecoveryCaseKind::Flow,
        &fresh_scope,
        &RecoveryContext {
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
    assert_eq!(cache.stats()?.entries, 1);
    assert!(cache.lookup(&key, CacheReadPolicy::AllowPartial)?.is_some());
    Ok(())
}

#[test]
fn cache_keys_require_a_strong_source_identity() -> Result<(), Box<dyn Error>> {
    let (_, mut scope) = case_and_scope(b"4142", 23)?;
    scope["source_id"] = Value::String(String::from("not-a-sha256-id"));

    assert!(recovery_key(RecoveryCaseKind::Flow, &scope, &RecoveryOptions::default()).is_err());
    Ok(())
}

#[test]
fn recovery_rejects_a_valid_digest_outside_the_case_sources() -> Result<(), Box<dyn Error>> {
    let (mut case, mut scope) = case_and_scope(b"4142", 29)?;
    scope["source_id"] = json!(format!("sha256:{}", sha256(b"different source")));
    let options = RecoveryOptions::default();

    assert!(
        recover(
            &mut case,
            RecoveryCaseKind::Flow,
            &scope,
            &RecoveryContext {
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
    Ok(Cache::open_at(
        root.join("cache"),
        root.join("state"),
        16 * 1024 * 1024,
    )?)
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
        json!({"source_id": source_id.clone()}),
    )?;
    let scope = json!({
        "kind": "flow",
        "source_id": source_id,
        "flow_id": flow_id,
    });
    Ok((case, scope))
}
