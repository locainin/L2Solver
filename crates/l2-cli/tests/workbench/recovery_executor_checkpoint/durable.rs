use super::*;
use crate::arguments::RecoveryOptions;
use crate::workbench::recovery_executor::{
    JobProgress, recover_case_with_job, resume::RecoveryResume,
};
use l2_workbench::job::{
    Counter, Job, MemoryBudget, MemoryClass,
    cache::{Cache, Lease, SourceIdentity, StageKey},
};
use serde_json::json;

#[test]
fn resume_without_attached_budget_shares_one_session_memory_limit() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let options = RecoveryOptions {
        memory_limit: 1024,
        ..RecoveryOptions::default()
    };
    let cache = Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        options.cache_max_bytes,
    )?;
    let key = StageKey::new(
        "shared_session_memory",
        1,
        "test",
        &json!({}),
        &SourceIdentity::from_sha256("f".repeat(64))?,
        &[],
    )?;
    let mut lease = cache.lease(&key)?;
    let resume = RecoveryResume::new(&mut lease, &options, None);
    let first = resume.session_memory();
    let second = resume.session_memory();
    let retained = first.try_reserve(MemoryClass::Executor, 800)?;
    assert!(second.try_reserve(MemoryClass::Executor, 300).is_err());
    drop(retained);
    assert!(second.try_reserve(MemoryClass::Executor, 300).is_ok());
    drop(resume);

    // An attached startup budget must remain the shared ledger for resumed work
    let attached = MemoryBudget::new(1024);
    let resume = RecoveryResume::new(&mut lease, &options, Some(&attached));
    let retained = attached.try_reserve(MemoryClass::Executor, 800)?;
    assert!(
        resume
            .session_memory()
            .try_reserve(MemoryClass::Executor, 300)
            .is_err()
    );
    drop(retained);
    assert!(
        resume
            .session_memory()
            .try_reserve(MemoryClass::Executor, 300)
            .is_ok()
    );
    Ok(())
}

#[test]
fn checkpoint_save_memory_denial_preserves_the_prior_generation() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let options = RecoveryOptions {
        memory_limit: 64 * 1024 * 1024,
        cache_max_bytes: 128 * 1024 * 1024,
        strict_cache: true,
        ..RecoveryOptions::default()
    };
    let key = StageKey::new(
        "checkpoint_metadata_memory",
        1,
        "checkpoint_metadata_memory",
        &json!({}),
        &SourceIdentity::from_sha256("e".repeat(64))?,
        &[],
    )?;
    let memory = MemoryBudget::new(16 * 1024 * 1024);
    let cache = Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        options.cache_max_bytes,
    )?;
    cache.attach_memory_budget(memory.clone())?;
    let mut case = Case::new();
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    let job = Job::with_memory_budget("checkpoint metadata memory", &memory);
    executor.job = Some(JobProgress::new(job.work_scope(key.as_str())?));
    let cursor = SchedulerCursor::default();
    let mut lease = cache.lease(&key)?;
    let mut resume = RecoveryResume::new(&mut lease, &options, Some(&memory));
    resume.prepare(executor.case)?;
    resume.save(&executor, &cursor)?;
    drop(resume);
    let limits = l2_workbench::job::cache::ExecutionCheckpointLimits {
        max_encoded_bytes: options.cache_max_bytes,
        max_executor_bytes: options.memory_limit / 8,
        max_metadata_bytes: 4 * 1024 * 1024,
    };
    let active = lease
        .load_active(limits)?
        .ok_or("missing prior checkpoint")?;
    let prior_metadata = active.metadata().clone();
    let prior_executor_bytes = active.executor_bytes();
    drop(active);

    let snapshot = memory.snapshot()?;
    let remaining = snapshot
        .limit_bytes
        .checked_sub(snapshot.used_bytes)
        .ok_or("invalid memory use")?;
    assert!(remaining > 1);
    let reservation = memory.try_reserve(MemoryClass::Executor, remaining - 1)?;
    let mut resume = RecoveryResume::new(&mut lease, &options, Some(&memory));
    resume.prepare(executor.case)?;
    let error = resume
        .save(&executor, &cursor)
        .err()
        .ok_or("checkpoint unexpectedly fit the exhausted budget")?;
    assert!(crate::memory_error::find(&error).is_some());
    drop(resume);
    drop(reservation);
    let active = lease
        .load_active(limits)?
        .ok_or("prior checkpoint was lost")?;
    assert_eq!(active.metadata(), &prior_metadata);
    assert_eq!(active.executor_bytes(), prior_executor_bytes);
    Ok(())
}

#[test]
fn invalid_executor_state_keeps_native_evidence_and_respects_strict_cache()
-> Result<(), Box<dyn Error>> {
    for legacy_format in [false, true] {
        for strict_cache in [false, true] {
            exercise_invalid_executor_state(legacy_format, strict_cache)?;
        }
    }
    Ok(())
}

fn exercise_invalid_executor_state(
    legacy_format: bool,
    strict_cache: bool,
) -> Result<(), Box<dyn Error>> {
    let options = RecoveryOptions {
        profile: RecoveryProfile::Fast,
        strict_cache,
        ..RecoveryOptions::default()
    };
    let key = StageKey::new(
        "invalid_executor_state",
        1,
        "test",
        &json!({}),
        &SourceIdentity::from_sha256("b".repeat(64))?,
        &[],
    )?;
    let temporary = tempfile::tempdir()?;
    let cache = Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        options.cache_max_bytes,
    )?;
    let mut native = Case::new();
    native.add_bytes_node("http_body", b"4142", Vec::new(), json!({}))?;
    let mut expected = native.try_clone()?;
    recover_case_with_job(
        &mut expected,
        options.profile,
        options.memory_limit,
        None,
        None,
        None,
    )?;
    let original = native.to_json()?;
    let mut poisoned = native.try_clone()?;
    poisoned.add_bytes_node(
        "invalid_checkpoint_extension",
        b"not recovered",
        Vec::new(),
        json!({}),
    )?;
    let saved_state = saved_executor_state(&native, &mut poisoned, &options, legacy_format)?;
    let job = Job::new("invalid checkpoint fallback");
    let scoped = job.work_scope(key.as_str())?;
    let mut lease = cache.lease(&key)?;
    save_invalid_generation(&mut lease, &poisoned, &options, &job, &scoped, &saved_state)?;
    let mut resume = RecoveryResume::new(&mut lease, &options, None);
    let result = recover_case_with_job(
        &mut native,
        options.profile,
        options.memory_limit,
        Some(&scoped),
        None,
        Some(&mut resume),
    );
    if strict_cache {
        assert!(result.is_err());
        assert_eq!(native.to_json()?, original);
        assert!(job.snapshot()?.cache_fallbacks.records().is_empty());
    } else {
        result?;
        assert_eq!(native.to_json()?, expected.to_json()?);
        let snapshot = job.snapshot()?;
        assert!(snapshot.cache_fallbacks.records().iter().any(|record| {
            record.stage() == l2_workbench::job::CacheStage::Checkpoint
                && record.kind() == l2_workbench::job::CacheFallbackKind::InvalidEntry
        }));
    }
    Ok(())
}

fn save_invalid_generation(
    lease: &mut Lease,
    poisoned: &Case,
    options: &RecoveryOptions,
    job: &Job,
    scoped: &Job,
    saved_state: &[u8],
) -> Result<(), Box<dyn Error>> {
    let limits = l2_workbench::job::cache::ExecutionCheckpointLimits {
        max_encoded_bytes: 1024 * 1024,
        max_executor_bytes: 1024 * 1024,
        max_metadata_bytes: 1024 * 1024,
    };
    lease.save_active(&job.checkpoint_snapshot()?, limits, |writer| {
        let (mut graph, mut blobs, state) = writer.streams();
        let usage = crate::case_snapshot::write_streams(
            &mut graph,
            &mut blobs,
            poisoned,
            CaseSnapshotLimits::new(options.cache_max_bytes, options.memory_limit / 4),
            None,
        )
        .map_err(|_| l2_workbench::job::cache::CacheError::CorruptCheckpoint)?;
        state.write_all(saved_state)?;
        let work = scoped
            .work_snapshot()
            .map_err(|_| l2_workbench::job::cache::CacheError::CorruptCheckpoint)?;
        Ok(json!({"version":1,"usage":usage,"work":work}))
    })?;
    Ok(())
}

fn saved_executor_state(
    native: &Case,
    poisoned: &mut Case,
    options: &RecoveryOptions,
    legacy_format: bool,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let saved_state = if legacy_format {
        // Start with a valid current snapshot and alter only its executor format
        let plan = RecoveryPlan {
            discover_transforms: true,
            discover_framing: true,
            discover_records: true,
            ..RecoveryPlan::default()
        };
        let policy =
            super::super::policy_for_profile(native, options.profile, options.memory_limit)?;
        let mut executor = test_support::build_executor(poisoned, &plan, &policy)?;
        executor.case_index = CaseIndex::with_ledger(CaseIndexScanLedger::new()?);
        let mut bytes = Vec::new();
        checkpoint::write(
            &executor,
            &SchedulerCursor::default(),
            &mut bytes,
            1024 * 1024,
        )?;
        drop(executor);
        let mut roundtrip_case = poisoned.try_clone()?;
        let (roundtrip, _) = checkpoint::read(
            &mut roundtrip_case,
            &plan,
            &policy,
            &bytes,
            1024 * 1024,
            None,
        )?;
        drop(roundtrip);
        let mut saved: serde_json::Value = serde_json::from_slice(&bytes)?;
        let version = saved.get_mut("version").ok_or("missing executor version")?;
        assert_eq!(*version, json!(2));
        *version = json!(1);
        serde_json::to_vec(&saved)?
    } else {
        b"{}".to_vec()
    };
    Ok(saved_state)
}

#[test]
fn default_recovery_resumes_a_durable_generation_without_repeating_committed_candidates()
-> Result<(), Box<dyn Error>> {
    let fixture = build_session_relative_fixture()?;
    let initial = fixture.case.try_clone()?;
    let options = RecoveryOptions {
        memory_limit: 64 * 1024 * 1024,
        cache_max_bytes: 128 * 1024 * 1024,
        strict_cache: true,
        ..RecoveryOptions::default()
    };
    let key = StageKey::new(
        "executor_resume_test",
        1,
        "executor_resume_test",
        &json!({"profile":"normal"}),
        &SourceIdentity::from_sha256("a".repeat(64))?,
        &[],
    )?;
    let temporary = tempfile::tempdir()?;
    let cache = Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        options.cache_max_bytes,
    )?;

    let mut uninterrupted = initial.try_clone()?;
    let expected_job = Job::new("uninterrupted recovery");
    let expected = recover_case_with_job(
        &mut uninterrupted,
        options.profile,
        options.memory_limit,
        Some(&expected_job),
        None,
        None,
    )?;
    assert!(
        uninterrupted
            .blobs()
            .iter()
            .any(|blob| blob.bytes == fixture.plaintext)
    );

    let committed_candidates =
        save_pending_assembly_generation(fixture.case, &options, &key, &cache)?;

    // A new invocation starts with the native Case and restores its committed extension
    let mut resumed = initial;
    let resumed_job = Job::new("second recovery process");
    let resumed_scope = resumed_job.work_scope(key.as_str())?;
    let mut lease = cache.lease(&key)?;
    let mut resume = RecoveryResume::new(&mut lease, &options, None);
    let actual = recover_case_with_job(
        &mut resumed,
        options.profile,
        options.memory_limit,
        Some(&resumed_scope),
        None,
        Some(&mut resume),
    )?;

    assert_eq!(resumed.to_json()?, uninterrupted.to_json()?);
    assert_eq!(actual.omissions, expected.omissions);
    assert_eq!(actual.resources, expected.resources);
    assert_eq!(
        actual.validated_artifact_count,
        expected.validated_artifact_count
    );
    assert_eq!(actual.candidate_count, expected.candidate_count);
    let restored_work = resumed_scope.work_snapshot()?;
    assert_eq!(
        Some(restored_work.counter(Counter::CandidatesExamined)),
        expected_job
            .snapshot()?
            .counters
            .get(&Counter::CandidatesExamined)
            .copied(),
    );
    assert_eq!(restored_work.counter(Counter::CacheHits), 1);
    assert!(restored_work.counter(Counter::CandidatesExamined) > committed_candidates);
    Ok(())
}

fn save_pending_assembly_generation(
    case: Case,
    options: &RecoveryOptions,
    key: &StageKey,
    cache: &Cache,
) -> Result<u64, Box<dyn Error>> {
    let plan = RecoveryPlan {
        discover_transforms: true,
        discover_framing: true,
        discover_records: true,
        ..RecoveryPlan::default()
    };
    let mut interrupted = case;
    let policy = super::super::policy::policy_for_profile(
        &interrupted,
        options.profile,
        options.memory_limit,
    )?;
    let first_job = Job::new("first recovery process");
    let first_scope = first_job.work_scope(key.as_str())?;
    let mut lease = cache.lease(key)?;
    let mut resume = RecoveryResume::new(&mut lease, options, None);
    resume.prepare(&interrupted)?;
    let mut executor = test_support::build_executor(&mut interrupted, &plan, &policy)?;
    executor.case_index = CaseIndex::with_ledger(CaseIndexScanLedger::new()?);
    executor.job = Some(JobProgress::new(first_scope.clone()));
    let mut cursor = SchedulerCursor::default();
    for _ in 0..20_000 {
        assert!(
            step(&mut executor, &mut cursor)?,
            "no pending assembly was reached"
        );
        if executor.pending_record_assembly_count > 0 {
            break;
        }
    }
    assert!(executor.pending_record_assembly_count > 0);
    let committed_candidates = first_scope
        .work_snapshot()?
        .counter(Counter::CandidatesExamined);
    assert!(committed_candidates > 0);
    resume.save(&executor, &cursor)?;
    Ok(committed_candidates)
}
