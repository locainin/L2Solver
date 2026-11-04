use super::*;
use crate::arguments::RecoveryOptions;
use crate::workbench::recovery_executor::{
    JobProgress, RecoveryExecutionError, RecoveryExecutionPolicy, recover_case_with_job,
    resume::RecoveryResume,
};
use l2_workbench::job::{
    Counter, Job, MemoryBudget, MemoryClass,
    cache::{
        Cache, ExecutionCheckpointLimits, ExecutionGeneration, Lease, SourceIdentity, StageKey,
    },
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
fn budgetless_resume_charges_the_native_case_and_cache_to_one_session() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let options = RecoveryOptions {
        memory_limit: 8 * 1024 * 1024,
        ..RecoveryOptions::default()
    };
    let cache = Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        options.cache_max_bytes,
    )?;
    let key = StageKey::new(
        "budgetless_resume",
        1,
        "budgetless_resume",
        &json!({}),
        &SourceIdentity::from_sha256("c".repeat(64))?,
        &[],
    )?;
    let mut native = Case::new();
    native.add_bytes_node("native", b"native evidence", Vec::new(), json!({}))?;
    let mut lease = cache.lease(&key)?;
    let mut resume = RecoveryResume::new(&mut lease, &options, None);
    resume.prepare(&mut native)?;
    let memory = resume.session_memory();
    let charged = native
        .charged_memory_bytes()
        .ok_or("native Case was not admitted")?;
    assert!(charged > 0);
    assert_eq!(memory.snapshot()?.used(MemoryClass::Case), charged);
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&native)?;
    let executor = test_support::build_executor(&mut native, &plan, &policy)?;
    let available = memory.snapshot()?.limit_bytes - memory.snapshot()?.used_bytes;
    let held = memory.try_reserve(MemoryClass::Executor, available - 1)?;
    let error = resume
        .save(&executor, &SchedulerCursor::default())
        .err()
        .ok_or("unbudgeted cache write unexpectedly succeeded")?;
    assert!(matches!(
        crate::memory_error::find(&error),
        Some(l2_workbench::job::MemoryError::Limit { .. })
    ));
    drop(held);
    Ok(())
}

#[test]
fn budgetless_resume_reuses_a_native_cases_existing_ledger() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let options = RecoveryOptions {
        memory_limit: 8 * 1024 * 1024,
        ..RecoveryOptions::default()
    };
    let cache = Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        options.cache_max_bytes,
    )?;
    let key = StageKey::new(
        "existing_session_memory",
        1,
        "existing_session_memory",
        &json!({}),
        &SourceIdentity::from_sha256("d".repeat(64))?,
        &[],
    )?;
    let mut case = Case::new();
    case.add_bytes_node("native", b"evidence", Vec::new(), json!({}))?;
    let original_budget = {
        let mut lease = cache.lease(&key)?;
        let mut resume = RecoveryResume::new(&mut lease, &options, None);
        resume.prepare(&mut case)?;
        resume.session_memory()
    };
    let mut lease = cache.lease(&key)?;
    let mut resume = RecoveryResume::new(&mut lease, &options, None);
    resume.prepare(&mut case)?;
    assert!(resume.session_memory().same_ledger(&original_budget));
    assert!(case.charged_memory_bytes().unwrap_or_default() > 0);
    drop(resume);
    drop(lease);

    // A cache that already owns a ledger supplies it to an uncharged native Case
    let attached = MemoryBudget::new(options.memory_limit);
    let attached_cache = Cache::open_at_with_memory_budget(
        temporary.path().join("attached-cache"),
        temporary.path().join("attached-state"),
        options.cache_max_bytes,
        attached.clone(),
    )?;
    let mut native = Case::new();
    let mut lease = attached_cache.lease(&key)?;
    let mut resume = RecoveryResume::new(&mut lease, &options, None);
    resume.prepare(&mut native)?;
    assert!(resume.session_memory().same_ledger(&attached));
    Ok(())
}

#[test]
fn resume_rejects_a_supplied_ledger_larger_than_the_declared_policy() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let options = RecoveryOptions {
        memory_limit: 8 * 1024 * 1024,
        ..RecoveryOptions::default()
    };
    let cache = Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        options.cache_max_bytes,
    )?;
    let key = StageKey::new(
        "oversized_session_memory",
        1,
        "oversized_session_memory",
        &json!({}),
        &SourceIdentity::from_sha256("f".repeat(64))?,
        &[],
    )?;
    let memory = MemoryBudget::new(16 * 1024 * 1024);
    let mut case = Case::new();
    let mut lease = cache.lease(&key)?;
    let mut resume = RecoveryResume::new(&mut lease, &options, Some(&memory));
    let error = resume
        .prepare(&mut case)
        .err()
        .ok_or("oversized ledger accepted")?;
    assert!(matches!(
        crate::memory_error::find(&error),
        Some(l2_workbench::job::MemoryError::IncompatibleWorkingSet)
    ));
    assert_eq!(case.charged_memory_bytes(), None);
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
    let limits = checkpoint_limits(&options);
    let active = lease
        .load_active(limits)?
        .ok_or("missing prior checkpoint")?;
    let prior_metadata = active.metadata().clone();
    let prior_executor_bytes = active.executor_bytes();
    let prior_generation = active.generation().clone();
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
    drop(active);
    assert_checkpoint_generation_restores(
        &mut lease,
        &options,
        &memory,
        &prior_generation,
        limits,
        &plan,
        &policy,
    )?;
    Ok(())
}

#[test]
fn cancelled_checkpoint_save_keeps_the_previous_durable_generation() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let options = RecoveryOptions {
        memory_limit: 64 * 1024 * 1024,
        cache_max_bytes: 128 * 1024 * 1024,
        strict_cache: true,
        ..RecoveryOptions::default()
    };
    let memory = MemoryBudget::new(options.memory_limit);
    let cache = Cache::open_at_with_memory_budget(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        options.cache_max_bytes,
        memory.clone(),
    )?;
    let key = StageKey::new(
        "cancelled_checkpoint_save",
        1,
        "cancelled_checkpoint_save",
        &json!({}),
        &SourceIdentity::from_sha256("e".repeat(64))?,
        &[],
    )?;
    let mut case = Case::with_memory_budget(&memory)?;
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let job = Job::with_memory_budget("cancelled checkpoint", &memory);
    let mut lease = cache.lease(&key)?;
    let mut resume = RecoveryResume::new(&mut lease, &options, Some(&memory));
    resume.prepare(&mut case)?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    executor.memory = Some(memory.clone());
    executor.job = Some(JobProgress::new(job.work_scope(key.as_str())?));
    resume.save(&executor, &SchedulerCursor::default())?;
    drop(resume);
    let prior = lease
        .load_active(checkpoint_limits(&options))?
        .ok_or("checkpoint missing")?
        .generation()
        .clone();
    let mut resume = RecoveryResume::new(&mut lease, &options, Some(&memory));
    resume.prepare(executor.case)?;
    resume.cancel_after_next_case_snapshot();
    assert!(matches!(
        resume.save(&executor, &SchedulerCursor::default()),
        Err(RecoveryExecutionError::Job(
            l2_workbench::job::JobError::Cancelled
        ))
    ));
    drop(resume);
    assert_eq!(
        lease
            .load_active(checkpoint_limits(&options))?
            .ok_or("generation disappeared")?
            .generation(),
        &prior
    );
    Ok(())
}

#[test]
fn oversized_case_checkpoint_preserves_the_prior_generation_and_cache_policy()
-> Result<(), Box<dyn Error>> {
    for strict in [true, false] {
        exercise_oversized_case_checkpoint(strict, 16 * 1024 * 1024 + 1)?;
    }
    Ok(())
}

#[test]
fn historical_case_checkpoint_restores_with_native_case_and_shared_memory()
-> Result<(), Box<dyn Error>> {
    exercise_historical_case_checkpoint(64 * 1024 * 1024)
}

#[test]
fn historical_case_checkpoint_restores_with_128_mib_shared_memory() -> Result<(), Box<dyn Error>> {
    exercise_historical_case_checkpoint(128 * 1024 * 1024)
}

#[test]
fn historical_case_checkpoint_restores_with_512_mib_shared_memory() -> Result<(), Box<dyn Error>> {
    exercise_historical_case_checkpoint(512 * 1024 * 1024)
}

fn exercise_historical_case_checkpoint(memory_limit: u64) -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let options = RecoveryOptions {
        memory_limit,
        cache_max_bytes: 128 * 1024 * 1024,
        strict_cache: true,
        ..RecoveryOptions::default()
    };
    let memory = MemoryBudget::new(options.memory_limit);
    let worker = memory.try_working_set(options.memory_limit / 2)?;
    let cache = Cache::open_at_with_memory_budget(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        options.cache_max_bytes,
        memory.clone(),
    )?
    .with_memory_scope(worker.budget())?;
    let key = StageKey::new(
        "historical_case_checkpoint",
        1,
        "historical_case_checkpoint",
        &json!({}),
        &SourceIdentity::from_sha256("b".repeat(64))?,
        &[],
    )?;
    let mut native = Case::with_memory_budget(worker.budget())?;
    let native_bytes = vec![0x31; 8 * 1024 * 1024];
    native.add_bytes_node("native", &native_bytes, Vec::new(), json!({}))?;
    drop(native_bytes);
    let mut recovered = native.try_clone()?;
    let growth = vec![0x52; 31_311_328 - 8 * 1024 * 1024];
    recovered.add_bytes_node("recovered", &growth, Vec::new(), json!({}))?;
    drop(growth);
    assert_eq!(recovered.resource_usage().blob_bytes, 31_311_328);
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&native)?;
    let mut executor = test_support::build_executor(&mut recovered, &plan, &policy)?;
    executor.memory = Some(worker.budget().clone());
    let mut lease = cache.lease(&key)?;
    let mut resume = RecoveryResume::new(&mut lease, &options, Some(worker.budget()));
    resume.prepare(&mut native)?;
    let mut cursor = SchedulerCursor::default();
    cursor.phase = super::super::execution_state::SchedulerPhase::Running;
    resume.save(&executor, &cursor)?;
    drop(executor);
    drop(recovered);

    let native_charge = native
        .charged_memory_bytes()
        .ok_or("native Case uncharged")?;
    let mut loaded = resume.load()?.ok_or("checkpoint missing")?;
    assert_eq!(loaded.case.resource_usage().blob_bytes, 31_311_328);
    assert!(native.checkpoint_prefix()?.matches(&loaded.case)?);
    assert!(memory.snapshot()?.used(MemoryClass::Case) > native_charge);
    let (restored, cursor) = checkpoint::read(
        &mut loaded.case,
        &plan,
        &policy,
        &loaded.state,
        resume.executor_limit(),
        Some(worker.budget()),
    )?;
    cursor.validate(&restored)?;
    assert!(memory.snapshot()?.peak_bytes <= options.memory_limit);
    drop(restored);
    Ok(())
}

#[test]
fn checkpoint_restore_refuses_when_native_and_restored_cases_exceed_the_shared_limit()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let options = RecoveryOptions {
        memory_limit: 64 * 1024 * 1024,
        cache_max_bytes: 128 * 1024 * 1024,
        strict_cache: true,
        ..RecoveryOptions::default()
    };
    let memory = MemoryBudget::new(options.memory_limit);
    let worker = memory.try_working_set(options.memory_limit / 2)?;
    let cache = Cache::open_at_with_memory_budget(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        options.cache_max_bytes,
        memory,
    )?
    .with_memory_scope(worker.budget())?;
    let key = StageKey::new(
        "restore_case_memory_denial",
        1,
        "restore_case_memory_denial",
        &json!({}),
        &SourceIdentity::from_sha256("a".repeat(64))?,
        &[],
    )?;
    let mut native = Case::with_memory_budget(worker.budget())?;
    let bytes = vec![0x73; 34 * 1024 * 1024];
    native.add_bytes_node("native", &bytes, Vec::new(), json!({}))?;
    drop(bytes);
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&native)?;
    let mut lease = cache.lease(&key)?;
    let mut resume = RecoveryResume::new(&mut lease, &options, Some(worker.budget()));
    resume.prepare(&mut native)?;
    let mut executor = test_support::build_executor(&mut native, &plan, &policy)?;
    executor.memory = Some(worker.budget().clone());
    let mut cursor = SchedulerCursor::default();
    cursor.phase = super::super::execution_state::SchedulerPhase::Running;
    resume.save(&executor, &cursor)?;
    drop(executor);
    drop(resume);
    let prior = lease
        .load_active(checkpoint_limits(&options))?
        .ok_or("saved generation missing")?
        .generation()
        .clone();
    assert_restore_limit_denied(&mut lease, &options, worker.budget(), &mut native)?;
    drop(native);
    let mut empty = Case::with_memory_budget(worker.budget())?;
    let mut resume = RecoveryResume::new(&mut lease, &options, Some(worker.budget()));
    resume.prepare(&mut empty)?;
    let mut loaded = resume.load()?.ok_or("durable generation did not restore")?;
    assert_eq!(loaded.case.resource_usage().blob_bytes, 34 * 1024 * 1024);
    let (executor, cursor) = checkpoint::read(
        &mut loaded.case,
        &plan,
        &policy,
        &loaded.state,
        resume.executor_limit(),
        Some(worker.budget()),
    )?;
    cursor.validate(&executor)?;
    drop(executor);
    drop(loaded);
    drop(resume);
    assert_eq!(
        lease
            .load_active(checkpoint_limits(&options))?
            .ok_or("generation disappeared")?
            .generation(),
        &prior
    );
    Ok(())
}

fn assert_restore_limit_denied(
    lease: &mut Lease,
    options: &RecoveryOptions,
    memory: &MemoryBudget,
    native: &mut Case,
) -> Result<(), Box<dyn Error>> {
    for strict in [true, false] {
        let mut configured = options.clone();
        configured.strict_cache = strict;
        let mut resume = RecoveryResume::new(lease, &configured, Some(memory));
        resume.prepare(native)?;
        let error = resume
            .load()
            .err()
            .ok_or("restoration exceeded the live budget")?;
        let error = resume
            .invalid(error, None)
            .err()
            .ok_or("memory denial was treated as an optional cache failure")?;
        assert!(matches!(
            crate::memory_error::find(&error),
            Some(l2_workbench::job::MemoryError::Limit { limit, .. })
                if limit == options.memory_limit
        ));
        native.validate()?;
        assert_eq!(native.resource_usage().blob_bytes, 34 * 1024 * 1024);
        assert!(memory.snapshot()?.peak_bytes <= options.memory_limit);
    }
    Ok(())
}

fn exercise_oversized_case_checkpoint(
    strict: bool,
    blob_bytes: usize,
) -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let options = RecoveryOptions {
        memory_limit: 64 * 1024 * 1024,
        cache_max_bytes: 16 * 1024 * 1024,
        strict_cache: strict,
        ..RecoveryOptions::default()
    };
    let memory = MemoryBudget::new(options.memory_limit);
    let worker = memory.try_working_set(options.memory_limit / 2)?;
    let cache = Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        options.cache_max_bytes,
    )?;
    cache.attach_memory_budget(memory.clone())?;
    let cache = cache.with_memory_scope(worker.budget())?;
    let key = StageKey::new(
        "oversized_case_checkpoint",
        1,
        "oversized_case_checkpoint",
        &json!({}),
        &SourceIdentity::from_sha256("d".repeat(64))?,
        &[],
    )?;
    let mut case = Case::new();
    case.use_working_set(&worker)?;
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    let job = Job::with_memory_budget("oversized Case checkpoint", worker.budget());
    executor.job = Some(JobProgress::new(job.work_scope(key.as_str())?));
    let cursor = SchedulerCursor::default();
    let mut lease = cache.lease(&key)?;

    // Save and restore a valid generation before the retained Case grows
    let mut resume = RecoveryResume::new(&mut lease, &options, Some(worker.budget()));
    resume.prepare(executor.case)?;
    resume.save(&executor, &cursor)?;
    drop(resume);
    let limits = checkpoint_limits(&options);
    let active = lease
        .load_active(limits)?
        .ok_or("missing prior checkpoint")?;
    let prior = active.generation().clone();
    drop(active);

    let mut resume = RecoveryResume::new(&mut lease, &options, Some(worker.budget()));
    resume.prepare(executor.case)?;
    let loaded = resume.load()?.ok_or("checkpoint did not restore")?;
    assert_eq!(loaded.case.resource_usage().blob_bytes, 0);
    drop(loaded);

    // The disk quota is independent of the live-memory allowance
    let maximum = usize::try_from(options.cache_max_bytes)?;
    let bytes = vec![0x5a; blob_bytes];
    executor
        .case
        .add_bytes_node("checkpoint_growth", &bytes, Vec::new(), json!({}))?;
    drop(bytes);
    assert_eq!(executor.case.resource_usage().blob_bytes, blob_bytes);
    let result = resume.save_or_fallback(&executor, &cursor);
    assert_oversized_checkpoint_policy(result, strict, blob_bytes, maximum, &resume, &job)?;
    drop(resume);

    assert_checkpoint_generation_restores(
        &mut lease,
        &options,
        worker.budget(),
        &prior,
        limits,
        &plan,
        &policy,
    )?;
    assert!(memory.snapshot()?.peak_bytes <= options.memory_limit);
    Ok(())
}

fn assert_oversized_checkpoint_policy(
    result: Result<(), RecoveryExecutionError>,
    strict: bool,
    blob_bytes: usize,
    maximum: usize,
    resume: &RecoveryResume<'_>,
    job: &Job,
) -> Result<(), Box<dyn Error>> {
    use l2_workbench::{
        evidence::EvidenceError,
        job::{CacheFallbackKind, CacheStage},
    };

    if strict {
        let error = result
            .err()
            .ok_or("strict checkpoint unexpectedly succeeded")?;
        assert!(matches!(
            error.source().and_then(|cause| cause.downcast_ref::<EvidenceError>()),
            Some(EvidenceError::CaseTooLarge { length, maximum: limit })
                if *length == blob_bytes && *limit == maximum
        ));
    } else {
        result?;
        assert!(!resume.due());
        assert!(
            job.snapshot()?
                .cache_fallbacks
                .records()
                .iter()
                .any(|record| {
                    record.stage() == CacheStage::Checkpoint
                        && record.kind() == CacheFallbackKind::CommitFailed
                })
        );
    }
    Ok(())
}

fn checkpoint_limits(options: &RecoveryOptions) -> ExecutionCheckpointLimits {
    ExecutionCheckpointLimits {
        max_encoded_bytes: options.cache_max_bytes,
        max_executor_bytes: options.memory_limit / 8,
        max_metadata_bytes: 4 * 1024 * 1024,
    }
}

fn assert_checkpoint_generation_restores(
    lease: &mut Lease,
    options: &RecoveryOptions,
    memory: &MemoryBudget,
    prior: &ExecutionGeneration,
    limits: ExecutionCheckpointLimits,
    plan: &RecoveryPlan,
    policy: &RecoveryExecutionPolicy,
) -> Result<(), Box<dyn Error>> {
    // A failed save must leave the old Case and executor cursor usable
    let active = lease
        .load_active(limits)?
        .ok_or("prior checkpoint was lost")?;
    assert_eq!(active.generation(), prior);
    drop(active);
    let mut original = Case::new();
    let mut restored = RecoveryResume::new(lease, options, Some(memory));
    restored.prepare(&mut original)?;
    let mut prior_case = restored.load()?.ok_or("prior checkpoint did not restore")?;
    let (prior_executor, prior_cursor) = checkpoint::read(
        &mut prior_case.case,
        plan,
        policy,
        prior_case.state.as_slice(),
        usize::try_from(options.memory_limit / 8)?,
        Some(memory),
    )?;
    prior_cursor.validate(&prior_executor)?;
    drop(prior_executor);
    assert_eq!(prior_case.case, original);
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
        assert_eq!(job.snapshot()?.cache_fallbacks.records().len(), 0);
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
        let (graph, blobs, state) = writer.streams();
        let usage = crate::case_snapshot::with_cancellation(None, |cancellation| {
            crate::case_snapshot::write_streams(
                graph,
                blobs,
                poisoned,
                CaseSnapshotLimits::new(options.cache_max_bytes, options.memory_limit),
                None,
                cancellation,
            )
        })
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
fn relational_fixture_refuses_when_the_real_budget_is_64_mib() -> Result<(), Box<dyn Error>> {
    let mut fixture = build_session_relative_fixture()?;
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    fixture.case.admit_memory_budget(&memory)?;
    let prefix = fixture.case.checkpoint_prefix()?;
    let job = Job::with_memory_budget("bounded relational recovery", &memory);
    let error = recover_case_with_job(
        &mut fixture.case,
        RecoveryProfile::Normal,
        64 * 1024 * 1024,
        Some(&job),
        Some(&memory),
        None,
    )
    .err()
    .ok_or("the historical fixture unexpectedly fit the real 64 MiB ledger")?;
    assert!(matches!(
        crate::memory_error::find(&error),
        Some(l2_workbench::job::MemoryError::Limit { limit, .. })
            if limit == 64 * 1024 * 1024
    ));
    assert!(prefix.matches(&fixture.case)?);
    fixture.case.validate()?;
    assert!(memory.snapshot()?.peak_bytes <= 64 * 1024 * 1024);
    Ok(())
}

#[test]
fn bounded_relational_recovery_resumes_without_repeating_committed_candidates()
-> Result<(), Box<dyn Error>> {
    let fixture = build_session_relative_fixture()?;
    let initial = fixture.case.try_clone()?;
    let options = RecoveryOptions {
        memory_limit: 256 * 1024 * 1024,
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
    let expected_memory = MemoryBudget::new(options.memory_limit);
    uninterrupted.admit_memory_budget(&expected_memory)?;
    let expected_job = Job::with_memory_budget("uninterrupted recovery", &expected_memory);
    let plan = bounded_relational_plan();
    // Run the historical input with a finite plan and a matching live ledger
    let work_policy = super::super::policy::policy_for_profile(
        &uninterrupted,
        options.profile,
        options.memory_limit,
    )?;
    let expected_progress = JobProgress::new(expected_job.clone());
    let expected = super::super::execute_internal(
        &mut uninterrupted,
        &plan,
        &work_policy,
        false,
        Some(&expected_progress),
        Some(&expected_memory),
        None,
    )?;
    assert!(
        uninterrupted
            .nodes()
            .iter()
            .any(|node| node.kind == "decoding_output")
    );

    let committed_candidates =
        save_relational_witness_generation(fixture.case, &options, &key, &cache)?;

    // A new invocation starts with the native Case and restores its committed extension
    let mut resumed = initial;
    let resumed_memory = MemoryBudget::new(options.memory_limit);
    resumed.admit_memory_budget(&resumed_memory)?;
    let resumed_job = Job::with_memory_budget("second recovery process", &resumed_memory);
    let resumed_scope = resumed_job.work_scope(key.as_str())?;
    let resumed_policy =
        super::super::policy::policy_for_profile(&resumed, options.profile, options.memory_limit)?;
    let resumed_progress = JobProgress::new(resumed_scope.clone());
    let mut lease = cache.lease(&key)?;
    let mut resume = RecoveryResume::new(&mut lease, &options, Some(&resumed_memory));
    let actual = super::super::execute_internal(
        &mut resumed,
        &plan,
        &resumed_policy,
        false,
        Some(&resumed_progress),
        Some(&resumed_memory),
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
    assert_resumed_work(&expected_job, &resumed_scope, committed_candidates)?;
    Ok(())
}

fn assert_resumed_work(
    expected_job: &Job,
    resumed_scope: &Job,
    committed_candidates: u64,
) -> Result<(), Box<dyn Error>> {
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

fn bounded_relational_plan() -> RecoveryPlan {
    use l2_workbench::derivation::{Operation, Recipe};
    RecoveryPlan {
        recipes: vec![Recipe {
            steps: vec![Operation::Reverse {}],
            constraints: Vec::new(),
        }],
        ..RecoveryPlan::default()
    }
}

fn save_relational_witness_generation(
    case: Case,
    options: &RecoveryOptions,
    key: &StageKey,
    cache: &Cache,
) -> Result<u64, Box<dyn Error>> {
    let plan = bounded_relational_plan();
    let mut interrupted = case;
    let policy = super::super::policy::policy_for_profile(
        &interrupted,
        options.profile,
        options.memory_limit,
    )?;
    let mut lease = cache.lease(key)?;
    let mut resume = RecoveryResume::new(&mut lease, options, None);
    resume.prepare(&mut interrupted)?;
    let memory = resume.session_memory();
    let first_job = Job::with_memory_budget("first recovery process", &memory);
    let first_scope = first_job.work_scope(key.as_str())?;
    let policy = super::super::policy::resolve_policy(policy)?;
    let progress = JobProgress::new(first_scope.clone());
    let mut executor = super::super::new_executor(
        &mut interrupted,
        &plan,
        policy,
        false,
        Some(&progress),
        Some(&memory),
    )?;
    let mut cursor = SchedulerCursor::default();
    for _ in 0..1_000 {
        assert!(
            step(&mut executor, &mut cursor)?,
            "no committed transform witness was reached"
        );
        if executor
            .case
            .nodes()
            .iter()
            .any(|node| node.kind == "decoding_output")
        {
            break;
        }
    }
    assert!(
        executor
            .case
            .nodes()
            .iter()
            .any(|node| node.kind == "decoding_output")
    );
    let committed_candidates = first_scope
        .work_snapshot()?
        .counter(Counter::CandidatesExamined);
    assert!(committed_candidates > 0);
    resume.save(&executor, &cursor)?;
    Ok(committed_candidates)
}
