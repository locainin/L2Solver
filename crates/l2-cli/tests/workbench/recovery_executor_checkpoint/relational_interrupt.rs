use super::*;
use crate::arguments::RecoveryOptions;
use crate::workbench::recovery_executor::{
    JobProgress, RecoveryExecutionError, RecoveryExecutionOutcome, RecoveryPlan,
    recover_case_with_job,
    resume::{RecoveryResume, TestCheckpointPart},
};
use l2_workbench::job::{
    Counter, Job, JobError, MemoryBudget, MemoryWorkingSet,
    cache::{Cache, SourceIdentity, StageKey},
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::process::ExitStatusExt,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const CHILD_ROOT: &str = "L2_TEST_RELATIONAL_RESUME_CRASH_ROOT";
const CHILD_INTERRUPT: &str = "L2_TEST_RELATIONAL_RESUME_INTERRUPT";
const CHILD_TEST: &str = "workbench::recovery_executor::checkpoint_tests::relational_interrupt::relational_checkpoint_crash_child";
const AGGREGATE_MEMORY: u64 = 512 * 1024 * 1024;
const WORKER_MEMORY: u64 = 128 * 1024 * 1024;
const WORK_POLICY_MEMORY: u64 = 64 * 1024 * 1024;

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn options() -> RecoveryOptions {
    RecoveryOptions {
        memory_limit: AGGREGATE_MEMORY,
        cache_max_bytes: 128 * 1024 * 1024,
        strict_cache: true,
        ..RecoveryOptions::default()
    }
}

fn recover_bounded(
    case: &mut Case,
    profile: RecoveryProfile,
    job: Option<&Job>,
    memory: Option<&MemoryBudget>,
    resume: Option<&mut RecoveryResume<'_>>,
) -> Result<RecoveryExecutionOutcome, RecoveryExecutionError> {
    let policy = super::super::policy::policy_for_profile(case, profile, WORK_POLICY_MEMORY)?;
    let plan = RecoveryPlan {
        discover_transforms: true,
        discover_framing: true,
        discover_records: true,
        ..RecoveryPlan::default()
    };
    let progress = job.cloned().map(JobProgress::new);
    super::super::execute_internal(
        case,
        &plan,
        &policy,
        false,
        progress.as_ref(),
        memory,
        resume,
    )
}

fn stage_key() -> Result<StageKey, Box<dyn Error>> {
    Ok(StageKey::new(
        "relational_cursor_crash",
        1,
        "relational_cursor_crash",
        &json!({"profile":"normal"}),
        &SourceIdentity::from_sha256("c".repeat(64))?,
        &[],
    )?)
}

fn cache(
    root: &Path,
    options: &RecoveryOptions,
    memory: &MemoryBudget,
) -> Result<Cache, Box<dyn Error>> {
    let cache = Cache::open_at(
        root.join("cache"),
        root.join("state"),
        options.cache_max_bytes,
    )?;
    cache.attach_memory_budget(memory.clone())?;
    Ok(cache)
}

fn admit_case(case: &mut Case, memory: &MemoryBudget) -> Result<MemoryWorkingSet, Box<dyn Error>> {
    let worker = memory.try_working_set(WORKER_MEMORY)?;
    case.use_working_set(&worker)?;
    Ok(worker)
}

#[test]
fn relational_checkpoint_crash_child() -> Result<(), Box<dyn Error>> {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return Ok(());
    };
    let root = Path::new(&root);
    let options = options();
    let key = stage_key()?;
    let mut fixture = build_session_relative_fixture()?;
    add_previous_output(&mut fixture.case)?;
    let memory = MemoryBudget::new(AGGREGATE_MEMORY);
    let worker = admit_case(&mut fixture.case, &memory)?;
    let cache = cache(root, &options, &memory)?.with_memory_scope(worker.budget())?;
    let job = Job::with_memory_budget("relational checkpoint child", worker.budget());
    let handler = l2_cli::job_ui::CancellationHandler::install()?;
    let _active = handler.activate(job.clone())?;
    let scope = job.work_scope(key.as_str())?;
    let mut lease = cache.lease(&key)?;
    let mut resume = RecoveryResume::new(&mut lease, &options, Some(worker.budget()));
    resume.pause_after_populated_relational_checkpoint(root.join("ready"));
    let result = recover_bounded(
        &mut fixture.case,
        options.profile,
        Some(&scope),
        Some(worker.budget()),
        Some(&mut resume),
    );
    if std::env::var_os(CHILD_INTERRUPT).is_some() && job.is_cancelled() {
        return match result {
            Err(RecoveryExecutionError::Job(JobError::Cancelled)) => Ok(()),
            other => Err(format!("expected cooperative cancellation, got {other:?}").into()),
        };
    }
    Err("recovery finished before the parent killed the committed search".into())
}

#[test]
fn sigkill_during_populated_relational_search_resumes_committed_candidates()
-> Result<(), Box<dyn Error>> {
    exercise_interrupted_search(Interruption::Kill)
}

#[test]
fn sigint_during_populated_relational_search_resumes_committed_candidates()
-> Result<(), Box<dyn Error>> {
    exercise_interrupted_search(Interruption::Interrupt)
}

#[test]
fn oversized_inner_checkpoint_preserves_prior_generation_and_respects_cache_mode()
-> Result<(), Box<dyn Error>> {
    let options = options();
    let key = stage_key()?;
    let mut fixture = build_session_relative_fixture()?;
    add_previous_output(&mut fixture.case)?;
    let mut uninterrupted = fixture.case.try_clone()?;
    let expected_memory = MemoryBudget::new(AGGREGATE_MEMORY);
    let expected_worker = admit_case(&mut uninterrupted, &expected_memory)?;
    let expected_job =
        Job::with_memory_budget("uninterrupted overflow reference", expected_worker.budget());
    let expected_scope = expected_job.work_scope(key.as_str())?;
    let expected = recover_bounded(
        &mut uninterrupted,
        options.profile,
        Some(&expected_scope),
        Some(expected_worker.budget()),
        None,
    )?;
    assert!(
        uninterrupted
            .blobs()
            .iter()
            .any(|blob| blob.bytes == fixture.plaintext)
    );
    drop(expected_worker);
    let reference = OverflowReference {
        initial: &fixture.case,
        uninterrupted: &uninterrupted,
        expected: &expected,
        work: without_cache_hits(serde_json::to_value(expected_scope.work_snapshot()?)?)?,
        options: &options,
        key: &key,
    };
    for part in [TestCheckpointPart::Gate, TestCheckpointPart::Cursor] {
        for strict in [true, false] {
            reference.exercise(part, strict)?;
        }
    }
    Ok(())
}

#[test]
fn relational_fixture_respects_its_configured_shared_memory_limit() -> Result<(), Box<dyn Error>> {
    let mut options = options();
    options.memory_limit = WORK_POLICY_MEMORY;
    let mut fixture = build_session_relative_fixture()?;
    add_previous_output(&mut fixture.case)?;
    let native = fixture.case.checkpoint_prefix()?;
    // Exercise the same limit for policy sizing and the shared memory ledger
    let memory = MemoryBudget::new(options.memory_limit);
    let worker = memory.try_working_set(options.memory_limit / 2)?;
    fixture.case.use_working_set(&worker)?;
    let job = Job::with_memory_budget("bounded relational recovery", worker.budget());
    let result = recover_case_with_job(
        &mut fixture.case,
        options.profile,
        options.memory_limit,
        Some(&job),
        Some(worker.budget()),
        None,
    );
    let observation = memory.snapshot()?;
    assert!(observation.peak_bytes <= options.memory_limit);
    fixture.case.validate()?;
    assert!(native.matches(&fixture.case)?);
    // A successful run must recover the artifact; otherwise admission must explain the stop
    match result {
        Ok(_) => assert!(
            fixture
                .case
                .blobs()
                .iter()
                .any(|blob| blob.bytes == fixture.plaintext)
        ),
        Err(error) => {
            assert!(
                matches!(
                    crate::memory_error::find(&error),
                    Some(l2_workbench::job::MemoryError::Limit {
                        limit,
                        used,
                        requested,
                    }) if limit == options.memory_limit && requested > limit.saturating_sub(used)
                ),
                "expected a shared-memory denial, got {error}"
            );
            assert!(observation.rejected > 0);
        }
    }
    Ok(())
}

struct OverflowReference<'a> {
    initial: &'a Case,
    uninterrupted: &'a Case,
    expected: &'a RecoveryExecutionOutcome,
    work: Value,
    options: &'a RecoveryOptions,
    key: &'a StageKey,
}

impl OverflowReference<'_> {
    fn exercise(&self, part: TestCheckpointPart, strict: bool) -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let mut actual_case = self.initial.try_clone()?;
        let prefix = actual_case.checkpoint_prefix()?;
        let memory = MemoryBudget::new(AGGREGATE_MEMORY);
        let worker = admit_case(&mut actual_case, &memory)?;
        let cache =
            cache(temporary.path(), self.options, &memory)?.with_memory_scope(worker.budget())?;
        let job = Job::with_memory_budget("inner checkpoint overflow", worker.budget());
        let scope = job.work_scope(self.key.as_str())?;
        let mut configured = self.options.clone();
        configured.strict_cache = strict;
        let mut lease = cache.lease(self.key)?;
        let mut resume = RecoveryResume::new(&mut lease, &configured, Some(worker.budget()));
        resume.force_inner_checkpoint_limit(part, 1);
        let result = recover_bounded(
            &mut actual_case,
            configured.profile,
            Some(&scope),
            Some(worker.budget()),
            Some(&mut resume),
        );
        let prior = resume
            .forced_boundary_generation()
            .ok_or("missing prior generation")?;
        if strict {
            let error = result
                .err()
                .ok_or("strict overflow unexpectedly succeeded")?;
            if part == TestCheckpointPart::Cursor {
                assert!(caused_by_cursor_size_limit(&error));
            } else {
                assert_eq!(
                    super::checkpoint::unavailable_reason(&error),
                    Some(super::checkpoint::CheckpointUnavailable::SizeLimit)
                );
            }
            assert!(prefix.matches(&actual_case)?);
            actual_case.validate()?;
        } else {
            let actual = result?;
            assert_eq!(actual_case.to_json()?, self.uninterrupted.to_json()?);
            assert_same_summary(&actual, self.expected);
            assert_eq!(
                without_cache_hits(serde_json::to_value(scope.work_snapshot()?)?)?,
                self.work
            );
            assert!(
                job.snapshot()?
                    .cache_fallbacks
                    .records()
                    .iter()
                    .any(|record| {
                        record.kind() == l2_workbench::job::CacheFallbackKind::CommitFailed
                    })
            );
        }
        drop(resume);
        let limits = l2_workbench::job::cache::ExecutionCheckpointLimits {
            max_encoded_bytes: configured.cache_max_bytes,
            max_executor_bytes: configured.memory_limit / 8,
            max_metadata_bytes: 4 * 1024 * 1024,
        };
        let saved = lease
            .load_active(limits)?
            .ok_or("prior generation was lost")?;
        assert_eq!(saved.generation(), &prior);
        Ok(())
    }
}

#[test]
fn allocation_failure_during_relational_restore_does_not_restart_optional_cache()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut options = options();
    let key = stage_key()?;
    let mut fixture = build_session_relative_fixture()?;
    add_previous_output(&mut fixture.case)?;
    let native = fixture.case.to_json()?;
    run_interrupted_child(temporary.path(), Interruption::Kill)?;

    options.strict_cache = false;
    let memory = MemoryBudget::new(AGGREGATE_MEMORY);
    let worker = admit_case(&mut fixture.case, &memory)?;
    let cache = cache(temporary.path(), &options, &memory)?.with_memory_scope(worker.budget())?;
    let job = Job::with_memory_budget("restore allocation failure", worker.budget());
    let scope = job.work_scope(key.as_str())?;
    let mut lease = cache.lease(&key)?;
    let limits = l2_workbench::job::cache::ExecutionCheckpointLimits {
        max_encoded_bytes: options.cache_max_bytes,
        max_executor_bytes: options.memory_limit / 8,
        max_metadata_bytes: 4 * 1024 * 1024,
    };
    let prior = lease
        .load_active(limits)?
        .ok_or("missing prior generation")?
        .generation()
        .clone();
    let mut resume = RecoveryResume::new(&mut lease, &options, Some(worker.budget()));
    resume.fail_allocation_during_relational_load();
    let error = recover_bounded(
        &mut fixture.case,
        options.profile,
        Some(&scope),
        Some(worker.budget()),
        Some(&mut resume),
    )
    .err()
    .ok_or("allocation failure restarted recovery")?;
    assert!(matches!(
        error,
        super::super::RecoveryExecutionError::Coordinator(
            l2_workbench::recovery::RecoveryError::AllocationFailed
        )
    ));
    assert_eq!(fixture.case.to_json()?, native);
    assert!(job.snapshot()?.cache_fallbacks.records().is_empty());
    drop(resume);
    let saved = lease
        .load_active(limits)?
        .ok_or("prior generation was lost")?;
    assert_eq!(saved.generation(), &prior);
    Ok(())
}

fn caused_by_cursor_size_limit(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if matches!(
            error.downcast_ref::<l2_workbench::protocol::RelationalCursorError<
                super::super::RecoveryExecutionError,
            >>(),
            Some(l2_workbench::protocol::RelationalCursorError::CheckpointTooLarge)
        ) {
            return true;
        }
        current = error.source();
    }
    false
}

#[derive(Clone, Copy)]
enum Interruption {
    Kill,
    Interrupt,
}

fn exercise_interrupted_search(interruption: Interruption) -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let options = options();
    let key = stage_key()?;
    let mut fixture = build_session_relative_fixture()?;
    add_previous_output(&mut fixture.case)?;
    let mut uninterrupted = fixture.case.try_clone()?;
    let expected_memory = MemoryBudget::new(AGGREGATE_MEMORY);
    let expected_worker = admit_case(&mut uninterrupted, &expected_memory)?;
    let expected_job = Job::with_memory_budget(
        "uninterrupted relational recovery",
        expected_worker.budget(),
    );
    let expected_scope = expected_job.work_scope(key.as_str())?;
    let expected = recover_bounded(
        &mut uninterrupted,
        options.profile,
        Some(&expected_scope),
        Some(expected_worker.budget()),
        None,
    )?;
    assert!(
        uninterrupted
            .blobs()
            .iter()
            .any(|blob| blob.bytes == fixture.plaintext)
    );
    let reference_blob_bytes = uninterrupted.resource_usage().blob_bytes;
    let checkpoint_decoded_limit = options.memory_limit;
    println!(
        "uninterrupted Case: {reference_blob_bytes} retained blob bytes; checkpoint decoded limit: {checkpoint_decoded_limit} bytes"
    );
    drop(expected_worker);

    let committed = run_interrupted_child(temporary.path(), interruption)?;

    let memory = MemoryBudget::new(AGGREGATE_MEMORY);
    let cache = cache(temporary.path(), &options, &memory)?;
    if matches!(interruption, Interruption::Kill) {
        corrupt_inner_cursor_preserves_native_and_restores_work(
            &cache,
            &key,
            &options,
            &fixture.case,
            &uninterrupted,
            &without_cache_hits(serde_json::to_value(expected_scope.work_snapshot()?)?)?,
            &memory,
        )?;
    }
    assert_cancel_after_restore(&cache, &key, &options, &fixture.case, &memory, committed)?;

    let mut resumed = fixture.case;
    let worker = admit_case(&mut resumed, &memory)?;
    let worker_cache = cache.with_memory_scope(worker.budget())?;
    let resumed_job = Job::with_memory_budget("resumed relational recovery", worker.budget());
    let resumed_scope = resumed_job.work_scope(key.as_str())?;
    let mut lease = worker_cache.lease(&key)?;
    let mut resume = RecoveryResume::new(&mut lease, &options, Some(worker.budget()));
    let actual = recover_bounded(
        &mut resumed,
        options.profile,
        Some(&resumed_scope),
        Some(worker.budget()),
        Some(&mut resume),
    )?;
    assert_eq!(resume.restored_relational_candidates(), Some(committed));
    assert_eq!(resumed.to_json()?, uninterrupted.to_json()?);
    assert_same_summary(&actual, &expected);
    assert_eq!(
        resumed_scope.work_snapshot()?.counter(Counter::CacheHits),
        1
    );
    assert_eq!(
        without_cache_hits(serde_json::to_value(resumed_scope.work_snapshot()?)?)?,
        without_cache_hits(serde_json::to_value(expected_scope.work_snapshot()?)?)?,
    );
    let snapshot = memory.snapshot()?;
    assert!(snapshot.peak_bytes > 0 && snapshot.peak_bytes <= AGGREGATE_MEMORY);
    Ok(())
}

fn assert_same_summary(actual: &RecoveryExecutionOutcome, expected: &RecoveryExecutionOutcome) {
    assert_eq!(actual.omissions, expected.omissions);
    assert_eq!(actual.resources, expected.resources);
    assert_eq!(actual.candidate_count, expected.candidate_count);
    assert_eq!(
        actual.validated_artifact_count,
        expected.validated_artifact_count
    );
}

fn run_interrupted_child(root: &Path, interruption: Interruption) -> Result<u64, Box<dyn Error>> {
    let child_log = fs::File::create(root.join("child.log"))?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--exact", CHILD_TEST, "--nocapture"])
        .env(CHILD_ROOT, root)
        .env_remove(CHILD_INTERRUPT)
        .stdout(Stdio::from(child_log.try_clone()?))
        .stderr(Stdio::from(child_log));
    if matches!(interruption, Interruption::Interrupt) {
        command.env(CHILD_INTERRUPT, "1");
    }
    let mut child = OwnedChild(command.spawn()?);
    let ready = root.join("ready");
    let deadline = Instant::now() + Duration::from_mins(3);
    while !ready.exists() && Instant::now() < deadline {
        if child.0.try_wait()?.is_some() {
            return Err(format!(
                "child exited before committing a populated search: {}",
                fs::read_to_string(root.join("child.log"))?
            )
            .into());
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        ready.exists(),
        "no populated relational checkpoint was committed"
    );
    let committed = check_checkpoint_marker(&ready)?;
    interrupt_child(&mut child, interruption, root)?;
    Ok(committed)
}

fn check_checkpoint_marker(ready: &Path) -> Result<u64, Box<dyn Error>> {
    let marker: Value = serde_json::from_slice(&fs::read(ready)?)?;
    let committed = marker
        .get("candidates_examined")
        .and_then(Value::as_u64)
        .ok_or("missing candidate count")?;
    assert!(committed > 0);
    let work_candidates = marker
        .get("work_candidates_examined")
        .and_then(Value::as_u64)
        .ok_or("missing committed candidate work")?;
    let work_bytes = marker
        .get("work_bytes")
        .and_then(Value::as_u64)
        .ok_or("missing committed byte work")?;
    let history_bytes = marker
        .get("history_storage_bytes")
        .and_then(Value::as_u64)
        .ok_or("missing committed history storage")?;
    let history_ceiling = marker
        .get("history_ceiling_bytes")
        .and_then(Value::as_u64)
        .ok_or("missing committed history ceiling")?;
    let history_entries = marker
        .get("history_entries")
        .and_then(Value::as_u64)
        .ok_or("missing committed history count")?;
    assert!(work_candidates >= committed && work_bytes > 0);
    assert!(history_bytes <= history_ceiling);
    assert!(history_entries == 0 || history_bytes > 0);
    assert!(
        marker
            .get("cached_plans")
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0)
    );
    println!("committed relational checkpoint: {marker}");
    assert!(
        marker
            .get("aggregate_peak_bytes")
            .and_then(Value::as_u64)
            .is_some_and(|peak| peak > 0 && peak <= AGGREGATE_MEMORY)
    );
    Ok(committed)
}

fn interrupt_child(
    child: &mut OwnedChild,
    interruption: Interruption,
    root: &Path,
) -> Result<(), Box<dyn Error>> {
    match interruption {
        Interruption::Kill => {
            child.0.kill()?;
            assert_eq!(child.0.wait()?.signal(), Some(libc::SIGKILL));
        }
        Interruption::Interrupt => {
            let pid = i32::try_from(child.0.id())?;
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGINT,
            )?;
            let deadline = Instant::now() + Duration::from_secs(30);
            let status = loop {
                if let Some(status) = child.0.try_wait()? {
                    break status;
                }
                if Instant::now() >= deadline {
                    return Err("child did not stop after SIGINT".into());
                }
                thread::sleep(Duration::from_millis(20));
            };
            assert!(
                status.success(),
                "child did not cancel cooperatively: {}",
                fs::read_to_string(root.join("child.log"))?
            );
        }
    }
    Ok(())
}

fn assert_cancel_after_restore(
    cache: &Cache,
    key: &StageKey,
    options: &RecoveryOptions,
    initial: &Case,
    memory: &MemoryBudget,
    committed: u64,
) -> Result<(), Box<dyn Error>> {
    let mut cancelled = initial.try_clone()?;
    let worker = admit_case(&mut cancelled, memory)?;
    let worker_cache = cache.with_memory_scope(worker.budget())?;
    let job = Job::with_memory_budget(
        "cancel immediately after restoring the cursor",
        worker.budget(),
    );
    let scope = job.work_scope(key.as_str())?;
    let mut lease = worker_cache.lease(key)?;
    let mut resume = RecoveryResume::new(&mut lease, options, Some(worker.budget()));
    resume.cancel_after_loading_relational_checkpoint();
    let result = recover_bounded(
        &mut cancelled,
        options.profile,
        Some(&scope),
        Some(worker.budget()),
        Some(&mut resume),
    );
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(RecoveryExecutionError::Job(JobError::Cancelled))
    ));
    assert_eq!(resume.restored_relational_candidates(), Some(committed));
    assert_eq!(cancelled.to_json()?, initial.to_json()?);
    Ok(())
}

fn add_previous_output(case: &mut Case) -> Result<(), Box<dyn Error>> {
    case.add_bytes_node(
        "previous_recovery_output",
        b"preserved output",
        Vec::new(),
        json!({}),
    )?;
    Ok(())
}

fn corrupt_inner_cursor_preserves_native_and_restores_work(
    cache: &Cache,
    key: &StageKey,
    options: &RecoveryOptions,
    initial: &Case,
    expected: &Case,
    expected_work: &Value,
    memory: &MemoryBudget,
) -> Result<(), Box<dyn Error>> {
    let limits = l2_workbench::job::cache::ExecutionCheckpointLimits {
        max_encoded_bytes: options.cache_max_bytes,
        max_executor_bytes: options.memory_limit / 8,
        max_metadata_bytes: 4 * 1024 * 1024,
    };
    let mut lease = cache.lease(key)?;
    let mut active = lease
        .load_active(limits)?
        .ok_or("missing committed cursor")?;
    let mut generation = active.generation().clone();
    let snapshot = active.snapshot().clone();
    let metadata = active.metadata().clone();
    let mut original = Vec::new();
    active.streams().2.read_to_end(&mut original)?;
    drop(active);
    let mut corrupted: Value = serde_json::from_slice(&original)?;
    *corrupted
        .pointer_mut("/cursor/active_relational/active/cursor")
        .ok_or("missing active inner cursor")? = json!("e30=");
    let bytes = serde_json::to_vec(&corrupted)?;
    lease.update_active_executor(&mut generation, &snapshot, limits, |output| {
        output.write_all(&bytes)?;
        Ok(&metadata)
    })?;
    drop(lease);

    for strict in [true, false] {
        let mut native = initial.try_clone()?;
        let before = native.to_json()?;
        let worker = admit_case(&mut native, memory)?;
        let worker_cache = cache.with_memory_scope(worker.budget())?;
        let job = Job::with_memory_budget("corrupt inner cursor", worker.budget());
        let scope = job.work_scope(key.as_str())?;
        let mut lease = worker_cache.lease(key)?;
        let mut configured = options.clone();
        configured.strict_cache = strict;
        let mut resume = RecoveryResume::new(&mut lease, &configured, Some(worker.budget()));
        let result = recover_bounded(
            &mut native,
            configured.profile,
            Some(&scope),
            Some(worker.budget()),
            Some(&mut resume),
        );
        if strict {
            assert!(result.is_err());
            assert_eq!(native.to_json()?, before);
        } else {
            result?;
            assert_eq!(native.to_json()?, expected.to_json()?);
            assert_eq!(
                &without_cache_hits(serde_json::to_value(scope.work_snapshot()?)?)?,
                expected_work
            );
            assert!(
                job.snapshot()?
                    .cache_fallbacks
                    .records()
                    .iter()
                    .any(|record| {
                        record.kind() == l2_workbench::job::CacheFallbackKind::InvalidEntry
                    })
            );
        }
    }

    // Put the valid generation back so the subsequent cancellation and resume use it
    let mut lease = cache.lease(key)?;
    lease.update_active_executor(&mut generation, &snapshot, limits, |output| {
        output.write_all(&original)?;
        Ok(&metadata)
    })?;
    Ok(())
}
