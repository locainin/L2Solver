use super::{
    Cache, CacheError, CacheFallbackKind, CacheStage, CheckpointStatus, Counter, Job, Value,
    cache_at, missing, stage_key,
};
use l2_workbench::job::{
    JobSnapshot, Phase, PhaseState, RecoveryFunnelAdmission, RecoveryFunnelIdentity,
    RecoveryFunnelInput, RecoveryFunnelRegistration, RecoveryPublicationSourceBasis,
    RecoveryTransition, RecoveryTransitionOutcome, RecoveryTransitionSample,
    RecoveryTransitionStage, cache::ExecutionCheckpointLimits,
};
use std::{error::Error, path::Path};

type TestResult = Result<(), Box<dyn Error>>;

const LEGACY_FIXTURES: [(u32, &str, Counter, u64); 4] = [
    (
        1,
        include_str!("fixtures/job_snapshot_v1.json"),
        Counter::Flows,
        7,
    ),
    (
        2,
        include_str!("fixtures/job_snapshot_v2.json"),
        Counter::Bytes,
        240,
    ),
    (
        3,
        include_str!("fixtures/job_snapshot_v3.json"),
        Counter::Packets,
        6,
    ),
    (
        4,
        include_str!("fixtures/job_snapshot_v4.json"),
        Counter::RecordInputApplications,
        11,
    ),
];

fn store_legacy_snapshot(
    cache: &Cache,
    directory: &Path,
    version: u32,
    payload: &str,
) -> Result<l2_workbench::job::cache::Checkpoint, Box<dyn Error>> {
    let key = stage_key(&format!("legacy-job-snapshot-{version}"))?;
    cache.write_checkpoint(
        &key,
        &Job::new("legacy snapshot placeholder").snapshot()?,
        CheckpointStatus::Active,
    )?;
    let database = rusqlite::Connection::open(directory.join("state").join("cache.sqlite3"))?;
    database.execute(
        "UPDATE checkpoints SET snapshot_version = ?1, snapshot_json = ?2 WHERE key = ?3",
        rusqlite::params![version, payload, key.as_str()],
    )?;
    drop(database);
    cache
        .read_checkpoint(&key)?
        .ok_or_else(|| missing("legacy checkpoint should be available"))
}

#[test]
fn legacy_versions_restore_valid_phases_and_fixture_counters() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    for (version, payload, counter, expected) in LEGACY_FIXTURES {
        let wire: Value = serde_json::from_str(payload)?;
        let decoded: JobSnapshot = serde_json::from_str(payload)
            .map_err(|error| format!("legacy snapshot v{version} is invalid: {error}"))?;
        assert!(decoded.is_valid_checkpoint(), "legacy snapshot v{version}");
        assert_eq!(decoded.label, format!("synthetic checkpoint v{version}"));
        // Older snapshots omit fields introduced by later formats
        assert_eq!(wire.get("cache_fallbacks").is_some(), version >= 2);
        assert_eq!(wire.get("recovery_transitions").is_some(), version >= 3);
        assert_eq!(
            wire.pointer("/counters/record_input_applications")
                .is_some(),
            version >= 3
        );
        assert_eq!(
            wire.pointer("/counters/source_read_bytes").is_some(),
            version >= 4
        );
        assert_eq!(decoded.current_phase, Some(Phase::Reconstruction));
        assert_eq!(
            decoded
                .phase(Phase::Reconstruction)
                .map(|phase| phase.state),
            Some(PhaseState::InProgress)
        );
        let saved = store_legacy_snapshot(&cache, temporary.path(), version, payload)?;
        assert_eq!(saved.snapshot_version, version);
        assert_eq!(saved.snapshot.counters.get(&counter), Some(&expected));
        assert_eq!(
            saved.snapshot.recovery_transitions,
            decoded.recovery_transitions
        );
        let records = saved.snapshot.recovery_transitions.records().to_vec();
        let fallbacks = saved.snapshot.cache_fallbacks.records().to_vec();
        let restored = Job::new("restored legacy snapshot");
        restored.restore(saved.snapshot)?;
        let restored = restored.snapshot()?;
        assert_eq!(restored.counters.get(&counter), Some(&expected));
        assert_eq!(
            restored
                .phase(Phase::Reconstruction)
                .map(|phase| phase.state),
            Some(PhaseState::Pending)
        );
        if version == 4 {
            // Saved source reads become prior work when the job resumes
            assert_eq!(restored.counters.get(&Counter::SourceReadBytes), Some(&0));
            assert_eq!(
                restored.counters.get(&Counter::PriorSourceReadBytes),
                Some(&60)
            );
        }
        assert_eq!(restored.recovery_transitions.records(), records);
        assert_eq!(restored.cache_fallbacks.records(), fallbacks);
    }
    Ok(())
}

#[test]
fn legacy_cache_fallbacks_retain_stage_kind_count_and_detail() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    for (index, stage, kind, count, detail) in [
        (
            1,
            CacheStage::CaptureIndex,
            CacheFallbackKind::LookupFailed,
            2,
            "synthetic cache miss",
        ),
        (
            2,
            CacheStage::Checkpoint,
            CacheFallbackKind::CheckpointUnsupported,
            1,
            "synthetic checkpoint unavailable",
        ),
    ] {
        let (version, payload, _, _) = LEGACY_FIXTURES
            .get(index)
            .ok_or("legacy fixture is missing")?;
        let saved = store_legacy_snapshot(&cache, temporary.path(), *version, payload)?;
        let fallback = saved
            .snapshot
            .cache_fallbacks
            .records()
            .first()
            .ok_or("legacy fallback is missing")?;
        assert_eq!(fallback.stage(), stage);
        assert_eq!(fallback.kind(), kind);
        assert_eq!(fallback.count(), count);
        assert_eq!(fallback.sample_detail(), Some(detail));
    }
    Ok(())
}

#[test]
fn version_three_restores_an_untagged_candidate_with_its_source_range() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let (_, payload, _, _) = LEGACY_FIXTURES
        .get(2)
        .ok_or("version three fixture is missing")?;
    let wire: Value = serde_json::from_str(payload)?;
    assert!(
        wire.pointer("/recovery_transitions/records/0/sample/kind")
            .is_none()
    );
    let saved = store_legacy_snapshot(&cache, temporary.path(), 3, payload)?;
    let record = saved
        .snapshot
        .recovery_transitions
        .records()
        .first()
        .ok_or("version three candidate is missing")?;
    assert_eq!(record.stage(), RecoveryTransitionStage::Framing);
    assert_eq!(record.outcome(), RecoveryTransitionOutcome::Derived);
    assert_eq!(record.count(), 2);
    let Some(RecoveryTransitionSample::Candidate(sample)) = record.sample() else {
        return Err("version three candidate did not restore".into());
    };
    assert_eq!(sample.candidate_index, 3);
    assert_eq!(sample.input_node_id, 7);
    assert_eq!(sample.input_count, 2);
    let range = sample
        .source_range
        .ok_or("candidate source range is missing")?;
    assert_eq!(range.source_sha256, [0x11; 32]);
    assert_eq!((range.packet, range.offset, range.length), (Some(1), 24, 8));
    Ok(())
}

#[test]
fn version_four_restores_linked_cohort_candidate_and_publication_samples() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let (_, payload, _, _) = LEGACY_FIXTURES
        .get(3)
        .ok_or("version four fixture is missing")?;
    let wire: Value = serde_json::from_str(payload)?;
    let transitions = wire
        .get("recovery_transitions")
        .and_then(Value::as_object)
        .ok_or("version four transitions are missing")?;
    assert_eq!(
        transitions.len(),
        1,
        "legacy version four has no funnel fields"
    );
    let saved = store_legacy_snapshot(&cache, temporary.path(), 4, payload)?;
    let records = saved.snapshot.recovery_transitions.records();
    assert_eq!(records.len(), 3);
    let find = |stage, outcome| {
        records
            .iter()
            .find(|record| record.stage() == stage && record.outcome() == outcome)
            .and_then(|record| record.sample())
    };
    let Some(RecoveryTransitionSample::Cohort(cohort)) = find(
        RecoveryTransitionStage::Cohort,
        RecoveryTransitionOutcome::CohortAdmitted,
    ) else {
        return Err("cohort sample is missing".into());
    };
    let Some(RecoveryTransitionSample::Candidate(candidate)) = find(
        RecoveryTransitionStage::Framing,
        RecoveryTransitionOutcome::Derived,
    ) else {
        return Err("candidate sample is missing".into());
    };
    let Some(RecoveryTransitionSample::Publication(publication)) = find(
        RecoveryTransitionStage::Publication,
        RecoveryTransitionOutcome::Published,
    ) else {
        return Err("publication sample is missing".into());
    };
    // The cohort and candidate describe the same fabricated source and input batch
    let range = candidate
        .source_range
        .ok_or("candidate source range is missing")?;
    assert_eq!(range.source_sha256, [0x11; 32]);
    assert_eq!(candidate.candidate_index, 3);
    assert_eq!(cohort.source_sha256, Some(range.source_sha256));
    assert_eq!(cohort.input_node_id, Some(candidate.input_node_id));
    assert_eq!(cohort.input_blob_sha256, Some(candidate.input_blob_sha256));
    assert_eq!(cohort.input_count, candidate.input_count);
    assert_eq!(cohort.candidate_index, Some(candidate.candidate_index));
    assert_eq!(
        cohort.input_batch_sha256,
        Some(candidate.input_batch_sha256)
    );
    assert_eq!(cohort.task_sha256, Some(candidate.task_sha256));
    assert_eq!(
        publication.source_basis,
        RecoveryPublicationSourceBasis::StagedManifest
    );
    assert_eq!(publication.source_set_sha256, Some([0x55; 32]));
    assert_eq!(publication.artifact_count, Some(1));
    let artifact = publication
        .artifact
        .ok_or("publication artifact is missing")?;
    assert_eq!(artifact.sha256, [0x66; 32]);
    assert_eq!(artifact.byte_length, 12);
    Ok(())
}

#[test]
fn unknown_future_fallback_kind_is_rejected_in_a_legacy_snapshot() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let (_, payload, _, _) = LEGACY_FIXTURES
        .get(2)
        .ok_or("legacy v3 fixture is missing")?;
    let mut snapshot: Value = serde_json::from_str(payload)?;
    *snapshot
        .pointer_mut("/cache_fallbacks/records/0/kind")
        .ok_or("legacy fallback kind is missing")? =
        serde_json::json!("unknown_future_checkpoint_kind");
    let error = store_legacy_snapshot(
        &cache,
        temporary.path(),
        3,
        &serde_json::to_string(&snapshot)?,
    )
    .err()
    .ok_or("an unknown fallback kind was accepted")?;
    assert!(matches!(
        error.downcast_ref::<CacheError>(),
        Some(CacheError::CorruptCheckpoint)
    ));
    Ok(())
}

fn funnel_snapshot() -> Result<JobSnapshot, Box<dyn Error>> {
    let job = Job::new("funnel checkpoint");
    job.increment(Counter::RecordInputApplications, 3)?;
    job.record_recovery_transition(RecoveryTransition {
        stage: RecoveryTransitionStage::Schema,
        outcome: RecoveryTransitionOutcome::ReportRetained,
        sample: None,
    })?;
    let input = RecoveryFunnelInput {
        node_id: 20,
        session_node_id: 30,
    };
    job.register_recovery_cohort(RecoveryFunnelRegistration {
        identity: RecoveryFunnelIdentity {
            source_sha256: [1; 32],
            cohort_sha256: [2; 32],
        },
        inputs: &[input],
        total_inputs: 1,
        admission: RecoveryFunnelAdmission::Unknown,
    })?;
    Ok(job.snapshot()?)
}

#[test]
fn version_five_checkpoints_round_trip_funnel_state() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("funnel-checkpoint-version")?;
    let snapshot = funnel_snapshot()?;
    let wire = serde_json::to_value(&snapshot.recovery_transitions)?;
    assert_eq!(
        wire.get("cohorts").and_then(Value::as_array).map(Vec::len),
        Some(1)
    );
    cache.write_checkpoint(&key, &snapshot, CheckpointStatus::Active)?;
    let saved = cache
        .read_checkpoint(&key)?
        .ok_or_else(|| missing("funnel checkpoint should be available"))?;
    assert_eq!(saved.snapshot_version, 5);
    assert_eq!(saved.snapshot, snapshot);
    let restored = Job::new("restored funnel checkpoint");
    restored.restore(saved.snapshot)?;
    assert_eq!(
        serde_json::to_value(restored.snapshot()?.recovery_transitions)?,
        wire
    );
    Ok(())
}

#[test]
fn active_generation_saves_version_five_with_funnel_state() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 128 * 1024)?;
    let key = stage_key("funnel-generation-version")?;
    let snapshot = funnel_snapshot()?;
    let limits = ExecutionCheckpointLimits {
        max_encoded_bytes: 64 * 1024,
        max_executor_bytes: 4 * 1024,
        max_metadata_bytes: 64 * 1024,
    };
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits, |_| {
        Ok(serde_json::json!({"checkpoint": true}))
    })?;
    let database =
        rusqlite::Connection::open(temporary.path().join("state").join("cache.sqlite3"))?;
    let envelope: String = database.query_row(
        "SELECT envelope_json FROM executions WHERE key = ?1",
        [key.as_str()],
        |row| row.get(0),
    )?;
    drop(database);
    let wire: Value = serde_json::from_str(&envelope)?;
    assert_eq!(wire.get("snapshot_version"), Some(&serde_json::json!(5)));
    assert_eq!(
        wire.pointer("/snapshot/recovery_transitions/cohorts")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    let saved = lease
        .load_active(limits)?
        .ok_or("active generation is missing")?;
    assert_eq!(saved.snapshot(), &snapshot);
    Ok(())
}

#[test]
fn unknown_next_snapshot_version_is_rejected() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("future-job-snapshot")?;
    cache.write_checkpoint(
        &key,
        &Job::new("future snapshot").snapshot()?,
        CheckpointStatus::Active,
    )?;
    let database =
        rusqlite::Connection::open(temporary.path().join("state").join("cache.sqlite3"))?;
    database.execute(
        "UPDATE checkpoints SET snapshot_version = 6 WHERE key = ?1",
        [key.as_str()],
    )?;
    drop(database);
    assert!(matches!(
        cache.read_checkpoint(&key),
        Err(CacheError::CorruptCheckpoint)
    ));
    Ok(())
}
