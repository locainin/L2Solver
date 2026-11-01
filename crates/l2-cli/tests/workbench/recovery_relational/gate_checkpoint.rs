use super::{
    DecodedFrameOutput, StoredSample,
    materialization_tests::{
        ReplayMessage, frozen_session_relative_report, frozen_session_relative_rule,
        replay_frozen_frames, session_ids, session_relative_messages,
    },
    record_gate::{GateStatus, SchemaCacheRestoreContext, SchemaCandidateOptions, SchemaPlanCache},
};
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationPolicy},
    job::MemoryBudget,
    protocol::{
        RecordSchemaProposalLimits, RelationalOperationTemplate, RelationalRecordSample,
        RelationalRestoreBudget, RelationalSessionId, RelationalTransformLimits,
        RelationalTransformReport, RelationalTransformRule,
    },
};
use std::error::Error;

const CHECKPOINT_LIMIT: usize = 4 * 1024 * 1024;
const PLAN_WORKSPACE_LIMIT: usize = 64 * 1024 * 1024;
const LEARNING_WORK: usize = 64 * 1024 * 1024;
const RESTORE_WORK: usize = 128 * 1024 * 1024;
const PROBE_WORK: usize = 16 * 1024;

pub(super) struct Fixture {
    pub(super) messages: Vec<ReplayMessage>,
    pub(super) sessions: Vec<RelationalSessionId>,
    pub(super) report: RelationalTransformReport,
    pub(super) correct: RelationalTransformRule,
    decoy: RelationalTransformRule,
}

impl Fixture {
    pub(super) fn new() -> Result<Self, Box<dyn Error>> {
        let fixture = super::super::record_discovery_tests::build_session_relative_fixture()?;
        let messages = session_relative_messages(&fixture.case, &fixture.episode_nodes)?;
        let sessions = session_ids(&messages);
        let report = frozen_session_relative_report(&sessions, LEARNING_WORK)?;
        let correct = frozen_session_relative_rule();
        let mut decoy = correct.clone();
        let RelationalOperationTemplate::Sha256CounterXor(parameters) = &mut decoy.operation;
        parameters.initial_counter = 1;
        Ok(Self {
            messages,
            sessions,
            report,
            correct,
            decoy,
        })
    }

    pub(super) fn samples(&self) -> Vec<RelationalRecordSample<'_>> {
        self.messages
            .iter()
            .map(|sample| RelationalRecordSample {
                sample: sample.sample,
                context: sample.context.clone(),
                session_order: sample.session_order,
                bytes: &sample.bytes,
            })
            .collect()
    }

    pub(super) fn stored(&self) -> Vec<StoredSample> {
        self.messages
            .iter()
            .map(|sample| StoredSample {
                node_id: sample.sample,
                context: sample.context.clone(),
                session_order: sample.session_order,
                direction_node_id: sample.direction_node_id,
                episode_node_id: sample.episode_node_id,
                stream_offset: sample.stream_offset,
            })
            .collect()
    }
}

fn options(rule: &RelationalTransformRule, work_limit: usize) -> SchemaCandidateOptions<'_> {
    SchemaCandidateOptions {
        parser_format: ArtifactValidationFormat::Png,
        schema_limits: RecordSchemaProposalLimits::default(),
        artifact_policy: ArtifactValidationPolicy::default(),
        work_limit,
        job: None,
        producer_rule: Some(rule),
        structural_admission: None,
    }
}

fn learn_decoy(
    fixture: &Fixture,
    samples: &[RelationalRecordSample<'_>],
    stored: &[StoredSample],
    memory: &MemoryBudget,
) -> Result<(SchemaPlanCache, Vec<DecodedFrameOutput>), Box<dyn Error>> {
    let frames = replay_frozen_frames(
        samples,
        stored,
        &fixture.sessions,
        &fixture.decoy,
        LEARNING_WORK,
    )?;
    let mut cache = SchemaPlanCache::default();
    let mut checkpoint_options = options(&fixture.decoy, LEARNING_WORK);
    let admission = super::record_gate::StructuralAdmission {
        memory,
        maximum: CHECKPOINT_LIMIT,
    };
    checkpoint_options.structural_admission = Some(&admission);
    let learned = cache.screen_candidate(&frames, &fixture.report, checkpoint_options)?;
    assert_ne!(learned.status, GateStatus::ArtifactValidated);
    Ok((cache, frames))
}

#[test]
fn gate_checkpoint_rejects_the_prior_format_before_replaying_rules() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let samples = fixture.samples();
    let stored = fixture.stored();
    let memory = MemoryBudget::new(256 * 1024 * 1024);
    let (cache, _) = learn_decoy(&fixture, &samples, &stored, &memory)?;
    let limits = RecordSchemaProposalLimits::default()
        .discovery
        .record_limits;
    let mut description =
        serde_json::to_value(cache.checkpoint_description(limits, CHECKPOINT_LIMIT)?)?;
    let version = description
        .get_mut("version")
        .ok_or("missing gate version")?;
    assert_eq!(*version, serde_json::json!(3));
    *version = serde_json::json!(2);
    let bytes = serde_json::to_vec(&description)?;
    let mut work = RelationalRestoreBudget::new(LEARNING_WORK, 100_000);
    let result = SchemaPlanCache::restore_checkpoint(
        &bytes,
        SchemaCacheRestoreContext {
            raw_directional_run: false,
            samples: &samples,
            stored_samples: &stored,
            report: &fixture.report,
            relational_limits: RelationalTransformLimits::default(),
            schema_limits: RecordSchemaProposalLimits::default(),
            artifact_policy: ArtifactValidationPolicy::default(),
            maximum_checkpoint_bytes: CHECKPOINT_LIMIT,
            maximum_workspace_bytes: PLAN_WORKSPACE_LIMIT,
            memory: &memory,
            work: &mut work,
            job: None,
        },
    );
    assert!(result.is_err());
    assert_eq!(work.verification_work_bytes(), bytes.len() * 2);
    Ok(())
}

#[test]
fn gate_checkpoint_reports_a_typed_size_limit() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let samples = fixture.samples();
    let stored = fixture.stored();
    let memory = MemoryBudget::new(256 * 1024 * 1024);
    let (cache, _) = learn_decoy(&fixture, &samples, &stored, &memory)?;
    let limits = RecordSchemaProposalLimits::default()
        .discovery
        .record_limits;
    let Err(error) = cache.checkpoint_description(limits, 1) else {
        return Err("gate size limit was ignored".into());
    };
    assert_eq!(
        super::super::checkpoint::unavailable_reason(&error),
        Some(super::super::checkpoint::CheckpointUnavailable::SizeLimit),
    );
    Ok(())
}

#[test]
fn restored_gate_reuses_a_verified_decoy_plan_and_validates_the_artifact()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let samples = fixture.samples();
    let stored = fixture.stored();
    let memory = MemoryBudget::new(256 * 1024 * 1024);
    let (mut original, decoy) = learn_decoy(&fixture, &samples, &stored, &memory)?;
    let correct = replay_frozen_frames(
        &samples,
        &stored,
        &fixture.sessions,
        &fixture.correct,
        LEARNING_WORK,
    )?;
    let limits = RecordSchemaProposalLimits::default()
        .discovery
        .record_limits;
    assert!(original.checkpoint_description(limits, 0).is_err());
    let encoded = {
        let description = original.checkpoint_description(limits, CHECKPOINT_LIMIT)?;
        serde_json::to_vec(&description)?
    };
    assert!(encoded.len() <= CHECKPOINT_LIMIT);
    let mut work = RelationalRestoreBudget::new(RESTORE_WORK, 100_000);
    let mut restored = SchemaPlanCache::restore_checkpoint(
        &encoded,
        SchemaCacheRestoreContext {
            raw_directional_run: false,
            samples: &samples,
            stored_samples: &stored,
            report: &fixture.report,
            relational_limits: RelationalTransformLimits::default(),
            schema_limits: RecordSchemaProposalLimits::default(),
            artifact_policy: ArtifactValidationPolicy::default(),
            maximum_checkpoint_bytes: CHECKPOINT_LIMIT,
            maximum_workspace_bytes: PLAN_WORKSPACE_LIMIT,
            memory: &memory,
            work: &mut work,
            job: None,
        },
    )?;
    assert!(work.verification_work_bytes() > 0);

    let expected = original.screen_candidate(
        &decoy,
        &fixture.report,
        options(&fixture.decoy, LEARNING_WORK),
    )?;
    let actual = restored.screen_candidate(
        &decoy,
        &fixture.report,
        options(&fixture.decoy, LEARNING_WORK),
    )?;
    assert_eq!(actual.status, expected.status);
    assert_eq!(actual.work_bytes, expected.work_bytes);
    assert_eq!(actual.details, expected.details);
    assert_eq!(
        actual.details.get("schema_plan_cache_hit"),
        Some(&serde_json::Value::Bool(true))
    );

    let expected = original.screen_candidate(
        &correct,
        &fixture.report,
        options(&fixture.correct, PROBE_WORK),
    )?;
    let actual = restored.screen_candidate(
        &correct,
        &fixture.report,
        options(&fixture.correct, PROBE_WORK),
    )?;
    assert_eq!(actual.status, expected.status);
    assert_eq!(actual.work_bytes, expected.work_bytes);
    assert_eq!(actual.details, expected.details);
    let expected = expected
        .accepted_schema
        .ok_or("original artifact was not accepted")?;
    let actual = actual
        .accepted_schema
        .ok_or("restored artifact was not accepted")?;
    assert_eq!(actual.schema, expected.schema);
    assert_eq!(actual.frame_indices, expected.frame_indices);
    assert_eq!(actual.artifact_receipt, expected.artifact_receipt);
    Ok(())
}

#[test]
fn gate_checkpoint_rejects_a_changed_producer_source_and_forged_output_digest()
-> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new()?;
    let samples = fixture.samples();
    let stored = fixture.stored();
    let memory = MemoryBudget::new(256 * 1024 * 1024);
    let (cache, _) = learn_decoy(&fixture, &samples, &stored, &memory)?;
    let limits = RecordSchemaProposalLimits::default()
        .discovery
        .record_limits;
    let encoded = {
        let description = cache.checkpoint_description(limits, CHECKPOINT_LIMIT)?;
        serde_json::to_vec(&description)?
    };
    drop(samples);

    let first = fixture.messages.first_mut().ok_or("missing seed sample")?;
    *first.bytes.get_mut(10).ok_or("missing seed byte")? ^= 1;
    let changed = fixture.samples();
    let mut work = RelationalRestoreBudget::new(LEARNING_WORK, 100_000);
    assert!(
        SchemaPlanCache::restore_checkpoint(
            &encoded,
            SchemaCacheRestoreContext {
                raw_directional_run: false,
                samples: &changed,
                stored_samples: &stored,
                report: &fixture.report,
                relational_limits: RelationalTransformLimits::default(),
                schema_limits: RecordSchemaProposalLimits::default(),
                artifact_policy: ArtifactValidationPolicy::default(),
                maximum_checkpoint_bytes: CHECKPOINT_LIMIT,
                maximum_workspace_bytes: PLAN_WORKSPACE_LIMIT,
                memory: &memory,
                work: &mut work,
                job: None,
            },
        )
        .is_err()
    );
    drop(changed);
    *fixture
        .messages
        .first_mut()
        .and_then(|sample| sample.bytes.get_mut(10))
        .ok_or("missing seed byte")? ^= 1;
    let samples = fixture.samples();
    let mut forged: serde_json::Value = serde_json::from_slice(&encoded)?;
    *forged
        .pointer_mut("/plans/0/key/frames/0/transformed_output_sha256")
        .ok_or("missing cached producer digest")? = serde_json::Value::String("0".repeat(64));
    let forged = serde_json::to_vec(&forged)?;
    let mut work = RelationalRestoreBudget::new(LEARNING_WORK, 100_000);
    assert!(
        SchemaPlanCache::restore_checkpoint(
            &forged,
            SchemaCacheRestoreContext {
                raw_directional_run: false,
                samples: &samples,
                stored_samples: &stored,
                report: &fixture.report,
                relational_limits: RelationalTransformLimits::default(),
                schema_limits: RecordSchemaProposalLimits::default(),
                artifact_policy: ArtifactValidationPolicy::default(),
                maximum_checkpoint_bytes: CHECKPOINT_LIMIT,
                maximum_workspace_bytes: PLAN_WORKSPACE_LIMIT,
                memory: &memory,
                work: &mut work,
                job: None,
            },
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn a_gate_checkpoint_preserves_positive_cached_schema_evidence() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let samples = fixture.samples();
    let stored = fixture.stored();
    let frames = replay_frozen_frames(
        &samples,
        &stored,
        &fixture.sessions,
        &fixture.correct,
        LEARNING_WORK,
    )?;
    let mut cache = SchemaPlanCache::default();
    let accepted = cache.screen_candidate(
        &frames,
        &fixture.report,
        options(&fixture.correct, LEARNING_WORK),
    )?;
    assert_eq!(accepted.status, GateStatus::ArtifactValidated);
    let limits = RecordSchemaProposalLimits::default()
        .discovery
        .record_limits;
    let encoded = {
        let description = cache.checkpoint_description(limits, CHECKPOINT_LIMIT)?;
        serde_json::to_vec(&description)?
    };
    let memory = MemoryBudget::new(256 * 1024 * 1024);
    let mut work = RelationalRestoreBudget::new(LEARNING_WORK, 100_000);
    let mut restored = SchemaPlanCache::restore_checkpoint(
        &encoded,
        SchemaCacheRestoreContext {
            raw_directional_run: false,
            samples: &samples,
            stored_samples: &stored,
            report: &fixture.report,
            relational_limits: RelationalTransformLimits::default(),
            schema_limits: RecordSchemaProposalLimits::default(),
            artifact_policy: ArtifactValidationPolicy::default(),
            maximum_checkpoint_bytes: CHECKPOINT_LIMIT,
            maximum_workspace_bytes: PLAN_WORKSPACE_LIMIT,
            memory: &memory,
            work: &mut work,
            job: None,
        },
    )?;
    let expected = cache.screen_candidate(
        &frames,
        &fixture.report,
        options(&fixture.correct, LEARNING_WORK),
    )?;
    let actual = restored.screen_candidate(
        &frames,
        &fixture.report,
        options(&fixture.correct, LEARNING_WORK),
    )?;
    assert_eq!(actual.status, GateStatus::ArtifactValidated);
    assert_eq!(actual.work_bytes, expected.work_bytes);
    assert_eq!(actual.details, expected.details);
    assert_eq!(
        actual
            .accepted_schema
            .ok_or("restored positive schema missing")?
            .artifact_receipt,
        expected
            .accepted_schema
            .ok_or("expected positive schema missing")?
            .artifact_receipt
    );
    assert!(memory.snapshot()?.used_bytes > 0);
    drop(restored);
    assert_eq!(memory.snapshot()?.used_bytes, 0);

    rejects_forged_cached_schema_receipt(&fixture, &encoded)
}

fn rejects_forged_cached_schema_receipt(
    fixture: &Fixture,
    encoded: &[u8],
) -> Result<(), Box<dyn Error>> {
    let samples = fixture.samples();
    let stored = fixture.stored();
    let memory = MemoryBudget::new(256 * 1024 * 1024);
    // A saved success must still match newly assembled bytes after restoration
    let mut forged: serde_json::Value = serde_json::from_slice(encoded)?;
    let plans = forged
        .get_mut("plans")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("missing checkpoint plans")?;
    let mut changed = false;
    for plan in plans {
        let alternatives = plan
            .pointer_mut("/plan/alternatives")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or("missing checkpoint alternatives")?;
        for alternative in alternatives {
            if let Some(digest) =
                alternative.pointer_mut("/observed/accepted_schema/artifact_receipt/output_sha256")
            {
                *digest = serde_json::Value::String("0".repeat(64));
                changed = true;
            }
        }
    }
    assert!(
        changed,
        "checkpoint did not retain positive schema evidence"
    );
    let forged = serde_json::to_vec(&forged)?;
    let mut work = RelationalRestoreBudget::new(LEARNING_WORK, 100_000);
    assert!(
        SchemaPlanCache::restore_checkpoint(
            &forged,
            SchemaCacheRestoreContext {
                raw_directional_run: false,
                samples: &samples,
                stored_samples: &stored,
                report: &fixture.report,
                relational_limits: RelationalTransformLimits::default(),
                schema_limits: RecordSchemaProposalLimits::default(),
                artifact_policy: ArtifactValidationPolicy::default(),
                maximum_checkpoint_bytes: CHECKPOINT_LIMIT,
                maximum_workspace_bytes: PLAN_WORKSPACE_LIMIT,
                memory: &memory,
                work: &mut work,
                job: None,
            },
        )
        .is_err()
    );
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn failed_late_session_replay_charges_the_remaining_verification_allowance()
-> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new()?;
    let sessions = fixture
        .report
        .discovery_sessions
        .iter()
        .chain(&fixture.report.heldout_sessions)
        .collect::<Vec<_>>();
    let first = sessions
        .first()
        .ok_or("missing first replay session")?
        .session;
    let later = sessions
        .get(1)
        .ok_or("missing later replay session")?
        .session;
    let first_samples = fixture
        .samples()
        .into_iter()
        .filter(|sample| sample.context.session == first)
        .collect::<Vec<_>>();
    l2_workbench::protocol::apply_relational_transform_rule(
        &first_samples,
        &fixture.correct,
        RelationalTransformLimits::default(),
        LEARNING_WORK,
    )?;
    drop(first_samples);
    for message in fixture
        .messages
        .iter_mut()
        .filter(|message| message.context.session == later)
    {
        message.bytes.fill(0);
    }
    let samples = fixture.samples();
    let stored = fixture.stored();
    let memory = MemoryBudget::new(256 * 1024 * 1024);
    let mut work = RelationalRestoreBudget::new(LEARNING_WORK, 100_000);
    let mut context = SchemaCacheRestoreContext {
        raw_directional_run: false,
        samples: &samples,
        stored_samples: &stored,
        report: &fixture.report,
        relational_limits: RelationalTransformLimits::default(),
        schema_limits: RecordSchemaProposalLimits::default(),
        artifact_policy: ArtifactValidationPolicy::default(),
        maximum_checkpoint_bytes: CHECKPOINT_LIMIT,
        maximum_workspace_bytes: PLAN_WORKSPACE_LIMIT,
        memory: &memory,
        work: &mut work,
        job: None,
    };
    assert!(
        super::record_gate::checkpoint::replay::replay(&fixture.correct, &mut context).is_err()
    );
    assert_eq!(work.remaining_verification_work_bytes(), 0);
    Ok(())
}

#[test]
fn gate_replay_charges_frame_lookup_and_order_vector_work() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let samples = fixture.samples();
    let stored = fixture.stored();
    let sessions = fixture
        .report
        .discovery_sessions
        .iter()
        .chain(&fixture.report.heldout_sessions)
        .collect::<Vec<_>>();
    let mut baseline = 0_usize;
    let mut mappings = 0_usize;
    for session in &sessions {
        let selected = samples
            .iter()
            .filter(|sample| {
                sample.context.source == session.source
                    && sample.context.scope == session.scope
                    && sample.context.session == session.session
            })
            .cloned()
            .collect::<Vec<_>>();
        let output = l2_workbench::protocol::apply_relational_transform_rule(
            &selected,
            &fixture.correct,
            RelationalTransformLimits::default(),
            LEARNING_WORK,
        )?;
        baseline += samples.len()
            * (fixture.correct.seed_locator.marker.len()
                + fixture.correct.payload_locator.marker.len()
                + 4 * size_of::<usize>());
        baseline += output.work_bytes + output.bytes.len();
        mappings += output.payload_mappings.len();
    }
    let required_frame_scans = mappings * (samples.len() + stored.len()) * size_of::<u64>();
    let required_orders = mappings * sessions.len() * size_of::<u64>();
    let memory = MemoryBudget::new(256 * 1024 * 1024);
    let mut work = RelationalRestoreBudget::new(LEARNING_WORK, 100_000);
    let mut context = SchemaCacheRestoreContext {
        raw_directional_run: false,
        samples: &samples,
        stored_samples: &stored,
        report: &fixture.report,
        relational_limits: RelationalTransformLimits::default(),
        schema_limits: RecordSchemaProposalLimits::default(),
        artifact_policy: ArtifactValidationPolicy::default(),
        maximum_checkpoint_bytes: CHECKPOINT_LIMIT,
        maximum_workspace_bytes: PLAN_WORKSPACE_LIMIT,
        memory: &memory,
        work: &mut work,
        job: None,
    };
    super::record_gate::checkpoint::replay::replay(&fixture.correct, &mut context)?;
    assert!(work.verification_work_bytes() >= baseline + required_frame_scans + required_orders);
    Ok(())
}

#[test]
fn restoring_header_plan_requires_work_after_producer_replay() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let samples = fixture.samples();
    let stored = fixture.stored();
    let memory = MemoryBudget::new(256 * 1024 * 1024);
    let (cache, _) = learn_decoy(&fixture, &samples, &stored, &memory)?;
    let limits = RecordSchemaProposalLimits::default()
        .discovery
        .record_limits;
    let mut description =
        serde_json::to_value(cache.checkpoint_description(limits, CHECKPOINT_LIMIT)?)?;
    let headers = description
        .get("headers")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing headers")?;
    assert_eq!(
        headers.len(),
        1,
        "fixture must contain one cached header plan"
    );
    assert_eq!(
        description
            .get("producers")
            .and_then(serde_json::Value::as_array)
            .ok_or("missing producers")?
            .len(),
        1
    );
    // Isolate header verification from the separately metered full schema plans
    *description.get_mut("plans").ok_or("missing plans")? = serde_json::json!([]);
    let bytes = serde_json::to_vec(&description)?;
    let mut replay_work = RelationalRestoreBudget::new(LEARNING_WORK, 100_000);
    let mut replay_context = SchemaCacheRestoreContext {
        raw_directional_run: false,
        samples: &samples,
        stored_samples: &stored,
        report: &fixture.report,
        relational_limits: RelationalTransformLimits::default(),
        schema_limits: RecordSchemaProposalLimits::default(),
        artifact_policy: ArtifactValidationPolicy::default(),
        maximum_checkpoint_bytes: CHECKPOINT_LIMIT,
        maximum_workspace_bytes: PLAN_WORKSPACE_LIMIT,
        memory: &memory,
        work: &mut replay_work,
        job: None,
    };
    super::record_gate::checkpoint::replay::replay(&fixture.decoy, &mut replay_context)?;
    let allowance = bytes.len() * 2 + replay_work.verification_work_bytes();
    let mut work = RelationalRestoreBudget::new(allowance, 100_000);
    let result = SchemaPlanCache::restore_checkpoint(
        &bytes,
        SchemaCacheRestoreContext {
            raw_directional_run: false,
            samples: &samples,
            stored_samples: &stored,
            report: &fixture.report,
            relational_limits: RelationalTransformLimits::default(),
            schema_limits: RecordSchemaProposalLimits::default(),
            artifact_policy: ArtifactValidationPolicy::default(),
            maximum_checkpoint_bytes: CHECKPOINT_LIMIT,
            maximum_workspace_bytes: PLAN_WORKSPACE_LIMIT,
            memory: &memory,
            work: &mut work,
            job: None,
        },
    );
    assert_restore_work_limited(result)?;
    assert_eq!(work.remaining_verification_work_bytes(), 0);
    Ok(())
}

fn assert_restore_work_limited(
    result: Result<SchemaPlanCache, crate::workbench::recovery_executor::RecoveryExecutionError>,
) -> Result<(), Box<dyn Error>> {
    let error = result
        .err()
        .ok_or("header reconstruction ignored exhausted work")?;
    let mut source: Option<&(dyn Error + 'static)> = Some(&error);
    let mut work_limited = false;
    while let Some(error) = source {
        work_limited |= matches!(
            error.downcast_ref::<l2_workbench::protocol::RelationalCursorError<std::convert::Infallible>>(),
            Some(l2_workbench::protocol::RelationalCursorError::RestoreWorkLimit)
        );
        source = error.source();
    }
    assert!(
        work_limited,
        "header reconstruction must report the exhausted verification allowance"
    );
    Ok(())
}

#[test]
fn restored_header_rejects_duplicate_or_unadmitted_saved_entries() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let samples = fixture.samples();
    let stored = fixture.stored();
    let memory = MemoryBudget::new(256 * 1024 * 1024);
    let (cache, _) = learn_decoy(&fixture, &samples, &stored, &memory)?;
    let mut limits = RecordSchemaProposalLimits::default();
    let mut description = serde_json::to_value(
        cache.checkpoint_description(limits.discovery.record_limits, CHECKPOINT_LIMIT)?,
    )?;
    *description.get_mut("plans").ok_or("missing plans")? = serde_json::json!([]);
    let original_header = description
        .get("headers")
        .and_then(serde_json::Value::as_array)
        .and_then(|headers| headers.first())
        .ok_or("missing header")?
        .clone();

    let mut duplicate = description.clone();
    duplicate
        .get_mut("headers")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("missing header list")?
        .push(original_header.clone());
    assert_invalid_header_restore(&fixture, &samples, &stored, &memory, limits, &duplicate)?;

    let key_bytes = original_header
        .pointer("/key/retained_bytes")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or("missing header key size")?;
    let saved: l2_workbench::protocol::RecordAssemblyPlanDescription = serde_json::from_value(
        original_header
            .get("description")
            .ok_or("missing plan")?
            .clone(),
    )?;
    let plan = saved.restore(
        limits.discovery.record_limits,
        CHECKPOINT_LIMIT,
        PLAN_WORKSPACE_LIMIT,
        &mut |_| Ok(()),
    )?;
    let ceiling = key_bytes
        .checked_add(plan.retained_bytes())
        .and_then(|bytes| bytes.checked_sub(1))
        .ok_or("invalid fixture size")?;
    limits.discovery.record_limits.max_report_bytes = ceiling;
    let header = description
        .get_mut("headers")
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|headers| headers.first_mut())
        .ok_or("missing header")?;
    *header
        .pointer_mut("/key/schema_limits/discovery/record_limits/max_report_bytes")
        .ok_or("missing key report limit")? = serde_json::json!(ceiling);
    *header
        .pointer_mut("/description/limits/max_report_bytes")
        .ok_or("missing plan report limit")? = serde_json::json!(ceiling);
    for model in header
        .pointer_mut("/description/models")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("missing plan models")?
    {
        *model
            .pointer_mut("/limits/max_report_bytes")
            .ok_or("missing model report limit")? = serde_json::json!(ceiling);
    }
    assert_invalid_header_restore(&fixture, &samples, &stored, &memory, limits, &description)
}

fn assert_invalid_header_restore(
    fixture: &Fixture,
    samples: &[RelationalRecordSample<'_>],
    stored: &[StoredSample],
    memory: &MemoryBudget,
    limits: RecordSchemaProposalLimits,
    description: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let bytes = serde_json::to_vec(description)?;
    let mut work = RelationalRestoreBudget::new(RESTORE_WORK, 100_000);
    let result = SchemaPlanCache::restore_checkpoint(
        &bytes,
        SchemaCacheRestoreContext {
            raw_directional_run: false,
            samples,
            stored_samples: stored,
            report: &fixture.report,
            relational_limits: RelationalTransformLimits::default(),
            schema_limits: limits,
            artifact_policy: ArtifactValidationPolicy::default(),
            maximum_checkpoint_bytes: CHECKPOINT_LIMIT,
            maximum_workspace_bytes: PLAN_WORKSPACE_LIMIT,
            memory,
            work: &mut work,
            job: None,
        },
    );
    match result {
        Err(crate::workbench::recovery_executor::RecoveryExecutionError::Coordinator(
            l2_workbench::recovery::RecoveryError::InvalidCheckpoint,
        )) => Ok(()),
        Ok(_) => Err("restored header cache silently discarded a saved entry".into()),
        Err(error) => Err(format!("unexpected header restore failure: {error:?}").into()),
    }
}
