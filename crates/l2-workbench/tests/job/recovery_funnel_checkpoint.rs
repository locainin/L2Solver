use l2_workbench::job::{
    Counter, Job, JobSnapshot, MemoryBudget, Phase, RecoveryCandidateSample,
    RecoveryFunnelAdmission, RecoveryFunnelAttribution, RecoveryFunnelEvent,
    RecoveryFunnelIdentity, RecoveryFunnelInput, RecoveryFunnelRegistration, RecoveryTransition,
    RecoveryTransitionOutcome, RecoveryTransitionStage, WorkSnapshot,
};
use serde_json::Value;
use std::{error::Error, fmt::Write};

type TestResult = Result<(), Box<dyn Error>>;

fn maximum_work_snapshot() -> Result<WorkSnapshot, Box<dyn Error>> {
    let mut wire = String::with_capacity(16 * 1024 * 1024);
    let digest = "0".repeat(64);
    let scope = "5".repeat(64);
    write!(
        wire,
        r#"{{"schema_version":1,"scope_id":"{scope}","counts":{{"counters":{{"candidates_examined":1234}},"phase_work":{{"framing_record_discovery":37}},"recovery_transitions":{{"records":[],"cohorts":["#
    )?;
    for cohort in 1..=64_u64 {
        if cohort > 1 {
            wire.push(',');
        }
        write!(
            wire,
            r#"{{"source_sha256":"{digest}","cohort_sha256":"{cohort:064x}","sessions":["#
        )?;
        for session in 1..=128_u64 {
            if session > 1 {
                wire.push(',');
            }
            write!(wire, "{session}")?;
        }
        wire.push_str(r#"],"stages":[],"last_viable_stage":null,"input_limit_reached":false,"hypothesis_limit_reached":false,"input_links":["#);
        for input in 1..=1024_u64 {
            if input > 1 {
                wire.push(',');
            }
            write!(wire, r#"{{"node_id":{input},"session_node_id":1}}"#)?;
        }
        wire.push_str(r#"],"hypotheses":["#);
        for candidate in 0..512_u64 {
            if candidate > 0 {
                wire.push(',');
            }
            write!(
                wire,
                r#"{{"stage":"validation","candidate_index":{candidate},"input_batch_sha256":"{candidate:064x}","task_sha256":"{digest}","input_blob_sha256":"{digest}","validated_artifact_sha256":null,"outcomes":8,"evidence_node_id":null}}"#
            )?;
        }
        wire.push_str("]}");
    }
    wire.push_str("]}}}");
    Ok(serde_json::from_str(&wire)?)
}

#[test]
fn maximal_diagnostic_checkpoint_fits_and_preserves_progress_with_explicit_omissions() -> TestResult
{
    let saved = maximum_work_snapshot()?;
    let budget = MemoryBudget::new(128 * 1024 * 1024);
    let producer = Job::with_memory_budget("maximum diagnostic snapshot", &budget);
    let worker = producer.work_scope(&"5".repeat(64))?;
    worker.restore_work(saved)?;
    let live_charge = budget.snapshot()?.used_bytes;
    let snapshot = worker.work_snapshot()?;
    let copied = snapshot.clone();
    assert!(
        budget.snapshot()?.used_bytes > live_charge,
        "the maximum snapshot copy must receive separate admission"
    );
    let encoded = serde_json::to_vec(&snapshot.checkpoint_view(1024 * 1024))?;
    drop(worker);
    drop(producer);
    drop(snapshot);
    assert!(
        budget.snapshot()?.used_bytes > 0,
        "a snapshot copy keeps its shared charge"
    );
    drop(copied);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    assert!(
        encoded.len() < 1024 * 1024,
        "optional diagnostics must leave room inside the recovery metadata envelope; got {} bytes",
        encoded.len()
    );
    let projected: WorkSnapshot = serde_json::from_slice(&encoded)?;
    assert_eq!(projected.counter(Counter::CandidatesExamined), 1234);
    assert_eq!(projected.phase_work(Phase::FramingRecordDiscovery), 37);

    assert_invalid_projection_is_rejected(&encoded)?;

    let resumed = Job::new("projected work");
    let worker = resumed.work_scope(&"5".repeat(64))?;
    worker.restore_work(projected)?;
    let summary = serde_json::to_value(resumed.snapshot()?.recovery_transitions)?;
    assert_projected_cohorts(&summary)
}

fn assert_invalid_projection_is_rejected(encoded: &[u8]) -> TestResult {
    let mut invalid_version: Value = serde_json::from_slice(encoded)?;
    *invalid_version
        .pointer_mut("/counts/recovery_transitions/checkpoint_projection_version")
        .ok_or("checkpoint projection version is missing")? = serde_json::json!(99);
    assert!(serde_json::from_value::<WorkSnapshot>(invalid_version).is_err());

    let mut invalid_stage: Value = serde_json::from_slice(encoded)?;
    *invalid_stage
        .pointer_mut("/counts/recovery_transitions/cohorts/0/stages/5/observed_candidates")
        .ok_or("projected stage count is missing")? = serde_json::json!(513);
    assert!(serde_json::from_value::<WorkSnapshot>(invalid_stage).is_err());

    let mut unsupported_count: Value = serde_json::from_slice(encoded)?;
    *unsupported_count
        .pointer_mut("/counts/recovery_transitions/cohorts/0/checkpoint_omitted_hypotheses")
        .ok_or("projected hypothesis omission count is missing")? = serde_json::json!(0);
    assert!(serde_json::from_value::<WorkSnapshot>(unsupported_count).is_err());

    Ok(())
}

fn assert_projected_cohorts(summary: &Value) -> TestResult {
    let cohorts = summary
        .get("cohorts")
        .and_then(Value::as_array)
        .ok_or("projected cohort identities are missing")?;
    assert_eq!(cohorts.len(), 64);
    for cohort in cohorts {
        assert_eq!(
            cohort.get("last_viable_stage"),
            Some(&serde_json::json!("validation"))
        );
        assert_eq!(
            cohort.get("checkpoint_omitted_input_links"),
            Some(&serde_json::json!(1024))
        );
        assert_eq!(
            cohort.get("checkpoint_omitted_hypotheses"),
            Some(&serde_json::json!(512))
        );
        assert_eq!(
            cohort
                .get("sessions")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(128)
        );
        let validation = cohort
            .get("stages")
            .and_then(Value::as_array)
            .and_then(|stages| {
                stages
                    .iter()
                    .find(|stage| stage.get("stage") == Some(&serde_json::json!("validation")))
            })
            .ok_or("validation stage is missing")?;
        assert_eq!(
            validation.get("candidates_with_survivors"),
            Some(&serde_json::json!(512))
        );
    }
    Ok(())
}

#[test]
fn small_checkpoint_keeps_full_diagnostics_and_zero_allowance_reports_reduction() -> TestResult {
    let job = Job::new("small checkpoint");
    let worker = job.work_scope(&"a".repeat(64))?;
    worker.increment(Counter::CandidatesExamined, 7)?;
    worker.register_recovery_cohort(RecoveryFunnelRegistration {
        identity: RecoveryFunnelIdentity {
            source_sha256: [1; 32],
            cohort_sha256: [2; 32],
        },
        inputs: &[RecoveryFunnelInput {
            node_id: 3,
            session_node_id: 4,
        }],
        total_inputs: 1,
        admission: RecoveryFunnelAdmission::Unknown,
    })?;
    worker.record_recovery_transition(RecoveryTransition {
        stage: RecoveryTransitionStage::Schema,
        outcome: RecoveryTransitionOutcome::WorkOmitted,
        sample: None,
    })?;
    let saved = worker.work_snapshot()?;
    assert_eq!(
        serde_json::to_value(saved.checkpoint_view(1024 * 1024))?,
        serde_json::to_value(&saved)?,
        "small checkpoints retain the original full representation"
    );

    let minimal = serde_json::to_value(saved.checkpoint_view(0))?;
    assert_eq!(
        minimal.pointer("/counts/counters/candidates_examined"),
        Some(&serde_json::json!(7))
    );
    assert_eq!(
        minimal.pointer("/counts/recovery_transitions/funnel_omission_reasons/checkpoint_size"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        minimal.pointer("/counts/recovery_transitions/checkpoint_omitted_transition_records"),
        Some(&serde_json::json!(1))
    );
    let restored: WorkSnapshot = serde_json::from_value(minimal)?;
    assert_eq!(restored.counter(Counter::CandidatesExamined), 7);
    Ok(())
}

#[test]
fn maximal_root_checkpoint_projects_diagnostics_before_persistence() -> TestResult {
    let saved = maximum_work_snapshot()?;
    let mut work_wire = serde_json::to_value(&saved)?;
    let transitions = work_wire
        .pointer_mut("/counts/recovery_transitions")
        .ok_or("work diagnostic summary is missing")?
        .take();
    let mut root_wire = serde_json::to_value(Job::new("root source").snapshot()?)?;
    *root_wire
        .get_mut("recovery_transitions")
        .ok_or("root diagnostic summary is missing")? = transitions;
    let restored: JobSnapshot = serde_json::from_value(root_wire)?;
    let root = Job::new("root resume");
    root.restore(restored)?;
    let encoded = serde_json::to_vec(&root.checkpoint_snapshot()?)?;
    assert!(
        encoded.len() < 1024 * 1024,
        "root checkpoint exceeded its diagnostic allowance: {}",
        encoded.len()
    );
    let checkpoint: JobSnapshot = serde_json::from_slice(&encoded)?;
    let wire = serde_json::to_value(checkpoint.recovery_transitions)?;
    assert_eq!(
        wire.pointer("/cohorts/0/last_viable_stage"),
        Some(&serde_json::json!("validation"))
    );
    assert_eq!(
        wire.pointer("/cohorts/0/checkpoint_omitted_input_links"),
        Some(&serde_json::json!(1024))
    );
    assert_eq!(
        wire.pointer("/cohorts/0/checkpoint_omitted_hypotheses"),
        Some(&serde_json::json!(512))
    );
    Ok(())
}

#[test]
fn repeated_candidate_after_projection_does_not_inflate_survivor_counts() -> TestResult {
    let scope = "b".repeat(64);
    let identity = RecoveryFunnelIdentity {
        source_sha256: [1; 32],
        cohort_sha256: [2; 32],
    };
    let inputs = [RecoveryFunnelInput {
        node_id: 3,
        session_node_id: 4,
    }];
    let first = Job::new("first work");
    let worker = first.work_scope(&scope)?;
    worker.register_recovery_cohort(RecoveryFunnelRegistration {
        identity,
        inputs: &inputs,
        total_inputs: 1,
        admission: RecoveryFunnelAdmission::Unknown,
    })?;
    for index in 0..32_u8 {
        let candidate = candidate(index);
        worker.record_recovery_funnel_candidate(RecoveryFunnelEvent {
            stage: RecoveryTransitionStage::Schema,
            outcome: RecoveryTransitionOutcome::Hypothesis,
            candidate: &candidate,
            input_nodes: &[3],
            parent_candidates: &[],
            attribution_complete: true,
            attribution: RecoveryFunnelAttribution::CandidateAndParents,
            validated_artifact_sha256: None,
        })?;
    }
    let saved = worker.work_snapshot()?;
    let encoded = serde_json::to_vec(&saved.checkpoint_view(8 * 1024))?;
    let restored: WorkSnapshot = serde_json::from_slice(&encoded)?;
    let resumed = Job::new("resumed work");
    let worker = resumed.work_scope(&scope)?;
    worker.restore_work(restored)?;
    worker.register_recovery_cohort(RecoveryFunnelRegistration {
        identity,
        inputs: &inputs,
        total_inputs: 1,
        admission: RecoveryFunnelAdmission::Unknown,
    })?;
    let repeated = candidate(0);
    worker.record_recovery_funnel_candidate(RecoveryFunnelEvent {
        stage: RecoveryTransitionStage::Schema,
        outcome: RecoveryTransitionOutcome::Hypothesis,
        candidate: &repeated,
        input_nodes: &[3],
        parent_candidates: &[],
        attribution_complete: true,
        attribution: RecoveryFunnelAttribution::CandidateAndParents,
        validated_artifact_sha256: None,
    })?;
    let summary = serde_json::to_value(resumed.snapshot()?.recovery_transitions)?;
    let stages = summary
        .pointer("/cohorts/0/stages")
        .and_then(Value::as_array)
        .ok_or("stage rows are missing")?;
    let schema = stages
        .iter()
        .find(|row| row.get("stage") == Some(&serde_json::json!("schema")))
        .ok_or("schema row is missing")?;
    assert_eq!(
        schema.get("candidates_with_survivors"),
        Some(&serde_json::json!(32))
    );
    Ok(())
}

fn candidate(index: u8) -> RecoveryCandidateSample {
    RecoveryCandidateSample {
        candidate_index: u64::from(index),
        input_node_id: 3,
        input_blob_sha256: [3; 32],
        input_batch_sha256: [index; 32],
        task_sha256: [4; 32],
        source_range: None,
        input_count: 1,
        evidence_node_id: None,
    }
}
