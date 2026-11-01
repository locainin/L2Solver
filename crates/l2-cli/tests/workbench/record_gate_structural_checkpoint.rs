use super::super::checkpoint::{SchemaCacheRestoreContext, structural};
use super::super::screen::screen_with_schema_plan_with_memory;
use super::*;
use l2_workbench::{
    job::MemoryBudget,
    protocol::{
        RelationalRestoreBudget, RelationalSessionId, RelationalTransformEvaluationContext,
        RelationalTransformLimits,
    },
};

#[test]
fn structural_positive_checkpoint_reparses_schema_and_rejects_forgery() -> TestResult {
    let frames = structural_frames();
    let plan = schema_plan(Some(surviving_report(frames.len())), true);
    let memory = MemoryBudget::new(8 * 1024 * 1024);
    let result = screen(&frames, &plan, &memory)?;
    assert_eq!(result.status, GateStatus::StructurallySupported);
    let encoded = serde_json::to_vec(
        result
            .structural_evidence
            .as_ref()
            .ok_or("missing structural witness")?,
    )?;
    let evidence: structural::StructuralEvidence = serde_json::from_slice(&encoded)?;
    verify(&evidence, &frames)?;

    let mut bad_schema = evidence.clone();
    bad_schema
        .witnesses
        .first_mut()
        .ok_or("missing schema witness")?
        .schema
        .length
        .offset = 0;
    assert!(verify(&bad_schema, &frames).is_err());
    let mut bad_membership = evidence;
    let witness = bad_membership
        .witnesses
        .first_mut()
        .ok_or("missing membership witness")?;
    let shortened = witness
        .frame_indices
        .len()
        .checked_sub(1)
        .ok_or("empty witness")?;
    witness.frame_indices = Arc::from(
        witness
            .frame_indices
            .get(..shortened)
            .ok_or("bad witness")?,
    );
    assert!(verify(&bad_membership, &frames).is_err());
    Ok(())
}

#[test]
fn structural_family_checkpoint_checks_selector_coverage() -> TestResult {
    let frames = structural_frames();
    let mut plan = schema_plan(Some(surviving_report(frames.len())), true);
    let alternative = plan.alternatives.first_mut().ok_or("missing alternative")?;
    alternative.frame_indices = Some(Arc::from([0_usize, 1, 2]));
    alternative.details = json!({"family":{"selector_range":{"start":0,"end":1}}});
    plan.details = json!({"family":{"family_analysis":{"selectors":[{
        "range":{"start":0,"end":1}, "families":[{"training_samples":[1,2],"heldout_samples":[3]}]
    }]}}});
    let memory = MemoryBudget::new(8 * 1024 * 1024);
    let result = screen(&frames, &plan, &memory)?;
    assert_eq!(result.status, GateStatus::StructurallySupported);
    let evidence = result.structural_evidence.ok_or("missing family witness")?;
    verify(&evidence, &frames)?;
    let mut forged = evidence;
    let byte = forged
        .family_selectors
        .first_mut()
        .and_then(|selector| selector.values.first_mut())
        .and_then(|value| value.first_mut())
        .ok_or("missing selector value")?;
    *byte ^= 1;
    assert!(verify(&forged, &frames).is_err());
    Ok(())
}

#[test]
fn one_supported_family_keeps_complete_membership_without_forging_other_support() -> TestResult {
    let frames = [
        structural_frame_with_length(1, 0, b'A', b"a"),
        structural_frame_with_length(2, 1, b'A', b"b"),
        structural_frame_with_length(3, 2, b'A', b"c"),
        structural_frame_with_length(4, 0, b'B', b"d"),
        structural_frame_with_length(5, 1, b'B', b"e"),
        structural_frame_with_length(6, 2, b'B', b"f"),
    ];
    let mut plan = schema_plan(Some(surviving_report(3)), true);
    let alternative = plan.alternatives.first_mut().ok_or("missing alternative")?;
    alternative.frame_indices = Some(Arc::from([0_usize, 1, 2]));
    alternative.details = json!({"family":{"selector_range":{"start":0,"end":1}}});
    plan.details = json!({"family":{"family_analysis":{"selectors":[{
        "range":{"start":0,"end":1}, "families":[
            {"training_samples":[1,2],"heldout_samples":[3]},
            {"training_samples":[4,5],"heldout_samples":[6]}
        ]
    }]}}});
    let memory = MemoryBudget::new(8 * 1024 * 1024);
    let evidence = screen(&frames, &plan, &memory)?
        .structural_evidence
        .ok_or("missing family witness")?;
    assert_eq!(evidence.witnesses.len(), 1);
    verify_with_partition(&evidence, &frames, &[1, 2, 4, 5], &[3, 6], 1024 * 1024)?;
    let mut changed = frames;
    *changed
        .last_mut()
        .and_then(|frame| frame.bytes.first_mut())
        .ok_or("missing family frame")? = b'C';
    assert!(
        verify_with_partition(&evidence, &changed, &[1, 2, 4, 5], &[3, 6], 1024 * 1024).is_err()
    );
    Ok(())
}

#[test]
fn structural_checkpoint_uses_a_bounded_verification_budget() -> TestResult {
    let frames = structural_frames();
    let plan = schema_plan(Some(surviving_report(frames.len())), true);
    let memory = MemoryBudget::new(8 * 1024 * 1024);
    let result = screen(&frames, &plan, &memory)?;
    let evidence = result
        .structural_evidence
        .ok_or("missing structural witness")?;
    assert!(verify_with_budget(&evidence, &frames, 0).is_err());
    verify_with_budget(&evidence, &frames, 1024 * 1024)
}

#[test]
fn structural_witness_admission_follows_shared_identity_lifetime() -> TestResult {
    let memory = MemoryBudget::new(64 * 1024);
    let witness =
        structural::capture_witness(&structural_schema(), &[0, 1, 2], Some(&memory), 4096)?
            .ok_or("small witness was not admitted")?;
    let charged = memory.snapshot()?.used_bytes;
    assert!(charged > 0);
    let shared = witness.clone();
    drop(witness);
    assert_eq!(memory.snapshot()?.used_bytes, charged);
    drop(shared);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    assert!(
        structural::capture_witness(&structural_schema(), &[0, 1, 2], Some(&memory), 1)?.is_none()
    );
    let witness =
        structural::capture_witness(&structural_schema(), &[0, 1, 2], Some(&memory), 4096)?
            .ok_or("small witness was not admitted")?;
    let mut plan = schema_plan(Some(surviving_report(3)), true);
    plan.alternatives
        .first_mut()
        .ok_or("missing alternative")?
        .limits
        .discovery
        .record_limits
        .max_report_bytes = 1;
    let evidence = structural::capture_evidence(
        &structural_frames(),
        &plan,
        std::slice::from_ref(&witness),
        None,
        Some(&memory),
        4096,
    )?
    .ok_or("valid checkpoint metadata was rejected by an unrelated report limit")?;
    drop(evidence);
    assert!(
        structural::capture_evidence(
            &structural_frames(),
            &plan,
            &[witness],
            None,
            Some(&memory),
            1,
        )?
        .is_none()
    );
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn completed_structural_evidence_transfers_its_charge_to_cohort_admission() -> TestResult {
    let frames = structural_frames();
    let plan = schema_plan(Some(surviving_report(frames.len())), true);
    let memory = MemoryBudget::new(8 * 1024 * 1024);
    let mut evidence = screen(&frames, &plan, &memory)?
        .structural_evidence
        .ok_or("missing structural evidence")?;
    let encoded = serde_json::to_vec(&evidence)?;
    let admission =
        l2_workbench::job::admit_json(&encoded, &memory, l2_workbench::job::MemoryClass::Executor)?;
    let retained = admission.into_retained();
    let before = memory.snapshot()?.used_bytes;
    evidence.release_capture_admission();
    let after = memory.snapshot()?.used_bytes;
    assert!(after > 0 && after < before);
    drop(evidence);
    drop(retained);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

fn verify(evidence: &structural::StructuralEvidence, frames: &[DecodedFrameOutput]) -> TestResult {
    verify_with_budget(evidence, frames, 1024 * 1024)
}

fn screen(
    frames: &[DecodedFrameOutput],
    plan: &SchemaPlan,
    memory: &MemoryBudget,
) -> Result<GateResult, crate::workbench::recovery_executor::RecoveryExecutionError> {
    screen_with_schema_plan_with_memory(
        frames,
        super::super::SchemaCandidateOptions {
            parser_format: ArtifactValidationFormat::Png,
            artifact_policy: ArtifactValidationPolicy::default(),
            schema_limits: RecordSchemaProposalLimits::default(),
            work_limit: STRUCTURAL_CHECK_WORK_LIMIT,
            job: None,
            producer_rule: None,
            structural_admission: Some(&super::super::StructuralAdmission {
                memory,
                maximum: 1024 * 1024,
            }),
        },
        plan,
        false,
    )
}

fn verify_with_budget(
    evidence: &structural::StructuralEvidence,
    frames: &[DecodedFrameOutput],
    maximum_work: usize,
) -> TestResult {
    verify_with_partition(evidence, frames, &[1, 2], &[3], maximum_work)
}

fn verify_with_partition(
    evidence: &structural::StructuralEvidence,
    frames: &[DecodedFrameOutput],
    discovery_ids: &[u64],
    heldout_ids: &[u64],
    maximum_work: usize,
) -> TestResult {
    let session = |&session| RelationalSessionId {
        source: "source".into(),
        scope: "scope".into(),
        session,
    };
    let discovery = discovery_ids.iter().map(session).collect::<Vec<_>>();
    let heldout = heldout_ids.iter().map(session).collect::<Vec<_>>();
    let report = crate::workbench::recovery_executor::relational::search::empty_gate_report(
        &RelationalTransformEvaluationContext {
            discovery_sessions: &discovery,
            heldout_sessions: &heldout,
            work_bytes_remaining: 0,
        },
    );
    let memory = MemoryBudget::new(8 * 1024 * 1024);
    let mut work = RelationalRestoreBudget::new(maximum_work, 1024);
    let mut context = SchemaCacheRestoreContext {
        raw_directional_run: false,
        samples: &[],
        stored_samples: &[],
        report: &report,
        relational_limits: RelationalTransformLimits::default(),
        schema_limits: RecordSchemaProposalLimits::default(),
        artifact_policy: ArtifactValidationPolicy::default(),
        maximum_checkpoint_bytes: 1024 * 1024,
        maximum_workspace_bytes: 2 * 1024 * 1024,
        memory: &memory,
        work: &mut work,
        job: None,
    };
    structural::verify(evidence, frames, &mut context)?;
    Ok(())
}
