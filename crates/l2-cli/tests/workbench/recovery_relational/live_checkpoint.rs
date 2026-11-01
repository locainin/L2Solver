use super::super::super::{
    GateAssessment, PreparedRelationalCohort, RelationalCohortKey, RelationalDiscoveryContext,
    RelationalLane, record_gate::GateStatus,
};
use super::{admit_prepared, decode_history, validate_saved_assessment};
use l2_workbench::{
    job::MemoryBudget,
    protocol::{Direction, RelationalReplayHistory},
};

#[test]
fn saved_history_rejects_forged_capacity_before_allocating()
-> Result<(), Box<dyn std::error::Error>> {
    let memory = MemoryBudget::new(2 * 1024 * 1024);
    let mut saved = serde_json::to_value(RelationalReplayHistory::new(1024))?;
    *saved.get_mut("max_bytes").ok_or("missing history limit")? = serde_json::json!(u64::MAX);
    *saved
        .get_mut("entry_capacity")
        .ok_or("missing history capacity")? = serde_json::json!(u64::MAX / 128);
    let encoded = serde_json::to_vec(&saved)?;
    assert!(decode_history(&encoded, 1024, &memory).is_err());
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    assert_eq!(memory.snapshot()?.rejected, 0);
    Ok(())
}

#[test]
fn saved_history_holds_an_admission_until_its_data_is_dropped()
-> Result<(), Box<dyn std::error::Error>> {
    let memory = MemoryBudget::new(2 * 1024 * 1024);
    let encoded = serde_json::to_vec(&RelationalReplayHistory::new(1024))?;
    let (history, leases) = decode_history(&encoded, 1024, &memory)?;
    assert_eq!(history.maximum_bytes(), 1024);
    assert!(memory.snapshot()?.used_bytes > 0);
    drop(history);
    drop(leases);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn restored_positive_assessment_requires_a_replayable_receipt() {
    let assessment = GateAssessment {
        status: GateStatus::ArtifactValidated,
        details: serde_json::json!({}),
        accepted_schema: None,
        structural_evidence: None,
        assessment_scope: None,
        work_limited_at: None,
    };
    assert!(validate_saved_assessment(None, &assessment).is_err());
}

#[test]
fn restored_structural_assessment_requires_a_schema_witness() {
    let assessment = GateAssessment {
        status: GateStatus::StructurallySupported,
        details: serde_json::json!({}),
        accepted_schema: None,
        structural_evidence: None,
        assessment_scope: None,
        work_limited_at: None,
    };
    assert!(validate_saved_assessment(None, &assessment).is_err());
}

#[test]
fn each_completed_cohort_keeps_a_separate_charge_until_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let memory = MemoryBudget::new(4 * 1024 * 1024);
    let mut first = prepared_cohort(4096);
    let mut second = prepared_cohort(8192);
    let first_charge = admit_prepared(&mut first, &memory)?;
    let first_used = memory.snapshot()?.used_bytes;
    assert!(first_used >= 4096);
    let second_charge = admit_prepared(&mut second, &memory)?;
    let both_used = memory.snapshot()?.used_bytes;
    assert!(both_used > first_used);
    drop(first);
    drop(first_charge);
    assert!(memory.snapshot()?.used_bytes > 0 && memory.snapshot()?.used_bytes < both_used);
    drop(second);
    drop(second_charge);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

fn prepared_cohort(report_bytes: usize) -> PreparedRelationalCohort {
    PreparedRelationalCohort {
        context: RelationalDiscoveryContext {
            lane: RelationalLane::Normal,
            key: RelationalCohortKey {
                source_id: "source".into(),
                scope_json: "scope".into(),
                endpoints_json: "{}".into(),
                direction: Direction::FirstToSecond,
                framing_rule_json: "framed".into(),
                schema_json: "{}".into(),
            },
            sample_node_ids: Vec::new(),
            samples: Vec::new(),
            sessions_available: 0,
            omitted_sessions: 0,
            omitted_samples: 0,
            source_eligibility_omissions: 0,
            input_coverage_complete: true,
        },
        report_bytes: vec![0x5a; report_bytes],
        outputs: Vec::new(),
        decoded_frames: Vec::new(),
        accepted_schemas: Vec::new(),
        structural_evidence: Vec::new(),
        producer_rules: Vec::new(),
        producer_memory: None,
        published_rules: Vec::new(),
        history_used: false,
        report_details_complete: true,
        search_exhaustive_within_plan: false,
        candidate_limit_remaining: 0,
        locator_candidate_limit_remaining: 0,
        work_bytes_remaining: 0,
        reason: None,
    }
}
